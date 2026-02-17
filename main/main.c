#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "driver/gpio.h"
#include "esp_event.h"
#include "esp_https_ota.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_app_desc.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "soc/gpio_struct.h"

#if __has_include("esp_crt_bundle.h")
#include "esp_crt_bundle.h"
#define HAS_CRT_BUNDLE 1
#else
#define HAS_CRT_BUNDLE 0
#endif

#define TAG "sniffer"

#define CLK_GPIO CONFIG_SNIFFER_CLK_GPIO
#define DATA_GPIO CONFIG_SNIFFER_DATA_GPIO
#define FRAME_GAP_US CONFIG_SNIFFER_FRAME_GAP_US

#define WIFI_SSID CONFIG_SNIFFER_WIFI_SSID
#define WIFI_PASS CONFIG_SNIFFER_WIFI_PASSWORD
#define OTA_URL CONFIG_SNIFFER_OTA_FIRMWARE_URL

#define MAX_FRAME_BITS 64
#define EVENT_QUEUE_LEN 256
#define MAX_MUX_SLOTS 8
#define MUX_DIGIT_STALE_US (500LL * 1000LL)
#define CROSS_FRAME_PAIR_US (20LL * 1000LL)
#define AUTO_GAP_MULTIPLIER 12
#define AUTO_GAP_MIN_US 120
#define TIMING_LOG_PERIOD_US (2000LL * 1000LL)
#define PAUSE_SHORT_US 6000
#define PAUSE_MID_US 11000
#define PAUSE_LONG_US 18000
#define MAX_CYCLE_BYTES 96

#define TELEGRAM_POLL_TIMEOUT_S 5
#define TELEGRAM_RESP_MAX 2048
#define STATUS_STALE_US (15LL * 1000LL * 1000LL)
#define OTA_HTTP_RX_BUFFER 8192
#define OTA_HTTP_TX_BUFFER 1024
#define OTA_HTTP_TIMEOUT_MS 30000

#define WIFI_CONNECTED_BIT BIT0
#define TELEGRAM_NVS_NS "telegram"
#define TELEGRAM_NVS_KEY_OFFSET "next_offset"

typedef struct {
    uint8_t bit;
    int64_t ts_us;
} bit_event_t;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} http_resp_buf_t;

static QueueHandle_t s_bit_queue;
static EventGroupHandle_t s_wifi_events;
static SemaphoreHandle_t s_state_mutex;
static esp_netif_t *s_sta_netif;

static char s_last_raw[96];
static char s_last_hex[64];
static char s_last_decoded[16];
static char s_last_decode_status[24];
static int64_t s_last_frame_us;
static bool s_last_decode_ok;
static int s_mux_digit[MAX_MUX_SLOTS];
static bool s_mux_valid[MAX_MUX_SLOTS];
static int64_t s_mux_seen_us[MAX_MUX_SLOTS];
static bool s_prev_single_valid;
static uint8_t s_prev_single_byte;
static int64_t s_prev_single_ts_us;

static inline uint32_t IRAM_ATTR gpio_level_fast(gpio_num_t gpio_num)
{
    if ((uint32_t)gpio_num < 32U) {
        return (GPIO.in >> (uint32_t)gpio_num) & 0x1U;
    }
    return (GPIO.in1.data >> ((uint32_t)gpio_num - 32U)) & 0x1U;
}

typedef struct {
    uint64_t dt_count;
    uint64_t dt_sum_us;
    int64_t dt_min_us;
    int64_t dt_max_us;
    uint32_t long_gap_count;
    int64_t long_gap_max_us;
    int64_t clk_period_ema_us;
    int64_t last_log_ts_us;
} timing_stats_t;

typedef enum {
    GAP_NONE = 0,
    GAP_SHORT,
    GAP_MID,
    GAP_LONG,
} gap_kind_t;

typedef struct {
    uint8_t bytes[MAX_CYCLE_BYTES];
    int nbytes;
    int subframes;
    int gap_short_count;
    int gap_mid_count;
    int gap_long_count;
    int64_t start_ts_us;
    int64_t last_ts_us;
} cycle_state_t;

static int64_t telegram_load_next_offset(void)
{
    nvs_handle_t nvs = 0;
    esp_err_t err = nvs_open(TELEGRAM_NVS_NS, NVS_READONLY, &nvs);
    if (err != ESP_OK) {
        return 0;
    }

    int64_t next_offset = 0;
    err = nvs_get_i64(nvs, TELEGRAM_NVS_KEY_OFFSET, &next_offset);
    nvs_close(nvs);
    if (err != ESP_OK) {
        return 0;
    }
    return next_offset;
}

static void telegram_store_next_offset(int64_t next_offset)
{
    nvs_handle_t nvs = 0;
    esp_err_t err = nvs_open(TELEGRAM_NVS_NS, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs_open(%s) failed: %s", TELEGRAM_NVS_NS, esp_err_to_name(err));
        return;
    }

    err = nvs_set_i64(nvs, TELEGRAM_NVS_KEY_OFFSET, next_offset);
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "store next_offset failed: %s", esp_err_to_name(err));
    }
}

static const uint8_t seg_map[10] = {
    0x3F, // 0
    0x06, // 1
    0x5B, // 2
    0x4F, // 3
    0x66, // 4
    0x6D, // 5
    0x7D, // 6
    0x07, // 7
    0x7F, // 8
    0x6F  // 9
};

typedef struct {
    bool active_low;
    bool bit_reversed;
} decode_mode_t;

static uint8_t reverse_bits8(uint8_t v)
{
    v = (uint8_t)(((v & 0xF0) >> 4) | ((v & 0x0F) << 4));
    v = (uint8_t)(((v & 0xCC) >> 2) | ((v & 0x33) << 2));
    v = (uint8_t)(((v & 0xAA) >> 1) | ((v & 0x55) << 1));
    return v;
}

static int selector_slot_from_byte(uint8_t v, bool *active_low)
{
    uint8_t low_mask = (uint8_t)(~v);
    if (__builtin_popcount((unsigned)low_mask) == 1) {
        *active_low = true;
        return (int)__builtin_ctz((unsigned)low_mask);
    }
    if (__builtin_popcount((unsigned)v) == 1) {
        *active_low = false;
        return (int)__builtin_ctz((unsigned)v);
    }
    return -1;
}

static int seg_to_digit(uint8_t seg, decode_mode_t mode)
{
    uint8_t norm = seg & 0x7F;
    if (mode.bit_reversed) {
        norm = reverse_bits8(norm) & 0x7F;
    }
    if (mode.active_low) {
        norm = (~norm) & 0x7F;
    }

    for (int i = 0; i < 10; ++i) {
        if (norm == seg_map[i]) {
            return i;
        }
    }
    return -1;
}

static bool decode_segment_byte(uint8_t seg, int *digit, decode_mode_t *mode_used)
{
    const decode_mode_t modes[] = {
        {.active_low = false, .bit_reversed = false},
        {.active_low = true, .bit_reversed = false},
        {.active_low = false, .bit_reversed = true},
        {.active_low = true, .bit_reversed = true},
    };

    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
        int d = seg_to_digit(seg, modes[i]);
        if (d >= 0) {
            *digit = d;
            *mode_used = modes[i];
            return true;
        }
    }
    return false;
}

static const char *mode_tag(decode_mode_t mode)
{
    if (!mode.active_low && !mode.bit_reversed) {
        return "ah_msb";
    }
    if (mode.active_low && !mode.bit_reversed) {
        return "al_msb";
    }
    if (!mode.active_low && mode.bit_reversed) {
        return "ah_lsb";
    }
    return "al_lsb";
}

static bool build_mux_2digit(char *decoded, size_t decoded_len)
{
    int first_slot = -1;
    int second_slot = -1;
    int64_t now = esp_timer_get_time();

    for (int i = 0; i < MAX_MUX_SLOTS; ++i) {
        if (!s_mux_valid[i]) {
            continue;
        }
        if ((now - s_mux_seen_us[i]) > MUX_DIGIT_STALE_US) {
            continue;
        }
        if (first_slot < 0) {
            first_slot = i;
            continue;
        }
        second_slot = i;
        break;
    }

    if (first_slot >= 0 && second_slot >= 0) {
        snprintf(decoded, decoded_len, "%d%d", s_mux_digit[first_slot], s_mux_digit[second_slot]);
        return true;
    }
    return false;
}

static int decode_status_rank(const char *status)
{
    if (!status) {
        return 0;
    }
    if (strncmp(status, "ok(", 3) == 0) {
        return 4;
    }
    if (strncmp(status, "partial(mux)", 12) == 0) {
        return 3;
    }
    if (strncmp(status, "partial(single)", 15) == 0) {
        return 2;
    }
    if (strncmp(status, "partial", 7) == 0) {
        return 1;
    }
    return 0;
}

static void build_raw_string(const uint8_t *bits, int nbits, char *out, size_t out_len)
{
    int max_bits = (int)out_len - 1;
    if (max_bits < 0) {
        return;
    }

    int use_bits = nbits < max_bits ? nbits : max_bits;
    for (int i = 0; i < use_bits; ++i) {
        out[i] = bits[i] ? '1' : '0';
    }
    out[use_bits] = '\0';
}

static int bits_to_bytes(const uint8_t *bits, int nbits, uint8_t *bytes, int max_bytes)
{
    int nbytes = nbits / 8;
    if (nbytes > max_bytes) {
        nbytes = max_bytes;
    }

    for (int b = 0; b < nbytes; ++b) {
        uint8_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v = (uint8_t)((v << 1) | (bits[b * 8 + i] & 0x01));
        }
        bytes[b] = v;
    }

    return nbytes;
}

static void build_hex_string(const uint8_t *bytes, int nbytes, char *out, size_t out_len)
{
    out[0] = '\0';
    size_t used = 0;

    for (int i = 0; i < nbytes; ++i) {
        int n = snprintf(out + used, out_len - used, "%s%02X", (i == 0) ? "" : " ", bytes[i]);
        if (n <= 0 || (size_t)n >= (out_len - used)) {
            break;
        }
        used += (size_t)n;
    }
}

static void decode_digits(const uint8_t *bytes, int nbytes, char *decoded, size_t decoded_len, const char **status)
{
    snprintf(decoded, decoded_len, "unknown");
    *status = "unknown";

    if (nbytes <= 0) {
        return;
    }

    if (nbytes >= 2) {
        const decode_mode_t modes[] = {
            {.active_low = false, .bit_reversed = false},
            {.active_low = true, .bit_reversed = false},
            {.active_low = false, .bit_reversed = true},
            {.active_low = true, .bit_reversed = true},
        };

        for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
            int d0 = seg_to_digit(bytes[0], modes[i]);
            int d1 = seg_to_digit(bytes[1], modes[i]);
            if (d0 >= 0 && d1 >= 0) {
                snprintf(decoded, decoded_len, "%d%d", d0, d1);
                *status = "ok(direct)";
                return;
            }
        }
    }

    for (int i = 0; i < nbytes - 1; ++i) {
        const uint8_t seg_cand[2] = {bytes[i], bytes[i + 1]};
        const uint8_t sel_cand[2] = {bytes[i + 1], bytes[i]};

        for (int p = 0; p < 2; ++p) {
            bool sel_active_low = false;
            int slot = selector_slot_from_byte(sel_cand[p], &sel_active_low);
            if (slot < 0 || slot >= MAX_MUX_SLOTS) {
                continue;
            }

            int digit = -1;
            decode_mode_t mode = {0};
            if (!decode_segment_byte(seg_cand[p], &digit, &mode)) {
                continue;
            }

            s_mux_digit[slot] = digit;
            s_mux_valid[slot] = true;
            s_mux_seen_us[slot] = esp_timer_get_time();

            if (build_mux_2digit(decoded, decoded_len)) {
                *status = "ok(mux)";
            } else {
                snprintf(decoded, decoded_len, "%d?", digit);
                *status = "partial(mux)";
            }
            ESP_LOGD(TAG, "mux slot=%d digit=%d sel=%s mode=%s", slot, digit, sel_active_low ? "active_low" : "active_high", mode_tag(mode));
            return;
        }
    }

    if (nbytes >= 1) {
        int d = -1;
        decode_mode_t mode = {0};
        if (decode_segment_byte(bytes[0], &d, &mode)) {
            snprintf(decoded, decoded_len, "%d?", d);
            *status = "partial(single)";
            return;
        }
    }

    if (nbytes >= 2) {
        *status = "partial";
        return;
    }
}

static esp_err_t telegram_http_event_handler(esp_http_client_event_t *evt)
{
    http_resp_buf_t *buf = (http_resp_buf_t *)evt->user_data;

    if (evt->event_id == HTTP_EVENT_ON_DATA && buf && evt->data && evt->data_len > 0) {
        if (buf->len + (size_t)evt->data_len >= buf->cap) {
            size_t available = (buf->cap > buf->len + 1) ? (buf->cap - buf->len - 1) : 0;
            if (available > 0) {
                memcpy(buf->data + buf->len, evt->data, available);
                buf->len += available;
                buf->data[buf->len] = '\0';
            }
            return ESP_ERR_NO_MEM;
        }

        memcpy(buf->data + buf->len, evt->data, evt->data_len);
        buf->len += (size_t)evt->data_len;
        buf->data[buf->len] = '\0';
    }

    return ESP_OK;
}

static bool telegram_http_get(const char *url, char *out, size_t out_len)
{
    out[0] = '\0';
    http_resp_buf_t resp = {
        .data = out,
        .len = 0,
        .cap = out_len,
    };

    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_GET,
        .timeout_ms = (TELEGRAM_POLL_TIMEOUT_S + 5) * 1000,
        .event_handler = telegram_http_event_handler,
        .user_data = &resp,
    };
#if HAS_CRT_BUNDLE
    cfg.crt_bundle_attach = esp_crt_bundle_attach;
#endif

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        return false;
    }

    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    return (err == ESP_OK && status == 200);
}

static bool telegram_send_text(const char *chat_id, const char *text)
{
#if CONFIG_SNIFFER_ENABLE_TELEGRAM
    if (strlen(CONFIG_SNIFFER_TELEGRAM_BOT_TOKEN) == 0) {
        return false;
    }

    char url[256];
    snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendMessage", CONFIG_SNIFFER_TELEGRAM_BOT_TOKEN);

    char body[512];
    snprintf(body, sizeof(body), "{\"chat_id\":\"%s\",\"text\":\"%s\"}", chat_id, text);

    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 5000,
    };
#if HAS_CRT_BUNDLE
    cfg.crt_bundle_attach = esp_crt_bundle_attach;
#endif

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        return false;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, body, (int)strlen(body));

    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    return (err == ESP_OK && status == 200);
#else
    (void)chat_id;
    (void)text;
    return false;
#endif
}

static bool ota_update_from_github(char *result, size_t result_len)
{
#if CONFIG_SNIFFER_ENABLE_OTA
    if (strlen(OTA_URL) == 0) {
        snprintf(result, result_len, "ota: URL is empty");
        return false;
    }

    esp_http_client_config_t http_cfg = {
        .url = OTA_URL,
        .timeout_ms = OTA_HTTP_TIMEOUT_MS,
        .buffer_size = OTA_HTTP_RX_BUFFER,
        .buffer_size_tx = OTA_HTTP_TX_BUFFER,
        .keep_alive_enable = true,
    };
#if HAS_CRT_BUNDLE
    http_cfg.crt_bundle_attach = esp_crt_bundle_attach;
#endif

    esp_https_ota_config_t ota_cfg = {
        .http_config = &http_cfg,
    };

    ESP_LOGI(TAG, "OTA start: %s", OTA_URL);
    esp_err_t err = esp_https_ota(&ota_cfg);
    if (err == ESP_OK) {
        snprintf(result, result_len, "ota: success, rebooting");
        return true;
    }

    snprintf(result, result_len, "ota: failed (%s)", esp_err_to_name(err));
    ESP_LOGW(TAG, "OTA failed: %s", esp_err_to_name(err));
    return false;
#else
    snprintf(result, result_len, "ota: disabled in config");
    return false;
#endif
}

static void build_decoded_reply(char *out, size_t out_len)
{
    char decoded[16] = {0};
    char decode_status[24] = {0};
    int64_t frame_us = 0;

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    strncpy(decoded, s_last_decoded, sizeof(decoded) - 1);
    strncpy(decode_status, s_last_decode_status, sizeof(decode_status) - 1);
    frame_us = s_last_frame_us;
    xSemaphoreGive(s_state_mutex);

    int64_t age_us = esp_timer_get_time() - frame_us;
    if (frame_us > 0 && age_us <= STATUS_STALE_US && strncmp(decode_status, "ok(", 3) == 0) {
        snprintf(out, out_len, "%s", decoded);
    } else {
        snprintf(out, out_len, "unknown");
    }
}

static void build_fw_version_reply(char *out, size_t out_len)
{
    const esp_app_desc_t *app_desc = esp_app_get_description();
    const char *fw_version = (app_desc && app_desc->version[0] != '\0') ? app_desc->version : "unknown";
    snprintf(out, out_len, "%s", fw_version);
}

static void send_temp_series(const char *chat_id)
{
    for (int i = 0; i < 10; ++i) {
        char reply[96];
        build_decoded_reply(reply, sizeof(reply));
        if (!telegram_send_text(chat_id, reply)) {
            ESP_LOGW(TAG, "telegram send failed");
            break;
        }

        if (i < 9) {
            vTaskDelay(pdMS_TO_TICKS(3000));
        }
    }
}

static void telegram_poll_and_respond(int64_t *next_offset)
{
#if CONFIG_SNIFFER_ENABLE_TELEGRAM
    if (strlen(CONFIG_SNIFFER_TELEGRAM_BOT_TOKEN) == 0) {
        vTaskDelay(pdMS_TO_TICKS(2000));
        return;
    }

    char url[320];
    snprintf(url,
             sizeof(url),
             "https://api.telegram.org/bot%s/getUpdates?timeout=%d&offset=%lld",
             CONFIG_SNIFFER_TELEGRAM_BOT_TOKEN,
             TELEGRAM_POLL_TIMEOUT_S,
             (long long)*next_offset);

    char response[TELEGRAM_RESP_MAX];
    if (!telegram_http_get(url, response, sizeof(response))) {
        vTaskDelay(pdMS_TO_TICKS(1500));
        return;
    }

    cJSON *root = cJSON_Parse(response);
    if (!root) {
        ESP_LOGW(TAG, "telegram parse failed");
        return;
    }

    cJSON *result = cJSON_GetObjectItem(root, "result");
    if (!cJSON_IsArray(result)) {
        cJSON_Delete(root);
        return;
    }

    cJSON *item = NULL;
    cJSON_ArrayForEach(item, result)
    {
        cJSON *update_id = cJSON_GetObjectItem(item, "update_id");
        if (cJSON_IsNumber(update_id)) {
            int64_t id = (int64_t)update_id->valuedouble;
            if (id >= *next_offset) {
                *next_offset = id + 1;
                telegram_store_next_offset(*next_offset);
            }
        }

        cJSON *message = cJSON_GetObjectItem(item, "message");
        if (!cJSON_IsObject(message)) {
            continue;
        }

        cJSON *text = cJSON_GetObjectItem(message, "text");
        if (!cJSON_IsString(text) || !text->valuestring) {
            continue;
        }

        bool cmd_status = (strcmp(text->valuestring, "/status") == 0);
        bool cmd_get_temp = (strcmp(text->valuestring, "/get_temp") == 0);
        bool cmd_update = (strcmp(text->valuestring, "/update") == 0);
        bool cmd_ota_legacy = (strcmp(text->valuestring, "/ota") == 0);
        if (!cmd_status && !cmd_get_temp && !cmd_update && !cmd_ota_legacy) {
            continue;
        }

        cJSON *chat = cJSON_GetObjectItem(message, "chat");
        cJSON *chat_id = chat ? cJSON_GetObjectItem(chat, "id") : NULL;
        char chat_id_str[32] = {0};

        if (cJSON_IsString(chat_id) && chat_id->valuestring) {
            strncpy(chat_id_str, chat_id->valuestring, sizeof(chat_id_str) - 1);
        } else if (cJSON_IsNumber(chat_id)) {
            snprintf(chat_id_str, sizeof(chat_id_str), "%.0f", chat_id->valuedouble);
        } else {
            continue;
        }

        if (strlen(CONFIG_SNIFFER_TELEGRAM_CHAT_ID) > 0 && strcmp(chat_id_str, CONFIG_SNIFFER_TELEGRAM_CHAT_ID) != 0) {
            continue;
        }

        if (cmd_status) {
            char reply[32];
            build_fw_version_reply(reply, sizeof(reply));
            if (!telegram_send_text(chat_id_str, reply)) {
                ESP_LOGW(TAG, "telegram send failed");
            }
            continue;
        }

        if (cmd_get_temp) {
            send_temp_series(chat_id_str);
            continue;
        }

        if (!telegram_send_text(chat_id_str, "ota: start (/update)")) {
            ESP_LOGW(TAG, "telegram send failed");
        }

        char ota_reply[96];
        bool ota_ok = ota_update_from_github(ota_reply, sizeof(ota_reply));
        if (!ota_ok && !telegram_send_text(chat_id_str, ota_reply)) {
            ESP_LOGW(TAG, "telegram send failed");
        }
        if (ota_ok) {
            if (!telegram_send_text(chat_id_str, ota_reply)) {
                ESP_LOGW(TAG, "telegram send failed");
            }
            vTaskDelay(pdMS_TO_TICKS(1000));
            esp_restart();
        }
    }

    cJSON_Delete(root);
#else
    (void)next_offset;
#endif
}

static void handle_frame(const uint8_t *bits, int nbits)
{
    if (nbits < 8 || (nbits % 8) != 0) {
        ESP_LOGD(TAG, "drop frame bits=%d (not byte-aligned)", nbits);
        return;
    }

    char raw[96];
    uint8_t bytes[8] = {0};
    char hex[64];
    char decoded[16];
    const char *status;

    build_raw_string(bits, nbits, raw, sizeof(raw));
    int nbytes = bits_to_bytes(bits, nbits, bytes, (int)(sizeof(bytes) / sizeof(bytes[0])));
    build_hex_string(bytes, nbytes, hex, sizeof(hex));
    decode_digits(bytes, nbytes, decoded, sizeof(decoded), &status);

    if (nbytes == 1) {
        int64_t now_us = esp_timer_get_time();
        if (s_prev_single_valid && (now_us - s_prev_single_ts_us) <= CROSS_FRAME_PAIR_US) {
            uint8_t pair[2] = {s_prev_single_byte, bytes[0]};
            char pair_decoded[16] = {0};
            const char *pair_status = "unknown";
            decode_digits(pair, 2, pair_decoded, sizeof(pair_decoded), &pair_status);
            if (decode_status_rank(pair_status) > decode_status_rank(status)) {
                strncpy(decoded, pair_decoded, sizeof(decoded) - 1);
                decoded[sizeof(decoded) - 1] = '\0';
                status = pair_status;
                snprintf(hex, sizeof(hex), "%02X %02X", pair[0], pair[1]);
            }
        }
        s_prev_single_valid = true;
        s_prev_single_byte = bytes[0];
        s_prev_single_ts_us = now_us;
    } else {
        s_prev_single_valid = false;
    }

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    strncpy(s_last_raw, raw, sizeof(s_last_raw) - 1);
    strncpy(s_last_hex, hex, sizeof(s_last_hex) - 1);
    strncpy(s_last_decoded, decoded, sizeof(s_last_decoded) - 1);
    strncpy(s_last_decode_status, status, sizeof(s_last_decode_status) - 1);
    s_last_decode_ok = (strncmp(status, "ok(", 3) == 0);
    s_last_frame_us = esp_timer_get_time();
    xSemaphoreGive(s_state_mutex);

    ESP_LOGD(TAG, "frame bits=%d raw=%s bytes=[%s] decoded=%s status=%s", nbits, raw, hex, decoded, status);
}

static gap_kind_t classify_gap_kind(int64_t dt_us)
{
    if (dt_us >= PAUSE_LONG_US) {
        return GAP_LONG;
    }
    if (dt_us >= PAUSE_MID_US) {
        return GAP_MID;
    }
    if (dt_us >= PAUSE_SHORT_US) {
        return GAP_SHORT;
    }
    return GAP_NONE;
}

static void cycle_reset(cycle_state_t *cycle)
{
    memset(cycle, 0, sizeof(*cycle));
}

static void cycle_add_subframe(cycle_state_t *cycle, const uint8_t *bytes, int nbytes, gap_kind_t gap_kind, int64_t ts_us)
{
    if (nbytes <= 0) {
        return;
    }

    if (cycle->start_ts_us == 0) {
        cycle->start_ts_us = ts_us;
    }
    cycle->last_ts_us = ts_us;
    cycle->subframes++;

    if (gap_kind == GAP_SHORT) {
        cycle->gap_short_count++;
    } else if (gap_kind == GAP_MID) {
        cycle->gap_mid_count++;
    } else if (gap_kind == GAP_LONG) {
        cycle->gap_long_count++;
    }

    for (int i = 0; i < nbytes && cycle->nbytes < MAX_CYCLE_BYTES; ++i) {
        cycle->bytes[cycle->nbytes++] = bytes[i];
    }
}

static int cycle_compact_bytes(const cycle_state_t *cycle, uint8_t *out, int out_max)
{
    int n = 0;
    bool has_prev = false;
    uint8_t prev = 0;

    for (int i = 0; i < cycle->nbytes && n < out_max; ++i) {
        uint8_t b = cycle->bytes[i];
        if (!has_prev || b != prev) {
            out[n++] = b;
            prev = b;
            has_prev = true;
        }
    }
    return n;
}

static void handle_cycle_decode(const cycle_state_t *cycle)
{
    if (!cycle || cycle->subframes == 0 || cycle->nbytes == 0) {
        return;
    }

    uint8_t compact[32] = {0};
    int compact_n = cycle_compact_bytes(cycle, compact, (int)(sizeof(compact) / sizeof(compact[0])));
    if (compact_n <= 0) {
        return;
    }

    char compact_hex[128] = {0};
    char decoded[16] = {0};
    const char *status = "unknown";
    build_hex_string(compact, compact_n, compact_hex, sizeof(compact_hex));
    decode_digits(compact, compact_n, decoded, sizeof(decoded), &status);

    ESP_LOGD(TAG,
             "cycle subframes=%d bytes=%d gaps[s/m/l]=%d/%d/%d compact=[%s] decoded=%s status=%s",
             cycle->subframes,
             cycle->nbytes,
             cycle->gap_short_count,
             cycle->gap_mid_count,
             cycle->gap_long_count,
             compact_hex,
             decoded,
             status);
}

static int64_t effective_gap_us_from_timing(const timing_stats_t *ts)
{
    int64_t gap_us = FRAME_GAP_US;
    if (ts->clk_period_ema_us > 0) {
        int64_t auto_gap_us = ts->clk_period_ema_us * AUTO_GAP_MULTIPLIER;
        if (auto_gap_us < AUTO_GAP_MIN_US) {
            auto_gap_us = AUTO_GAP_MIN_US;
        }
        if (auto_gap_us > gap_us) {
            gap_us = auto_gap_us;
        }
    }
    return gap_us;
}

static void update_timing_stats(timing_stats_t *ts, int64_t dt_us, int64_t used_gap_us)
{
    if (dt_us <= 0) {
        return;
    }

    ts->dt_count++;
    ts->dt_sum_us += (uint64_t)dt_us;

    if (ts->dt_min_us == 0 || dt_us < ts->dt_min_us) {
        ts->dt_min_us = dt_us;
    }
    if (dt_us > ts->dt_max_us) {
        ts->dt_max_us = dt_us;
    }

    if (dt_us <= used_gap_us) {
        if (ts->clk_period_ema_us == 0) {
            ts->clk_period_ema_us = dt_us;
        } else {
            ts->clk_period_ema_us = ((ts->clk_period_ema_us * 15) + dt_us) / 16;
        }
    } else {
        ts->long_gap_count++;
        if (dt_us > ts->long_gap_max_us) {
            ts->long_gap_max_us = dt_us;
        }
        ESP_LOGD(TAG, "gap candidate dt=%lldus (boundary, current_gap=%lldus)", (long long)dt_us, (long long)used_gap_us);
    }

    int64_t now_us = esp_timer_get_time();
    if (ts->last_log_ts_us == 0) {
        ts->last_log_ts_us = now_us;
        return;
    }

    if ((now_us - ts->last_log_ts_us) >= TIMING_LOG_PERIOD_US) {
        uint64_t avg = ts->dt_count ? (ts->dt_sum_us / ts->dt_count) : 0;
        ESP_LOGD(TAG,
                 "timing dt_us min=%lld avg=%llu max=%lld ema=%lld gap=%lld long_gaps=%u long_max=%lld",
                 (long long)ts->dt_min_us,
                 (unsigned long long)avg,
                 (long long)ts->dt_max_us,
                 (long long)ts->clk_period_ema_us,
                 (long long)effective_gap_us_from_timing(ts),
                 ts->long_gap_count,
                 (long long)ts->long_gap_max_us);
        ts->dt_count = 0;
        ts->dt_sum_us = 0;
        ts->dt_min_us = 0;
        ts->dt_max_us = 0;
        ts->long_gap_count = 0;
        ts->long_gap_max_us = 0;
        ts->last_log_ts_us = now_us;
    }
}

static void sniffer_task(void *arg)
{
    (void)arg;
    bit_event_t ev;
    uint8_t bits[MAX_FRAME_BITS] = {0};
    int nbits = 0;
    int64_t last_ts = 0;
    timing_stats_t t = {0};
    cycle_state_t cycle = {0};

    while (1) {
        if (xQueueReceive(s_bit_queue, &ev, pdMS_TO_TICKS(1000)) == pdTRUE) {
            int64_t gap_us = effective_gap_us_from_timing(&t);
            gap_kind_t gap_kind = GAP_NONE;
            int64_t dt_us = 0;
            if (last_ts > 0) {
                dt_us = ev.ts_us - last_ts;
                update_timing_stats(&t, dt_us, gap_us);
                gap_us = effective_gap_us_from_timing(&t);
                gap_kind = classify_gap_kind(dt_us);
            }

            if (nbits > 0 && (ev.ts_us - last_ts) > gap_us) {
                handle_frame(bits, nbits);
                if ((nbits % 8) == 0) {
                    uint8_t frame_bytes[8] = {0};
                    int nbytes = bits_to_bytes(bits, nbits, frame_bytes, (int)(sizeof(frame_bytes) / sizeof(frame_bytes[0])));
                    cycle_add_subframe(&cycle, frame_bytes, nbytes, gap_kind, last_ts);
                }

                if (gap_kind == GAP_LONG) {
                    handle_cycle_decode(&cycle);
                    cycle_reset(&cycle);
                }
                nbits = 0;
            }

            if (nbits < MAX_FRAME_BITS) {
                bits[nbits++] = ev.bit;
            } else {
                ESP_LOGW(TAG, "frame overflow, force flush bits=%d", nbits);
                handle_frame(bits, nbits);
                if ((nbits % 8) == 0) {
                    uint8_t frame_bytes[8] = {0};
                    int nbytes = bits_to_bytes(bits, nbits, frame_bytes, (int)(sizeof(frame_bytes) / sizeof(frame_bytes[0])));
                    cycle_add_subframe(&cycle, frame_bytes, nbytes, GAP_NONE, last_ts);
                }
                nbits = 0;
            }
            last_ts = ev.ts_us;
        } else if (nbits > 0) {
            int64_t gap_us = effective_gap_us_from_timing(&t);
            int64_t idle_us = esp_timer_get_time() - last_ts;
            if (idle_us > gap_us) {
                handle_frame(bits, nbits);
                if ((nbits % 8) == 0) {
                    uint8_t frame_bytes[8] = {0};
                    int nbytes = bits_to_bytes(bits, nbits, frame_bytes, (int)(sizeof(frame_bytes) / sizeof(frame_bytes[0])));
                    cycle_add_subframe(&cycle, frame_bytes, nbytes, GAP_NONE, last_ts);
                }
                nbits = 0;
            }
            if (idle_us > PAUSE_LONG_US) {
                handle_cycle_decode(&cycle);
                cycle_reset(&cycle);
            }
        }
    }
}

static void IRAM_ATTR clk_isr_handler(void *arg)
{
    (void)arg;
    bit_event_t ev;
    ev.bit = (uint8_t)gpio_level_fast((gpio_num_t)DATA_GPIO);
    ev.ts_us = esp_timer_get_time();

    BaseType_t hp_task_woken = pdFALSE;
    xQueueSendFromISR(s_bit_queue, &ev, &hp_task_woken);
    if (hp_task_woken) {
        portYIELD_FROM_ISR();
    }
}

static bool ip4_addr_is_zero(const esp_ip4_addr_t *addr)
{
    return addr && (addr->addr == 0);
}

static void log_dns_servers(esp_netif_t *netif)
{
    if (!netif) {
        return;
    }

    esp_netif_dns_info_t dns = {0};
    char ipbuf[INET_ADDRSTRLEN] = {0};

    if (esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK) {
        esp_ip4addr_ntoa(&dns.ip.u_addr.ip4, ipbuf, sizeof(ipbuf));
        ESP_LOGI(TAG, "dns main=%s", ipbuf);
    }
    if (esp_netif_get_dns_info(netif, ESP_NETIF_DNS_BACKUP, &dns) == ESP_OK) {
        esp_ip4addr_ntoa(&dns.ip.u_addr.ip4, ipbuf, sizeof(ipbuf));
        ESP_LOGI(TAG, "dns backup=%s", ipbuf);
    }
}

static void ensure_dns_servers(esp_netif_t *netif)
{
    if (!netif) {
        return;
    }

    esp_netif_dns_info_t dns_main = {0};
    if (esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns_main) != ESP_OK) {
        return;
    }

    if (!ip4_addr_is_zero(&dns_main.ip.u_addr.ip4)) {
        return;
    }

    ESP_LOGW(TAG, "DNS main server is empty, applying fallback DNS");

    esp_netif_dns_info_t dns_fallback = {
        .ip.type = ESP_IPADDR_TYPE_V4,
    };

    IP4_ADDR(&dns_fallback.ip.u_addr.ip4, 1, 1, 1, 1);
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_set_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns_fallback));

    IP4_ADDR(&dns_fallback.ip.u_addr.ip4, 8, 8, 8, 8);
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_set_dns_info(netif, ESP_NETIF_DNS_BACKUP, &dns_fallback));
}

static bool wait_dns_ready(uint32_t timeout_ms)
{
    const TickType_t delay = pdMS_TO_TICKS(250);
    uint32_t elapsed = 0;
    while (elapsed <= timeout_ms) {
        struct addrinfo hints = {
            .ai_family = AF_INET,
            .ai_socktype = SOCK_STREAM,
        };
        struct addrinfo *res = NULL;
        int err = getaddrinfo("api.telegram.org", "443", &hints, &res);
        if (err == 0 && res) {
            freeaddrinfo(res);
            return true;
        }

        if (res) {
            freeaddrinfo(res);
        }

        vTaskDelay(delay);
        elapsed += 250;
    }
    return false;
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    (void)arg;

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT);
        esp_wifi_connect();
        ESP_LOGW(TAG, "WiFi disconnected, reconnecting");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG,
                 "sta ip: " IPSTR ", mask: " IPSTR ", gw: " IPSTR,
                 IP2STR(&event->ip_info.ip),
                 IP2STR(&event->ip_info.netmask),
                 IP2STR(&event->ip_info.gw));
        ensure_dns_servers(s_sta_netif);
        log_dns_servers(s_sta_netif);
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
        ESP_LOGI(TAG, "WiFi connected");
    }
}

static void wifi_init_sta(void)
{
    s_wifi_events = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_sta_netif = esp_netif_create_default_wifi_sta();
    ESP_ERROR_CHECK(s_sta_netif ? ESP_OK : ESP_FAIL);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, WIFI_SSID, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, WIFI_PASS, sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    xEventGroupWaitBits(s_wifi_events, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, pdMS_TO_TICKS(15000));
}

static void net_task(void *arg)
{
    (void)arg;

    if (strlen(WIFI_SSID) == 0) {
        ESP_LOGW(TAG, "WiFi SSID is empty; telegram bot disabled");
        vTaskDelete(NULL);
        return;
    }

#if CONFIG_SNIFFER_ENABLE_TELEGRAM
    if (strlen(CONFIG_SNIFFER_TELEGRAM_BOT_TOKEN) == 0) {
        ESP_LOGW(TAG, "Telegram token is empty; telegram bot disabled");
        vTaskDelete(NULL);
        return;
    }
#endif

    wifi_init_sta();
    if (!wait_dns_ready(7000)) {
        ESP_LOGW(TAG, "DNS is not ready yet; Telegram requests may fail until DNS appears");
    }

    int64_t next_offset = telegram_load_next_offset();
    ESP_LOGI(TAG, "telegram next_offset=%lld", (long long)next_offset);
    while (1) {
        EventBits_t bits = xEventGroupWaitBits(s_wifi_events, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, pdMS_TO_TICKS(5000));
        if ((bits & WIFI_CONNECTED_BIT) == 0) {
            continue;
        }

        telegram_poll_and_respond(&next_offset);
    }
}

static void sniffer_gpio_init(void)
{
    gpio_config_t clk_cfg = {
        .pin_bit_mask = 1ULL << CLK_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_POSEDGE,
    };
    ESP_ERROR_CHECK(gpio_config(&clk_cfg));

    gpio_config_t data_cfg = {
        .pin_bit_mask = 1ULL << DATA_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&data_cfg));

    ESP_ERROR_CHECK(gpio_install_isr_service(ESP_INTR_FLAG_IRAM));
    ESP_ERROR_CHECK(gpio_isr_handler_add(CLK_GPIO, clk_isr_handler, NULL));
}

void app_main(void)
{
    esp_err_t nvs_err = nvs_flash_init();
    if (nvs_err == ESP_ERR_NVS_NO_FREE_PAGES || nvs_err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS init failed (%s), erasing NVS", esp_err_to_name(nvs_err));
        ESP_ERROR_CHECK(nvs_flash_erase());
        nvs_err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs_err);

    ESP_LOGI(TAG, "sniffer start, clk=%d data=%d gap_us=%d", CLK_GPIO, DATA_GPIO, FRAME_GAP_US);

    s_bit_queue = xQueueCreate(EVENT_QUEUE_LEN, sizeof(bit_event_t));
    if (!s_bit_queue) {
        ESP_LOGE(TAG, "queue allocation failed");
        return;
    }

    s_state_mutex = xSemaphoreCreateMutex();
    if (!s_state_mutex) {
        ESP_LOGE(TAG, "state mutex allocation failed");
        return;
    }

    sniffer_gpio_init();
    xTaskCreate(sniffer_task, "sniffer_task", 4096, NULL, 8, NULL);
    xTaskCreate(net_task, "net_task", 8192, NULL, 5, NULL);
}
