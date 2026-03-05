#include <stdio.h>
#include <stdlib.h>
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
#define DIGIT0_GPIO CONFIG_SNIFFER_DIGIT0_GPIO
#define DIGIT1_GPIO CONFIG_SNIFFER_DIGIT1_GPIO
#ifdef CONFIG_SNIFFER_DIGIT2_GPIO
#define DIGIT2_GPIO CONFIG_SNIFFER_DIGIT2_GPIO
#else
#define DIGIT2_GPIO 23
#endif
#define FRAME_GAP_US CONFIG_SNIFFER_FRAME_GAP_US

#define WIFI_SSID CONFIG_SNIFFER_WIFI_SSID
#define WIFI_PASS CONFIG_SNIFFER_WIFI_PASSWORD
#define OTA_URL CONFIG_SNIFFER_OTA_FIRMWARE_URL

#define MAX_FRAME_BITS 64
#define CONTINUOUS_FLUSH_BITS 16
#define EVENT_QUEUE_LEN 256
#define MAX_MUX_SLOTS 8
#define MAX_FRAME_HISTORY 30
#define FRAME_LINE_MAX 192
#define MUX_DIGIT_STALE_US (500LL * 1000LL)
#define CROSS_FRAME_PAIR_US (20LL * 1000LL)
#define AUTO_GAP_MULTIPLIER 12
#define AUTO_GAP_MIN_US 120
#define TIMING_LOG_PERIOD_US (2000LL * 1000LL)
#define PAUSE_SHORT_US 6000
#define PAUSE_MID_US 11000
#define PAUSE_LONG_US 18000
#define MAX_CYCLE_BYTES 96
#define ORDER_PINS_COUNT 3
#define ORDER_TIMEOUT_US (50LL * 1000LL)

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
    uint8_t digit0;
    uint8_t digit1;
    uint8_t digit2;
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
static uint8_t s_last_led_byte;
static int64_t s_last_led_us;
static bool s_last_led_valid;
static int64_t s_last_frame_us;
static bool s_last_decode_ok;
static int s_mux_digit[MAX_MUX_SLOTS];
static bool s_mux_valid[MAX_MUX_SLOTS];
static int64_t s_mux_seen_us[MAX_MUX_SLOTS];
static int s_gpio_mux_digit[2][2];
static bool s_gpio_mux_valid[2][2];
static int64_t s_gpio_mux_seen_us[2][2];
static bool s_prev_single_valid;
static uint8_t s_prev_single_byte;
static int64_t s_prev_single_ts_us;
static char s_frame_history[MAX_FRAME_HISTORY][FRAME_LINE_MAX];
static int s_frame_hist_head;
static int s_frame_hist_count;

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

typedef struct {
    uint32_t events;
    uint32_t cycles;
    uint32_t timeouts;
    bool last_valid;
    uint8_t last_order[ORDER_PINS_COUNT];
    int64_t last_cycle_us;
    uint8_t curr_order[ORDER_PINS_COUNT];
    bool seen[ORDER_PINS_COUNT];
    uint8_t curr_count;
    int64_t last_event_us;
} pin_order_state_t;

static portMUX_TYPE s_order_spinlock = portMUX_INITIALIZER_UNLOCKED;
static pin_order_state_t s_order_state;

typedef struct {
    uint32_t clk_edges;
    uint32_t data_ones;
    uint32_t data_zeros;
    int64_t first_edge_us;
    int64_t last_edge_us;
} clk_data_diag_t;

static portMUX_TYPE s_clk_data_spinlock = portMUX_INITIALIZER_UNLOCKED;
static clk_data_diag_t s_clk_data_diag;

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

// Build two digits using latest observed selector order (from /order detector).
// This helps when slot indices are not naturally ordered as left->right.
static bool build_ordered_mux_2digit(char *decoded, size_t decoded_len)
{
    pin_order_state_t order = {0};
    portENTER_CRITICAL(&s_order_spinlock);
    order = s_order_state;
    portEXIT_CRITICAL(&s_order_spinlock);

    if (!order.last_valid) {
        return false;
    }

    int64_t now = esp_timer_get_time();
    int picked[2] = {-1, -1};
    int n = 0;
    for (int i = 0; i < ORDER_PINS_COUNT && n < 2; ++i) {
        int slot = (int)order.last_order[i];
        if (slot < 0 || slot >= MAX_MUX_SLOTS) {
            continue;
        }
        if (!s_mux_valid[slot]) {
            continue;
        }
        if ((now - s_mux_seen_us[slot]) > MUX_DIGIT_STALE_US) {
            continue;
        }
        picked[n++] = slot;
    }

    if (n < 2) {
        return false;
    }

    snprintf(decoded, decoded_len, "%d%d", s_mux_digit[picked[0]], s_mux_digit[picked[1]]);
    return true;
}

static int selector_state_from_samples(const uint8_t *digit0_levels, const uint8_t *digit1_levels, int nbits, int *dominant_count)
{
    int counts[4] = {0};
    for (int i = 0; i < nbits; ++i) {
        int state = ((digit0_levels[i] & 0x01) << 1) | (digit1_levels[i] & 0x01);
        counts[state]++;
    }

    int best_state = 0;
    int best_count = counts[0];
    for (int s = 1; s < 4; ++s) {
        if (counts[s] > best_count) {
            best_count = counts[s];
            best_state = s;
        }
    }

    if (dominant_count) {
        *dominant_count = best_count;
    }
    return best_state;
}

static int dominant_level_from_samples(const uint8_t *levels, int nbits, int *dominant_count)
{
    int ones = 0;
    for (int i = 0; i < nbits; ++i) {
        ones += (levels[i] & 0x01);
    }
    int zeros = nbits - ones;
    if (dominant_count) {
        *dominant_count = (ones >= zeros) ? ones : zeros;
    }
    return (ones >= zeros) ? 1 : 0;
}

static bool selector3_slot_from_levels(int sel0, int sel1, int sel2, int *slot, bool *active_low)
{
    if (sel0 == 0 && sel1 == 1 && sel2 == 1) {
        *slot = 0;
        *active_low = true;
        return true;
    }
    if (sel0 == 1 && sel1 == 0 && sel2 == 1) {
        *slot = 1;
        *active_low = true;
        return true;
    }
    if (sel0 == 1 && sel1 == 1 && sel2 == 0) {
        *slot = 2;
        *active_low = true;
        return true;
    }
    if (sel0 == 1 && sel1 == 0 && sel2 == 0) {
        *slot = 0;
        *active_low = false;
        return true;
    }
    if (sel0 == 0 && sel1 == 1 && sel2 == 0) {
        *slot = 1;
        *active_low = false;
        return true;
    }
    if (sel0 == 0 && sel1 == 0 && sel2 == 1) {
        *slot = 2;
        *active_low = false;
        return true;
    }
    return false;
}

static bool selector_slots_from_state(int state, int *low_slot, int *high_slot)
{
    if (state == 0x1) { // digit0=0, digit1=1
        *low_slot = 0;
        *high_slot = 1;
        return true;
    }
    if (state == 0x2) { // digit0=1, digit1=0
        *low_slot = 1;
        *high_slot = 0;
        return true;
    }
    return false;
}

static bool build_gpio_mux_2digit(int polarity_idx, char *decoded, size_t decoded_len)
{
    int64_t now = esp_timer_get_time();
    if (polarity_idx < 0 || polarity_idx > 1) {
        return false;
    }

    for (int slot = 0; slot < 2; ++slot) {
        if (!s_gpio_mux_valid[polarity_idx][slot]) {
            return false;
        }
        if ((now - s_gpio_mux_seen_us[polarity_idx][slot]) > MUX_DIGIT_STALE_US) {
            return false;
        }
    }

    snprintf(decoded, decoded_len, "%d%d", s_gpio_mux_digit[polarity_idx][0], s_gpio_mux_digit[polarity_idx][1]);
    return true;
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
    if (strncmp(status, "partial(mux_gpio)", 17) == 0) {
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

static void json_escape_text(const char *src, char *dst, size_t dst_len)
{
    if (!dst || dst_len == 0) {
        return;
    }
    dst[0] = '\0';
    if (!src) {
        return;
    }

    size_t w = 0;
    for (size_t i = 0; src[i] != '\0' && w + 2 < dst_len; ++i) {
        char c = src[i];
        if (c == '\\' || c == '\"') {
            if (w + 2 >= dst_len) {
                break;
            }
            dst[w++] = '\\';
            dst[w++] = c;
            continue;
        }
        if (c == '\n') {
            if (w + 2 >= dst_len) {
                break;
            }
            dst[w++] = '\\';
            dst[w++] = 'n';
            continue;
        }
        if (c == '\r') {
            if (w + 2 >= dst_len) {
                break;
            }
            dst[w++] = '\\';
            dst[w++] = 'r';
            continue;
        }
        if (c == '\t') {
            if (w + 2 >= dst_len) {
                break;
            }
            dst[w++] = '\\';
            dst[w++] = 't';
            continue;
        }

        dst[w++] = c;
    }
    dst[w] = '\0';
}

static bool telegram_send_text(const char *chat_id, const char *text)
{
#if CONFIG_SNIFFER_ENABLE_TELEGRAM
    if (strlen(CONFIG_SNIFFER_TELEGRAM_BOT_TOKEN) == 0) {
        return false;
    }

    char url[256];
    snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendMessage", CONFIG_SNIFFER_TELEGRAM_BOT_TOKEN);

    char *escaped_text = (char *)malloc(1900);
    char *body = (char *)malloc(2200);
    if (!escaped_text || !body) {
        free(escaped_text);
        free(body);
        ESP_LOGW(TAG, "telegram send alloc failed");
        return false;
    }

    json_escape_text(text, escaped_text, 1900);

    snprintf(body,
             2200,
             "{\"chat_id\":\"%s\",\"text\":\"%s\"}",
             chat_id ? chat_id : "",
             escaped_text);

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
        free(escaped_text);
        free(body);
        return false;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, body, (int)strlen(body));

    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    free(escaped_text);
    free(body);

    if (!(err == ESP_OK && status == 200)) {
        ESP_LOGW(TAG, "telegram send failed err=%s status=%d", esp_err_to_name(err), status);
    }

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
    uint8_t led_byte = 0;
    int64_t led_us = 0;
    bool led_valid = false;
    int64_t frame_us = 0;

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    strncpy(decoded, s_last_decoded, sizeof(decoded) - 1);
    strncpy(decode_status, s_last_decode_status, sizeof(decode_status) - 1);
    led_byte = s_last_led_byte;
    led_us = s_last_led_us;
    led_valid = s_last_led_valid;
    frame_us = s_last_frame_us;
    xSemaphoreGive(s_state_mutex);

    int64_t now_us = esp_timer_get_time();
    int64_t age_us = now_us - frame_us;
    bool decode_fresh = (frame_us > 0 && age_us <= STATUS_STALE_US && strncmp(decode_status, "ok(", 3) == 0);
    bool led_fresh = (led_valid && led_us > 0 && (now_us - led_us) <= STATUS_STALE_US);

    if (decode_fresh && led_fresh) {
        snprintf(out, out_len, "%s led=%u", decoded, (unsigned)led_byte);
        return;
    }
    if (decode_fresh) {
        snprintf(out, out_len, "%s", decoded);
        return;
    }
    if (led_fresh) {
        snprintf(out, out_len, "unknown led=%u", (unsigned)led_byte);
        return;
    }
    snprintf(out, out_len, "unknown");
}

static void build_fw_version_reply(char *out, size_t out_len)
{
    const esp_app_desc_t *app_desc = esp_app_get_description();
    const char *fw_version = (app_desc && app_desc->version[0] != '\0') ? app_desc->version : "unknown";
    snprintf(out, out_len, "%s", fw_version);
}

static void send_temp_series(const char *chat_id)
{
    for (int i = 0; i < 2; ++i) {
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

static void push_frame_history_line(const char *line)
{
    if (!line) {
        return;
    }
    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    strncpy(s_frame_history[s_frame_hist_head], line, FRAME_LINE_MAX - 1);
    s_frame_history[s_frame_hist_head][FRAME_LINE_MAX - 1] = '\0';
    s_frame_hist_head = (s_frame_hist_head + 1) % MAX_FRAME_HISTORY;
    if (s_frame_hist_count < MAX_FRAME_HISTORY) {
        s_frame_hist_count++;
    }
    xSemaphoreGive(s_state_mutex);
}

static void send_frame_history(const char *chat_id)
{
    char *snapshot = (char *)calloc(MAX_FRAME_HISTORY, FRAME_LINE_MAX);
    if (!snapshot) {
        telegram_send_text(chat_id, "frames: alloc failed");
        return;
    }

    int count = 0;
    int oldest = 0;

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    count = s_frame_hist_count;
    oldest = (s_frame_hist_head - s_frame_hist_count + MAX_FRAME_HISTORY) % MAX_FRAME_HISTORY;
    for (int i = 0; i < count; ++i) {
        int idx = (oldest + i) % MAX_FRAME_HISTORY;
        char *dst = snapshot + ((size_t)i * FRAME_LINE_MAX);
        strncpy(dst, s_frame_history[idx], FRAME_LINE_MAX - 1);
        dst[FRAME_LINE_MAX - 1] = '\0';
    }
    xSemaphoreGive(s_state_mutex);

    if (count == 0) {
        telegram_send_text(chat_id, "frames: empty");
        free(snapshot);
        return;
    }

    char msg[1500];
    msg[0] = '\0';
    int chunk_start = 0;
    for (int i = 0; i < count; ++i) {
        char row[240];
        char *line = snapshot + ((size_t)i * FRAME_LINE_MAX);
        snprintf(row, sizeof(row), "%02d) %s\n", i + 1, line);
        if ((int)(strlen(msg) + strlen(row)) >= (int)sizeof(msg) - 1) {
            char head[64];
            snprintf(head, sizeof(head), "frames %d-%d/%d:\n", chunk_start + 1, i, count);
            char out[1600];
            snprintf(out, sizeof(out), "%s%s", head, msg);
            telegram_send_text(chat_id, out);
            vTaskDelay(pdMS_TO_TICKS(150));
            msg[0] = '\0';
            chunk_start = i;
        }
        strncat(msg, row, sizeof(msg) - strlen(msg) - 1);
    }

    if (msg[0] != '\0') {
        char head[64];
        snprintf(head, sizeof(head), "frames %d-%d/%d:\n", chunk_start + 1, count, count);
        char out[1600];
        snprintf(out, sizeof(out), "%s%s", head, msg);
        telegram_send_text(chat_id, out);
    }

    free(snapshot);
}

static void build_frames_count_reply(char *out, size_t out_len)
{
    int count = 0;
    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    count = s_frame_hist_count;
    xSemaphoreGive(s_state_mutex);
    snprintf(out, out_len, "frames_count: %d/%d", count, MAX_FRAME_HISTORY);
}

// Accepts "/cmd", "/cmd@botname" and "/cmd anything".
static bool telegram_cmd_is(const char *text, const char *cmd)
{
    if (!text || !cmd) {
        return false;
    }

    size_t cmd_len = strlen(cmd);
    if (strncmp(text, cmd, cmd_len) != 0) {
        return false;
    }

    char tail = text[cmd_len];
    return (tail == '\0' || tail == ' ' || tail == '\t' || tail == '\r' || tail == '\n' || tail == '@');
}

// One-hot active-low selector lines: returns active slot 0..2, otherwise -1.
static int active_slot_from_levels(uint8_t d0, uint8_t d1, uint8_t d2)
{
    if (d0 == 0 && d1 == 1 && d2 == 1) {
        return 0;
    }
    if (d0 == 1 && d1 == 0 && d2 == 1) {
        return 1;
    }
    if (d0 == 1 && d1 == 1 && d2 == 0) {
        return 2;
    }
    return -1;
}

static const char *order_pin_name(uint8_t idx)
{
    if (idx == 0) {
        return "d0";
    }
    if (idx == 1) {
        return "d1";
    }
    if (idx == 2) {
        return "d2";
    }
    return "?";
}

static void build_order_reply(char *out, size_t out_len)
{
    pin_order_state_t snap = {0};
    portENTER_CRITICAL(&s_order_spinlock);
    snap = s_order_state;
    portEXIT_CRITICAL(&s_order_spinlock);

    if (!snap.last_valid) {
        snprintf(out,
                 out_len,
                 "order: no full cycle yet, events=%u timeouts=%u",
                 (unsigned)snap.events,
                 (unsigned)snap.timeouts);
        return;
    }

    int64_t age_ms = 0;
    if (snap.last_cycle_us > 0) {
        age_ms = (esp_timer_get_time() - snap.last_cycle_us) / 1000;
    }

    snprintf(out,
             out_len,
             "order: %s->%s->%s age=%lldms cycles=%u events=%u",
             order_pin_name(snap.last_order[0]),
             order_pin_name(snap.last_order[1]),
             order_pin_name(snap.last_order[2]),
             (long long)age_ms,
             (unsigned)snap.cycles,
             (unsigned)snap.events);
}

static void build_clkdata_reply(char *out, size_t out_len)
{
    clk_data_diag_t snap = {0};
    portENTER_CRITICAL(&s_clk_data_spinlock);
    snap = s_clk_data_diag;
    portEXIT_CRITICAL(&s_clk_data_spinlock);

    int clk_now = gpio_get_level((gpio_num_t)CLK_GPIO);
    int data_now = gpio_get_level((gpio_num_t)DATA_GPIO);

    if (snap.clk_edges == 0 || snap.first_edge_us == 0 || snap.last_edge_us <= snap.first_edge_us) {
        snprintf(out,
                 out_len,
                 "clkdata: no edges yet clk=%d data=%d",
                 clk_now,
                 data_now);
        return;
    }

    int64_t span_us = snap.last_edge_us - snap.first_edge_us;
    uint32_t edges = snap.clk_edges;
    uint32_t ones = snap.data_ones;
    uint32_t zeros = snap.data_zeros;
    uint32_t data_total = ones + zeros;
    uint32_t ones_pct = (data_total > 0) ? (uint32_t)((ones * 100U) / data_total) : 0;
    uint32_t hz = (span_us > 0) ? (uint32_t)(((uint64_t)edges * 1000000ULL) / (uint64_t)span_us) : 0;

    snprintf(out,
             out_len,
             "clkdata: edges=%u rate~%uHz data1=%u data0=%u ones=%u%% now clk=%d data=%d",
             (unsigned)edges,
             (unsigned)hz,
             (unsigned)ones,
             (unsigned)zeros,
             (unsigned)ones_pct,
             clk_now,
             data_now);
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

    char *response = (char *)malloc(TELEGRAM_RESP_MAX);
    if (!response) {
        ESP_LOGW(TAG, "telegram getUpdates alloc failed");
        vTaskDelay(pdMS_TO_TICKS(1500));
        return;
    }

    if (!telegram_http_get(url, response, TELEGRAM_RESP_MAX)) {
        free(response);
        vTaskDelay(pdMS_TO_TICKS(1500));
        return;
    }

    cJSON *root = cJSON_Parse(response);
    free(response);
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

        bool cmd_status = telegram_cmd_is(text->valuestring, "/status");
        bool cmd_get_temp = telegram_cmd_is(text->valuestring, "/get_temp");
        bool cmd_order = telegram_cmd_is(text->valuestring, "/order");
        bool cmd_clkdata = telegram_cmd_is(text->valuestring, "/clkdata");
        bool cmd_frames = telegram_cmd_is(text->valuestring, "/frames");
        bool cmd_frames_count = telegram_cmd_is(text->valuestring, "/frames_count");
        bool cmd_update = telegram_cmd_is(text->valuestring, "/update");
        bool cmd_ota_legacy = telegram_cmd_is(text->valuestring, "/ota");
        if (!cmd_status && !cmd_get_temp && !cmd_order && !cmd_clkdata && !cmd_frames && !cmd_frames_count && !cmd_update &&
            !cmd_ota_legacy) {
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

        if (cmd_order) {
            char reply[128];
            build_order_reply(reply, sizeof(reply));
            if (!telegram_send_text(chat_id_str, reply)) {
                ESP_LOGW(TAG, "telegram send failed");
            }
            continue;
        }

        if (cmd_clkdata) {
            char reply[160];
            build_clkdata_reply(reply, sizeof(reply));
            if (!telegram_send_text(chat_id_str, reply)) {
                ESP_LOGW(TAG, "telegram send failed");
            }
            continue;
        }

        if (cmd_frames) {
            send_frame_history(chat_id_str);
            continue;
        }

        if (cmd_frames_count) {
            char reply[64];
            build_frames_count_reply(reply, sizeof(reply));
            if (!telegram_send_text(chat_id_str, reply)) {
                ESP_LOGW(TAG, "telegram send failed");
            }
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

static void handle_frame(const uint8_t *bits,
                         const uint8_t *digit0_levels,
                         const uint8_t *digit1_levels,
                         const uint8_t *digit2_levels,
                         int slot_hint,
                         int nbits)
{
    if (nbits < 8 || (nbits % 8) != 0) {
        ESP_LOGD(TAG, "drop frame bits=%d (not byte-aligned)", nbits);
        return;
    }

    char raw[96];
    uint8_t bytes[8] = {0};
    char hex[64];
    char decoded[16];
    char sel_summary[40] = {0};
    const char *status;

    build_raw_string(bits, nbits, raw, sizeof(raw));
    int nbytes = bits_to_bytes(bits, nbits, bytes, (int)(sizeof(bytes) / sizeof(bytes[0])));
    build_hex_string(bytes, nbytes, hex, sizeof(hex));
    decode_digits(bytes, nbytes, decoded, sizeof(decoded), &status);

    int dominant_count = 0;
    int sel_state = selector_state_from_samples(digit0_levels, digit1_levels, nbits, &dominant_count);
    int sel0 = (sel_state >> 1) & 0x01;
    int sel1 = sel_state & 0x01;
    int sel2_count = 0;
    int sel2 = dominant_level_from_samples(digit2_levels, nbits, &sel2_count);
    int sel3_slot = -1;
    bool sel3_active_low = false;
    bool sel3_valid = selector3_slot_from_levels(sel0, sel1, sel2, &sel3_slot, &sel3_active_low);
    snprintf(sel_summary, sizeof(sel_summary), "%d%d%d(%d/%d|%d/%d)", sel0, sel1, sel2, dominant_count, nbits, sel2_count, nbits);

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

    if (decode_status_rank(status) < 3 && nbytes == 1) {
        if (slot_hint >= 0 && slot_hint < MAX_MUX_SLOTS) {
            int d = -1;
            decode_mode_t mode = {0};
            if (decode_segment_byte(bytes[0], &d, &mode)) {
                s_mux_digit[slot_hint] = d;
                s_mux_valid[slot_hint] = true;
                s_mux_seen_us[slot_hint] = esp_timer_get_time();
                if (build_ordered_mux_2digit(decoded, sizeof(decoded))) {
                    status = "ok(slot_order)";
                } else if (build_mux_2digit(decoded, sizeof(decoded))) {
                    status = "ok(slot)";
                } else {
                    snprintf(decoded, sizeof(decoded), "%d?", d);
                    status = "partial(slot)";
                }
            }
        }

        int low_slot = -1;
        int high_slot = -1;
        int digit = -1;
        decode_mode_t mode = {0};

        if (selector_slots_from_state(sel_state, &low_slot, &high_slot) && decode_segment_byte(bytes[0], &digit, &mode)) {
            int64_t now_us = esp_timer_get_time();
            // active-low hypothesis
            s_gpio_mux_digit[0][low_slot] = digit;
            s_gpio_mux_valid[0][low_slot] = true;
            s_gpio_mux_seen_us[0][low_slot] = now_us;
            // active-high hypothesis
            s_gpio_mux_digit[1][high_slot] = digit;
            s_gpio_mux_valid[1][high_slot] = true;
            s_gpio_mux_seen_us[1][high_slot] = now_us;

            if (build_gpio_mux_2digit(0, decoded, sizeof(decoded))) {
                status = "ok(mux_gpio_al)";
            } else if (build_gpio_mux_2digit(1, decoded, sizeof(decoded))) {
                status = "ok(mux_gpio_ah)";
            } else {
                snprintf(decoded, sizeof(decoded), "%d?", digit);
                status = "partial(mux_gpio)";
            }
            ESP_LOGD(TAG,
                     "mux_gpio state=%s low_slot=%d high_slot=%d digit=%d mode=%s",
                     sel_summary,
                     low_slot,
                     high_slot,
                     digit,
                     mode_tag(mode));
        }
    }

    if (nbytes == 1 && sel3_valid && sel3_slot == 2) {
        xSemaphoreTake(s_state_mutex, portMAX_DELAY);
        s_last_led_byte = bytes[0];
        s_last_led_us = esp_timer_get_time();
        s_last_led_valid = true;
        xSemaphoreGive(s_state_mutex);
    }

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    strncpy(s_last_raw, raw, sizeof(s_last_raw) - 1);
    strncpy(s_last_hex, hex, sizeof(s_last_hex) - 1);
    strncpy(s_last_decoded, decoded, sizeof(s_last_decoded) - 1);
    strncpy(s_last_decode_status, status, sizeof(s_last_decode_status) - 1);
    s_last_decode_ok = (strncmp(status, "ok(", 3) == 0);
    s_last_frame_us = esp_timer_get_time();
    xSemaphoreGive(s_state_mutex);

    ESP_LOGD(TAG,
             "frame bits=%d raw=%s bytes=[%s] sel=%s slot3=%d(%s) decoded=%s status=%s led=%u",
             nbits,
             raw,
             hex,
             sel_summary,
             (slot_hint >= 0) ? slot_hint : (sel3_valid ? sel3_slot : -1),
             sel3_valid ? (sel3_active_low ? "al" : "ah") : "na",
             decoded,
             status,
             (unsigned)s_last_led_byte);

    char hist_line[FRAME_LINE_MAX];
    snprintf(hist_line,
             sizeof(hist_line),
             "bits=%d bytes=[%s] sel=%s dec=%s st=%s",
             nbits,
             hex,
             sel_summary,
             decoded,
             status);
    push_frame_history_line(hist_line);
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

static void flush_frame_buffer(const uint8_t *bits,
                               const uint8_t *digit0_levels,
                               const uint8_t *digit1_levels,
                               const uint8_t *digit2_levels,
                               int nbits,
                               cycle_state_t *cycle,
                               gap_kind_t gap_kind,
                               int64_t frame_ts_us,
                               int slot_hint)
{
    handle_frame(bits, digit0_levels, digit1_levels, digit2_levels, slot_hint, nbits);
    if ((nbits % 8) == 0) {
        uint8_t frame_bytes[8] = {0};
        int nbytes = bits_to_bytes(bits, nbits, frame_bytes, (int)(sizeof(frame_bytes) / sizeof(frame_bytes[0])));
        cycle_add_subframe(cycle, frame_bytes, nbytes, gap_kind, frame_ts_us);
    }
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
    uint8_t digit0_levels[MAX_FRAME_BITS] = {0};
    uint8_t digit1_levels[MAX_FRAME_BITS] = {0};
    uint8_t digit2_levels[MAX_FRAME_BITS] = {0};
    int nbits = 0;
    int64_t last_ts = 0;
    timing_stats_t t = {0};
    cycle_state_t cycle = {0};
    int current_slot = -1;

    while (1) {
        if (xQueueReceive(s_bit_queue, &ev, pdMS_TO_TICKS(1000)) == pdTRUE) {
            int64_t gap_us = effective_gap_us_from_timing(&t);
            gap_kind_t gap_kind = GAP_NONE;
            int64_t dt_us = 0;
            int event_slot = active_slot_from_levels(ev.digit0, ev.digit1, ev.digit2);
            if (last_ts > 0) {
                dt_us = ev.ts_us - last_ts;
                update_timing_stats(&t, dt_us, gap_us);
                gap_us = effective_gap_us_from_timing(&t);
                gap_kind = classify_gap_kind(dt_us);
            }

            if (nbits > 0 && current_slot >= 0 && event_slot != current_slot) {
                flush_frame_buffer(bits,
                                   digit0_levels,
                                   digit1_levels,
                                   digit2_levels,
                                   nbits,
                                   &cycle,
                                   GAP_NONE,
                                   last_ts,
                                   current_slot);
                nbits = 0;
            }

            if (nbits > 0 && (ev.ts_us - last_ts) > gap_us) {
                flush_frame_buffer(bits,
                                   digit0_levels,
                                   digit1_levels,
                                   digit2_levels,
                                   nbits,
                                   &cycle,
                                   gap_kind,
                                   last_ts,
                                   current_slot);

                if (gap_kind == GAP_LONG) {
                    handle_cycle_decode(&cycle);
                    cycle_reset(&cycle);
                }
                nbits = 0;
            }

            if (event_slot >= 0) {
                current_slot = event_slot;
            }

            if (current_slot < 0) {
                last_ts = ev.ts_us;
                continue;
            }

            if (nbits < MAX_FRAME_BITS) {
                bits[nbits++] = ev.bit;
                digit0_levels[nbits - 1] = ev.digit0;
                digit1_levels[nbits - 1] = ev.digit1;
                digit2_levels[nbits - 1] = ev.digit2;
            } else {
                ESP_LOGW(TAG, "frame overflow, force flush bits=%d", nbits);
                flush_frame_buffer(bits,
                                   digit0_levels,
                                   digit1_levels,
                                   digit2_levels,
                                   nbits,
                                   &cycle,
                                   GAP_NONE,
                                   last_ts,
                                   current_slot);
                nbits = 0;
            }

            if (gap_kind == GAP_NONE && nbits == CONTINUOUS_FLUSH_BITS) {
                // For continuous transfers without inter-frame gap, emit 2-byte chunks.
                flush_frame_buffer(bits,
                                   digit0_levels,
                                   digit1_levels,
                                   digit2_levels,
                                   nbits,
                                   &cycle,
                                   GAP_NONE,
                                   ev.ts_us,
                                   current_slot);
                nbits = 0;
            }
            last_ts = ev.ts_us;
        } else if (nbits > 0) {
            int64_t gap_us = effective_gap_us_from_timing(&t);
            int64_t idle_us = esp_timer_get_time() - last_ts;
            if (idle_us > gap_us) {
                flush_frame_buffer(bits,
                                   digit0_levels,
                                   digit1_levels,
                                   digit2_levels,
                                   nbits,
                                   &cycle,
                                   GAP_NONE,
                                   last_ts,
                                   current_slot);
                nbits = 0;
                current_slot = -1;
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
    ev.digit0 = (uint8_t)gpio_level_fast((gpio_num_t)DIGIT0_GPIO);
    ev.digit1 = (uint8_t)gpio_level_fast((gpio_num_t)DIGIT1_GPIO);
    ev.digit2 = (uint8_t)gpio_level_fast((gpio_num_t)DIGIT2_GPIO);
    ev.ts_us = esp_timer_get_time();

    portENTER_CRITICAL_ISR(&s_clk_data_spinlock);
    if (s_clk_data_diag.clk_edges == 0) {
        s_clk_data_diag.first_edge_us = ev.ts_us;
    }
    s_clk_data_diag.clk_edges++;
    s_clk_data_diag.last_edge_us = ev.ts_us;
    if (ev.bit) {
        s_clk_data_diag.data_ones++;
    } else {
        s_clk_data_diag.data_zeros++;
    }
    portEXIT_CRITICAL_ISR(&s_clk_data_spinlock);

    BaseType_t hp_task_woken = pdFALSE;
    xQueueSendFromISR(s_bit_queue, &ev, &hp_task_woken);
    if (hp_task_woken) {
        portYIELD_FROM_ISR();
    }
}

static void IRAM_ATTR order_isr_handler(void *arg)
{
    uint32_t idx = (uint32_t)arg;
    if (idx >= ORDER_PINS_COUNT) {
        return;
    }

    int64_t now_us = esp_timer_get_time();
    portENTER_CRITICAL_ISR(&s_order_spinlock);
    s_order_state.events++;

    if (s_order_state.last_event_us > 0 && (now_us - s_order_state.last_event_us) > ORDER_TIMEOUT_US) {
        memset(s_order_state.seen, 0, sizeof(s_order_state.seen));
        s_order_state.curr_count = 0;
        s_order_state.timeouts++;
    }
    s_order_state.last_event_us = now_us;

    if (!s_order_state.seen[idx]) {
        s_order_state.seen[idx] = true;
        s_order_state.curr_order[s_order_state.curr_count++] = (uint8_t)idx;

        if (s_order_state.curr_count == ORDER_PINS_COUNT) {
            for (int i = 0; i < ORDER_PINS_COUNT; ++i) {
                s_order_state.last_order[i] = s_order_state.curr_order[i];
            }
            s_order_state.last_valid = true;
            s_order_state.last_cycle_us = now_us;
            s_order_state.cycles++;
            memset(s_order_state.seen, 0, sizeof(s_order_state.seen));
            s_order_state.curr_count = 0;
        }
    }
    portEXIT_CRITICAL_ISR(&s_order_spinlock);
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

    gpio_config_t digit_cfg = {
        .pin_bit_mask = (1ULL << DIGIT0_GPIO) | (1ULL << DIGIT1_GPIO) | (1ULL << DIGIT2_GPIO),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_POSEDGE,
    };
    ESP_ERROR_CHECK(gpio_config(&digit_cfg));

    ESP_ERROR_CHECK(gpio_install_isr_service(ESP_INTR_FLAG_IRAM));
    ESP_ERROR_CHECK(gpio_isr_handler_add(CLK_GPIO, clk_isr_handler, NULL));
    ESP_ERROR_CHECK(gpio_isr_handler_add(DIGIT0_GPIO, order_isr_handler, (void *)0));
    ESP_ERROR_CHECK(gpio_isr_handler_add(DIGIT1_GPIO, order_isr_handler, (void *)1));
    ESP_ERROR_CHECK(gpio_isr_handler_add(DIGIT2_GPIO, order_isr_handler, (void *)2));
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

    ESP_LOGI(TAG,
             "sniffer start, clk=%d data=%d digit0=%d digit1=%d digit2=%d gap_us=%d",
             CLK_GPIO,
             DATA_GPIO,
             DIGIT0_GPIO,
             DIGIT1_GPIO,
             DIGIT2_GPIO,
             FRAME_GAP_US);

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
    xTaskCreate(net_task, "net_task", 12288, NULL, 5, NULL);
}
