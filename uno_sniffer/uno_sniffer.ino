/*
  Arduino Uno passive sniffer for 7-segment shift-register traffic.
  Signals (listen only):
    - CLK
    - DATA
    - PIN_A (display tens select)
    - PIN_B (display ones select)
    - PIN_C (LED bank select)
*/

#include <Arduino.h>

// ---------------- Pins ----------------
static const uint8_t PIN_DATA = 2;
static const uint8_t PIN_CLK = 3;    // INT1 on Uno
static const uint8_t PIN_SEL_A = 4;
static const uint8_t PIN_SEL_B = 5;
static const uint8_t PIN_SEL_C = 6;

// ---------------- Capture tuning ----------------
static const uint16_t EVENT_QUEUE_LEN = 128;
static const uint8_t MAX_FRAME_BITS = 16;
static const uint32_t FRAME_GAP_US = 2500;      // new frame if gap between CLK edges > this
static const uint8_t CONTINUOUS_FLUSH_BITS = 8; // flush fixed chunks when CLK is continuous
static const uint32_t MUX_STALE_US = 500000;    // digit memory stale timeout
static const bool USE_FALLING_EDGE = false;     // set true if data is stable on CLK falling edge
static const uint8_t CAPTURE_DELAY_US = 0;      // wait after CLK edge before sampling DATA/DIGIT
static const uint8_t STABLE_REPEAT = 2;         // same digit must repeat on slot before commit
static const uint32_t STROBE_LINK_MAX_US = 4500; // link byte to last non-zero digit strobe within this window
static const bool STROBE_ONLY_MODE = true;      // update mux only when slot is linked by recent digit strobe
static const uint8_t VALUE_CONFIRM_COUNT = 4;   // repeats required before publishing stable2d
static const uint32_t SLOT_PAIR_MAX_SKEW_US = 25000; // max skew between slot1 and slot2 updates
static const uint8_t SLOT_MODE_COUNT = 12;      // 2 polarity * 2 bit order * 3 shifts (-1/0/+1)
static const bool MINIMAL_LOG = true;           // reduces flash/RAM usage on Uno

// ---------------- ISR event queue ----------------
struct BitEvent {
  uint32_t ts_us;
  uint8_t bit;
  uint8_t digit_mask; // bit0=PIN_A, bit1=PIN_B, bit2=PIN_C
};

volatile BitEvent g_evq[EVENT_QUEUE_LEN];
volatile uint8_t g_q_head = 0;
volatile uint8_t g_q_tail = 0;
volatile uint16_t g_drop_count = 0;

// ---------------- Decoder state ----------------
int8_t g_mux_digit[2] = {-1, -1};
bool g_mux_valid[2] = {false, false};
uint32_t g_mux_seen_us[2] = {0, 0};
int8_t g_slot_candidate[2] = {-1, -1};
uint8_t g_slot_streak[2] = {0, 0};
uint16_t g_slot_samples[2] = {0, 0};
uint8_t g_last_strobe_mask = 0;
uint32_t g_last_strobe_ts = 0;
bool g_led_valid = false;
uint8_t g_led_byte = 0;
uint32_t g_led_seen_us = 0;
uint8_t g_led_candidate = 0;
uint8_t g_led_streak = 0;
int8_t g_value_tens_candidate = -1;
int8_t g_value_ones_candidate = -1;
uint8_t g_value_streak = 0;
bool g_value_valid = false;
int8_t g_value_tens = -1;
int8_t g_value_ones = -1;
uint32_t g_value_seen_us = 0;
uint16_t g_slot_mode_score[2][SLOT_MODE_COUNT] = {{0}};
int8_t g_slot_best_mode[2] = {-1, -1};

// ---------------- Segment map ----------------
static const uint8_t SEG_MAP[10] = {
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

static uint8_t reverseBits8(uint8_t v) {
  v = (uint8_t)(((v & 0xF0) >> 4) | ((v & 0x0F) << 4));
  v = (uint8_t)(((v & 0xCC) >> 2) | ((v & 0x33) << 2));
  v = (uint8_t)(((v & 0xAA) >> 1) | ((v & 0x55) << 1));
  return v;
}

static uint8_t normalizeSegment(uint8_t seg, bool active_low, bool bit_reversed) {
  uint8_t norm = seg & 0x7F;
  if (bit_reversed) norm = reverseBits8(norm) & 0x7F;
  if (active_low) norm = (~norm) & 0x7F;
  return norm;
}

static uint8_t applyShift8(uint8_t seg, int8_t shift) {
  if (shift < 0) return (uint8_t)(seg >> 1);
  if (shift > 0) return (uint8_t)(seg << 1);
  return seg;
}

static void modeParamsFromIndex(uint8_t idx, bool *active_low, bool *bit_reversed, int8_t *shift) {
  uint8_t shift_idx = idx % 3;      // 0:-1, 1:0, 2:+1
  uint8_t mode2 = idx / 3;          // 0..3
  *active_low = (mode2 & 0x01) != 0;
  *bit_reversed = (mode2 & 0x02) != 0;
  *shift = (shift_idx == 0) ? -1 : ((shift_idx == 1) ? 0 : 1);
}

static int decodeWithMode(uint8_t seg, uint8_t mode_idx, uint8_t max_dist, bool *fuzzy_out) {
  bool active_low = false;
  bool bit_reversed = false;
  int8_t shift = 0;
  modeParamsFromIndex(mode_idx, &active_low, &bit_reversed, &shift);

  uint8_t v = applyShift8(seg, shift);
  uint8_t norm = normalizeSegment(v, active_low, bit_reversed);

  uint8_t best_dist = 8;
  int best_digit = -1;
  for (uint8_t d = 0; d < 10; ++d) {
    uint8_t dist = (uint8_t)__builtin_popcount((uint8_t)(norm ^ SEG_MAP[d]));
    if (dist < best_dist) {
      best_dist = dist;
      best_digit = d;
    }
  }

  if (best_digit >= 0 && best_dist <= max_dist) {
    if (fuzzy_out) *fuzzy_out = (best_dist != 0);
    return best_digit;
  }
  if (fuzzy_out) *fuzzy_out = false;
  return -1;
}

static int decodeSegmentByteFuzzyWithThreshold(uint8_t seg, uint8_t max_dist, bool *fuzzy_out) {
  // Generic fallback decode across all modes.
  int best_digit = -1;
  bool best_fuzzy = false;
  uint8_t best_dist = 8;
  for (uint8_t m = 0; m < SLOT_MODE_COUNT; ++m) {
    bool fuzzy = false;
    int d = decodeWithMode(seg, m, max_dist, &fuzzy);
    if (d < 0) continue;
    uint8_t dist = fuzzy ? 1 : 0;
    if (dist < best_dist) {
      best_dist = dist;
      best_digit = d;
      best_fuzzy = fuzzy;
    }
  }
  if (best_digit >= 0) {
    if (fuzzy_out) *fuzzy_out = best_fuzzy;
    return best_digit;
  }
  if (fuzzy_out) *fuzzy_out = false;
  return -1;
}

static int decodeSegmentByte(uint8_t seg) {
  bool fuzzy = false;
  int d = decodeSegmentByteFuzzyWithThreshold(seg, 0, &fuzzy);
  return d;
}

static int decodeSegmentByteFuzzy(uint8_t seg, bool *fuzzy_out) {
  return decodeSegmentByteFuzzyWithThreshold(seg, 1, fuzzy_out);
}

static int dominantDigitMask(const uint8_t *masks, uint8_t nbits, uint8_t *count_out) {
  uint8_t cnt[8] = {0};
  for (uint8_t i = 0; i < nbits; ++i) cnt[masks[i] & 0x07]++;

  // Prefer active (non-zero) selector masks, because multiplex strobe is often short.
  uint8_t best_mask_nz = 0;
  uint8_t best_cnt_nz = 0;
  for (uint8_t m = 1; m < 8; ++m) {
    if (cnt[m] > best_cnt_nz) {
      best_cnt_nz = cnt[m];
      best_mask_nz = m;
    }
  }

  if (best_cnt_nz > 0) {
    if (count_out) *count_out = best_cnt_nz;
    return best_mask_nz;
  }

  if (count_out) *count_out = cnt[0];
  return 0;
}

// Returns slot index:
// 0=PIN_A, 1=PIN_B, 2=PIN_C.
// Supports both active-high one-hot and active-low one-zero selector forms.
static int selectorSlotFromMask(uint8_t m, bool *active_low) {
  if (m == 0x01) { if (active_low) *active_low = false; return 0; } // 001
  if (m == 0x02) { if (active_low) *active_low = false; return 1; } // 010
  if (m == 0x04) { if (active_low) *active_low = false; return 2; } // 100
  if (m == 0x06) { if (active_low) *active_low = true;  return 0; } // 110
  if (m == 0x05) { if (active_low) *active_low = true;  return 1; } // 101
  if (m == 0x03) { if (active_low) *active_low = true;  return 2; } // 011
  return -1;
}

static void printMuxValue() {
  char buf[4];
  for (uint8_t i = 0; i < 2; ++i) {
    bool fresh = g_mux_valid[i] && (uint32_t)(micros() - g_mux_seen_us[i]) <= MUX_STALE_US;
    buf[i] = fresh ? (char)('0' + g_mux_digit[i]) : '?';
  }
  buf[2] = '\0';
  Serial.print(F(" mux="));
  Serial.print(buf);
  if (g_led_valid && (uint32_t)(micros() - g_led_seen_us) <= MUX_STALE_US) {
    Serial.print(F(" led="));
    Serial.print(g_led_byte);
  }
}

static bool updateSlotDigitStable(uint8_t slot, int d, uint32_t ts_us) {
  if (slot >= 2 || d < 0 || d > 9) return false;

  if (g_slot_candidate[slot] == d) {
    if (g_slot_streak[slot] < 255) g_slot_streak[slot]++;
  } else {
    g_slot_candidate[slot] = (int8_t)d;
    g_slot_streak[slot] = 1;
  }

  if (g_slot_streak[slot] >= STABLE_REPEAT) {
    g_mux_digit[slot] = (int8_t)d;
    g_mux_valid[slot] = true;
    g_mux_seen_us[slot] = ts_us;
    return true;
  }
  return false;
}

static bool updateLedStable(uint8_t led_byte, uint32_t ts_us) {
  if (g_led_candidate == led_byte) {
    if (g_led_streak < 255) g_led_streak++;
  } else {
    g_led_candidate = led_byte;
    g_led_streak = 1;
  }

  if (g_led_streak >= STABLE_REPEAT) {
    bool changed = (!g_led_valid || g_led_byte != led_byte);
    g_led_valid = true;
    g_led_byte = led_byte;
    g_led_seen_us = ts_us;
    return changed;
  }
  return false;
}

static int decodeSlotAuto(uint8_t slot, uint8_t b, bool *fuzzy_out) {
  if (slot >= 2) {
    if (fuzzy_out) *fuzzy_out = false;
    return -1;
  }

  // Learn best mode for each slot from observations.
  int best_mode = -1;
  uint16_t best_score = 0;
  for (uint8_t m = 0; m < SLOT_MODE_COUNT; ++m) {
    bool fuzzy = false;
    int d = decodeWithMode(b, m, 1, &fuzzy);
    if (d >= 0) {
      uint16_t add = fuzzy ? 1 : 3;
      if (g_slot_mode_score[slot][m] <= (uint16_t)(65535U - add)) {
        g_slot_mode_score[slot][m] += add;
      }
    }
    if (g_slot_mode_score[slot][m] > best_score) {
      best_score = g_slot_mode_score[slot][m];
      best_mode = m;
    }
  }
  g_slot_best_mode[slot] = (int8_t)best_mode;

  if (best_mode >= 0) {
    return decodeWithMode(b, (uint8_t)best_mode, 1, fuzzy_out);
  }
  if (fuzzy_out) *fuzzy_out = false;
  return -1;
}

static void updateStable2D() {
  // Default mapping: slot0=tens, slot1=ones.
  bool tens_ok = g_mux_valid[0] && (uint32_t)(micros() - g_mux_seen_us[0]) <= MUX_STALE_US;
  bool ones_ok = g_mux_valid[1] && (uint32_t)(micros() - g_mux_seen_us[1]) <= MUX_STALE_US;
  if (!tens_ok || !ones_ok) return;

  uint32_t t0 = g_mux_seen_us[0];
  uint32_t t1 = g_mux_seen_us[1];
  uint32_t skew = (t0 >= t1) ? (t0 - t1) : (t1 - t0);
  if (skew > SLOT_PAIR_MAX_SKEW_US) return;

  int8_t tens = g_mux_digit[0];
  int8_t ones = g_mux_digit[1];
  if (tens < 0 || tens > 9 || ones < 0 || ones > 9) return;

  if (g_value_tens_candidate == tens && g_value_ones_candidate == ones) {
    if (g_value_streak < 255) g_value_streak++;
  } else {
    g_value_tens_candidate = tens;
    g_value_ones_candidate = ones;
    g_value_streak = 1;
  }

  if (g_value_streak >= VALUE_CONFIRM_COUNT) {
    g_value_valid = true;
    g_value_tens = tens;
    g_value_ones = ones;
    g_value_seen_us = micros();
  }
}

static bool printValue2D() {
  updateStable2D();
  bool printed = false;

  bool tens_ok = g_mux_valid[0] && (uint32_t)(micros() - g_mux_seen_us[0]) <= MUX_STALE_US;
  bool ones_ok = g_mux_valid[1] && (uint32_t)(micros() - g_mux_seen_us[1]) <= MUX_STALE_US;
  if (tens_ok && ones_ok) {
    Serial.print(F(" value2d="));
    Serial.print(g_mux_digit[0]);
    Serial.print(g_mux_digit[1]);
    printed = true;
  }
  if (g_value_valid) {
    Serial.print(F(" stable2d="));
    Serial.print(g_value_tens);
    Serial.print(g_value_ones);
    printed = true;
  }
  if (g_led_valid && (uint32_t)(micros() - g_led_seen_us) <= MUX_STALE_US) {
    Serial.print(F(" led="));
    Serial.print(g_led_byte);
    printed = true;
  }
  return printed;
}

static uint8_t bitsToBytes(const uint8_t *bits, uint8_t nbits, uint8_t *out, uint8_t out_cap) {
  uint8_t nbytes = nbits / 8;
  if (nbytes > out_cap) nbytes = out_cap;

  for (uint8_t b = 0; b < nbytes; ++b) {
    uint8_t v = 0;
    for (uint8_t i = 0; i < 8; ++i) {
      v = (uint8_t)((v << 1) | (bits[(uint8_t)(b * 8 + i)] & 0x01));
    }
    out[b] = v;
  }
  return nbytes;
}

static void decodeAndLogFrame(const uint8_t *bits, const uint8_t *digit_masks, uint8_t nbits, uint32_t frame_ts_us) {
  if (nbits < 8 || (nbits % 8) != 0) {
    if (!MINIMAL_LOG) {
      Serial.print(F("drop frame bits="));
      Serial.println(nbits);
    }
    return;
  }

  uint8_t nbytes = nbits / 8;
  uint8_t bytes[8];
  nbytes = bitsToBytes(bits, nbits, bytes, sizeof(bytes));

  uint8_t mask_cnt = 0;
  uint8_t dom_mask = (uint8_t)dominantDigitMask(digit_masks, nbits, &mask_cnt);

  if (!MINIMAL_LOG) {
    Serial.print(F("frame bits="));
    Serial.print(nbits);
    Serial.print(F(" raw="));
    for (uint8_t i = 0; i < nbits; ++i) Serial.print(bits[i] ? '1' : '0');
    Serial.print(F(" bytes=["));
    for (uint8_t i = 0; i < nbytes; ++i) {
      if (i) Serial.print(' ');
      if (bytes[i] < 16) Serial.print('0');
      Serial.print(bytes[i], HEX);
    }
    Serial.print(F("] sel="));
    Serial.print((dom_mask >> 2) & 0x01);
    Serial.print((dom_mask >> 1) & 0x01);
    Serial.print(dom_mask & 0x01);
    Serial.print('(');
    Serial.print(mask_cnt);
    Serial.print('/');
    Serial.print(nbits);
    Serial.print(')');
  }

  bool decoded_ok = false;

  // Mux-assisted decode for 1-byte frame with selector line state.
  if (!decoded_ok && nbytes == 1) {
    bool dom_active_low = false;
    int slot_dom = selectorSlotFromMask(dom_mask, &dom_active_low);
    int slot = slot_dom;
    bool slot_active_low = dom_active_low;
    const __FlashStringHelper *slot_link = F("dom");
    bool linked_by_strobe = false;
    bool strobe_active_low = false;

    uint32_t strobe_age = frame_ts_us - g_last_strobe_ts;
    if (g_last_strobe_mask != 0 && strobe_age <= STROBE_LINK_MAX_US) {
      int slot_strobe = selectorSlotFromMask(g_last_strobe_mask, &strobe_active_low);
      if (slot_strobe >= 0) {
        slot = slot_strobe;
        slot_active_low = strobe_active_low;
        slot_link = F("strobe");
        linked_by_strobe = true;
      }
    }

    if (STROBE_ONLY_MODE && !linked_by_strobe && slot_dom < 0) {
      slot = -1;
      slot_link = F("none");
    }

    if (slot == 2) {
      bool led_committed = updateLedStable(bytes[0], micros());
      if (MINIMAL_LOG) {
        if (led_committed && printValue2D()) {
          Serial.println();
        }
      } else {
        Serial.print(F(" led="));
        Serial.print(bytes[0]);
        Serial.print(F(" status=ok(led)"));
        Serial.print(F(" slot=3 link="));
        Serial.print(slot_link);
        Serial.print(F(" pol="));
        Serial.print(slot_active_low ? F("al") : F("ah"));
      }
      decoded_ok = true;
    }

    bool fuzzy = false;
    int d = decodeSegmentByteFuzzy(bytes[0], &fuzzy);
    if (!decoded_ok && slot >= 0 && slot <= 1 && d >= 0) {
      int auto_d = decodeSlotAuto((uint8_t)slot, bytes[0], &fuzzy);
      if (auto_d >= 0) {
        d = auto_d;
      }
      if (g_slot_samples[slot] < 65535) g_slot_samples[slot]++;

      bool committed = updateSlotDigitStable((uint8_t)slot, d, micros());

      if (MINIMAL_LOG) {
        if (committed) {
          if (printValue2D()) {
            Serial.println();
          }
        }
      } else {
        Serial.print(F(" decoded="));
        Serial.print(d);
        Serial.print(F("? status="));
        Serial.print(fuzzy ? F("partial(mux_fuzzy)") : F("partial(mux)"));
        Serial.print(F(" slot="));
        Serial.print(slot + 1);
        Serial.print(F(" link="));
        Serial.print(slot_link);
        Serial.print(F(" pol="));
        Serial.print(slot_active_low ? F("al") : F("ah"));
        Serial.print(F(" mode="));
        Serial.print(g_slot_best_mode[slot]);
        Serial.print(F(" stable="));
        Serial.print(committed ? F("yes") : F("no"));
        Serial.print(F(" samples="));
        Serial.print(g_slot_samples[slot]);
        printMuxValue();
        (void)printValue2D();
      }
      decoded_ok = true;
    }
  }
  if (!MINIMAL_LOG) {
    if (!decoded_ok && nbytes >= 1) {
      bool fuzzy = false;
      int d = decodeSegmentByteFuzzy(bytes[0], &fuzzy);
      if (d >= 0) {
        Serial.print(F(" decoded="));
        Serial.print(d);
        Serial.print(F("? status="));
        Serial.print(fuzzy ? F("partial(single_fuzzy)") : F("partial(single)"));
        decoded_ok = true;
      }
    }

    if (!decoded_ok) {
      Serial.print(F(" decoded=unknown status=unknown"));
    }
    Serial.println();
  }
}

static void flushAlignedAndKeepTail(uint8_t *bits, uint8_t *digit_masks, uint8_t *nbits_io, uint32_t frame_ts_us) {
  uint8_t nbits = *nbits_io;
  if (nbits < 8) {
    return;
  }

  uint8_t aligned_bits = (uint8_t)(nbits & 0xF8); // floor to full bytes
  if (aligned_bits > 0) {
    decodeAndLogFrame(bits, digit_masks, aligned_bits, frame_ts_us);
  }

  uint8_t rem = (uint8_t)(nbits - aligned_bits);
  if (rem > 0) {
    for (uint8_t i = 0; i < rem; ++i) {
      bits[i] = bits[(uint8_t)(aligned_bits + i)];
      digit_masks[i] = digit_masks[(uint8_t)(aligned_bits + i)];
    }
  }
  *nbits_io = rem;
}

// ---------------- ISR ----------------
void onClkRise() {
  uint8_t next = (uint8_t)(g_q_head + 1u);
  if (next >= EVENT_QUEUE_LEN) next = 0;

  if (next == g_q_tail) {
    g_drop_count++;
    return;
  }

  BitEvent ev;
  ev.ts_us = micros();
  if (CAPTURE_DELAY_US > 0) {
    delayMicroseconds(CAPTURE_DELAY_US);
  }
  ev.bit = (uint8_t)(digitalRead(PIN_DATA) ? 1 : 0);
  uint8_t d1 = (uint8_t)(digitalRead(PIN_SEL_A) ? 1 : 0);
  uint8_t d2 = (uint8_t)(digitalRead(PIN_SEL_B) ? 1 : 0);
  uint8_t d3 = (uint8_t)(digitalRead(PIN_SEL_C) ? 1 : 0);
  ev.digit_mask = (uint8_t)(d1 | (d2 << 1) | (d3 << 2));

  g_evq[g_q_head] = ev;
  g_q_head = next;
}

static bool popEvent(BitEvent &ev) {
  noInterrupts();
  if (g_q_tail == g_q_head) {
    interrupts();
    return false;
  }
  ev.ts_us = g_evq[g_q_tail].ts_us;
  ev.bit = g_evq[g_q_tail].bit;
  ev.digit_mask = g_evq[g_q_tail].digit_mask;
  g_q_tail = (uint8_t)(g_q_tail + 1u);
  if (g_q_tail >= EVENT_QUEUE_LEN) g_q_tail = 0;
  interrupts();
  return true;
}

void setup() {
  pinMode(PIN_CLK, INPUT);
  pinMode(PIN_DATA, INPUT);
  pinMode(PIN_SEL_A, INPUT);
  pinMode(PIN_SEL_B, INPUT);
  pinMode(PIN_SEL_C, INPUT);

  Serial.begin(115200);
  while (!Serial) { ; }

  attachInterrupt(
    digitalPinToInterrupt(PIN_CLK),
    onClkRise,
    USE_FALLING_EDGE ? FALLING : RISING
  );

  Serial.println(F("uno sniffer start"));
  Serial.print(F("pins clk=")); Serial.print(PIN_CLK);
  Serial.print(F(" data=")); Serial.print(PIN_DATA);
  Serial.print(F(" sel_a=")); Serial.print(PIN_SEL_A);
  Serial.print(F(" sel_b=")); Serial.print(PIN_SEL_B);
  Serial.print(F(" sel_c=")); Serial.println(PIN_SEL_C);
  Serial.print(F("clk_edge="));
  Serial.println(USE_FALLING_EDGE ? F("FALLING") : F("RISING"));
}

void loop() {
  static uint8_t bits[MAX_FRAME_BITS];
  static uint8_t digit_masks[MAX_FRAME_BITS];
  static uint8_t nbits = 0;
  static uint32_t last_ts = 0;
  static uint32_t last_drop_log = 0;
  static bool prev_digit_valid = false;
  static uint8_t prev_digit_mask = 0;

  BitEvent ev;
  bool had_event = false;

  while (popEvent(ev)) {
    had_event = true;

    if (!prev_digit_valid || ev.digit_mask != prev_digit_mask) {
      if (!MINIMAL_LOG) {
        Serial.print(F("digit change t_us="));
        Serial.print(ev.ts_us);
        Serial.print(F(" a="));
        Serial.print((ev.digit_mask >> 0) & 0x01);
        Serial.print(F(" b="));
        Serial.print((ev.digit_mask >> 1) & 0x01);
        Serial.print(F(" c="));
        Serial.println((ev.digit_mask >> 2) & 0x01);
      }

      bool active_low = false;
      if (selectorSlotFromMask(ev.digit_mask, &active_low) >= 0) {
        g_last_strobe_mask = ev.digit_mask;
        g_last_strobe_ts = ev.ts_us;
      }

      prev_digit_valid = true;
      prev_digit_mask = ev.digit_mask;
    }

    if (last_ts != 0 && nbits > 0) {
      uint32_t dt = ev.ts_us - last_ts;
      if (dt > FRAME_GAP_US) {
        flushAlignedAndKeepTail(bits, digit_masks, &nbits, last_ts);
      }
    }

    if (nbits < MAX_FRAME_BITS) {
      bits[nbits] = ev.bit;
      digit_masks[nbits] = ev.digit_mask;
      nbits++;

      // For continuous streams without gaps, emit 1-byte chunks.
      if (nbits >= CONTINUOUS_FLUSH_BITS) {
        flushAlignedAndKeepTail(bits, digit_masks, &nbits, ev.ts_us);
      }
    } else {
      if (!MINIMAL_LOG) {
        Serial.print(F("overflow flush bits="));
        Serial.println(nbits);
      }
      flushAlignedAndKeepTail(bits, digit_masks, &nbits, last_ts);
    }

    last_ts = ev.ts_us;
  }

  if (!had_event && nbits > 0 && (uint32_t)(micros() - last_ts) > FRAME_GAP_US) {
    flushAlignedAndKeepTail(bits, digit_masks, &nbits, last_ts);
  }

  if ((uint32_t)(millis() - last_drop_log) > 1000) {
    last_drop_log = millis();
    uint16_t dropped;
    noInterrupts();
    dropped = g_drop_count;
    g_drop_count = 0;
    interrupts();
    if (dropped > 0) {
      if (!MINIMAL_LOG) {
        Serial.print(F("warn dropped_events="));
        Serial.println(dropped);
      }
    }
  }
}
