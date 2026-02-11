# AGENTS.md

## Project Context
- Framework: ESP-IDF `v5.5.0`.
- Target MCU: `ESP32`.
- Purpose: build a passive sniffer that listens to signal lines driving shift register `SN74HC164N` (two-digit 7-segment display driver path).
- To enable `idf.py` in PowerShell, run:
  - `C:\Espressif\frameworks\esp-idf-v5.5\export.ps1`

## Hardware Scope
- Sniffer must connect in passive listen mode to:
  - `CLK`
  - `DATA`
  - `GND` (common ground)
- Sniffer must not drive these lines and must not interfere with the original circuit.

## Functional Requirements
1. Capture bitstream from `CLK` + `DATA` in real time.
2. Print logs with:
   - raw bits sequence;
   - grouping by frame/word (when frame boundary is detected);
   - decoded numeric representation, if decoding is possible.
3. If decoding is uncertain, log raw data and mark decode status explicitly (`unknown`/`partial`).

## Decode Goal
- Primary goal: recover values shown on the two-digit 7-segment indicator.
- Decoder should support at least:
  - direct segment mask output;
  - best-effort conversion to decimal digits `00..99` when mapping is identifiable.

## Telemetry Output
- Sniffer must support forwarding readings by at least one channel:
  - `MQTT` (preferred default), or
  - `Telegram` bot API.
- Expected payload fields:
  - timestamp;
  - raw bits;
  - decoded value (if available);
  - decode status.

## Implementation Notes
- Use GPIO interrupt or RMT/GPIO sampling approach suitable for stable capture on ESP32.
- Keep logging lightweight; avoid blocking in ISR.
- Buffer captured frames in queue/ring buffer, decode in task context.
- Network publishing (MQTT/Telegram) must run in separate task from signal capture.

## Done Criteria
- On real hardware, logs show stable bit capture from `CLK/DATA`.
- At least part of observed frames are decoded into digits when mapping is known.
- Device publishes captured/decoded readings to configured MQTT broker or Telegram chat.
