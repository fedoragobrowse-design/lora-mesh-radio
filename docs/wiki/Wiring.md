# Wiring

Build three identical copies: A, B, C. Logical table is authoritative;
breadboard drawings never override it. On a Pico viewed component-side
with USB at the top, physical pins 1–20 run down the left, 21–40 up the
right. Use the official pinout + printed GPIO labels, never breadboard
row counts. GPIO number 18 is not physical pin 18.

```
 USB computer / USB power bank
                │ USB power (and data when attached to a computer)
                ▼
     ┌────────────────────────┐                  ┌─────────────────────────┐
     │ Raspberry Pi Pico 2 W  │                  │ Adafruit RFM95W #3072  │
     │                        │                  │ SX1276 LoRa breakout    │
     │ 3V3 OUT  physical 36   ├──── power ──────►│ VIN                     │
     │ GND      physical 38   ├──── ground ──────┤ GND                     │
     │ GP18     physical 24   ├──── SCK ────────►│ SCK                     │
     │ GP19     physical 25   ├──── MOSI ───────►│ MOSI                    │
     │ GP16     physical 21   │◄─── MISO ───────┤ MISO                    │
     │ GP17     physical 22   ├──── select ─────►│ CS                      │
     │ GP20     physical 26   ├──── reset ──────►│ RST                     │
     │ GP21     physical 27   │◄─── interrupt ──┤ G0 / DIO0               │
     └────────────────────────┘                  │                         │
                                                 │ ANT RF pad ── antenna  │
                                                 └─────────────────────────┘
             No Wi-Fi/Bluetooth setup. No GPS/UWB. No wires between A/B/C.
```

| Pico signal | Physical pin | #3072 connection | Function |
|---|---|---|---|
| `3V3 OUT` | 36 | `VIN` | Regulated 3.3 V (VIN accepts 3.3–6 V @ 150 mA; Pico 3V3 OUT budget 300 mA) |
| `GND` | 38 | `GND` | Common reference |
| `GP18` | 24 | `SCK` | SPI0 clock, Pico → radio |
| `GP19` | 25 | `MOSI` | SPI0 transmit, Pico → radio |
| `GP16` | 21 | `MISO` | SPI0 receive, radio → Pico |
| `GP17` | 22 | `CS` | Active-low chip select |
| `GP20` | 26 | `RST` | Reset (driver pulses low-then-high for SX1276) |
| `GP21` | 27 | `G0`/`DIO0` | Radio interrupt (RX-done, TX-done, CAD-done) |

Only **DIO0/G0** is wired — DIO1 is unnecessary for this P2P protocol.
Leave EN unconnected (internally pulled high). Leave other breakout signals
unconnected. Regulator output may sit slightly below 3.3 V on 3.3 V VIN;
measure before misdiagnosing normal dropout.

## Assembly order

1. Pico across the breadboard trench (opposing rows not shorted). Breakout
   separately, one header pin per independent strip.
2. Ground, then 3.3 V, then six signal connections. Short SPI runs, away
   from the antenna. Bridge split rails only on same-voltage segments.
3. Power disconnected: check every signal end-to-end + 3V3-to-GND short.
4. Power one node: measure `3V3 OUT` vs ground; stop on wrong voltage,
   heat, or USB flapping. Never fix resets by raising voltage.
5. Repeat for the other two. See also `node-wiring.svg` in the radio repo.
