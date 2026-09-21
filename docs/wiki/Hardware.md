# Hardware

Exactly three identical nodes. No Feather parts, no chargers, no NeoPixels,
no extra radios, no GPS/UWB, no wires between nodes.

## Bill of materials (per node ×3)

| Qty/node | Part |
|---|---|
| 1 | Raspberry Pi Pico 2 W (micro-USB data cable each) |
| 1 | Adafruit RFM95W #3072 LoRa breakout (SX1276) |
| 1 | 915 MHz antenna (spring from BOM or quarter-wave wire) |
| 1 | Breadboard + jumper wires |
| — | Soldering station, ventilated area, multimeter |

Do not attach two antennas to one RF feed. Do not use a 433 MHz antenna.
**Never transmit without an antenna fitted.**

## Bench rules

1. Label the physical boards and assemblies **A**, **B**, **C**.
2. Disconnect all power before soldering or moving jumpers.
3. Check headers: do not assume Pico 2 Ws ship with them fitted.
4. USB power only for assembly. No raw LiPo-to-GPIO, no `3V3_EN`, no 5 V
   into a Pico GPIO. Radios share ground with their own Pico.
5. Identify each USB board **one at a time** via BOOTSEL. Record the stable
   USB serial beside A/B/C. Never trust `/dev/ttyACM0` means A.

## Known hardware caveats

- One node carries a **homemade cable antenna** — expect it may fail; keep
  the A/B/C label in every result so failures isolate to antenna vs
  wiring vs code.
- **None of the radio-side solder joints are trusted.** Before any TX:
  inspect every joint for bridges/cold joints, multimeter-check continuity
  end-to-end per the [[Wiring]] table, confirm no 3V3-to-GND short, confirm
  antennas fitted.
- Start bench radio testing at 1–3 m spacing, antennas not touching.
