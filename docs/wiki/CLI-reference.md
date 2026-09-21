# CLI reference

`--port` is a serial path; one process per port. Boards are USB serials —
resolve via `meshctl boards`, never guess ACM numbers. `dialout` group
required for live USB (`sg dialout -c '…'`).

## One-shot ops

```sh
meshctl ports                                    # no --port needed
meshctl --port $A status
meshctl --port $A provision --label A            # A|B|C, once
meshctl --port $A time set --utc now             # 'now', unix secs, or ISO-8601
meshctl --port $A time status
meshctl --port $A radio on | off | arm-next-boot
meshctl --port $A ping --count 1                 # 1-3
meshctl --port $A send --contact alice --text "hi"   # 1-160 UTF-8 bytes
meshctl --port $A contacts                       # id/present/blocked/name/fingerprint
meshctl --port $A block alice | unblock alice | contact-delete alice
meshctl --port $A pair offer --out offer-A.png
meshctl --port $A pair proof --out proof-A.png
meshctl --port $A pair confirm --out confirm-A.png
meshctl --port $B pair import --file offer-A.png --name alice [--replace]
meshctl history --port $A [--limit 20]
meshctl records list | prune --keep 20
```

## Receive loops (single owner)

```sh
meshctl --port $B listen [--seconds N]
meshctl --port $B chat [--contact A]   # /to /block /status /radio off /help /quit
meshctl tui                            # all boards; Tab boards, F2 contacts, type to send
meshchat                               # Tk GUI: roster left, chat center, debug right
```

Second opener while held → `PORT_BUSY`.

## Boards / firmware / debug (no --port)

```sh
meshctl boards
meshctl flash --uf2 fw.uf2 [--dev /dev/sda1]   # exactly one BOOTSEL volume
meshctl elf check fw.elf | elf info fw.elf
meshctl uf2 fw.elf --out fw.uf2
meshctl reboot [--bootsel]                     # needs raw USB (often PERMISSION)
meshctl --port $A debug log [--seconds N]
meshctl --port $A debug counters [--rounds N --interval S]
```

## Contact names

Arbitrary local labels (`alice`, `relay-2`, 1–32 chars), mapped
USB-serial → name → slot in `.mesh-local/host-contacts.json`, written only
on `pair_import` activation. Firmware slots authoritative; names never
transmitted.
