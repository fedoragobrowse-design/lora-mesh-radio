# Web installer (static, RP2350)

Static Meshtastic-flasher-style page for the Pico 2 W (RP2350) in
`index.html` + `app.js` + `styles.css`. Serve this directory statically:

```sh
cd web-installer && python3 -m http.server 8000
# open http://localhost:8000 (secure context: localhost counts)
```

## Flow

1. Pick a release from `releases.json` (**radio-secure default**,
   radio-free diagnostic second).
2. Enter BOOTSEL physically: hold BOOTSEL, plug in USB, release.
   The `RPI-RP2` mass-storage volume appears. WebUSB detection
   (`2e8a:000f` BOOTSEL vs `2e8a:0001` app) is informational only.
3. Download the UF2 (SHA-256 verified in-page when the manifest
   carries a hash), then either press **Write UF2 to drive**
   (Chromium File System Access directory write) or drag-drop the
   file onto `RPI-RP2` in a file manager. The board reboots itself.
4. Verify from a terminal: `python3 -m meshctl --port /dev/ttyACM0 status`
   and check `board`/`image`/`radio_available`. Identify boards by USB
   serial + status, never by `ttyACM` number.

## Publishing a release

Drop the built UF2s into `firmware/` (see `firmware/README.md`),
then fill in `file` + `sha256` in `releases.json`:

```sh
sha256sum firmware/radio-secure.uf2 firmware/radio-free.uf2
```

## RP2350 UF2 limits (no WebSerial/esptool path)

- The RP2350 has no ESP32-style ROM serial bootloader, so there is no
  WebSerial/esptool flashing route. The only browser-visible install
  path is the BOOTSEL UF2 mass-storage volume.
- The browser cannot mount volumes or force a BOOTSEL reboot; the
  hold-BOOTSEL-button step is physical and mandatory.
- WebUSB cannot claim the BOOTSEL mass-storage interface, so detection
  (`navigator.usb`, `2e8a:000f`) is read-only informational.
- Automated copy needs the File System Access API (`showDirectoryPicker`,
  Chromium, secure context). Firefox/Safari: download + manual drag-drop.
- No `sudo`, no keys in the browser: the page only moves opaque UF2
  bytes; provisioning/pairing stay in firmware + `meshctl`.

## Private mesh default

Private secure mesh is the default image. A Meshtastic-compatibility
mode, if ever listed here, must be labelled insecure; this installer
never enables it.
