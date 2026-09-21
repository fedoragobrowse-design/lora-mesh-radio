'use strict';
/* Static RP2350 web installer logic. No keys, no sudo, no network beyond
 * releases.json + UF2 downloads. Flashing = UF2 file copy onto the BOOTSEL
 * mass-storage volume (RPI-RP2); browsers cannot mount or reboot the board. */
(function () {
  const $ = (id) => document.getElementById(id);
  const releaseSel = $('release');
  const releaseInfo = $('release-info');
  const detectOut = $('detect-out');
  const copyOut = $('copy-out');
  const progress = $('copy-progress');
  const dlBtn = $('btn-download');
  const writeBtn = $('btn-write');

  let manifest = null;
  let uf2Bytes = null;   // ArrayBuffer of the downloaded/selected UF2
  let uf2Name = '';
  let driveHandle = null;

  function current() {
    return manifest.releases.find((r) => r.id === releaseSel.value) || manifest.releases[0];
  }

  function hex(buf) {
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  async function loadManifest() {
    const res = await fetch('releases.json', { cache: 'no-store' });
    if (!res.ok) throw new Error('releases.json HTTP ' + res.status);
    manifest = await res.json();
    releaseSel.innerHTML = '';
    for (const r of manifest.releases) {
      const o = document.createElement('option');
      o.value = r.id;
      o.textContent = r.label + ' — v' + r.version;
      releaseSel.appendChild(o);
    }
    releaseSel.value = manifest.default === 'radio-free-diag'
      ? 'radio-free-diag' : 'radio-secure-latest';
    if (![...releaseSel.options].some((o) => o.value === releaseSel.value)) {
      releaseSel.selectedIndex = 0;
    }
    renderRelease();
  }

  function renderRelease() {
    const r = current();
    uf2Bytes = null;
    uf2Name = r.file.split('/').pop();
    writeBtn.disabled = true;
    releaseInfo.textContent = r.id + '\nfile: ' + r.file + '\nsha256: ' +
      (r.sha256 || '(not published yet — verify out of band)') + '\n' + r.notes;
    dlBtn.href = r.file;
    dlBtn.setAttribute('download', uf2Name);
    copyOut.textContent = '';
    progress.hidden = true;
  }

  async function sha256(buf) {
    if (!crypto.subtle) return null;
    return hex(await crypto.subtle.digest('SHA-256', buf));
  }

  // UF2 sanity: 512-byte blocks each ending in 0x8A9DAD54-style magic is too
  // strict without parsing; check size multiple + "UF2\n" magic at offset 0.
  function uf2Sanity(buf) {
    const v = new Uint8Array(buf);
    if (v.length % 512 !== 0 || v.length === 0) return 'not a multiple of 512 bytes';
    if (v[0] !== 0x55 || v[1] !== 0x46 || v[2] !== 0x32 || v[3] !== 0x0a) {
      return 'missing UF2 magic at offset 0';
    }
    return null;
  }

  async function downloadUf2() {
    const r = current();
    copyOut.textContent = 'Downloading ' + r.file + ' …';
    const res = await fetch(r.file, { cache: 'no-store' });
    if (!res.ok) {
      copyOut.textContent = 'Download failed: HTTP ' + res.status +
        '. Host the UF2 next to this page at ' + r.file + '.';
      return;
    }
    const buf = await res.arrayBuffer();
    const problem = uf2Sanity(buf);
    if (problem) { copyOut.textContent = 'Downloaded file rejected: ' + problem; return; }
    if (r.sha256) {
      const got = await sha256(buf);
      if (got && got !== r.sha256.toLowerCase()) {
        copyOut.textContent = 'SHA-256 mismatch!\nexpected ' + r.sha256 + '\ngot      ' + got;
        return;
      }
      copyOut.textContent = 'Downloaded ' + (buf.byteLength / 1024).toFixed(1) +
        ' KiB, SHA-256 verified.';
    } else {
      copyOut.textContent = 'Downloaded ' + (buf.byteLength / 1024).toFixed(1) +
        ' KiB (no manifest hash — verify out of band).';
    }
    uf2Bytes = buf;
    writeBtn.disabled = !driveHandle;
  }

  dlBtn.addEventListener('click', (ev) => {
    // Let the anchor download normally AND preload bytes for auto-write.
    downloadUf2().catch((e) => { copyOut.textContent = 'Download error: ' + e.message; });
  });

  // --- Step 2: WebUSB detection (informational only) ---------------------
  // RP2350 BOOTSEL = 2e8a:000f (mass storage, cannot be claimed from the
  // browser). App mode = 2e8a:0001 (CDC; WebSerial flashing does not exist
  // for RP2350 — no esptool path — so this is detect-only too).
  $('btn-detect-usb').addEventListener('click', async () => {
    if (!navigator.usb) {
      detectOut.textContent = 'WebUSB unavailable in this browser. Use the physical cues: RPI-RP2 drive = BOOTSEL, serial port = app mode.';
      return;
    }
    try {
      const devs = await navigator.usb.getDevices();
      const known = devs.filter((d) => d.vendorId === 0x2e8a);
      const tagged = known.map((d) =>
        '2e8a:' + d.productId.toString(16).padStart(4, '0') +
        (d.productId === 0x000f ? ' → BOOTSEL volume (copy UF2 onto RPI-RP2)' :
          d.productId === 0x0001 ? ' → app mode (already flashed; run meshctl status)' :
          ' → unknown Raspberry Pi USB device'));
      detectOut.textContent = known.length === 0
        ? 'No Raspberry Pi USB devices visible. If you just entered BOOTSEL, your browser may still need permission — use “Request device…” via the console, or just look for the RPI-RP2 drive.'
        : 'Visible Raspberry Pi USB devices:\n' + tagged.join('\n');
      if (known.length === 0) {
        try {
          const d = await navigator.usb.requestDevice({ filters: [{ vendorId: 0x2e8a }] });
          detectOut.textContent = 'Granted: 2e8a:' +
            d.productId.toString(16).padStart(4, '0') +
            (d.productId === 0x000f ? ' → BOOTSEL (copy UF2 onto RPI-RP2).' : ' → app mode.');
        } catch (e) {
          detectOut.textContent += '\nDevice request cancelled or denied (' + e.message + ').';
        }
      }
    } catch (e) {
      detectOut.textContent = 'WebUSB error: ' + e.message;
    }
  });

  // --- Step 3: drive pick + automated copy (Chromium File System Access) --
  $('btn-pick-drive').addEventListener('click', async () => {
    if (!window.showDirectoryPicker) {
      copyOut.textContent = 'This browser has no directory-write API (Firefox/Safari). Download the UF2 and drag it onto the RPI-RP2 drive in your file manager.';
      return;
    }
    try {
      driveHandle = await window.showDirectoryPicker({ id: 'bootsel', mode: 'readwrite' });
      copyOut.textContent = 'Drive selected: ' + (driveHandle.name || '(unnamed)') +
        '. Confirm it is the RPI-RP2 BOOTSEL volume before writing.' +
        (uf2Bytes ? '' : ' Now download the UF2 (button above) to enable writing.');
      writeBtn.disabled = !uf2Bytes;
    } catch (e) {
      copyOut.textContent = 'Drive pick cancelled (' + e.message + ').';
    }
  });

  writeBtn.addEventListener('click', async () => {
    if (!driveHandle || !uf2Bytes) return;
    writeBtn.disabled = true;
    progress.hidden = false;
    try {
      // Stream in 128 KiB chunks so progress is real, not faked.
      const fh = await driveHandle.getFileHandle(uf2Name, { create: true });
      const w = await fh.createWritable();
      const CHUNK = 128 * 1024;
      const v = new Uint8Array(uf2Bytes);
      for (let off = 0; off < v.length; off += CHUNK) {
        await w.write(v.subarray(off, Math.min(off + CHUNK, v.length)));
        progress.value = Math.round((Math.min(off + CHUNK, v.length) / v.length) * 100);
      }
      await w.close();
      progress.value = 100;
      copyOut.textContent = 'Wrote ' + uf2Name + ' (' + (v.length / 1024).toFixed(1) +
        ' KiB) to ' + (driveHandle.name || 'selected drive') +
        '. The board reboots itself; the drive will vanish. Continue at step 4 (meshctl status).';
    } catch (e) {
      copyOut.textContent = 'Write failed: ' + e.message +
        ' — fall back to dragging the downloaded UF2 onto RPI-RP2 in your file manager.';
    } finally {
      writeBtn.disabled = false;
    }
  });

  // Drag-drop selects a local UF2 (for manual-copy users to sanity-check).
  const drop = $('drop');
  async function takeFile(f) {
    if (!f) return;
    const buf = await f.arrayBuffer();
    const problem = uf2Sanity(buf);
    if (problem) { copyOut.textContent = f.name + ' rejected: ' + problem; return; }
    uf2Bytes = buf;
    uf2Name = f.name;
    copyOut.textContent = f.name + ' selected (' + (buf.byteLength / 1024).toFixed(1) +
      ' KiB, UF2 magic OK). Copy it onto RPI-RP2 in your file manager.' +
      (driveHandle ? ' Or press Write UF2 to drive.' : '');
    writeBtn.disabled = !driveHandle;
  }
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault(); drop.classList.remove('over');
    takeFile(e.dataTransfer.files[0]).catch((err) => { copyOut.textContent = 'Read error: ' + err.message; });
  });
  drop.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    e.preventDefault();
    const inp = document.createElement('input');
    inp.type = 'file'; inp.accept = '.uf2';
    inp.onchange = () => takeFile(inp.files[0]).catch((err) => { copyOut.textContent = 'Read error: ' + err.message; });
    inp.click();
  });
  drop.addEventListener('click', () => {
    const inp = document.createElement('input');
    inp.type = 'file'; inp.accept = '.uf2';
    inp.onchange = () => takeFile(inp.files[0]).catch((err) => { copyOut.textContent = 'Read error: ' + err.message; });
    inp.click();
  });

  // --- Step 4: verify command copy ---------------------------------------
  $('btn-copy-cmd').addEventListener('click', async () => {
    const cmd = $('verify-cmd').textContent.trim();
    try {
      await navigator.clipboard.writeText(cmd);
      $('btn-copy-cmd').textContent = 'Copied';
      setTimeout(() => { $('btn-copy-cmd').textContent = 'Copy command'; }, 1500);
    } catch (e) {
      $('btn-copy-cmd').textContent = 'Copy failed — select the text manually';
    }
  });

  releaseSel.addEventListener('change', renderRelease);

  loadManifest().catch((e) => {
    releaseInfo.textContent = 'Could not load releases.json: ' + e.message +
      ' (serve this directory over HTTP; fetch is blocked on file://).';
  });
})();
