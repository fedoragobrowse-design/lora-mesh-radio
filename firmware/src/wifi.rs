//! WiFi TCP transport: same newline-JSON wire as USB CDC, over TCP.
//!
//! The host talks newline-delimited JSON (``{id, op, params}`` per line;
//! replies echo ``id`` with ``ok`` + ``result``/``error``) to a TCP
//! server on port [`TCP_PORT`]. Bytes are NOT parsed here: this task is
//! an opaque byte pipe between the CYW43 TCP socket and the single
//! engine owner, exactly like the USB CDC directions in `main.rs`.
//!
//! Ownership (radio image only, behind `feature = "radio"`):
//! - Inbound TCP bytes feed the shared [`USB_RX`](crate::USB_RX)
//!   channel as 64-byte chunks — the same queue the USB receive
//!   direction fills. The runtime task drains it, runs
//!   `usb::pump_byte` per byte, and owns every request deadline.
//! - Outbound records leave via
//!   [`USB_TX`](crate::runtime::USB_TX); this task only polls it with
//!   `try_receive` (a quiet queue means no progress, never a block on
//!   the engine; the runtime itself drops async events when full).
//!
//! WiFi bring-up (Pico 2 W): CYW43 over PIO0 `PioSpi` with the
//! trouble-host pinout — power `PIN_23`, chip-select `PIN_25`, clock
//! `PIN_24`, data `PIN_29` — and [`cyw43::PowerManagementMode::PowerSave`]
//! (the default). Network credentials arrive via the future `wifi_cred`
//! op (stored by the settings owner); until that op exists this task
//! waits on [`WIFI_CRED`] instead of joining with baked-in secrets.
//! There is deliberately NO fallback SSID/password here.
//!
//! RF is untouched: TX power, spreading factor, bandwidth and sync word
//! stay exactly as `radio.rs` defines them (+2 dBm / SF7 / BW500 / 0x12).
//! The onboard LED is driven via `control.gpio_set(0, …)` (off while
//! listening, on while a client is connected), mirroring the upstream
//! `wifi_tcp_server` example — no wireless subsystem is initialized
//! merely to blink.
//!
//! BLE is deferred: this module MUST NOT grow BLE roles/services.
//!
//! This file needs `cyw43`, `cyw43-pio`, `embassy-net` (features `tcp`,
//! `dhcpv4`, `medium-ethernet`, `proto-ipv4`) plus the vendored blobs in
//! `firmware/firmware-blobs/` (`43439A0.bin` + `43439A0_clm.bin` from the
//! `cyw43-firmware` crate, `nvram_pico2w.bin` from upstream embassy). Blobs
//! arrive as `&'static [u8]` from `main` and are wrapped in
//! `cyw43::Aligned` here (4-byte alignment required). The task is
//! `#[cfg(feature = "radio")]` so the default radio-free image never
//! touches PIO0/SPI GPIOs.
#[cfg(feature = "radio")]
use crate::board::Irqs;
#[cfg(feature = "radio")]
use cyw43_pio::{PioSpi, DEFAULT_CLOCK_DIVIDER};
#[cfg(feature = "radio")]
use embassy_executor::Spawner;
#[cfg(feature = "radio")]
use embassy_net::tcp::TcpSocket;
#[cfg(feature = "radio")]
use embassy_net::{Runner as NetRunner, Stack};
#[cfg(feature = "radio")]
use embassy_rp::clocks::RoscRng;
#[cfg(feature = "radio")]
use embassy_rp::gpio::{Level, Output};
#[cfg(feature = "radio")]
use embassy_rp::pio::Pio;
#[cfg(feature = "radio")]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[cfg(feature = "radio")]
use embassy_sync::channel::Channel;
#[cfg(feature = "radio")]
use embassy_time::Duration;
#[cfg(feature = "radio")]
use embedded_io_async::{Read, Write};
#[cfg(feature = "radio")]
use static_cell::StaticCell;
/// TCP server port for the newline-JSON wire (mirrors
/// `host/meshctl/transports` `DEFAULT_TCP_PORT`).
#[cfg(feature = "radio")]
pub const TCP_PORT: u16 = 7777;

/// Pending WiFi credentials, set by the future `wifi_cred` op.
///
/// The settings owner will publish `(ssid_len, pass_len, ssid, pass)`
/// here once that op lands; until then the WiFi task pends on this
/// channel instead of joining any network. Bounded depth 1: a newer
/// credential overwrites via drain + send, never blocks.
#[cfg(feature = "radio")]
pub static WIFI_CRED: Channel<CriticalSectionRawMutex, WifiCred, 1> = Channel::new();

/// One WiFi credential set: lengths + fixed buffers (no heap).
#[cfg(feature = "radio")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WifiCred {
    /// SSID bytes in use (`ssid[..ssid_len]`).
    pub ssid_len: u8,
    /// Password bytes in use (`pass[..pass_len]`).
    pub pass_len: u8,
    /// SSID, max 32 bytes (802.11 limit).
    pub ssid: [u8; 32],
    /// Password, max 63 bytes (WPA2 limit).
    pub pass: [u8; 63],
}

/// Magic + version + fixed length of the standalone WiFi record.
/// Layout: magic(4) ver(1) ssid_len(1) pass_len(1) ssid(32) pass(63).
#[cfg(feature = "radio")]
pub const WIFI_MAGIC: [u8; 4] = *b"WSET";
#[cfg(feature = "radio")]
pub const WIFI_VERSION: u8 = 1;
#[cfg(feature = "radio")]
pub const WIFI_LEN: usize = 102;

#[cfg(feature = "radio")]
impl WifiCred {
    /// Blank credential (zeroed buffers, zero lengths).
    pub const fn empty() -> Self {
        Self {
            ssid_len: 0,
            pass_len: 0,
            ssid: [0u8; 32],
            pass: [0u8; 63],
        }
    }

    /// Build from validated byte slices; lengths are exact, buffers rest zero.
    pub fn from_slices(ssid: &[u8], pass: &[u8]) -> Option<Self> {
        if ssid.is_empty() || ssid.len() > 32 || pass.len() > 63 {
            return None;
        }
        let mut c = Self::empty();
        c.ssid_len = ssid.len() as u8;
        c.pass_len = pass.len() as u8;
        c.ssid[..ssid.len()].copy_from_slice(ssid);
        c.pass[..pass.len()].copy_from_slice(pass);
        Some(c)
    }

    /// Encode the fixed 102-byte record.
    pub fn encode(&self) -> [u8; WIFI_LEN] {
        let mut out = [0u8; WIFI_LEN];
        out[0..4].copy_from_slice(&WIFI_MAGIC);
        out[4] = WIFI_VERSION;
        out[5] = self.ssid_len;
        out[6] = self.pass_len;
        out[7..39].copy_from_slice(&self.ssid);
        out[39..102].copy_from_slice(&self.pass);
        out
    }

    /// Decode; `None` on length/magic/version mismatch or bad lengths
    /// (caller: keep prior credential, fail the op honestly).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != WIFI_LEN || bytes[0..4] != WIFI_MAGIC || bytes[4] != WIFI_VERSION {
            return None;
        }
        let ssid_len = bytes[5] as usize;
        let pass_len = bytes[6] as usize;
        if ssid_len == 0 || ssid_len > 32 || pass_len > 63 {
            return None;
        }
        let mut c = Self::empty();
        c.ssid_len = ssid_len as u8;
        c.pass_len = pass_len as u8;
        c.ssid.copy_from_slice(bytes[7..39].try_into().ok()?);
        c.pass.copy_from_slice(bytes[39..102].try_into().ok()?);
        // Lengths must cover non-zero bytes only (no trailing secret bytes
        // beyond the declared length).
        if c.ssid[ssid_len..].iter().any(|&b| b != 0) || c.pass[pass_len..].iter().any(|&b| b != 0)
        {
            return None;
        }
        Some(c)
    }
}

#[cfg(feature = "radio")]
#[embassy_executor::task]
async fn cyw43_task(
    runner: cyw43::Runner<
        'static,
        cyw43::SpiBus<Output<'static>, PioSpi<'static, embassy_rp::peripherals::PIO0, 0>>,
    >,
) -> ! {
    runner.run().await
}

#[cfg(feature = "radio")]
#[embassy_executor::task]
async fn net_task(mut runner: NetRunner<'static, cyw43::NetDriver<'static>>) -> ! {
    runner.run().await
}

/// WiFi TCP byte-pipe task (radio image only).
///
/// Bring up CYW43 on PIO0, wait for `wifi_cred` credentials, join with
/// PowerSave, then serve one client at a time on [`TCP_PORT`]:
/// socket bytes → `USB_RX` chunks; `USB_TX` records → socket lines.
/// Single client (no lock, no starvation): a second connection waits
/// on `accept` until the first drops.
///
/// `spawner` is our own task spawner: `main` spawns `wifi_task` with
#[cfg(feature = "radio")]
#[embassy_executor::task]
pub async fn wifi_task(
    pio0: embassy_rp::Peri<'static, embassy_rp::peripherals::PIO0>,
    dma_ch3: embassy_rp::Peri<'static, embassy_rp::peripherals::DMA_CH3>,
    pin_23: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_23>,
    pin_24: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_24>,
    pin_25: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_25>,
    pin_29: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_29>,
    boot_cred: Option<WifiCred>,
) -> ! {
    // SAFETY: single executor; the returned Spawner only spawns tasks onto it.
    let spawner = unsafe { embassy_executor::Spawner::for_current_executor().await };
    let fw: &cyw43::Aligned<cyw43::A4, [u8]> =
        cyw43::aligned_bytes!("../firmware-blobs/43439A0.bin");
    let nvram: &cyw43::Aligned<cyw43::A4, [u8]> =
        cyw43::aligned_bytes!("../firmware-blobs/nvram_pico2w.bin");
    let clm = include_bytes!("../firmware-blobs/43439A0_clm.bin");
    use embassy_rp::dma;

    let pwr = Output::new(pin_23, Level::Low);
    let cs = Output::new(pin_25, Level::High);
    let mut pio = Pio::new(pio0, Irqs);
    let spi = PioSpi::new(
        &mut pio.common,
        pio.sm0,
        DEFAULT_CLOCK_DIVIDER,
        pio.irq0,
        cs,
        pin_24,
        pin_29,
        dma::Channel::new(dma_ch3, Irqs),
    );
    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let (net_device, mut control, runner) = cyw43::new(state, pwr, spi, fw, nvram).await;
    spawner.spawn(cyw43_task(runner).unwrap());

    control.init(clm).await;
    control
        .set_power_management(cyw43::PowerManagementMode::PowerSave)
        .await;

    let mut rng = RoscRng;
    let seed = rng.next_u64();

    static RESOURCES: StaticCell<embassy_net::StackResources<3>> = StaticCell::new();
    let (stack, runner) = embassy_net::new(
        net_device,
        embassy_net::Config::dhcpv4(Default::default()),
        RESOURCES.init(embassy_net::StackResources::new()),
        seed,
    );
    spawner.spawn(net_task(runner).unwrap());

    static STACK: StaticCell<Stack<'static>> = StaticCell::new();
    let stack: &'static Stack<'static> = STACK.init(stack);
    serve(stack, &mut control, boot_cred).await
}
/// Join (once credentials arrive) and serve the TCP byte-pipe forever.
/// `boot_cred` (durable `KEY_WIFI` record) joins first when present; live
/// `wifi_set` publishes to `WIFI_CRED` and the task rejoins on rotation.
#[cfg(feature = "radio")]
async fn serve(
    stack: &'static Stack<'static>,
    control: &mut cyw43::Control<'static>,
    boot_cred: Option<WifiCred>,
) -> ! {
    let mut cred = match boot_cred {
        Some(c) => c,
        None => WIFI_CRED.receive().await,
    };
    let ssid = &cred.ssid[..cred.ssid_len as usize];
    let pass = &cred.pass[..cred.pass_len as usize];
    // `join` wants `&str`; credentials are validated UTF-8 by the
    // `wifi_cred` handler before publish, so lossy fallback never fires.
    let ssid = core::str::from_utf8(ssid).unwrap_or("");
    let pass = core::str::from_utf8(pass).unwrap_or("");
    while control
        .join(ssid, cyw43::JoinOptions::new(pass.as_bytes()))
        .await
        .is_err()
    {
        embassy_time::Timer::after(Duration::from_secs(5)).await;
    }
    stack.wait_link_up().await;
    stack.wait_config_up().await;

    // One socket for the process lifetime; `accept` is retried in-loop.
    let mut rx_buf = [0u8; 1024];
    let mut tx_buf = [0u8; 1024];
    let mut buf = [0u8; 64];
    control.gpio_set(0, false).await;
    let mut socket = TcpSocket::new(*stack, &mut rx_buf, &mut tx_buf);
    socket.set_timeout(Some(Duration::from_secs(10)));
    loop {
        control.gpio_set(0, false).await;
        if socket.accept(TCP_PORT).await.is_err() {
            socket.abort();
            continue;
        }
        // On while a client is connected.
        control.gpio_set(0, true).await;

        // Pump both directions until the client drops or errors.
        // Inbound: socket bytes -> USB_RX 64-byte chunks (backpressure,
        // never cancelled mid-chunk). Outbound: USB_TX records -> lines.
        loop {
            // Prefer fresh socket bytes; drain one pending reply per
            // iteration so neither direction starves the other.
            let mut progress = false;
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    progress = true;
                    let mut off = 0;
                    while off < n {
                        let take = core::cmp::min(64, n - off);
                        let mut pkt = [0u8; 64];
                        pkt[..take].copy_from_slice(&buf[off..off + take]);
                        // Backpressure: the runtime drains independently.
                        crate::USB_RX.send((pkt, take)).await;
                        off += take;
                    }
                }
            }
            match crate::runtime::USB_TX.try_receive() {
                Ok(rec) => {
                    progress = true;
                    let mut ok = true;
                    for chunk in rec.as_slice().chunks(1024) {
                        if socket.write_all(chunk).await.is_err() {
                            ok = false;
                            break;
                        }
                    }
                    if ok {
                        ok = socket.write_all(b"\n").await.is_ok();
                    }
                    if !ok {
                        break;
                    }
                }
                Err(_) => {}
            }
            if !progress {
                embassy_time::Timer::after(Duration::from_millis(5)).await;
            }
        }
    }
}
