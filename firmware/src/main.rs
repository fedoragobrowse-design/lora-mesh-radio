#![no_std]
#![no_main]

//! Radio-free secure firmware: Embassy USB CDC + TRNG + sequential-storage
//! owner + transport-independent `mesh-node` engine. No SPI/GPIO radio
//! initialization in this image; every RF call returns RADIO_UNAVAILABLE
//! and `status` reports `radio_available:false` with no `radio_version`.

mod board;
mod led;
#[cfg(feature = "radio")]
mod radio;
#[cfg(feature = "radio")]
mod runtime;
mod storage;
mod usb;
#[cfg(feature = "radio")]
mod wifi;

use embassy_executor::Spawner;
use embassy_rp::peripherals::USB;
use embassy_rp::usb::Driver;
use embassy_sync::channel::Channel;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::{Builder, Config};
use panic_probe as _;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::board::Irqs;
use crate::storage::{StorageChannel, StorageReq, StorageResp, StorageRespChannel, StorageService};

static STORAGE_REQ: StorageChannel = Channel::new();
static STORAGE_RESP: StorageRespChannel = Channel::new();

/// Radio image: USB bytes enter here; the runtime task owns the engine.
/// Single owner => no lock, no starvation: the runtime drains radio events
/// and ACK/retry timeouts on a 50ms tick even with no host traffic, and the
/// USB `read_packet` future is never cancelled.
#[cfg(feature = "radio")]
static USB_RX: Channel<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    ([u8; 64], usize),
    8,
> = Channel::new();

#[embassy_executor::task]
async fn storage_task(
    svc: StorageService,
    flash: embassy_rp::Peri<'static, embassy_rp::peripherals::FLASH>,
    dma: embassy_rp::Peri<'static, embassy_rp::peripherals::DMA_CH2>,
    irqs: Irqs,
) -> ! {
    svc.run(flash, dma, irqs).await
}

#[cfg(feature = "radio")]
#[embassy_executor::task]
async fn radio_task(radio: crate::radio::Radio) -> ! {
    radio.run().await
}

/// Radio image: owns engine + TRNG + radio drains. USB bytes arrive via
/// `USB_RX`; replies/events leave via `runtime::USB_TX`. Ticks every 50ms
/// so ACK/retry/relay deadlines advance with no host traffic.
#[cfg(feature = "radio")]
#[embassy_executor::task]
async fn runtime_task(
    engine: mesh_node::Engine,
    health: crate::storage::StoreHealth,
    radio_version: Option<u8>,
    hw_present: bool,
    boot_settings: mesh_node::settings::Settings,
    boot_wifi: Option<([u8; 32], u8, [u8; 63], u8)>,
    mut trng: embassy_rp::trng::Trng<'static, embassy_rp::peripherals::TRNG>,
) -> ! {
    use embassy_time::{Duration, Timer};
    let mut usb_state0 = usb::UsbState::new(engine, health);
    usb_state0.settings = boot_settings;
    usb_state0.wifi_configured = boot_wifi.is_some();
    usb_state0.wifi_ssid_len = boot_wifi.map(|(_, sl, _, _)| sl).unwrap_or(0);
    let mut entropy = crate::runtime::TrngEntropy::new(&mut trng);
    let mut rt = crate::runtime::Runtime::new(
        usb_state0,
        &mut entropy,
        crate::runtime::StorageChannels {
            req: &STORAGE_REQ,
            resp: &STORAGE_RESP,
        },
    );
    rt.usb.radio_version = radio_version;
    rt.set_hw_present(hw_present);
    let mut lines = usb::LineBuffer::new();
    let mut parse_scratch = [0u8; usb::PARSE_SCRATCH_LEN];
    loop {
        // Commit hour transitions before handling USB commands or radio RX.
        rt.advance_time().await;
        while let Ok((pkt, n)) = USB_RX.try_receive() {
            for &b in pkt[..n].iter() {
                if let Some(outcome) = rt.pump_byte(&mut lines, b, &mut parse_scratch) {
                    rt.on_usb_outcome(outcome).await;
                }
            }
        }
        // BOOTSEL reboot: reply already flushed via USB_TX; wait for the
        // transmit task to drain it, then invoke the ROM (never returns).
        if matches!(
            rt.usb.pending_op,
            Some(usb::PendingOp::RebootBootsel { .. })
        ) {
            rt.usb.pending_op = None;
            embassy_time::Timer::after(embassy_time::Duration::from_millis(300)).await;
            embassy_rp::rom_data::reset_to_usb_boot(0, 0);
        }
        while let Ok(evt) = crate::radio::RADIO_EVT.try_receive() {
            rt.on_radio_evt(evt).await;
        }
        rt.poll_timeouts().await;
        Timer::after(Duration::from_millis(50)).await;
    }
}

async fn write_line<'d, D: embassy_usb::driver::Driver<'d>>(
    class: &mut CdcAcmClass<'d, D>,
    bytes: &[u8],
) -> Result<(), embassy_usb::driver::EndpointError> {
    for chunk in bytes.chunks(64) {
        class.write_packet(chunk).await?;
    }
    class.write_packet(b"\n").await
}

async fn commit_staged(usb_state: &mut usb::UsbState) -> bool {
    if let Some((bytes, len)) = usb_state.staged.take() {
        STORAGE_REQ.send(StorageReq::Commit { bytes, len }).await;
        let ok = loop {
            match STORAGE_RESP.receive().await {
                StorageResp::Committed(r) => break r.is_ok(),
                // L9: a mid-run storage Fault must fail closed, never hang.
                StorageResp::Fault => break false,
                _ => continue,
            }
        };
        if ok {
            usb_state.engine.commit_ok();
            return true;
        }
        usb_state.engine.discard_staged();
        usb_state.engine.mark_fault();
        usb_state.health = crate::storage::StoreHealth::Fault;
        return false;
    }
    // SettingsSet carries no node bytes: commit the LSET record under
    // KEY_SETTINGS. Rendered only after durable commit; on fault revert
    // live settings to defaults and fail the reply.
    if matches!(
        usb_state.staged_reply,
        Some(usb::StagedReply::SettingsSet { .. })
    ) {
        let bytes = usb_state.settings.encode();
        STORAGE_REQ.send(StorageReq::CommitSettings { bytes }).await;
        let ok = loop {
            match STORAGE_RESP.receive().await {
                StorageResp::Committed(r) => break r.is_ok(),
                // L9: a mid-run storage Fault must fail closed, never hang.
                StorageResp::Fault => break false,
                _ => continue,
            }
        };
        if ok {
            return true;
        }
        usb_state.settings = mesh_node::settings::Settings::default();
        usb_state.settings_tx_pending = false;
        return false;
    }
    // WifiSet/WifiForget carry no node bytes: commit the WSET record under
    // KEY_WIFI. Radio-free has no wifi module, so it only tracks the
    // configured flag (commit_reply renders shape-only replies).
    if matches!(
        usb_state.staged_reply,
        Some(usb::StagedReply::WifiSet { .. }) | Some(usb::StagedReply::WifiForget { .. })
    ) {
        let is_forget = matches!(
            usb_state.staged_reply,
            Some(usb::StagedReply::WifiForget { .. })
        );
        let bytes = match usb_state.staged_wifi {
            Some((ssid, sl, pass, pl)) => {
                let mut out = [0u8; 102];
                out[0..4].copy_from_slice(b"WSET");
                out[4] = 1;
                out[5] = sl;
                out[6] = pl;
                out[7..39].copy_from_slice(&ssid);
                out[39..102].copy_from_slice(&pass);
                out
            }
            None => {
                let mut out = [0u8; 102];
                out[0..4].copy_from_slice(b"WSET");
                out[4] = 1;
                out
            }
        };
        STORAGE_REQ.send(StorageReq::CommitWifi { bytes }).await;
        let ok = loop {
            match STORAGE_RESP.receive().await {
                StorageResp::Committed(r) => break r.is_ok(),
                // L9: a mid-run storage Fault must fail closed, never hang.
                StorageResp::Fault => break false,
                _ => continue,
            }
        };
        if ok {
            usb_state.wifi_configured = !is_forget;
            // Keep the display length in sync: staged ssid_len on set,
            // zero on forget or when nothing was staged.
            usb_state.wifi_ssid_len = if is_forget {
                0
            } else {
                usb_state.staged_wifi.map(|(_, sl, _, _)| sl).unwrap_or(0)
            };
            usb_state.staged_wifi = None;
            return true;
        }
        // H2: commit failure must fail closed, never report success.
        usb_state.staged_wifi = None;
        usb_state.staged_reply = None;
        return false;
    }
    true
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    let chip_id = embassy_rp::otp::get_chipid().unwrap_or(0);
    let uid = chip_id.to_be_bytes();
    let mut serial_str = [0u8; 16];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in uid.iter().enumerate() {
        serial_str[2 * i] = HEX[(b >> 4) as usize];
        serial_str[2 * i + 1] = HEX[(b & 0xf) as usize];
    }
    let serial_str = unsafe { core::str::from_utf8_unchecked(&serial_str) };

    let svc = StorageService::new(&STORAGE_REQ, &STORAGE_RESP);
    spawner.spawn(storage_task(svc, p.FLASH, p.DMA_CH2, Irqs).unwrap());
    STORAGE_REQ.send(StorageReq::Load).await;
    let mut engine = mesh_node::Engine::new(false);
    let mut health = crate::storage::StoreHealth::Unprovisioned;
    loop {
        match STORAGE_RESP.receive().await {
            StorageResp::Loaded { bytes } => {
                match engine.restore(&bytes) {
                    Ok(()) => health = crate::storage::StoreHealth::Ready,
                    Err(_) => health = crate::storage::StoreHealth::Fault,
                }
                break;
            }
            StorageResp::Empty => break,
            StorageResp::Fault => {
                health = crate::storage::StoreHealth::Fault;
                break;
            }
            StorageResp::Committed(_)
            | StorageResp::SettingsLoaded { .. }
            | StorageResp::WifiLoaded { .. } => continue,
        }
    }
    // Settings load rides the same boot request; absent/corrupt means
    // defaults (decode fails closed, never touches the node record).
    let boot_settings = loop {
        match STORAGE_RESP.receive().await {
            StorageResp::SettingsLoaded { bytes } => {
                break mesh_node::settings::Settings::decode(&bytes).unwrap_or_default()
            }
            StorageResp::Fault => break mesh_node::settings::Settings::default(),
            _ => continue,
        }
    };
    // WiFi credential rides the same boot request; absent/corrupt means
    // unconfigured (decode fails closed, secrets never logged).
    let boot_wifi: Option<([u8; 32], u8, [u8; 63], u8)> = loop {
        match STORAGE_RESP.receive().await {
            StorageResp::WifiLoaded { bytes } => {
                #[cfg(feature = "radio")]
                {
                    break crate::wifi::WifiCred::decode(&bytes)
                        .map(|c| (c.ssid, c.ssid_len, c.pass, c.pass_len));
                }
                #[cfg(not(feature = "radio"))]
                {
                    let _ = bytes;
                    break None;
                }
            }
            StorageResp::Fault => break None,
            _ => continue,
        }
    };
    engine.set_identity(uid);

    let mut trng_config = embassy_rp::trng::Config::default();
    // Match upstream's corrected default: 25 can repeatedly fail entropy
    // health checks while the async executor sleeps; keep every check enabled.
    trng_config.sample_count = 200;
    let mut trng = embassy_rp::trng::Trng::new(p.TRNG, Irqs, trng_config);
    #[cfg(not(feature = "radio"))]
    // Chip-detect: one raw SPI RegVersion read before USB starts. Never
    // transmits; the byte is reported honestly in `status.radio_version`.
    // `None` = SPI error; `Some(b)` = whatever the bus returned, including
    // 0x00/0xFF wiring faults (never fabricated as 0x12).
    let radio_version: Option<u8> = {
        use embassy_rp::gpio::{Input, Level, Output, Pull};
        use embassy_rp::peripherals::{PIN_16, PIN_17, PIN_18, PIN_19, SPI0};
        use embassy_rp::spi::{Async, Config as SpiConfig, Spi};
        let mut spi = Spi::new(
            p.SPI0,
            p.PIN_18,
            p.PIN_19,
            p.PIN_16,
            p.DMA_CH0,
            p.DMA_CH1,
            Irqs,
            SpiConfig::default(),
        );
        spi.set_frequency(1_000_000);
        let mut cs = Output::new(p.PIN_17, Level::High);
        let _rst = Input::new(p.PIN_20, Pull::None);
        let _dio0 = Input::new(p.PIN_21, Pull::None);
        cs.set_low();
        let mut byte = [0u8];
        let w = spi.write(&[0x42 & 0x7F]).await;
        let r = if w.is_ok() {
            spi.read(&mut byte).await
        } else {
            w
        };
        cs.set_high();
        r.ok().map(|_| byte[0])
    };
    #[cfg(feature = "radio")]
    let (radio_version, radio_result) = crate::radio::init(
        p.SPI0, p.PIN_18, p.PIN_19, p.PIN_16, p.PIN_17, p.PIN_20, p.PIN_21, p.DMA_CH0, p.DMA_CH1,
        Irqs,
    )
    .await;
    #[cfg(feature = "radio")]
    engine.set_radio_available(radio_result.is_ok());
    #[cfg(feature = "radio")]
    let hw_present = radio_result.is_ok();
    // WiFi TCP transport: same newline-JSON wire as USB CDC, served on
    // TCP 7777 by `wifi::wifi_task` (PIO0 PioSpi: power PIN_23, CS PIN_25,
    // clock PIN_24, data PIN_29, DMA_CH3; blobs vendored in
    // `firmware/firmware-blobs/`; PowerSave; LED via gpio_set(0)).
    // Credentials arrive via the future `wifi_cred` op (`wifi::WIFI_CRED`);
    // until that op exists the task pends without joining any network.
    // Spawn stays cfg-gated so the radio-free image never touches PIO0/SPI
    // GPIOs.
    #[cfg(feature = "radio")]
    spawner.spawn(
        crate::wifi::wifi_task(
            p.PIO0,
            p.DMA_CH3,
            p.PIN_23,
            p.PIN_24,
            p.PIN_25,
            p.PIN_29,
            boot_wifi.map(|(ssid, sl, pass, pl)| {
                let mut c = crate::wifi::WifiCred::empty();
                c.ssid = ssid;
                c.ssid_len = sl;
                c.pass = pass;
                c.pass_len = pl;
                c
            }),
        )
        .unwrap(),
    );
    #[cfg(feature = "radio")]
    if let Some(radio) = match radio_result {
        Ok(radio) => Some(radio),
        Err(_) => None,
    } {
        spawner.spawn(radio_task(radio).unwrap());
    }
    let driver = Driver::new(p.USB, Irqs);
    let config = {
        let mut c = Config::new(0x2E8A, 0x0001);
        c.manufacturer = Some("mesh");
        c.product = Some(if cfg!(feature = "radio") {
            "mesh-node radio-secure"
        } else {
            "mesh-node radio-free"
        });
        c.serial_number = Some(serial_str);
        c.max_power = 100;
        c.max_packet_size_0 = 64;
        c
    };
    let mut config_desc = [0u8; 256];
    let mut bos_desc = [0u8; 256];
    let mut control_buf = [0u8; 64];
    let mut state = State::new();
    let mut builder = Builder::new(
        driver,
        config,
        &mut config_desc,
        &mut bos_desc,
        &mut [],
        &mut control_buf,
    );
    let mut class = CdcAcmClass::new(&mut builder, &mut state, 64);
    let mut device = builder.build();
    #[cfg(feature = "radio")]
    {
        spawner.spawn(
            runtime_task(
                engine,
                health,
                radio_version,
                hw_present,
                boot_settings,
                boot_wifi,
                trng,
            )
            .unwrap(),
        );
        // independently so a reply or received event needs no further input.
        let (mut tx, mut rx) = class.split();
        let receive = async {
            loop {
                rx.wait_connection().await;
                let mut pkt = [0u8; 64];
                while let Ok(n) = rx.read_packet(&mut pkt).await {
                    // Apply USB backpressure instead of dropping arbitrary
                    // chunks of a JSON command. Reads are never cancelled.
                    USB_RX.send((pkt, n)).await;
                }
            }
        };
        let transmit = async {
            loop {
                tx.wait_connection().await;
                let rec = crate::runtime::USB_TX.receive().await;
                let mut connected = true;
                for chunk in rec.as_slice().chunks(64) {
                    if tx.write_packet(chunk).await.is_err() {
                        connected = false;
                        break;
                    }
                }
                // Terminate the line like radio-free `write_line`: the host
                // frames replies on `\n`; without it every reply stalls.
                if connected {
                    let _ = tx.write_packet(b"\n").await;
                }
            }
        };
        embassy_futures::join::join3(device.run(), receive, transmit).await;
    }
    #[cfg(not(feature = "radio"))]
    {
        embassy_futures::join::join(device.run(), async {
            let mut usb_state = usb::UsbState::new(engine, health);
            usb_state.settings = boot_settings;
            usb_state.wifi_configured = boot_wifi.is_some();
            usb_state.wifi_ssid_len = boot_wifi.map(|(_, sl, _, _)| sl).unwrap_or(0);
            let mut lines = usb::LineBuffer::new();
            let mut out = [0u8; usb::REPLY_LEN];
            let mut scratch = [0u8; usb::PARSE_SCRATCH_LEN];

            class.wait_connection().await;
            // Stay silent during enumeration: normal hosts clear their receive
            // buffer at open, which would drop an early banner mid-line and turn
            // the tail into an unparseable line on the next request.

            loop {
                let mut pkt = [0u8; 64];
                let n = match class.read_packet(&mut pkt).await {
                    Ok(n) => n,
                    Err(_) => {
                        lines = usb::LineBuffer::new();
                        class.wait_connection().await;
                        continue;
                    }
                };
                for &b in pkt[..n].iter() {
                    usb_state
                        .engine
                        .set_mono_s(embassy_time::Instant::now().as_secs());
                    let Some(outcome) =
                        usb::pump_byte(&mut usb_state, &mut lines, b, &mut out, &mut scratch)
                    else {
                        continue;
                    };
                    let mut outcome = outcome;
                    if outcome == usb::Outcome::NeedsTrng {
                        outcome = match usb_state.pending_op.take() {
                            Some(usb::PendingOp::Provision { id, label }) => {
                                let mut key = [0u8; 32];
                                // Yield while collecting entropy so USB control traffic keeps running.
                                trng.fill_bytes(&mut key).await;
                                let result = usb::complete_provision(
                                    &mut usb_state,
                                    id,
                                    label,
                                    key,
                                    &mut out,
                                );
                                key.zeroize();
                                result
                            }
                            Some(usb::PendingOp::PairOffer { id }) => {
                                let mut eph_priv = [0u8; 32];
                                let mut challenge = [0u8; 32];
                                trng.fill_bytes(&mut eph_priv).await;
                                trng.fill_bytes(&mut challenge).await;
                                let eph_pub =
                                    PublicKey::from(&StaticSecret::from(eph_priv)).to_bytes();
                                let result = usb::complete_pair_offer(
                                    &mut usb_state,
                                    id,
                                    eph_priv,
                                    eph_pub,
                                    challenge,
                                    &mut out,
                                );
                                eph_priv.zeroize();
                                result
                            }
                            Some(usb::PendingOp::SendPrep { .. })
                            | Some(usb::PendingOp::PingPrep { .. }) => {
                                usb::reply_unexpected_prep(&mut usb_state, &mut out)
                            }
                            Some(usb::PendingOp::RebootBootsel { .. }) => {
                                usb::Outcome::NeedsRebootBootsel
                            }
                            None => usb::Outcome::Silent,
                        };
                    }
                    if !commit_staged(&mut usb_state).await {
                        outcome = usb::storage_failure(&mut usb_state, &mut out);
                    }
                    let len = match outcome {
                        usb::Outcome::Inline(n) => Some(n),
                        usb::Outcome::NeedsCommit(_) => usb::commit_reply(&mut usb_state, &mut out),
                        usb::Outcome::NeedsRebootBootsel => {
                            usb::reply_rebooting(&mut usb_state, &mut out)
                        }
                        _ => None,
                    };
                    if let Some(len) = len {
                        let _ = write_line(&mut class, &out[..len]).await;
                    }
                    if matches!(
                        usb_state.pending_op,
                        Some(usb::PendingOp::RebootBootsel { .. })
                    ) {
                        usb_state.pending_op = None;
                        embassy_time::Timer::after(embassy_time::Duration::from_millis(100)).await;
                        embassy_rp::rom_data::reset_to_usb_boot(0, 0);
                    }
                }
            }
        })
        .await;
    }
}
