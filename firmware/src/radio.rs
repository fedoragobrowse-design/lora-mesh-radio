//! Secure radio byte-pipe (radio feature only).
//!
//! Lowest supported TX power is a hard constraint for every TX class.
//!
//! RF profile: 915 MHz, SF7, BW500, CR4/5, explicit header, 8-symbol
//! preamble, hardware CRC on, normal IQ, private SX127x sync word 0x12.
//! Every transmission funnels through one choke (`do_tx` → `tx_prepare` +
//! `tx_wait`), which always passes [`TX_POWER_DBM`]; there is no power
//! parameter anywhere.
//!
//! This module is an opaque byte pipe: it moves [`AirFrame`] bytes between
//! the air and the runtime over bounded channels. It never parses frame
//! versions, plaintext bodies, ACKs, or delivery state; all secure framing
//! and reliability live in `mesh-core`/`mesh-node`. Queues are bounded
//! (cap 8): terminal/control events (`ControlDone`, `TxDone`, `CadDone`)
//! use reliable `send().await` (the runtime drains independently of USB);
//! `RxFrame`/`RxCrcError`/`Fault` use lossy `try_send` and may drop when
//! full. The USB side reports `BUSY` when the command queue is full instead
//! of blocking.
//!
//! Policy gate: [`tx_token`] / [`set_policy`] form a synchronous failclosed
//! atomic gate (critical-section mutex, no async). `off` invalidates every
//! old token; a newly blocked contact bit invalidates that contact's
//! tokens; `None` (opaque forward) ignores the block mask. `on`/`unblock`
//! never revives old tokens (generations only advance). The gate is checked
//! at dequeue, between CAD attempts, AND immediately pre-TX; CAD/backoff
//! aborts on invalidation, while an already-airborne frame runs to
//! completion before a queued [`RadioCmd::Barrier`] completes.
//!
//! Cancellation safety: the driver holds the `Sx127x` `RadioKind` directly
//! (not the `LoRa` façade) so every SPI burst runs to completion and is
//! never selected across or wrapped in a timeout. Only the GPIO DIO0 wait
//! (`await_irq`, explicitly droppable per the `RadioKind` contract) is timed
//! out (CAD/TX) or raced against commands (RX). After an IRQ fires, flag
//! processing (`process_irq_event`) and FIFO/status reads run to
//! completion. CAD/TX IRQ waits are bounded by timeouts (absent DIO0 fails
//! as [`TxFault::Radio`], never hangs, never transmits blindly). There are
//! no blind TX retries: one CAD-gated attempt per `Tx` command.
//!
//! Power/recovery: `SetEnabled(false)` enters radio sleep (cold); errors
//! attempt `enter_standby` recovery and report failclosed (`Radio` or
//! `ok:false`); RX faults back off (no tight loop) and re-enter RX.

use core::cell::Cell;

use crate::board::Irqs;
use embassy_futures::select::{select, Either};
use embassy_rp::gpio::{Input, Level, Output, Pull};
use embassy_rp::peripherals::{
    DMA_CH0, DMA_CH1, PIN_16, PIN_17, PIN_18, PIN_19, PIN_20, PIN_21, SPI0,
};
use embassy_rp::spi::{Async, Config as SpiConfig, Spi};
use embassy_rp::Peri;
use embassy_sync::blocking_mutex::{raw::CriticalSectionRawMutex, Mutex as BlockingMutex};
use embassy_sync::channel::Channel;
use embassy_time::{with_timeout, Delay, Duration, Timer};
use embedded_hal_bus::spi::ExclusiveDevice;
use lora_phy::iv::GenericSx127xInterfaceVariant;
use lora_phy::mod_params::{
    Bandwidth, CodingRate, ModulationParams, RadioError, RadioMode, RxMode, SpreadingFactor,
};
use lora_phy::mod_traits::{IrqState, RadioKind};
use lora_phy::sx127x::{Config as Sx127xConfig, Sx1276, Sx127x};

/// SX1276 PA_BOOST minimum on the RFM95W antenna path: +2 dBm (~1.58 mW).
/// Every transmission uses this. No override exists.
pub const TX_POWER_DBM: i32 = 2;

/// Fixed RF profile: 915 MHz, SF7, BW500, CR4-5, explicit header,
/// 8-symbol preamble, hardware CRC, normal IQ, private sync word 0x12.
pub const RF_PROFILE_LABEL: &str = "915000000/SF7/BW500/CR4-5/pre8/CRC/sync12";

/// 255-byte fixed radio buffers.
pub const RADIO_BUF_LEN: usize = 255;

/// RF constants of the fixed profile.
pub const RF_FREQ_HZ: u32 = 915_000_000;
pub const RF_PREAMBLE_SYMBOLS: u16 = 8;
/// SX127x private-network sync word (legacy single-byte form).
pub const RF_SYNC_WORD: u8 = 0x12;
/// Same word in the 16-bit sx126x-register form the driver programs
/// (legacy `0xYZ` maps to `0xY4Z4`, so `0x12` programs as `0x1424`).
const SYNC_WORD_16: u16 = 0x1424;
/// SX1276 version register and expected chip ID.
pub const REG_VERSION: u8 = 0x42;
pub const SX1276_VERSION: u8 = 0x12;

/// SPI0 clock for bring-up: 1 MHz, mode 0.
pub const SPI_FREQ_HZ: u32 = 1_000_000;

/// CAD before every TX: at most 5 attempts, initial caller-supplied jitter
/// 20-100 ms, per-attempt backoff doubling capped at 800 ms.
pub const CAD_MAX_ATTEMPTS: u8 = 5;
pub const CAD_BACKOFF_CAP_MS: u64 = 800;
/// Fixed jitter for CAD-only probes (no TX).
pub const CAD_PROBE_JITTER_MS: u64 = 50;

/// Bounded DIO0 waits: absent DIO0 fails as `Radio`, never hangs.
const CAD_IRQ_TIMEOUT_MS: u64 = 500;
const TX_IRQ_TIMEOUT_MS: u64 = 2_500;
/// Backoff on RX/Fault paths so a dead radio never busy-loops.
const RX_ERROR_DELAY_MS: u64 = 10;
const FAULT_DELAY_MS: u64 = 100;

/// Bounded command/event queues shared with the runtime. Full command side
/// => `BUSY` (never block); full event side drops RX/Fault, never blocks.
pub const RADIO_QUEUE_CAP: usize = 8;

const _: () = assert!(RADIO_BUF_LEN == 255);

/// One opaque over-the-air frame: `len` valid bytes in `bytes`.
/// The radio never interprets the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AirFrame {
    pub len: u8,
    pub bytes: [u8; RADIO_BUF_LEN],
}

/// Opaque transmit authorization. Bound to the `contact_id` it was issued
/// for; fields are private so only [`tx_token`] can mint one. `Copy` so the
/// runtime can embed it in [`RadioCmd::Tx`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxToken {
    all: u32,
    contact_gen: u32,
    contact: Option<u8>,
}

#[derive(Clone, Copy)]
struct PolicyState {
    enabled: bool,
    blocked_mask: u32,
    all_gen: u32,
    contact_gen: [u32; mesh_node::MAX_CONTACTS],
}

static POLICY_STATE: BlockingMutex<CriticalSectionRawMutex, Cell<PolicyState>> =
    BlockingMutex::new(Cell::new(PolicyState {
        enabled: false,
        blocked_mask: 0,
        all_gen: 0,
        contact_gen: [0; mesh_node::MAX_CONTACTS],
    }));

fn contact_idx(contact: u8) -> Option<usize> {
    if contact >= 1 && (contact as usize) <= mesh_node::MAX_CONTACTS {
        Some((contact - 1) as usize)
    } else {
        None
    }
}

/// Mint a transmit token for `contact_id` (`None` = opaque forward).
/// Snapshots the current policy generations; synchronous, never blocks.
pub fn tx_token(contact_id: Option<u8>) -> TxToken {
    POLICY_STATE.lock(|cell| {
        let p = cell.get();
        let cgen = match contact_id {
            Some(c) => match contact_idx(c) {
                Some(i) => p.contact_gen[i],
                None => 0,
            },
            None => 0,
        };
        TxToken {
            all: p.all_gen,
            contact_gen: cgen,
            contact: contact_id,
        }
    })
}

/// Synchronous failclosed atomic policy gate. Any `enabled` edge bumps the
/// global generation (so `off` invalidates all old tokens AND `on` never
/// revives tokens minted while off); any block-bit change bumps that
/// contact's generation (so a newly blocked bit invalidates that contact's
/// tokens AND `unblock` never revives tokens minted while blocked).
/// Generations only advance, never retreat. All 16 contact bits are stored.
/// Call before queueing the matching
/// [`RadioCmd::SetEnabled`]/[`RadioCmd::Barrier`] so invalidation
/// is immediate even while the radio task finishes airborne work.
pub fn set_policy(enabled: bool, blocked_mask: u32) {
    let mask = blocked_mask;
    // Short critical section, one lock, no nesting, no await: atomic
    // failclosed invalidation synchronous with the caller.
    POLICY_STATE.lock(|cell| {
        let mut p = cell.get();
        if p.enabled != enabled {
            p.all_gen = p.all_gen.wrapping_add(1);
        }
        let mut i = 0u32;
        while (i as usize) < mesh_node::MAX_CONTACTS {
            let bit = (mask >> i) & 1;
            let was = (p.blocked_mask >> i) & 1;
            if was != bit {
                let slot = i as usize;
                p.contact_gen[slot] = p.contact_gen[slot].wrapping_add(1);
            }
            i += 1;
        }
        p.enabled = enabled;
        p.blocked_mask = mask;
        cell.set(p);
    })
}

fn policy_enabled() -> bool {
    POLICY_STATE.lock(|cell| cell.get().enabled)
}

/// Failclosed gate check, called at dequeue, between CAD attempts, AND
/// immediately pre-TX. `None` forwards ignore the block mask but still
/// require global enable and a fresh global generation; `Some`
/// additionally requires the contact bit clear, a matching per-contact
/// generation, and exact token binding.
fn token_valid(contact: Option<u8>, token: TxToken) -> bool {
    POLICY_STATE.lock(|cell| {
        let p = cell.get();
        if !p.enabled {
            return false;
        }
        if token.all != p.all_gen {
            return false;
        }
        if token.contact != contact {
            return false;
        }
        match contact {
            None => true,
            Some(c) => {
                let i = match contact_idx(c) {
                    Some(i) => i,
                    None => return false,
                };
                if (p.blocked_mask >> i) & 1 == 1 {
                    return false;
                }
                if token.contact_gen != p.contact_gen[i] {
                    return false;
                }
                true
            }
        }
    })
}

/// Commands into the radio task. `id` is a runtime-allocated monotonic u64
/// (distinct from USB IDs); every command gets exactly one correlated
/// terminal event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioCmd {
    /// Enable/disable the RF frontend. Completes with `ControlDone`.
    SetEnabled { id: u64, enabled: bool },
    /// Ordering fence: completes with `ControlDone` only after all prior
    /// queued work (including an airborne frame) has finished.
    Barrier { id: u64 },
    /// Transmit one opaque frame (CAD-gated, +2 dBm). Completes with
    /// `TxDone`. `attempted` is true iff the driver TX trigger (`do_tx`)
    /// was actually invoked.
    Tx {
        id: u64,
        frame: AirFrame,
        jitter_ms: u64,
        contact_id: Option<u8>,
        token: TxToken,
    },
    /// CAD-only probe, finite, never transmits. Completes with `CadDone`.
    CadProbe { id: u64 },
}

/// Events out of the radio task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioEvt {
    /// A `SetEnabled`/`Barrier` command completed.
    ControlDone { id: u64, ok: bool },
    /// A `Tx` command reached its terminal state. `attempted` is true only
    /// when the driver TX trigger was actually invoked.
    TxDone {
        id: u64,
        result: Result<(), TxFault>,
        attempted: bool,
    },
    /// A `CadProbe` finished: `Ok(true)` = clear, `Ok(false)` = busy.
    CadDone {
        id: u64,
        result: Result<bool, TxFault>,
    },
    /// One received frame (RX only runs while enabled). May drop if full.
    RxFrame(AirFrame),
    /// One failed receive while enabled (hardware CRC/driver error).
    /// May drop if full.
    RxCrcError,
    /// Unrecoverable radio fault (prepare/sleep path). May drop if full.
    Fault,
}

/// Terminal TX/CAD failure modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxFault {
    /// CAD backoff exhausted (TX never touched the air).
    ChannelBusy,
    /// Driver/radio error (bounded DIO0 timeout, SPI/bus error).
    Radio,
    /// Policy gate rejected it (off/block/stale token). Never attempted.
    Cancelled,
}

/// Bounded command queue into the radio task. Full => `BUSY`, never block.
pub static RADIO_CMD: Channel<CriticalSectionRawMutex, RadioCmd, RADIO_QUEUE_CAP> = Channel::new();
/// Bounded event queue out of the radio task. Terminal/control events use
/// reliable `send().await`; RX/Fault use lossy `try_send`.
pub static RADIO_EVT: Channel<CriticalSectionRawMutex, RadioEvt, RADIO_QUEUE_CAP> = Channel::new();

/// What `init` found on the SPI bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BringupError {
    /// `RegVersion` read `0x00` or `0xFF`: check power, ground, CS, MISO.
    NoChip(u8),
    /// Any other unexpected version byte.
    WrongChip(u8),
    /// SPI/bus failure (wiring or driver error, not a version mismatch).
    Bus,
}

type RadioBus = ExclusiveDevice<Spi<'static, SPI0, Async>, Output<'static>, Delay>;
type Iv = GenericSx127xInterfaceVariant<Output<'static>, Input<'static>>;
type Kind = Sx127x<RadioBus, Iv, Sx1276>;

/// Single owner of the radio. Holds the `Sx127x` `RadioKind` directly so
/// SPI bursts always run to completion and only the droppable DIO0 wait is
/// ever timed out or raced. Construct once from `init`, then `run`.
pub struct Radio {
    kind: Kind,
    delay: Delay,
    mode: RadioMode,
    cold_start: bool,
    calibrate_image: bool,
    sync_word: u16,
    enabled: bool,
    /// Continuous-RX scratch.
    rx_buf: [u8; RADIO_BUF_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RxErr {
    Crc,
    Fault,
}

/// Classify a `RegVersion` byte without owning the radio yet.
fn classify_version(byte: u8) -> Result<(), BringupError> {
    match byte {
        SX1276_VERSION => Ok(()),
        0x00 | 0xFF => Err(BringupError::NoChip(byte)),
        other => Err(BringupError::WrongChip(other)),
    }
}

/// Bring up SPI0 (1 MHz, mode 0), check the SX1276 version register, then
/// hand ownership to the lora-phy driver via upstream async
/// `ExclusiveDevice`.
///
/// Pins: SCK GP18, MOSI GP19, MISO GP16, CS GP17 (initially high),
/// RST GP20 (driver pulses low-then-high), DIO0 GP21 (input, RX/TX/CAD-done).
/// DMA: CH0 TX, CH1 RX. Consumes the SPI pins once; hardware is available
/// only on successful init.
///
/// Returns the raw observed `RegVersion` byte alongside the result: `Some`
/// even when classification or later driver init fails (`0x00`/`0xFF`
/// wiring faults included, never fabricated); `None` only on an SPI bus
/// error before any byte was observed. All init steps are SPI/delay only
/// (no DIO0 wait), so init itself is inherently bounded.
#[allow(clippy::too_many_arguments)]
pub async fn init(
    spi0: Peri<'static, SPI0>,
    p18: Peri<'static, PIN_18>,
    p19: Peri<'static, PIN_19>,
    p16: Peri<'static, PIN_16>,
    p17: Peri<'static, PIN_17>,
    p20: Peri<'static, PIN_20>,
    p21: Peri<'static, PIN_21>,
    tx_dma: Peri<'static, DMA_CH0>,
    rx_dma: Peri<'static, DMA_CH1>,
    irqs: Irqs,
) -> (Option<u8>, Result<Radio, BringupError>) {
    let mut spi = Spi::new(
        spi0,
        p18,
        p19,
        p16,
        tx_dma,
        rx_dma,
        irqs,
        SpiConfig::default(),
    );
    spi.set_frequency(SPI_FREQ_HZ);

    // Release reset first and let the chip settle: a version read while the
    // SX1276 is still in reset returns 0x00 (indistinguishable from a MOSI
    // fault). The radio-free chip-detect path never touches reset, which is
    // why it observes 0x12 on the same board.
    let mut rst = Output::new(p20, Level::High);
    rst.set_high();
    embassy_time::Timer::after(embassy_time::Duration::from_millis(10)).await;
    let mut cs = Output::new(p17, Level::High);
    // Retry the version read: first attempt can catch the tail of reset.
    let mut observed: Option<u8> = None;
    for _ in 0..3 {
        cs.set_low();
        let mut byte = [0u8];
        let w = spi.write(&[REG_VERSION & 0x7F]).await;
        let r = if w.is_ok() {
            spi.read(&mut byte).await
        } else {
            w
        };
        cs.set_high();
        match r {
            Ok(()) => {
                observed = Some(byte[0]);
                if byte[0] == SX1276_VERSION {
                    break;
                }
            }
            Err(_) => return (None, Err(BringupError::Bus)),
        }
        embassy_time::Timer::after(embassy_time::Duration::from_millis(5)).await;
    }
    let raw = observed;
    let observed = raw.unwrap_or(0xFF);
    if let Err(e) = classify_version(observed) {
        return (raw, Err(e));
    }

    let dev = match ExclusiveDevice::new(spi, cs, Delay) {
        Ok(d) => d,
        Err(_) => return (raw, Err(BringupError::Bus)),
    };
    // Hand the settled reset output to the driver (starts released; the
    // driver pulses low/high itself during init).
    let dio0 = Input::new(p21, Pull::None);
    let iv = match Iv::new(rst, dio0, None, None) {
        Ok(v) => v,
        Err(_) => return (raw, Err(BringupError::Bus)),
    };
    let kind = Kind::new(
        dev,
        iv,
        Sx127xConfig {
            chip: Sx1276,
            tcxo_used: false,
            tx_boost: true,
            rx_boost: false,
        },
    );

    // Private network => SX127x sync word 0x12 (programmed as 0x1424).
    // Mirrors `LoRa::init` + cold start: reset, standby, LoRa init, idle
    // power/ramp setup, IRQ params. All SPI/delay, no DIO0 wait.
    let mut radio = Radio {
        kind,
        delay: Delay,
        mode: RadioMode::Standby,
        cold_start: true,
        calibrate_image: true,
        sync_word: SYNC_WORD_16,
        enabled: false,
        rx_buf: [0u8; RADIO_BUF_LEN],
    };
    if radio.kind.reset(&mut radio.delay).await.is_err() {
        return (raw, Err(BringupError::Bus));
    }
    if radio.kind.ensure_ready(RadioMode::Sleep).await.is_err() {
        return (raw, Err(BringupError::Bus));
    }
    if radio.kind.set_standby().await.is_err() {
        return (raw, Err(BringupError::Bus));
    }
    radio.mode = RadioMode::Standby;
    if radio.do_cold_start().await.is_err() {
        return (raw, Err(BringupError::Bus));
    }
    (raw, Ok(radio))
}

impl Radio {
    fn modulation(&self) -> Result<ModulationParams, RadioError> {
        self.kind.create_modulation_params(
            SpreadingFactor::_7,
            Bandwidth::_500KHz,
            CodingRate::_4_5,
            RF_FREQ_HZ,
        )
    }

    async fn do_cold_start(&mut self) -> Result<(), RadioError> {
        self.kind.init_lora(self.sync_word).await?;
        self.kind.set_tx_power_and_ramp_time(0, None, false).await?;
        self.kind.set_irq_params(Some(self.mode)).await?;
        self.cold_start = false;
        self.calibrate_image = true;
        Ok(())
    }

    async fn prepare_modem(&mut self) -> Result<(), RadioError> {
        self.kind.ensure_ready(self.mode).await?;
        if self.mode != RadioMode::Standby {
            self.kind.set_standby().await?;
            self.mode = RadioMode::Standby;
        }
        if self.cold_start {
            self.do_cold_start().await?;
        }
        if self.calibrate_image {
            self.kind.calibrate_image(RF_FREQ_HZ).await?;
            self.calibrate_image = false;
        }
        Ok(())
    }

    /// Own the LoRa driver forever: handle commands while receiving.
    ///
    /// While enabled, RX continuous is (re-)entered, then each iteration
    /// races one droppable DIO0 wait against one command — the only
    /// cancellable boundary. Every SPI burst runs to completion; commands
    /// are handled between operations. While disabled, only commands are
    /// awaited (no RX, radio asleep). Terminal/control events are reliable
    /// (`send().await`); RX/Fault may drop when full.
    pub async fn run(mut self) -> ! {
        loop {
            if !(self.enabled && policy_enabled()) {
                let cmd = RADIO_CMD.receive().await;
                self.handle_cmd(cmd).await;
                continue;
            }
            if self.mode != RadioMode::Receive(RxMode::Continuous) && self.enter_rx().await.is_err()
            {
                let _ = RADIO_EVT.try_send(RadioEvt::Fault);
                Timer::after(Duration::from_millis(FAULT_DELAY_MS)).await;
                continue;
            }
            match select(self.kind.await_irq(), RADIO_CMD.receive()).await {
                Either::First(irq) => {
                    if irq.is_err() {
                        let _ = RADIO_EVT.try_send(RadioEvt::RxCrcError);
                        Timer::after(Duration::from_millis(RX_ERROR_DELAY_MS)).await;
                        continue;
                    }
                    match self.finish_rx().await {
                        Ok(Some(frame)) => {
                            let _ = RADIO_EVT.try_send(RadioEvt::RxFrame(frame));
                        }
                        Ok(None) => {}
                        Err(RxErr::Crc) => {
                            let _ = RADIO_EVT.try_send(RadioEvt::RxCrcError);
                            Timer::after(Duration::from_millis(RX_ERROR_DELAY_MS)).await;
                        }
                        Err(RxErr::Fault) => {
                            let _ = RADIO_EVT.try_send(RadioEvt::Fault);
                            Timer::after(Duration::from_millis(FAULT_DELAY_MS)).await;
                        }
                    }
                }
                Either::Second(cmd) => {
                    self.handle_cmd(cmd).await;
                }
            }
        }
    }

    async fn handle_cmd(&mut self, cmd: RadioCmd) {
        match cmd {
            RadioCmd::SetEnabled { id, enabled } => {
                self.enabled = enabled;
                let ok = if enabled {
                    true
                } else {
                    match self.kind.set_sleep(false, &mut self.delay).await {
                        Ok(()) => {
                            self.mode = RadioMode::Sleep;
                            true
                        }
                        Err(_) => {
                            self.mode = RadioMode::Standby;
                            let _ = RADIO_EVT.try_send(RadioEvt::Fault);
                            false
                        }
                    }
                };
                RADIO_EVT.send(RadioEvt::ControlDone { id, ok }).await;
            }
            RadioCmd::Barrier { id } => {
                // Sequential processing guarantees every prior command —
                // including an airborne frame — finished before this
                // dequeue.
                RADIO_EVT.send(RadioEvt::ControlDone { id, ok: true }).await;
            }
            RadioCmd::Tx {
                id,
                frame,
                jitter_ms,
                contact_id,
                token,
            } => {
                let (result, attempted) = self.do_tx(frame, jitter_ms, contact_id, token).await;
                RADIO_EVT
                    .send(RadioEvt::TxDone {
                        id,
                        result,
                        attempted,
                    })
                    .await;
            }
            RadioCmd::CadProbe { id } => {
                let result = self.do_cad_probe().await;
                RADIO_EVT.send(RadioEvt::CadDone { id, result }).await;
            }
        }
    }

    /// Enter continuous RX (SPI bursts run to completion; called before the
    /// cancellable IRQ/command race, never inside it).
    async fn enter_rx(&mut self) -> Result<(), TxFault> {
        let mdltn = self.modulation().map_err(|_| TxFault::Radio)?;
        self.prepare_modem().await.map_err(|_| TxFault::Radio)?;
        let pkt = self
            .kind
            .create_packet_params(
                RF_PREAMBLE_SYMBOLS,
                false,
                RADIO_BUF_LEN as u8,
                true,
                false,
                &mdltn,
            )
            .map_err(|_| TxFault::Radio)?;
        self.kind
            .set_modulation_params(&mdltn)
            .await
            .map_err(|_| TxFault::Radio)?;
        self.kind
            .set_packet_params(&pkt)
            .await
            .map_err(|_| TxFault::Radio)?;
        self.kind
            .set_channel(RF_FREQ_HZ)
            .await
            .map_err(|_| TxFault::Radio)?;
        self.mode = RadioMode::Receive(RxMode::Continuous);
        self.kind
            .set_irq_params(Some(self.mode))
            .await
            .map_err(|_| TxFault::Radio)?;
        self.kind
            .do_rx(RxMode::Continuous)
            .await
            .map_err(|_| TxFault::Radio)?;
        Ok(())
    }

    /// Finish one RX IRQ (runs to completion after the IRQ won the race).
    /// `Ok(None)` = spurious wake, no event. Reception-path failures
    /// (flag processing, FIFO payload extraction, length) classify as
    /// `Crc` — the hardware-CRC bucket, kept separate from `Fault`, which
    /// is reserved for unrecoverable prepare/path failures.
    async fn finish_rx(&mut self) -> Result<Option<AirFrame>, RxErr> {
        let state = self
            .kind
            .process_irq_event(self.mode, None, true)
            .await
            .map_err(|_| RxErr::Crc)?;
        if !matches!(state, Some(IrqState::Done)) {
            return Ok(None);
        }
        let mdltn = self.modulation().map_err(|_| RxErr::Fault)?;
        let pkt = self
            .kind
            .create_packet_params(
                RF_PREAMBLE_SYMBOLS,
                false,
                RADIO_BUF_LEN as u8,
                true,
                false,
                &mdltn,
            )
            .map_err(|_| RxErr::Fault)?;
        let len = self
            .kind
            .get_rx_payload(&pkt, &mut self.rx_buf)
            .await
            .map_err(|_| RxErr::Crc)?;
        let n = len as usize;
        if n == 0 || n > RADIO_BUF_LEN {
            return Err(RxErr::Crc);
        }
        let mut frame = AirFrame {
            len: n as u8,
            bytes: [0u8; RADIO_BUF_LEN],
        };
        frame.bytes[..n].copy_from_slice(&self.rx_buf[..n]);
        Ok(Some(frame))
    }

    /// One bounded CAD attempt: prepare + trigger run to completion (SPI
    /// bursts, never cancelled); only the DIO0 `await_irq` is timed.
    /// Flags are classified with `process_irq_event` (SPI read, runs to
    /// completion). Returns `Ok(false)` = clear, `Ok(true)` = activity.
    async fn cad_once(&mut self, mdltn: &ModulationParams) -> Result<bool, TxFault> {
        self.prepare_modem().await.map_err(|_| TxFault::Radio)?;
        self.kind
            .set_modulation_params(mdltn)
            .await
            .map_err(|_| TxFault::Radio)?;
        self.kind
            .set_channel(RF_FREQ_HZ)
            .await
            .map_err(|_| TxFault::Radio)?;
        self.mode = RadioMode::ChannelActivityDetection;
        self.kind
            .set_irq_params(Some(self.mode))
            .await
            .map_err(|_| TxFault::Radio)?;
        // Trigger (SPI burst): runs to completion, never timed out.
        self.kind.do_cad(mdltn).await.map_err(|_| TxFault::Radio)?;
        // Bounded DIO0 wait only: absent DIO0 fails here, never transmits.
        match with_timeout(
            Duration::from_millis(CAD_IRQ_TIMEOUT_MS),
            self.kind.await_irq(),
        )
        .await
        {
            Ok(Ok(())) => {}
            _ => {
                let _ = self.kind.set_standby().await;
                self.mode = RadioMode::Standby;
                return Err(TxFault::Radio);
            }
        }
        let mut detected = false;
        match self
            .kind
            .process_irq_event(self.mode, Some(&mut detected), true)
            .await
        {
            Ok(Some(IrqState::Done)) => {
                if self.kind.set_standby().await.is_err() {
                    return Err(TxFault::Radio);
                }
                self.mode = RadioMode::Standby;
                Ok(detected)
            }
            _ => {
                let _ = self.kind.ensure_ready(self.mode).await;
                let _ = self.kind.set_standby().await;
                self.mode = RadioMode::Standby;
                Err(TxFault::Radio)
            }
        }
    }

    /// Prepare one transmission (SPI bursts, runs to completion). Always
    /// programs [`TX_POWER_DBM`]; the power is a constant, never a
    /// parameter. Payload length is fixed at creation (≤255, checked by the
    /// caller).
    async fn tx_prepare(
        &mut self,
        mdltn: &ModulationParams,
        payload: &[u8],
    ) -> Result<(), TxFault> {
        self.prepare_modem().await.map_err(|_| TxFault::Radio)?;
        self.kind
            .set_modulation_params(mdltn)
            .await
            .map_err(|_| TxFault::Radio)?;
        self.kind
            .set_tx_power_and_ramp_time(TX_POWER_DBM, Some(mdltn), true)
            .await
            .map_err(|_| TxFault::Radio)?;
        self.kind
            .ensure_ready(self.mode)
            .await
            .map_err(|_| TxFault::Radio)?;
        if self.mode != RadioMode::Standby {
            self.kind.set_standby().await.map_err(|_| TxFault::Radio)?;
            self.mode = RadioMode::Standby;
        }
        let pkt = self
            .kind
            .create_packet_params(
                RF_PREAMBLE_SYMBOLS,
                false,
                payload.len() as u8,
                true,
                false,
                mdltn,
            )
            .map_err(|_| TxFault::Radio)?;
        self.kind
            .set_packet_params(&pkt)
            .await
            .map_err(|_| TxFault::Radio)?;
        self.kind
            .set_channel(RF_FREQ_HZ)
            .await
            .map_err(|_| TxFault::Radio)?;
        self.kind
            .set_payload(payload)
            .await
            .map_err(|_| TxFault::Radio)?;
        self.mode = RadioMode::Transmit;
        self.kind
            .set_irq_params(Some(self.mode))
            .await
            .map_err(|_| TxFault::Radio)?;
        Ok(())
    }

    /// Trigger + bounded completion wait. The trigger (SPI burst) runs to
    /// completion; only the DIO0 `await_irq` is timed. Completion flags run
    /// to completion. Returns `Radio` (with `attempted=true` upstream) on
    /// trigger/IRQ/flag failures.
    async fn tx_wait(&mut self) -> Result<(), TxFault> {
        self.kind.do_tx().await.map_err(|_| TxFault::Radio)?;
        loop {
            match with_timeout(
                Duration::from_millis(TX_IRQ_TIMEOUT_MS),
                self.kind.await_irq(),
            )
            .await
            {
                Ok(Ok(())) => {}
                _ => {
                    let _ = self.kind.set_standby().await;
                    self.mode = RadioMode::Standby;
                    return Err(TxFault::Radio);
                }
            }
            match self.kind.process_irq_event(self.mode, None, true).await {
                Ok(Some(IrqState::Done)) => {
                    self.mode = RadioMode::Standby;
                    return Ok(());
                }
                Ok(_) => continue,
                Err(_) => {
                    let _ = self.kind.ensure_ready(self.mode).await;
                    let _ = self.kind.set_standby().await;
                    self.mode = RadioMode::Standby;
                    return Err(TxFault::Radio);
                }
            }
        }
    }

    /// The single TX routine. Every transmission funnels through here:
    /// CAD-gated, always [`TX_POWER_DBM`]. Returns the terminal result plus
    /// whether the driver TX trigger was actually invoked. Gate checks at
    /// dequeue, between CAD attempts, and immediately pre-TX; an airborne
    /// frame runs to completion even if the policy flips mid-air. Single
    /// CAD-gated attempt: no blind retries.
    async fn do_tx(
        &mut self,
        frame: AirFrame,
        jitter_ms: u64,
        contact_id: Option<u8>,
        token: TxToken,
    ) -> (Result<(), TxFault>, bool) {
        if !self.enabled || !token_valid(contact_id, token) {
            return (Err(TxFault::Cancelled), false);
        }
        let n = frame.len as usize;
        if n == 0 || n > RADIO_BUF_LEN {
            return (Err(TxFault::Cancelled), false);
        }
        let mdltn = match self.modulation() {
            Ok(m) => m,
            Err(_) => return (Err(TxFault::Radio), false),
        };
        let mut backoff = jitter_ms.clamp(20, 100);
        for attempt in 0..CAD_MAX_ATTEMPTS {
            if !self.enabled || !token_valid(contact_id, token) {
                return (Err(TxFault::Cancelled), false);
            }
            match self.cad_once(&mdltn).await {
                Ok(false) => break,
                Ok(true) => {
                    if attempt + 1 >= CAD_MAX_ATTEMPTS {
                        return (Err(TxFault::ChannelBusy), false);
                    }
                    Timer::after(Duration::from_millis(backoff)).await;
                    backoff = (backoff * 2).min(CAD_BACKOFF_CAP_MS);
                }
                Err(e) => return (Err(e), false),
            }
        }
        // Gate immediately pre-TX: a policy flip during the final CAD still
        // cancels without airtime.
        if !self.enabled || !token_valid(contact_id, token) {
            return (Err(TxFault::Cancelled), false);
        }
        let payload = &frame.bytes[..n];
        if self.tx_prepare(&mdltn, payload).await.is_err() {
            let _ = self.kind.set_standby().await;
            self.mode = RadioMode::Standby;
            return (Err(TxFault::Radio), false);
        }
        match self.tx_wait().await {
            Ok(()) => (Ok(()), true),
            Err(e) => (Err(e), true),
        }
    }

    /// CAD-only probe: finite (max 5, 50 ms jitter doubling to the 800 ms
    /// cap), never transmits. `Ok(true)` = clear, `Ok(false)` = busy.
    async fn do_cad_probe(&mut self) -> Result<bool, TxFault> {
        if !self.enabled || !policy_enabled() {
            return Err(TxFault::Cancelled);
        }
        let mdltn = match self.modulation() {
            Ok(m) => m,
            Err(_) => return Err(TxFault::Radio),
        };
        let mut backoff = CAD_PROBE_JITTER_MS.clamp(20, 100);
        for attempt in 0..CAD_MAX_ATTEMPTS {
            if !self.enabled || !policy_enabled() {
                return Err(TxFault::Cancelled);
            }
            match self.cad_once(&mdltn).await {
                Ok(false) => return Ok(true),
                Ok(true) => {
                    if attempt + 1 >= CAD_MAX_ATTEMPTS {
                        return Ok(false);
                    }
                    Timer::after(Duration::from_millis(backoff)).await;
                    backoff = (backoff * 2).min(CAD_BACKOFF_CAP_MS);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }
}
