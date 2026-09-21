//! Onboard-LED blink codes for field usability.
//!
//! Pico 2 W reality: the onboard LED hangs off the CYW43 wireless chip
//! (`WL_GPIO0`), NOT a plain RP2350 GPIO. Driving it goes through the
//! wireless driver's `control.gpio_set(0, ...)` — so this module NEVER
//! initializes wireless itself (no wireless bring-up just to blink; USB
//! status stays the authoritative indication). The [`signal`] driver is
//! gated by the `radio` feature and takes an already-running control handle
//! from Main; without `radio` this module is only the pattern table.
//!
//! Patterns (single-shot; the caller repeats [`LedEvent::Fault`] while
//! faulted, and emits Tx/Rx flashes from the radio completion paths):
//! - boot: 3 slow blinks (200 ms on/off) at startup.
//! - pairing: 8 fast blinks (80 ms) while a pairing ceremony is open.
//! - tx: single 100 ms flash per completed transmission.
//! - rx: two 100 ms flashes per authenticated delivery.
//! - fault: 5 rapid blinks (60 ms) — unmistakable vs pairing's 8x80 ms.

/// LED-signalled firmware events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedEvent {
    Boot,
    Pairing,
    Tx,
    Rx,
    Fault,
}

/// One blink pattern: `count` flashes of `on_ms`/`off_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blink {
    pub on_ms: u64,
    pub off_ms: u64,
    pub count: u8,
}

impl LedEvent {
    /// Single-shot pattern for the event.
    pub const fn pattern(self) -> Blink {
        match self {
            LedEvent::Boot => Blink {
                on_ms: 200,
                off_ms: 200,
                count: 3,
            },
            LedEvent::Pairing => Blink {
                on_ms: 80,
                off_ms: 80,
                count: 8,
            },
            LedEvent::Tx => Blink {
                on_ms: 100,
                off_ms: 100,
                count: 1,
            },
            LedEvent::Rx => Blink {
                on_ms: 100,
                off_ms: 100,
                count: 2,
            },
            LedEvent::Fault => Blink {
                on_ms: 60,
                off_ms: 60,
                count: 5,
            },
        }
    }
}

/// Already-running wireless control handle. Main implements this for the
/// CYW43 `Control` (`control.gpio_set(0, on)`); this crate never names the
/// driver type, so no wireless dependency leaks in here.
pub trait Gpio0 {
    fn set_gpio0(&mut self, on: bool);
}

/// Drive one single-shot pattern on `WL_GPIO0`. Only compiled with the
/// `radio` feature (the wireless task owns the CYW43 control handle); call
/// only when wireless is already up.
#[cfg(feature = "radio")]
pub async fn signal<G: Gpio0>(control: &mut G, ev: LedEvent) {
    use embassy_time::{Duration, Timer};
    let b = ev.pattern();
    let mut i = 0;
    while i < b.count {
        control.set_gpio0(true);
        Timer::after(Duration::from_millis(b.on_ms)).await;
        control.set_gpio0(false);
        Timer::after(Duration::from_millis(b.off_ms)).await;
        i += 1;
    }
}
