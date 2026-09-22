#![no_std]
//! Board-independent LoRa mesh protocol: framing, security, pairing, relay, clock.
//! Host-testable without a Pico. Frame codec lands in Phase 1;
//! security/pairing/relay/clock behaviour lands in Phases 2-4.

pub mod clock;
#[cfg(feature = "meshtastic")]
pub mod compat;
pub mod frame;
pub mod pairing;
pub mod relay;
pub mod security;
