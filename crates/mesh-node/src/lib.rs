#![no_std]
//! Transport-independent production node engine shared by the RP2350
//! firmware and the native exerciser. Owns pairing ceremony state,
//! persistent identity/contact secrets, encrypted DATA/ACK processing,
//! durable transmit reservation, inbound replay windows, hourly aliases,
//! blocking/cancel, and relay decisions — no RF, no USB, no storage IO.
//!
//! Both targets drive the SAME engine over the SAME persisted encoding
//! (see [`encode_persist`]/[`decode_persist`]): the Pico persists through
//! sequential-storage, the native exerciser through files, byte-identical.

pub mod engine;
pub mod persist;

pub use engine::{
    BlockOutcome, Engine, EngineError, IncomingKind, NodeEvent, OutgoingFrame, PairImportOutcome,
    PairStep, PendingSend, MAX_CONTACTS,
};
pub use persist::{
    decode_persist, decode_view, encode_persist, migrate_to_v3, Decoded, OwnedView, PersistContact,
    PersistError, PersistView, CONTACT_BYTES, PERSIST_LEN, PERSIST_MAGIC, PERSIST_V2_LEN,
    PERSIST_VERSION,
};
