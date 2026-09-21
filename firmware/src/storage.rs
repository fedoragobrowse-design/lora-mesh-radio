//! Persisted node state: single async owner over the top 64 KiB of flash.
//!
//! Flash map: `STORAGE_START..STORAGE_END` (top 64 KiB of the Pico 2 W's
//! 4 MiB); `firmware/memory.x` caps firmware FLASH at `STORAGE_START` so
//! code never overlaps storage. One task owns all flash operations through
//! [`StorageService`]; in-progress writes are awaited, never cancelled.
//!
//! The stored value bytes are the SAME fixed encoding as the native
//! exerciser (`mesh-node` persist module): magic `LMSH`, version byte,
//! big-endian fields. Unknown magic/version fails closed to
//! [`StoreHealth::Fault`] — never quiet key regeneration. Erased flash
//! (absent key) reports [`StoreHealth::Unprovisioned`]. Reboot skips the
//! last reserved transmit block and leaves the clock unset (boot time is
//! RAM-only); the stored seconds are only a rollback floor.

use embassy_rp::flash::{Async, Flash};
use embassy_rp::peripherals::{DMA_CH2, FLASH};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use mesh_node::persist::{decode_view, migrate_to_v3, PERSIST_LEN, PERSIST_V2_LEN};
use sequential_storage::cache::Cache;
use sequential_storage::map::{MapConfig, MapStorage};

/// Reserved flash offsets for the sequential-storage map (byte offsets).
pub const STORAGE_START: u32 = 0x003F_0000;
/// End (exclusive) of the reserved storage region: top 64 KiB of 4 MiB.
pub const STORAGE_END: u32 = 0x0040_0000;

/// Map key for the single node record.
pub const KEY_NODE: u8 = 0x01;

/// Up to 16 paired contacts (contact_id 1..=16); persist V3 migrates V1/V2 2-slot records.
pub const MAX_CONTACTS: usize = mesh_node::MAX_CONTACTS;

/// Lab label encodings: 0 = none, 1 = A, 2 = B, 3 = C.
pub const LABEL_NONE: u8 = 0;
pub const LABEL_A: u8 = 1;
pub const LABEL_B: u8 = 2;
pub const LABEL_C: u8 = 3;

/// Parse an operator label (`A`/`B`/`C`) into its stored encoding.
pub fn label_from_str(s: &str) -> Option<u8> {
    match s {
        "A" => Some(LABEL_A),
        "B" => Some(LABEL_B),
        "C" => Some(LABEL_C),
        _ => None,
    }
}

/// Render a stored label encoding for USB replies (`""` when unset).
pub fn label_to_str(label: u8) -> &'static str {
    match label {
        LABEL_A => "A",
        LABEL_B => "B",
        LABEL_C => "C",
        _ => "",
    }
}

/// Health of the persisted record, mirroring the USB-visible states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreHealth {
    /// Fresh/erased board: explicit `provision` required.
    Unprovisioned,
    /// Provisioned and readable.
    Ready,
    /// Unreadable record: secure endpoint operation is disabled until an
    /// explicit fresh pairing/reset; never quietly regenerate keys.
    Fault,
}

/// Errors for state mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// Operation needs provisioning first (`UNPROVISIONED` on USB).
    Unprovisioned,
    /// Record unreadable; endpoint disabled (`STORAGE_FAULT` on USB).
    Fault,
    /// Clock would move backwards (`TIME_ROLLBACK` on USB).
    TooOld,
}

/// Requests to the single storage owner. Every commit is awaited; the
/// owner serializes load/commit and never cancels an in-flight write.
pub enum StorageReq {
    /// Load at boot: reports erased vs fault vs bytes.
    Load,
    /// Durably commit `len` bytes of `bytes` (PERSIST_LEN encoding).
    Commit {
        bytes: [u8; PERSIST_LEN],
        len: usize,
    },
}

pub enum StorageResp {
    /// No record found (erased flash): caller reports UNPROVISIONED.
    Empty,
    /// Persisted bytes (validated length; content validated by engine).
    Loaded {
        bytes: [u8; PERSIST_LEN],
    },
    /// Commit completed (or faulted).
    Committed(Result<(), StoreError>),
    Fault,
}

pub type StorageChannel = Channel<CriticalSectionRawMutex, StorageReq, 2>;
pub type StorageRespChannel = Channel<CriticalSectionRawMutex, StorageResp, 2>;

/// Single async owner of flash. Construct once in `main` from the flash
/// peripheral + DMA_CH2, then `run()` forever serving [`StorageReq`].
pub struct StorageService {
    rx: &'static StorageChannel,
    tx: &'static StorageRespChannel,
}

impl StorageService {
    pub const fn new(rx: &'static StorageChannel, tx: &'static StorageRespChannel) -> Self {
        Self { rx, tx }
    }

    pub async fn run(
        self,
        flash: embassy_rp::Peri<'static, FLASH>,
        dma: embassy_rp::Peri<'static, DMA_CH2>,
        irqs: crate::board::Irqs,
    ) -> ! {
        let flash = Flash::<_, Async, 4_194_304>::new(flash, dma, irqs);
        let config = match MapConfig::<Flash<'static, FLASH, Async, 4_194_304>>::try_new(
            STORAGE_START..STORAGE_END,
        ) {
            Ok(c) => c,
            Err(_) => loop {
                let _ = self.tx.try_send(StorageResp::Fault);
                let _ = self.rx.receive().await;
            },
        };
        let mut map: MapStorage<u8, _, _> = MapStorage::new(flash, config, Cache::new_uncached());
        let mut buf = [0u8; PERSIST_LEN + 8];
        loop {
            match self.rx.receive().await {
                StorageReq::Load => {
                    match map
                        .fetch_item::<heapless::Vec<u8, PERSIST_LEN>>(&mut buf, &KEY_NODE)
                        .await
                    {
                        Ok(Some(v)) => {
                            let len = v.len();
                            if len != PERSIST_LEN && len != PERSIST_V2_LEN {
                                let _ = self.tx.send(StorageResp::Fault).await;
                            } else {
                                // V1/V2 records migrate via canonical re-encode
                                // (zero-padding Faults: empty windows are e=1).
                                match migrate_to_v3(&v) {
                                    Ok(bytes) => {
                                        let _ = self.tx.send(StorageResp::Loaded { bytes }).await;
                                    }
                                    Err(_) => {
                                        let _ = self.tx.send(StorageResp::Fault).await;
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            let _ = self.tx.send(StorageResp::Empty).await;
                        }
                        Err(_) => {
                            let _ = self.tx.send(StorageResp::Fault).await;
                        }
                    }
                }
                StorageReq::Commit { bytes, len } => {
                    if len != PERSIST_LEN {
                        let _ = self
                            .tx
                            .send(StorageResp::Committed(Err(StoreError::Fault)))
                            .await;
                        continue;
                    }
                    let mut v: heapless::Vec<u8, PERSIST_LEN> = heapless::Vec::new();
                    let _ = v.extend_from_slice(&bytes);
                    // Await the write; never cancel it. Awaited commit
                    // precedes every nonce use/delivery/ACK upstream.
                    match map.store_item(&mut buf, &KEY_NODE, &v).await {
                        Ok(()) => {
                            let _ = self.tx.send(StorageResp::Committed(Ok(()))).await;
                        }
                        Err(_) => {
                            let _ = self
                                .tx
                                .send(StorageResp::Committed(Err(StoreError::Fault)))
                                .await;
                        }
                    }
                }
            }
        }
    }
}

/// Flash-UID identity accessor: copies the 8-byte UID for local use
/// (stable USB device paths). Never transmitted on RF, never key material.
pub fn local_identity(flash_uid: &[u8; 8]) -> [u8; 8] {
    *flash_uid
}
