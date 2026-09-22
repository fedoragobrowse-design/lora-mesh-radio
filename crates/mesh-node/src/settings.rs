//! Usability-tunable TX/relay parameters with safe defaults.
//!
//! Defaults mirror the currently compiled firmware constants so a fresh
//! board behaves exactly like before: `+2 dBm` TX power, 3 bounded
//! transmit attempts, 12 s ACK waits, 8 s relay-cache TTL, 100 ms relay
//! jitter, 5 CAD attempts. The RF-affecting field (`tx_power`) latches at
//! radio enable; every other field is read live from the stored value.
//!
//! Persisted as a SEPARATE 13-byte record (`LSET` magic + version) under
//! map key [`crate::persist::KEY_SETTINGS`]. It never touches the node
//! record, so `PERSIST_VERSION` is unchanged and existing node images keep
//! working. Unknown magic/version/length fails closed: [`Settings::decode`]
//! returns `None` and the caller falls back to [`Settings::default`]; the
//! secure node record is never reinterpreted.

/// Tunable parameters. All integer; ranges live in [`KEYS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// TX power in dBm. RF field: applies at next radio-on.
    pub tx_power_dbm: u8,
    /// Bounded transmit attempts per send.
    pub max_tx: u8,
    /// ACK wait per attempt, seconds.
    pub ack_wait_s: u8,
    /// Relay-cache entry lifetime, milliseconds.
    pub relay_ttl_ms: u16,
    /// Relay forward jitter, milliseconds.
    pub relay_jitter_ms: u16,
    /// CAD attempts before reporting channel-busy.
    pub cad_attempts: u8,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            tx_power_dbm: 2,
            max_tx: 3,
            ack_wait_s: 12,
            relay_ttl_ms: 8000,
            relay_jitter_ms: 100,
            cad_attempts: 5,
        }
    }
}

/// Wire metadata for one setting, reported verbatim by `settings_get`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMeta {
    pub key: &'static str,
    pub min: u32,
    pub max: u32,
    pub readonly: bool,
    /// Latches at radio enable (`applied:false` when customized).
    pub rf: bool,
}

/// Canonical key table. `sync_word` exposes the frozen private sync word
/// (`0x12`) as a readonly entry so hosts can display the full RF picture
/// without implying it is tunable.
pub const KEYS: [KeyMeta; 7] = [
    // M3: RF policy cap. Firmware always transmits at +2 dBm
    // (SX1276 PA_BOOST minimum); the stored value is display-only so the
    // surface cannot promise power the radio never produces.
    KeyMeta {
        key: "tx_power",
        min: 2,
        max: 2,
        readonly: true,
        rf: true,
    },
    KeyMeta {
        key: "max_tx",
        min: 1,
        max: 10,
        readonly: false,
        rf: false,
    },
    KeyMeta {
        key: "ack_wait",
        min: 1,
        max: 60,
        readonly: false,
        rf: false,
    },
    KeyMeta {
        key: "relay_ttl",
        min: 1000,
        max: 60000,
        readonly: false,
        rf: false,
    },
    KeyMeta {
        key: "relay_jitter",
        min: 20,
        max: 300,
        readonly: false,
        rf: false,
    },
    KeyMeta {
        key: "cad_attempts",
        min: 1,
        max: 10,
        readonly: false,
        rf: false,
    },
    KeyMeta {
        key: "sync_word",
        min: 18,
        max: 18,
        readonly: true,
        rf: true,
    },
];

/// Magic + version of the standalone settings record.
pub const SETTINGS_MAGIC: [u8; 4] = *b"LSET";
pub const SETTINGS_VERSION: u8 = 1;
/// Fixed record length: magic(4) ver(1) tx_power(1) max_tx(1) ack_wait(1)
/// relay_ttl(2) relay_jitter(2) cad_attempts(1).
pub const SETTINGS_LEN: usize = 13;

fn clamp_u32(v: u32, min: u32, max: u32) -> (u32, bool) {
    if v < min {
        (min, true)
    } else if v > max {
        (max, true)
    } else {
        (v, false)
    }
}

impl Settings {
    /// Metadata for `key`, or `None` when unknown (firmware: BAD_REQUEST).
    pub fn meta(key: &str) -> Option<KeyMeta> {
        KEYS.iter().find(|m| m.key == key).copied()
    }

    /// Current value of `key`, or `None` when unknown.
    pub fn value(&self, key: &str) -> Option<u32> {
        match key {
            "tx_power" => Some(self.tx_power_dbm as u32),
            "max_tx" => Some(self.max_tx as u32),
            "ack_wait" => Some(self.ack_wait_s as u32),
            "relay_ttl" => Some(self.relay_ttl_ms as u32),
            "relay_jitter" => Some(self.relay_jitter_ms as u32),
            "cad_attempts" => Some(self.cad_attempts as u32),
            "sync_word" => Some(0x12),
            _ => None,
        }
    }

    /// Set `key` to `value`, clamping into range. Returns `Ok(true)` when
    /// the value was clamped, `Ok(false)` when stored as given, and
    /// `Err(())` for unknown or readonly keys (firmware: BAD_REQUEST).
    pub fn set(&mut self, key: &str, value: i64) -> Result<bool, ()> {
        let m = Self::meta(key).ok_or(())?;
        if m.readonly {
            return Err(());
        }
        let v = value.clamp(m.min as i64, m.max as i64) as u32;
        match key {
            "tx_power" => self.tx_power_dbm = v as u8,
            "max_tx" => self.max_tx = v as u8,
            "ack_wait" => self.ack_wait_s = v as u8,
            "relay_ttl" => self.relay_ttl_ms = v as u16,
            "relay_jitter" => self.relay_jitter_ms = v as u16,
            "cad_attempts" => self.cad_attempts = v as u8,
            _ => return Err(()),
        }
        Ok(v as i64 != value)
    }

    /// Clamp every stored field into its range; true when anything moved.
    /// Applied on decode so a record written by a newer range set can never
    /// push the runtime out of band.
    pub fn clamp_all(&mut self) -> bool {
        let mut changed = false;
        // M3: matches the readonly KEYS cap; older records clamp down to 2.
        let (v, c) = clamp_u32(self.tx_power_dbm as u32, 2, 2);
        self.tx_power_dbm = v as u8;
        changed |= c;
        let (v, c) = clamp_u32(self.max_tx as u32, 1, 10);
        self.max_tx = v as u8;
        changed |= c;
        let (v, c) = clamp_u32(self.ack_wait_s as u32, 1, 60);
        self.ack_wait_s = v as u8;
        changed |= c;
        let (v, c) = clamp_u32(self.relay_ttl_ms as u32, 1000, 60000);
        self.relay_ttl_ms = v as u16;
        changed |= c;
        let (v, c) = clamp_u32(self.relay_jitter_ms as u32, 20, 300);
        self.relay_jitter_ms = v as u16;
        changed |= c;
        let (v, c) = clamp_u32(self.cad_attempts as u32, 1, 10);
        self.cad_attempts = v as u8;
        changed |= c;
        changed
    }

    /// Encode the fixed 13-byte record.
    pub fn encode(&self) -> [u8; SETTINGS_LEN] {
        let mut out = [0u8; SETTINGS_LEN];
        out[0..4].copy_from_slice(&SETTINGS_MAGIC);
        out[4] = SETTINGS_VERSION;
        out[5] = self.tx_power_dbm;
        out[6] = self.max_tx;
        out[7] = self.ack_wait_s;
        out[8..10].copy_from_slice(&self.relay_ttl_ms.to_be_bytes());
        out[10..12].copy_from_slice(&self.relay_jitter_ms.to_be_bytes());
        out[12] = self.cad_attempts;
        out
    }

    /// Decode; `None` on length/magic/version mismatch (caller: default).
    /// Decoded values are clamped, never trusted blindly.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SETTINGS_LEN {
            return None;
        }
        if bytes[0..4] != SETTINGS_MAGIC || bytes[4] != SETTINGS_VERSION {
            return None;
        }
        let mut s = Self {
            tx_power_dbm: bytes[5],
            max_tx: bytes[6],
            ack_wait_s: bytes[7],
            relay_ttl_ms: u16::from_be_bytes([bytes[8], bytes[9]]),
            relay_jitter_ms: u16::from_be_bytes([bytes[10], bytes[11]]),
            cad_attempts: bytes[12],
        };
        s.clamp_all();
        Some(s)
    }
}
