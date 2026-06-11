//! Sealed envelope and per-slot wire shapes.
//!
//! The field names mirror the on-wire `enc` map exactly. Every per-slot field
//! is a single CBOR byte string: the classical slot is `{ epk: bstr(32),
//! wrap: bstr(48) }` and the hybrid slot is `{ kem_ct: bstr(1120),
//! wrap: bstr(48) }`. The record body travels as a whole-body transport chunk
//! array, so no individual field needs its own chunking.

/// The envelope-level KEM discriminator string for the classical age-style path.
pub const KEM_X25519: &str = "x25519";

/// The envelope-level KEM discriminator string for the X-Wing hybrid path.
pub const KEM_MLKEM768X25519: &str = "mlkem768x25519";

/// The sole registered content-format identifier under `enc.scheme: 1`:
/// ChaCha20-Poly1305 (RFC 8439) in the 64 KiB segmented STREAM layout.
pub const AEAD_CHACHA20_POLY1305_STREAM64K: &str = "chacha20-poly1305-stream64k";

/// A classical (`x25519`) recipient slot: an age-style ECIES stanza.
///
/// `epk` is the 32-byte ephemeral X25519 public key; `wrap` is the 48-byte
/// AEAD-wrapped CEK (32-byte CEK + 16-byte Poly1305 tag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519Slot {
    /// The 32-byte ephemeral X25519 public key.
    pub epk: Vec<u8>,
    /// The 48-byte AEAD-wrapped content-encryption key.
    pub wrap: Vec<u8>,
}

/// A hybrid (`mlkem768x25519`) recipient slot.
///
/// `kem_ct` is the 1120-byte X-Wing ciphertext, carried as a single CBOR byte
/// string (there is no per-slot `epk` and no per-slot `kem` field — the KEM
/// identifier is hoisted to envelope scope). `wrap` is the 48-byte AEAD-wrapped
/// CEK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mlkem768X25519Slot {
    /// The 1120-byte X-Wing ciphertext (a single byte string).
    pub kem_ct: Vec<u8>,
    /// The 48-byte AEAD-wrapped content-encryption key.
    pub wrap: Vec<u8>,
}

/// The per-KEM slot array of a sealed envelope.
///
/// A sealed envelope carries homogeneous slots — every slot uses the same KEM,
/// named by the envelope's `kem` field. This enum keeps the two concrete slot
/// shapes separate so consumers branch on the KEM once and then touch only the
/// KEM-relevant fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedSlots {
    /// Classical age-style slots (`{ epk, wrap }`).
    X25519(Vec<X25519Slot>),
    /// X-Wing hybrid slots (`{ kem_ct, wrap }`).
    Mlkem768X25519(Vec<Mlkem768X25519Slot>),
}

impl SealedSlots {
    /// The number of recipient slots.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            SealedSlots::X25519(s) => s.len(),
            SealedSlots::Mlkem768X25519(s) => s.len(),
        }
    }

    /// Whether the slot array is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An in-memory sealed envelope.
///
/// The field names mirror the on-wire `enc` map exactly: `scheme`, `aead`,
/// `kem`, `nonce`, `slots`, `slots_mac`. The algorithm-identifier fields are
/// stored raw (an `i64` scheme, owned strings for `aead` and `kem`) rather than
/// as Rust enums so that an envelope carrying an unsupported algorithm can be
/// constructed and then rejected with the correct typed error by the unwrap
/// path — the structural validation lives in one place, not in the type system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEnvelope {
    /// The envelope scheme version. The only supported value is `1`.
    pub scheme: i64,
    /// The content-format identifier (`chacha20-poly1305-stream64k`).
    pub aead: String,
    /// The KEM algorithm identifier (`x25519` or `mlkem768x25519`).
    pub kem: String,
    /// The 24-byte envelope-unique nonce: the `payload_key` HKDF salt and an
    /// input to every per-slot KEK salt.
    pub nonce: Vec<u8>,
    /// The per-recipient slots.
    pub slots: SealedSlots,
    /// The 32-byte HMAC-SHA256 over the slots-transcript hash `slots_hash`,
    /// keyed by an HKDF expansion of the CEK.
    pub slots_mac: Vec<u8>,
}

/// The output of a sealed-PoE wrap: the in-memory envelope plus the content
/// ciphertext that lands off-chain (e.g. on Arweave).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPoeOutput {
    /// The sealed envelope (the on-chain header material).
    pub envelope: SealedEnvelope,
    /// The segmented-STREAM content ciphertext (the sealed chunk sequence).
    pub ciphertext: Vec<u8>,
}
