//! Bridge from a parsed-but-permissive on-wire `enc` block to the discriminated
//! [`SealedEnvelope`] the unwrap path consumes.
//!
//! A structural validator over the record CBOR yields an `enc` block whose
//! fields are all optional (the schema layer cannot know the envelope's KEM
//! from a slot in isolation, so it leaves every per-slot field optional). This
//! is the one place that conversion lives: it dispatches on `enc.kem`, picks the
//! matching per-slot fields, and returns `None` for anything that is not a
//! recognised sealed-recipient envelope (a passphrase-only block, a missing
//! `slots` / `nonce` / `slots_mac`, an unknown KEM, or a slot missing the KEM's
//! required field). Callers then hand the whole returned envelope plus their
//! [`RecipientKeyBundle`](super::unwrap::RecipientKeyBundle) straight to the
//! unwrap / trial-decrypt path — they never rebuild slots themselves.
//!
//! Per-slot length checks are NOT done here; they are re-asserted by the unwrap
//! path's partitioning-oracle pre-checks. This helper is purely the KEM-driven
//! shape projection.

use super::slots::{
    Mlkem768X25519Slot, SealedEnvelope, SealedSlots, X25519Slot, AEAD_CHACHA20_POLY1305_STREAM64K,
    KEM_MLKEM768X25519, KEM_X25519,
};

/// A parsed-but-permissive per-slot shape mirroring the structural validator's
/// output. Each field is optional because the schema layer cannot know the
/// envelope's KEM from a slot in isolation.
#[derive(Debug, Clone, Default)]
pub struct ParsedSlot {
    /// The 32-byte ephemeral X25519 public key (classical slots).
    pub epk: Option<Vec<u8>>,
    /// The 1120-byte X-Wing ciphertext (hybrid slots).
    pub kem_ct: Option<Vec<u8>>,
    /// The AEAD-wrapped CEK (both KEMs).
    pub wrap: Option<Vec<u8>>,
}

/// A parsed-but-permissive `enc` block mirroring the structural validator's
/// output.
#[derive(Debug, Clone, Default)]
pub struct ParsedEnvelope {
    /// The envelope scheme version, if present.
    pub scheme: Option<i64>,
    /// The content-format identifier, if present.
    pub aead: Option<String>,
    /// The KEM algorithm identifier, if present.
    pub kem: Option<String>,
    /// The envelope nonce, if present.
    pub nonce: Option<Vec<u8>>,
    /// The per-recipient slots, if present.
    pub slots: Option<Vec<ParsedSlot>>,
    /// The slot-set MAC, if present.
    pub slots_mac: Option<Vec<u8>>,
}

/// Build the discriminated [`SealedEnvelope`] from a parsed `enc` block, or
/// return `None` when the block is not a sealed-recipient envelope that can be
/// trial-decrypted.
///
/// Returns `None` for: a `scheme` other than `1`, an `aead` other than
/// `chacha20-poly1305-stream64k`, a missing `nonce` / `slots_mac`, an empty or
/// missing `slots` list, an unrecognised `kem`, or any slot missing the KEM's
/// required field. This keeps every consumer's "this item is not for the
/// recipient path → no match, no crypto" branch.
#[must_use]
pub fn sealed_envelope_from_parsed(enc: &ParsedEnvelope) -> Option<SealedEnvelope> {
    if enc.scheme != Some(1) || enc.aead.as_deref() != Some(AEAD_CHACHA20_POLY1305_STREAM64K) {
        return None;
    }
    let nonce = enc.nonce.clone()?;
    let slots_mac = enc.slots_mac.clone()?;
    let slots = enc.slots.as_ref()?;
    if slots.is_empty() {
        return None;
    }

    let kem = enc.kem.as_deref()?;
    let sealed_slots = match kem {
        KEM_X25519 => {
            let mut out = Vec::with_capacity(slots.len());
            for s in slots {
                let epk = s.epk.clone()?;
                let wrap = s.wrap.clone()?;
                out.push(X25519Slot { epk, wrap });
            }
            SealedSlots::X25519(out)
        }
        KEM_MLKEM768X25519 => {
            let mut out = Vec::with_capacity(slots.len());
            for s in slots {
                let kem_ct = s.kem_ct.clone()?;
                let wrap = s.wrap.clone()?;
                out.push(Mlkem768X25519Slot { kem_ct, wrap });
            }
            SealedSlots::Mlkem768X25519(out)
        }
        _ => return None,
    };

    Some(SealedEnvelope {
        scheme: 1,
        aead: AEAD_CHACHA20_POLY1305_STREAM64K.to_string(),
        kem: kem.to_string(),
        nonce,
        slots: sealed_slots,
        slots_mac,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_none_for_passphrase_only_or_unknown_kem() {
        // Missing kem.
        let mut enc = ParsedEnvelope {
            scheme: Some(1),
            aead: Some(AEAD_CHACHA20_POLY1305_STREAM64K.to_string()),
            kem: None,
            nonce: Some(vec![0u8; 24]),
            slots: Some(vec![ParsedSlot {
                epk: Some(vec![0u8; 32]),
                kem_ct: None,
                wrap: Some(vec![0u8; 48]),
            }]),
            slots_mac: Some(vec![0u8; 32]),
        };
        assert!(sealed_envelope_from_parsed(&enc).is_none());

        // Unknown kem.
        enc.kem = Some("rsa".to_string());
        assert!(sealed_envelope_from_parsed(&enc).is_none());

        // Wrong scheme.
        enc.kem = Some(KEM_X25519.to_string());
        enc.scheme = Some(2);
        assert!(sealed_envelope_from_parsed(&enc).is_none());
    }

    #[test]
    fn builds_a_classical_envelope() {
        let enc = ParsedEnvelope {
            scheme: Some(1),
            aead: Some(AEAD_CHACHA20_POLY1305_STREAM64K.to_string()),
            kem: Some(KEM_X25519.to_string()),
            nonce: Some(vec![1u8; 24]),
            slots: Some(vec![ParsedSlot {
                epk: Some(vec![2u8; 32]),
                kem_ct: None,
                wrap: Some(vec![3u8; 48]),
            }]),
            slots_mac: Some(vec![4u8; 32]),
        };
        let env = sealed_envelope_from_parsed(&enc).expect("valid classical envelope");
        assert_eq!(env.kem, KEM_X25519);
        match env.slots {
            SealedSlots::X25519(s) => assert_eq!(s.len(), 1),
            SealedSlots::Mlkem768X25519(_) => panic!("expected classical slots"),
        }
    }
}
