//! The recipient-scan invariant: given ONLY (a) a recipient's seed-derived
//! private key and (b) the on-chain record bytes — the canonical-CBOR record
//! body whose item carries the `enc` envelope (slots, slots_mac, nonce, kem,
//! aead) — the implementation determines that the sealed record is addressed
//! to that key AND recovers the CEK, with no ciphertext available at all.
//!
//! This is the contract an inbox feed-scan runs on: it walks a public records
//! feed of bare record bodies and trial-decrypts each one client-side; the
//! off-chain ciphertext is fetched only later, when the user opens a matched
//! record. Every function on this path consumes byte slices and returns
//! values — no HTTP client type appears anywhere in it — so the scan cannot
//! perform network I/O by construction; the panicking RNG additionally proves
//! the pinned wrap draws no entropy.

use std::collections::BTreeMap;

use cardanowall::hash::sha256;
use cardanowall::poe_standard::{
    encode_poe_record, validate_poe_record, EncScheme1, EncryptionEnvelope, ItemEntry, PoeRecord,
    Slot, ValidateResult, ValidatorOptions, ValidatorRole,
};
use cardanowall::sealed_poe::{
    ecies_sealed_poe_trial_decrypt, ecies_sealed_poe_wrap_with_rng, sealed_envelope_from_parsed,
    ParsedEnvelope, ParsedSlot, SealedEnvelope, SealedKem, SealedSlots, TrialDecryptKeys,
    TrialDecryptResult, WrapArgs,
};
use cardanowall::seed_derive::{derive_mlkem768x25519_keypair, derive_x25519_keypair};

const RECIPIENT_SEED: [u8; 32] = [0x42; 32];
const OTHER_SEED: [u8; 32] = [0x43; 32];
const STRANGER_SEED: [u8; 32] = [0x44; 32];

const PLAINTEXT: &[u8] = b"feed-scan invariant payload";

fn pattern(start: u8, length: usize) -> Vec<u8> {
    (0..length).map(|i| start.wrapping_add(i as u8)).collect()
}

fn cek() -> Vec<u8> {
    pattern(0xC0, 32)
}

fn hashes() -> BTreeMap<String, Vec<u8>> {
    let mut map = BTreeMap::new();
    map.insert("sha2-256".to_string(), sha256(PLAINTEXT).to_vec());
    map
}

/// All wrap material is pinned and the shuffle is skipped, so a draw from the
/// RNG would be a contract violation — panic instead of supplying entropy.
fn no_rng() -> impl FnMut(&mut [u8]) {
    |_buf: &mut [u8]| panic!("the pinned wrap must not draw randomness")
}

/// The on-chain record body: canonical CBOR of a one-item record whose item
/// carries the hash claim plus the `enc` envelope — and nothing else. Only the
/// envelope flows in; the wrap's ciphertext is deliberately discarded by the
/// callers.
fn encode_sealed_record(envelope: &SealedEnvelope) -> Vec<u8> {
    let slots: Vec<Slot> = match &envelope.slots {
        SealedSlots::X25519(slots) => slots
            .iter()
            .map(|s| Slot {
                epk: Some(s.epk.clone()),
                kem_ct: None,
                wrap: Some(s.wrap.clone()),
            })
            .collect(),
        SealedSlots::Mlkem768X25519(slots) => slots
            .iter()
            .map(|s| Slot {
                epk: None,
                kem_ct: Some(s.kem_ct.clone()),
                wrap: Some(s.wrap.clone()),
            })
            .collect(),
    };
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: hashes().into_iter().collect(),
            uris: None,
            enc: Some(EncryptionEnvelope::Scheme1(EncScheme1 {
                scheme: u64::try_from(envelope.scheme).expect("scheme"),
                aead: envelope.aead.clone(),
                nonce: envelope.nonce.clone(),
                kem: Some(envelope.kem.clone()),
                slots: Some(slots),
                slots_mac: Some(envelope.slots_mac.clone()),
                passphrase: None,
            })),
        }]),
        merkle: None,
        supersedes: None,
        sigs: None,
        crit: None,
        extensions: Vec::new(),
    };
    encode_poe_record(&record).expect("canonical record encoding")
}

/// Walk the product feed-scan path: structural validation of the bare record
/// bytes, envelope projection, then ciphertext-free trial-decrypt under one
/// seed-derived private key.
fn scan_record_bytes(record_bytes: &[u8], secret_key: &[u8]) -> TrialDecryptResult {
    let options = ValidatorOptions {
        role: ValidatorRole::RecipientOrStrict,
        ..ValidatorOptions::default()
    };
    let record = match validate_poe_record(record_bytes, &options) {
        ValidateResult::Ok { record, .. } => record,
        ValidateResult::Fail { issues } => {
            panic!("record bytes must validate structurally: {issues:?}")
        }
    };
    let items = record.items.as_deref().expect("items");
    assert_eq!(items.len(), 1, "expected one record item");
    let item = &items[0];
    let Some(EncryptionEnvelope::Scheme1(enc)) = &item.enc else {
        panic!("record does not carry a typed scheme-1 envelope");
    };
    let parsed = ParsedEnvelope {
        scheme: i64::try_from(enc.scheme).ok(),
        aead: Some(enc.aead.clone()),
        kem: enc.kem.clone(),
        nonce: Some(enc.nonce.clone()),
        slots: enc.slots.as_ref().map(|slots| {
            slots
                .iter()
                .map(|s| ParsedSlot {
                    epk: s.epk.clone(),
                    kem_ct: s.kem_ct.clone(),
                    wrap: s.wrap.clone(),
                })
                .collect()
        }),
        slots_mac: enc.slots_mac.clone(),
    };
    let envelope = sealed_envelope_from_parsed(&parsed)
        .expect("record does not carry a sealed-recipient envelope");
    let item_hashes: BTreeMap<String, Vec<u8>> = item.hashes.iter().cloned().collect();
    let keys = [secret_key.to_vec()];
    ecies_sealed_poe_trial_decrypt(
        &envelope,
        &item_hashes,
        TrialDecryptKeys::Multi(&keys),
        None,
    )
    .expect("trial decrypt over a structurally valid envelope")
}

/// A two-recipient x25519 record with the scanning recipient in the SECOND
/// slot, so the scan demonstrably walks past a foreign slot.
fn x25519_record_bytes() -> Vec<u8> {
    let recipient = derive_x25519_keypair(&RECIPIENT_SEED).expect("derive recipient");
    let other = derive_x25519_keypair(&OTHER_SEED).expect("derive other");
    let publics = [other.public_key.to_vec(), recipient.public_key.to_vec()];
    let ephemerals = [pattern(0x20, 32), pattern(0x60, 32)];
    let item_hashes = hashes();
    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: PLAINTEXT,
            recipient_public_keys: &publics,
            hashes: &item_hashes,
            kem: Some(SealedKem::X25519),
            cek: Some(&cek()),
            nonce: Some(&pattern(0x10, 24)),
            ephemeral_secrets: Some(&ephemerals),
            eseeds: None,
            skip_shuffle: true,
        },
        &mut no_rng(),
    )
    .expect("wrap");
    encode_sealed_record(&out.envelope)
}

/// The hybrid twin of [`x25519_record_bytes`].
fn hybrid_record_bytes() -> Vec<u8> {
    let recipient = derive_mlkem768x25519_keypair(&RECIPIENT_SEED).expect("derive recipient");
    let other = derive_mlkem768x25519_keypair(&OTHER_SEED).expect("derive other");
    let publics = [other.public_key.to_vec(), recipient.public_key.to_vec()];
    let eseeds = [pattern(0x21, 64), pattern(0x61, 64)];
    let item_hashes = hashes();
    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: PLAINTEXT,
            recipient_public_keys: &publics,
            hashes: &item_hashes,
            kem: Some(SealedKem::Mlkem768X25519),
            cek: Some(&cek()),
            nonce: Some(&pattern(0x30, 24)),
            ephemeral_secrets: None,
            eseeds: Some(&eseeds),
            skip_shuffle: true,
        },
        &mut no_rng(),
    )
    .expect("wrap");
    encode_sealed_record(&out.envelope)
}

#[test]
fn x25519_seed_scan_matches_and_recovers_the_cek_without_ciphertext() {
    let record_bytes = x25519_record_bytes();
    let scanned = derive_x25519_keypair(&RECIPIENT_SEED).expect("derive");
    match scan_record_bytes(&record_bytes, &scanned.secret_key) {
        TrialDecryptResult::Match {
            slot_idx,
            cek: recovered,
        } => {
            assert_eq!(slot_idx, 1, "the recipient sits in the second slot");
            assert_eq!(recovered, cek(), "the scan recovers the exact CEK");
        }
        TrialDecryptResult::NoMatch => panic!("the recipient's own seed must match"),
    }
}

#[test]
fn x25519_non_recipient_seed_scans_to_no_match() {
    let record_bytes = x25519_record_bytes();
    let stranger = derive_x25519_keypair(&STRANGER_SEED).expect("derive");
    assert_eq!(
        scan_record_bytes(&record_bytes, &stranger.secret_key),
        TrialDecryptResult::NoMatch
    );
}

#[test]
fn hybrid_seed_scan_matches_and_recovers_the_cek_without_ciphertext() {
    let record_bytes = hybrid_record_bytes();
    let scanned = derive_mlkem768x25519_keypair(&RECIPIENT_SEED).expect("derive");
    match scan_record_bytes(&record_bytes, &scanned.secret_seed) {
        TrialDecryptResult::Match {
            slot_idx,
            cek: recovered,
        } => {
            assert_eq!(slot_idx, 1, "the recipient sits in the second slot");
            assert_eq!(recovered, cek(), "the scan recovers the exact CEK");
        }
        TrialDecryptResult::NoMatch => panic!("the recipient's own seed must match"),
    }
}

#[test]
fn hybrid_non_recipient_seed_scans_to_no_match() {
    let record_bytes = hybrid_record_bytes();
    let stranger = derive_mlkem768x25519_keypair(&STRANGER_SEED).expect("derive");
    assert_eq!(
        scan_record_bytes(&record_bytes, &stranger.secret_seed),
        TrialDecryptResult::NoMatch
    );
}
