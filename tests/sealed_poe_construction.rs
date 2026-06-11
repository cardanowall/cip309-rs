//! Byte-parity and behavioural tests for the sealed-PoE `enc.scheme: 1`
//! construction: the passphrase-path seal/open KAT and behaviour matrix, the
//! per-slot KEK-salt pins for both KEMs, the construction negatives, the
//! passphrase normalization profile, per-slot KEK-uniqueness rejection, the
//! verifier resource bounds, and the canonical transcript byte pins.
//!
//! Every assertion pins bytes, verdicts, or structural error codes against the
//! shared fixtures under `crypto-core/tests/fixtures/sealed-poe/` (or against
//! in-test constructions), never log strings.

mod common;

use std::collections::BTreeMap;

use cardanowall::hex;
use cardanowall::poe_standard::{
    EncScheme1, EncryptionEnvelope, ItemEntry, PassphraseBlock, PoeRecord, Slot,
};
use cardanowall::sealed_poe::{
    compute_passphrase_hash, compute_slots_hash, ecies_sealed_poe_unwrap,
    ecies_sealed_poe_wrap_with_rng, item_hashes_hash, mlkem768x25519_public_key_from_seed,
    normalize_passphrase, passphrase_sealed_poe_open, passphrase_sealed_poe_seal,
    passphrase_transcript_bytes, slots_transcript_bytes, x25519_kek_salt, x25519_public_key,
    xwing_kek_salt, EciesSealedPoeError, Mlkem768X25519Slot, PassphraseOpenArgs,
    PassphraseOpenResult, PassphraseSealArgs, SealedEnvelope, SealedSlots, UnwrapFailureReason,
    UnwrapKeys, UnwrapResult, WrapArgs, X25519Slot, AEAD_CHACHA20_POLY1305_STREAM64K,
    MAX_DECODED_ENVELOPE_BYTES, MAX_SLOTS, PASSPHRASE_COMMITMENT_LENGTH, PASSPHRASE_KDF_ARGON2ID,
};
use cardanowall::seed_derive::xwing_keygen;
use cardanowall::verifier::fetch::{
    FetchOutboundOptions, FetchOutboundResult, FetchTransport, OutboundError,
};
use cardanowall::verifier::{
    decrypt_item, ContentFetchPolicy, Decryption, DecryptionOutcome, GatewayFetcher,
};
use common::{crypto_core_fixtures, read_fixture_json};
use serde_json::Value;

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

fn fixture(name: &str) -> Value {
    read_fixture_json(&crypto_core_fixtures().join("sealed-poe").join(name))
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("field `{key}` must be a string: {v}"))
}

fn b(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(s(v, key)).unwrap_or_else(|e| panic!("bad hex in `{key}`: {e}"))
}

fn fill(byte: u8, n: usize) -> Vec<u8> {
    vec![byte; n]
}

/// The fixture's `hashes` object (algorithm identifier → digest hex).
fn hashes_from(v: &Value) -> BTreeMap<String, Vec<u8>> {
    v["hashes"]
        .as_object()
        .unwrap_or_else(|| panic!("field `hashes` must be an object: {v}"))
        .iter()
        .map(|(alg, digest)| {
            (
                alg.clone(),
                hex::decode(digest.as_str().expect("hex digest")).expect("valid hex"),
            )
        })
        .collect()
}

/// A deterministic in-test hashes map for behavioural cases.
fn test_hashes() -> BTreeMap<String, Vec<u8>> {
    let mut map = BTreeMap::new();
    map.insert("sha2-256".to_string(), vec![0x5au8; 32]);
    map
}

/// A transport that refuses every call — every decrypt test here supplies the
/// ciphertext out-of-band, so the gateway is never consulted.
struct NoFetchTransport;

impl FetchTransport for NoFetchTransport {
    fn fetch(
        &self,
        url: &str,
        _opts: &FetchOutboundOptions,
    ) -> Result<FetchOutboundResult, OutboundError> {
        Err(OutboundError::Transport {
            url: url.to_string(),
            message: "no transport: ciphertext is supplied out-of-band".to_string(),
        })
    }
}

/// Build a passphrase-path single-item record around an `enc.passphrase` block.
fn passphrase_record(
    salt: &[u8],
    m: u64,
    t: u64,
    p: u64,
    nonce: &[u8],
    digest: Vec<u8>,
) -> PoeRecord {
    PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), digest)],
            uris: None,
            enc: Some(EncryptionEnvelope::Scheme1(EncScheme1 {
                scheme: 1,
                aead: AEAD_CHACHA20_POLY1305_STREAM64K.to_string(),
                nonce: nonce.to_vec(),
                kem: None,
                slots: None,
                slots_mac: None,
                passphrase: Some(PassphraseBlock {
                    alg: PASSPHRASE_KDF_ARGON2ID.to_string(),
                    salt: salt.to_vec(),
                    params: vec![
                        ("m".to_string(), m),
                        ("t".to_string(), t),
                        ("p".to_string(), p),
                    ],
                }),
            })),
        }]),
        ..PoeRecord::default()
    }
}

/// Run the recipient verifier's per-item decrypt over the record's first item
/// with out-of-band ciphertext and a single-credential keyring, returning the
/// per-item decryption outcome.
fn decrypt_row(record: &PoeRecord, ciphertext: &[u8], credential: Decryption) -> DecryptionOutcome {
    let transport = NoFetchTransport;
    let mut fetcher = GatewayFetcher::new(&transport, None);
    let mut issues = Vec::new();
    let policy = ContentFetchPolicy {
        arweave_gateways: &[],
        ipfs_gateways: &[],
        max_fetch_bytes: None,
    };
    let item = &record.items.as_ref().expect("items")[0];
    decrypt_item(
        item,
        0,
        &[credential],
        Some(ciphertext),
        true,
        &policy,
        &mut fetcher,
        &mut issues,
    )
    .decryption
}

/// [`decrypt_row`] for a passphrase credential.
fn decrypt_passphrase_row(
    record: &PoeRecord,
    ciphertext: Vec<u8>,
    passphrase: &str,
) -> DecryptionOutcome {
    decrypt_row(
        record,
        &ciphertext,
        Decryption::Passphrase {
            passphrase: passphrase.to_string(),
        },
    )
}

// --------------------------------------------------------------------------
// Passphrase-path KAT (passphrase-n1.json; fixture-driven)
// --------------------------------------------------------------------------

#[test]
fn passphrase_n1_full_kat() {
    let corpus = fixture("passphrase-n1.json");
    let v = &corpus["vector"];
    let passphrase = s(v, "passphrase");
    let salt = b(v, "salt_hex");
    let m = v["params"]["m"].as_u64().unwrap();
    let t = v["params"]["t"].as_u64().unwrap();
    let p = v["params"]["p"].as_u64().unwrap();
    let nonce = b(v, "nonce_hex");
    let plaintext = b(v, "plaintext_hex");
    let hashes = hashes_from(v);

    // Producer: blob = commitment(32) || STREAM chunks, byte-for-byte.
    let blob = passphrase_sealed_poe_seal(PassphraseSealArgs {
        plaintext: &plaintext,
        passphrase,
        salt: &salt,
        m,
        t,
        p,
        nonce: &nonce,
        hashes: &hashes,
    })
    .expect("seal");
    assert_eq!(
        hex::encode(&blob[..PASSPHRASE_COMMITMENT_LENGTH]),
        s(v, "expected_commitment_hex"),
        "commitment header must match the fixture byte-for-byte"
    );
    assert_eq!(
        hex::encode(&blob),
        s(v, "expected_ciphertext_hex"),
        "blob (commitment || STREAM) must match the fixture byte-for-byte"
    );

    // Verifier: the pinned blob opens back to the plaintext.
    let opened = passphrase_sealed_poe_open(PassphraseOpenArgs {
        blob: &blob,
        passphrase,
        aead: AEAD_CHACHA20_POLY1305_STREAM64K,
        alg: PASSPHRASE_KDF_ARGON2ID,
        salt: &salt,
        m,
        t,
        p,
        nonce: &nonce,
        hashes: &hashes,
    })
    .expect("open");
    assert_eq!(
        opened,
        PassphraseOpenResult::Opened {
            plaintext: b(v, "expected_plaintext_hex")
        }
    );

    // End-to-end through the production verifier decrypt path: the recovered
    // plaintext re-hashes to the committed digest (plaintext_hash_ok).
    let digest = cardanowall::hash::sha256(&plaintext).to_vec();
    let record = passphrase_record(&salt, m, t, p, &nonce, digest);
    let row = decrypt_passphrase_row(&record, blob, passphrase);
    assert!(row.decrypted, "passphrase decrypt should succeed");
    assert_eq!(row.plaintext_hash_ok, Some(true));
    assert!(row.code.is_none());
}

// --------------------------------------------------------------------------
// Passphrase-path negatives (passphrase-negative.json; fixture-driven)
// --------------------------------------------------------------------------

/// Open a fixture passphrase vector: envelope fields from the vector's
/// `envelope` object, blob from `ciphertext_hex`.
fn open_passphrase_vector(v: &Value) -> Result<PassphraseOpenResult, EciesSealedPoeError> {
    let env = &v["envelope"];
    let pw = &env["passphrase"];
    let hashes = hashes_from(v);
    passphrase_sealed_poe_open(PassphraseOpenArgs {
        blob: &b(v, "ciphertext_hex"),
        passphrase: s(v, "passphrase"),
        aead: s(env, "aead"),
        alg: s(pw, "alg"),
        salt: &b(pw, "salt_hex"),
        m: pw["params"]["m"].as_u64().expect("params.m"),
        t: pw["params"]["t"].as_u64().expect("params.t"),
        p: pw["params"]["p"].as_u64().expect("params.p"),
        nonce: &b(env, "nonce_hex"),
        hashes: &hashes,
    })
}

#[test]
fn passphrase_negative_matched_false_kats() {
    // Wrong passphrase, tampered salt/params, a flipped commitment header, and
    // a hashes splice all fail the in-ciphertext commitment BEFORE any chunk
    // opens, surfacing the single generic rejection.
    let corpus = fixture("passphrase-negative.json");
    for v in corpus["matched_false_vectors"]
        .as_array()
        .expect("matched_false_vectors")
    {
        let name = s(v, "name");
        assert_eq!(
            s(v, "expected_reason"),
            "TAMPERED_CIPHERTEXT",
            "{name}: the passphrase path has exactly one generic failure"
        );
        let result = open_passphrase_vector(v)
            .unwrap_or_else(|e| panic!("{name}: must be a structured rejection, not error: {e}"));
        assert_eq!(result, PassphraseOpenResult::Rejected, "{name}");
    }
}

#[test]
fn passphrase_negative_raise_kats() {
    // A whitespace-only passphrase and one carrying an unassigned codepoint
    // are typed rejections raised before any key derivation.
    let corpus = fixture("passphrase-negative.json");
    for v in corpus["raise_vectors"].as_array().expect("raise_vectors") {
        let name = s(v, "name");
        let err = open_passphrase_vector(v).expect_err(name);
        assert_eq!(err.code(), s(v, "expected_error_code"), "{name}");
    }
}

// --------------------------------------------------------------------------
// Per-slot KEK-salt pins (fixture-driven)
// --------------------------------------------------------------------------

#[test]
fn hybrid_kek_salt_recomputed_from_nonce_kem_ct_and_pub_r() {
    let corpus = fixture("hybrid-kek-salt.json");
    let v = &corpus["vector"];
    let seed = b(v, "recipient_seed_hex");
    let expected_public = b(v, "recipient_public_hex");
    let kem_ct = b(v, "kem_ct_hex");
    let enc_nonce = b(v, "enc_nonce_hex");
    let expected_kek_salt = b(v, "expected_kek_salt_hex");

    // pub_R is recomputed from the 32-byte seed via X-Wing keygen.
    let seed_arr: [u8; 32] = seed.clone().try_into().expect("32-byte seed");
    let pub_r = mlkem768x25519_public_key_from_seed(&seed).expect("derive pub_R");
    assert_eq!(
        hex::encode(&pub_r),
        s(v, "recipient_public_hex"),
        "pub_R recomputed from the seed must match the pinned recipient public key"
    );
    // The seed_derive keygen is the same derivation; both must agree.
    assert_eq!(xwing_keygen(&seed_arr).to_vec(), expected_public);

    // kek_salt = SHA-256(label || enc.nonce || kem_ct || pub_R).
    let salt = xwing_kek_salt(&enc_nonce, &kem_ct, &pub_r);
    assert_eq!(salt.to_vec(), expected_kek_salt);
}

#[test]
fn x25519_kek_salt_recomputed_from_nonce_epk_and_pub_r() {
    let corpus = fixture("x25519-kek-salt.json");
    let v = &corpus["vector"];
    let recipient_secret = b(v, "recipient_secret_hex");
    let epk = b(v, "epk_hex");
    let enc_nonce = b(v, "enc_nonce_hex");
    let expected_kek_salt = b(v, "expected_kek_salt_hex");

    let pub_r = x25519_public_key(&recipient_secret).expect("derive pub_R");
    assert_eq!(
        hex::encode(&pub_r),
        s(v, "recipient_public_hex"),
        "pub_R recomputed from the secret must match the pinned recipient public key"
    );

    // kek_salt = SHA-256(label || enc.nonce || epk || pub_R).
    let salt = x25519_kek_salt(&enc_nonce, &epk, &pub_r);
    assert_eq!(salt.to_vec(), expected_kek_salt);
}

// --------------------------------------------------------------------------
// Construction negatives (construction-negative.json; fixture-driven)
// --------------------------------------------------------------------------

/// Build an x25519 `SealedEnvelope` from a fixture envelope shape.
fn x25519_envelope_from_json(env: &Value) -> SealedEnvelope {
    let slots = env["slots"]
        .as_array()
        .expect("slots array")
        .iter()
        .map(|sv| X25519Slot {
            epk: b(sv, "epk_hex"),
            wrap: b(sv, "wrap_hex"),
        })
        .collect();
    SealedEnvelope {
        scheme: env["scheme"].as_i64().expect("scheme"),
        aead: s(env, "aead").to_string(),
        kem: s(env, "kem").to_string(),
        nonce: b(env, "nonce_hex"),
        slots: SealedSlots::X25519(slots),
        slots_mac: b(env, "slots_mac_hex"),
    }
}

/// Build a hybrid `SealedEnvelope` from a fixture envelope (single flat
/// `kem_ct_hex` per slot).
fn hybrid_envelope_from_json(env: &Value) -> SealedEnvelope {
    let slots = env["slots"]
        .as_array()
        .expect("slots array")
        .iter()
        .map(|sv| Mlkem768X25519Slot {
            kem_ct: b(sv, "kem_ct_hex"),
            wrap: b(sv, "wrap_hex"),
        })
        .collect();
    SealedEnvelope {
        scheme: env["scheme"].as_i64().expect("scheme"),
        aead: s(env, "aead").to_string(),
        kem: s(env, "kem").to_string(),
        nonce: b(env, "nonce_hex"),
        slots: SealedSlots::Mlkem768X25519(slots),
        slots_mac: b(env, "slots_mac_hex"),
    }
}

fn reason_from_str(reason: &str) -> UnwrapFailureReason {
    match reason {
        "WRONG_RECIPIENT_KEY" => UnwrapFailureReason::WrongRecipientKey,
        "TAMPERED_HEADER" => UnwrapFailureReason::TamperedHeader,
        "TAMPERED_CIPHERTEXT" => UnwrapFailureReason::TamperedCiphertext,
        other => panic!("unknown reason {other}"),
    }
}

#[test]
fn construction_negative_all_zero_shared() {
    let corpus = fixture("construction-negative.json");
    for v in corpus["all_zero_shared_vectors"]
        .as_array()
        .expect("all_zero_shared_vectors")
    {
        let name = s(v, "name");
        let envelope = x25519_envelope_from_json(&v["envelope"]);
        let ciphertext = b(v, "ciphertext_hex");
        let secret = b(v, "recipient_secret_hex");
        let hashes = hashes_from(v);
        let result = ecies_sealed_poe_unwrap(
            &envelope,
            &ciphertext,
            &hashes,
            UnwrapKeys::Single(&secret),
            None,
        )
        .unwrap_or_else(|e| panic!("{name}: must be a structured non-match, not error: {e}"));
        assert_eq!(
            result,
            UnwrapResult::NotMatched {
                reason: reason_from_str(s(v, "expected_reason"))
            },
            "{name}"
        );
    }
}

#[test]
fn construction_negative_hybrid_header_binding() {
    let corpus = fixture("construction-negative.json");
    for v in corpus["hybrid_header_binding_vectors"]
        .as_array()
        .expect("hybrid_header_binding_vectors")
    {
        let name = s(v, "name");
        let envelope = hybrid_envelope_from_json(&v["envelope"]);
        let ciphertext = b(v, "ciphertext_hex");
        // The recipient's X-Wing secret seed (the hybrid path's recipient secret).
        let seed = b(v, "recipient_secret_hex");
        let hashes = hashes_from(v);
        let result = ecies_sealed_poe_unwrap(
            &envelope,
            &ciphertext,
            &hashes,
            UnwrapKeys::Single(&seed),
            None,
        )
        .unwrap_or_else(|e| panic!("{name}: must be a structured non-match, not error: {e}"));
        assert_eq!(
            result,
            UnwrapResult::NotMatched {
                reason: reason_from_str(s(v, "expected_reason"))
            },
            "{name}: a swapped header field breaks the slots-transcript binding"
        );
    }
}

#[test]
fn construction_negative_cross_path_confusion() {
    // A slots-shaped record decrypted with a passphrase input, and a
    // passphrase-shaped record decrypted with a recipient key, MUST both be
    // refused as WRONG_DECRYPTION_INPUT_SHAPE before any crypto.
    let corpus = fixture("construction-negative.json");
    let v = &corpus["cross_path_vectors"][0];

    // Slots-shaped record, passphrase input → wrong-input-shape.
    let slots_env = &v["slots_envelope"];
    let slot = &slots_env["slots"][0];
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), fill(0u8, 32))],
            uris: None,
            enc: Some(EncryptionEnvelope::Scheme1(EncScheme1 {
                scheme: 1,
                aead: s(slots_env, "aead").to_string(),
                nonce: b(slots_env, "nonce_hex"),
                kem: Some(s(slots_env, "kem").to_string()),
                slots: Some(vec![Slot {
                    epk: Some(b(slot, "epk_hex")),
                    kem_ct: None,
                    wrap: Some(b(slot, "wrap_hex")),
                }]),
                slots_mac: Some(b(slots_env, "slots_mac_hex")),
                passphrase: None,
            })),
        }]),
        ..PoeRecord::default()
    };
    let row = decrypt_row(
        &record,
        &fill(0u8, 48),
        Decryption::Passphrase {
            passphrase: "anything".to_string(),
        },
    );
    assert_eq!(
        row.code.map(|c| c.code()),
        Some("WRONG_DECRYPTION_INPUT_SHAPE"),
        "slots record + passphrase keyring is a shape mismatch"
    );

    // Passphrase-shaped record, recipient-key input → wrong-input-shape.
    let pw_env = &v["passphrase_envelope"];
    let pw_block = &pw_env["passphrase"];
    let record = passphrase_record(
        &b(pw_block, "salt_hex"),
        pw_block["params"]["m"].as_u64().unwrap(),
        pw_block["params"]["t"].as_u64().unwrap(),
        pw_block["params"]["p"].as_u64().unwrap(),
        &b(pw_env, "nonce_hex"),
        fill(0u8, 32),
    );
    let row = decrypt_row(
        &record,
        &fill(0u8, 48),
        Decryption::Recipient {
            recipient_secret_key: fill(0x11, 32),
        },
    );
    assert_eq!(
        row.code.map(|c| c.code()),
        Some("WRONG_DECRYPTION_INPUT_SHAPE"),
        "passphrase record + recipient key is a shape mismatch"
    );
}

// --------------------------------------------------------------------------
// Behavioural pins: per-slot KEK-uniqueness rejection (producer + verifier)
// --------------------------------------------------------------------------

#[test]
fn producer_rejects_duplicate_recipient_public_keys() {
    // Duplicate ephemeral secret across two slots → duplicate epk → reject.
    let priv0 = fill(0x21, 32);
    let pub0 = x25519_public_key(&priv0).unwrap();
    let hashes = test_hashes();
    let err = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"dup",
            recipient_public_keys: &[pub0.to_vec(), pub0.to_vec()],
            hashes: &hashes,
            cek: Some(&fill(0x33, 32)),
            nonce: Some(&fill(0x44, 24)),
            ephemeral_secrets: Some(&[fill(0x55, 32), fill(0x55, 32)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut |_: &mut [u8]| panic!("deterministic wrap must not draw randomness"),
    )
    .expect_err("duplicate epk must be rejected at the producer");
    assert_eq!(err.code(), "ENC_SLOTS_DUPLICATE_KEM_MATERIAL");
}

#[test]
fn verifier_rejects_duplicate_epk_before_any_decapsulation() {
    let env = SealedEnvelope {
        scheme: 1,
        aead: AEAD_CHACHA20_POLY1305_STREAM64K.to_string(),
        kem: "x25519".to_string(),
        nonce: fill(0u8, 24),
        slots: SealedSlots::X25519(vec![
            X25519Slot {
                epk: fill(0xab, 32),
                wrap: fill(0xcd, 48),
            },
            X25519Slot {
                epk: fill(0xab, 32),
                wrap: fill(0xef, 48),
            },
        ]),
        slots_mac: fill(0u8, 32),
    };
    let err = ecies_sealed_poe_unwrap(
        &env,
        &fill(0u8, 16),
        &test_hashes(),
        UnwrapKeys::Single(&fill(0x11, 32)),
        None,
    )
    .expect_err("duplicate epk must be a structural rejection");
    assert_eq!(err.code(), "ENC_SLOTS_DUPLICATE_KEM_MATERIAL");
}

#[test]
fn verifier_rejects_duplicate_kem_ct_before_any_decapsulation() {
    // Two hybrid slots with identical 1120-byte kem_ct.
    let enc = fill(0x07, 1120);
    let env = SealedEnvelope {
        scheme: 1,
        aead: AEAD_CHACHA20_POLY1305_STREAM64K.to_string(),
        kem: "mlkem768x25519".to_string(),
        nonce: fill(0u8, 24),
        slots: SealedSlots::Mlkem768X25519(vec![
            Mlkem768X25519Slot {
                kem_ct: enc.clone(),
                wrap: fill(0xcd, 48),
            },
            Mlkem768X25519Slot {
                kem_ct: enc,
                wrap: fill(0xef, 48),
            },
        ]),
        slots_mac: fill(0u8, 32),
    };
    let err = ecies_sealed_poe_unwrap(
        &env,
        &fill(0u8, 16),
        &test_hashes(),
        UnwrapKeys::Single(&fill(0x11, 32)),
        None,
    )
    .expect_err("duplicate kem_ct must be a structural rejection");
    assert_eq!(err.code(), "ENC_SLOTS_DUPLICATE_KEM_MATERIAL");
}

// --------------------------------------------------------------------------
// Behavioural pins: the passphrase normalization profile
// --------------------------------------------------------------------------

#[test]
fn white_space_set_is_exactly_25_codepoints() {
    // These 25 are the Unicode 16.0 White_Space property set. The normalizer
    // collapses maximal runs of exactly these to one U+0020.
    let white_space: [u32; 25] = [
        0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0020, 0x0085, 0x00a0, 0x1680, 0x2000, 0x2001,
        0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029,
        0x202f, 0x205f, 0x3000,
    ];
    let expected: Vec<char> = white_space
        .iter()
        .map(|&cp| char::from_u32(cp).unwrap())
        .collect();
    assert_eq!(
        cardanowall::sealed_poe::UNICODE_WHITE_SPACE.to_vec(),
        expected
    );

    // U+200B ZERO WIDTH SPACE is NOT White_Space: a run of it does NOT collapse.
    // Two passphrases differing only by an interior U+200B normalize differently.
    let with_zwsp = normalize_passphrase("a\u{200b}b").unwrap();
    let without = normalize_passphrase("ab").unwrap();
    assert_eq!(
        with_zwsp, "a\u{200b}b",
        "U+200B is preserved verbatim, not collapsed"
    );
    assert_ne!(with_zwsp, without);

    // U+001C..U+001F (the C0 information separators) are NOT White_Space here,
    // even though `char::is_whitespace` matches them. They must survive verbatim
    // rather than collapse to a space.
    for cp in 0x1cu32..=0x1f {
        let ch = char::from_u32(cp).unwrap();
        let input = format!("a{ch}b");
        assert_eq!(
            normalize_passphrase(&input).unwrap(),
            input,
            "U+{cp:04X} must NOT be treated as White_Space"
        );
    }
}

#[test]
fn empty_and_whitespace_only_passphrases_are_rejected() {
    for vacuous in ["", " ", "\t \u{00a0}\u{3000}", "\u{2028}\u{2029}"] {
        let err = normalize_passphrase(vacuous).unwrap_err();
        assert_eq!(err.code(), "ENC_PASSPHRASE_EMPTY", "input {vacuous:?}");
    }

    // The same rejection surfaces from the seal API before any KDF work.
    let hashes = test_hashes();
    let err = passphrase_sealed_poe_seal(PassphraseSealArgs {
        plaintext: b"body",
        passphrase: " \t ",
        salt: &fill(0x55, 16),
        m: 65536,
        t: 3,
        p: 1,
        nonce: &fill(0x66, 24),
        hashes: &hashes,
    })
    .unwrap_err();
    assert_eq!(err.code(), "ENC_PASSPHRASE_EMPTY");
}

// --------------------------------------------------------------------------
// Behavioural pins: passphrase round-trip + commitment + normalization equiv
// --------------------------------------------------------------------------

/// Seal a plaintext under the passphrase path and return
/// (record, blob, hashes).
fn seal_passphrase(
    passphrase: &str,
    salt: &[u8],
    m: u64,
    t: u64,
    p: u64,
    nonce: &[u8],
    plaintext: &[u8],
) -> (PoeRecord, Vec<u8>, BTreeMap<String, Vec<u8>>) {
    let digest = cardanowall::hash::sha256(plaintext).to_vec();
    let hashes: BTreeMap<String, Vec<u8>> = [("sha2-256".to_string(), digest.clone())].into();
    let blob = passphrase_sealed_poe_seal(PassphraseSealArgs {
        plaintext,
        passphrase,
        salt,
        m,
        t,
        p,
        nonce,
        hashes: &hashes,
    })
    .expect("seal");
    let record = passphrase_record(salt, m, t, p, nonce, digest);
    (record, blob, hashes)
}

/// Open through the crypto-layer API with header fields taken from arguments.
#[allow(clippy::too_many_arguments)]
fn open_blob(
    blob: &[u8],
    passphrase: &str,
    salt: &[u8],
    m: u64,
    t: u64,
    p: u64,
    nonce: &[u8],
    hashes: &BTreeMap<String, Vec<u8>>,
) -> PassphraseOpenResult {
    passphrase_sealed_poe_open(PassphraseOpenArgs {
        blob,
        passphrase,
        aead: AEAD_CHACHA20_POLY1305_STREAM64K,
        alg: PASSPHRASE_KDF_ARGON2ID,
        salt,
        m,
        t,
        p,
        nonce,
        hashes,
    })
    .expect("structured open result")
}

#[test]
fn passphrase_round_trip_recovers_plaintext() {
    let salt = fill(0x55, 16);
    let nonce = fill(0x66, 24);
    let (record, blob, hashes) = seal_passphrase(
        "correct horse battery staple",
        &salt,
        65536,
        3,
        1,
        &nonce,
        b"sealed body",
    );

    // Crypto-layer open.
    assert_eq!(
        open_blob(
            &blob,
            "correct horse battery staple",
            &salt,
            65536,
            3,
            1,
            &nonce,
            &hashes
        ),
        PassphraseOpenResult::Opened {
            plaintext: b"sealed body".to_vec()
        }
    );

    // Verifier-path open.
    let row = decrypt_passphrase_row(&record, blob, "correct horse battery staple");
    assert!(row.decrypted);
    assert_eq!(row.plaintext_hash_ok, Some(true));
}

#[test]
fn wrong_passphrase_is_the_single_generic_rejection_before_any_chunk() {
    let salt = fill(0x55, 16);
    let nonce = fill(0x66, 24);
    let (record, blob, hashes) = seal_passphrase("pw", &salt, 65536, 3, 1, &nonce, b"body");
    assert_eq!(
        open_blob(&blob, "not the pw", &salt, 65536, 3, 1, &nonce, &hashes),
        PassphraseOpenResult::Rejected
    );
    let row = decrypt_passphrase_row(&record, blob, "not the pw");
    assert!(!row.decrypted);
    assert_eq!(row.code.map(|c| c.code()), Some("TAMPERED_CIPHERTEXT"));
}

#[test]
fn commitment_header_flip_is_rejected() {
    let salt = fill(0x55, 16);
    let nonce = fill(0x66, 24);
    let (record, mut blob, hashes) = seal_passphrase("pw", &salt, 65536, 3, 1, &nonce, b"body");
    // Flip one bit inside the 32-byte commitment header: the STREAM chunks are
    // untouched, so only the constant-time commitment check can reject this.
    blob[7] ^= 0x01;
    assert_eq!(
        open_blob(&blob, "pw", &salt, 65536, 3, 1, &nonce, &hashes),
        PassphraseOpenResult::Rejected
    );
    let row = decrypt_passphrase_row(&record, blob, "pw");
    assert!(!row.decrypted);
    assert_eq!(row.code.map(|c| c.code()), Some("TAMPERED_CIPHERTEXT"));
}

#[test]
fn tampered_salt_or_params_break_the_commitment() {
    let salt = fill(0x55, 16);
    let nonce = fill(0x66, 24);
    let (mut record, blob, hashes) = seal_passphrase("pw", &salt, 65536, 3, 1, &nonce, b"body");

    // Crypto layer: a flipped salt byte changes both the derived CEK and the
    // transcript → Rejected.
    let mut tampered_salt = salt.clone();
    tampered_salt[0] ^= 0x01;
    assert_eq!(
        open_blob(&blob, "pw", &tampered_salt, 65536, 3, 1, &nonce, &hashes),
        PassphraseOpenResult::Rejected
    );

    // A bumped `t` parameter likewise → Rejected.
    assert_eq!(
        open_blob(&blob, "pw", &salt, 65536, 4, 1, &nonce, &hashes),
        PassphraseOpenResult::Rejected
    );

    // Verifier path: tamper the record's params; the recomputed transcript no
    // longer matches the commitment.
    {
        let Some(EncryptionEnvelope::Scheme1(enc)) = record.items.as_mut().unwrap()[0].enc.as_mut()
        else {
            panic!("passphrase record carries a scheme-1 envelope");
        };
        let block = enc.passphrase.as_mut().unwrap();
        for (k, val) in block.params.iter_mut() {
            if k == "t" {
                *val = 4;
            }
        }
    }
    let row = decrypt_passphrase_row(&record, blob, "pw");
    assert!(
        !row.decrypted,
        "a changed Argon2 cost cannot reproduce the commitment"
    );
    assert_eq!(row.code.map(|c| c.code()), Some("TAMPERED_CIPHERTEXT"));
}

#[test]
fn passphrase_hashes_splice_breaks_the_commitment() {
    // The commitment binds the item's hashes map: the same blob against an
    // item with a different digest is rejected before any chunk.
    let salt = fill(0x55, 16);
    let nonce = fill(0x66, 24);
    let (_record, blob, hashes) = seal_passphrase("pw", &salt, 65536, 3, 1, &nonce, b"body");
    assert_eq!(
        open_blob(&blob, "pw", &salt, 65536, 3, 1, &nonce, &hashes),
        PassphraseOpenResult::Opened {
            plaintext: b"body".to_vec()
        }
    );
    let mut spliced = BTreeMap::new();
    spliced.insert("sha2-256".to_string(), vec![0xEEu8; 32]);
    assert_eq!(
        open_blob(&blob, "pw", &salt, 65536, 3, 1, &nonce, &spliced),
        PassphraseOpenResult::Rejected
    );
}

#[test]
fn tampered_stream_chunk_is_rejected_after_a_valid_commitment() {
    let salt = fill(0x55, 16);
    let nonce = fill(0x66, 24);
    let (record, mut blob, hashes) = seal_passphrase("pw", &salt, 65536, 3, 1, &nonce, b"body");
    // Flip a byte PAST the commitment header: the commitment verifies, the
    // chunk tag fails.
    let idx = PASSPHRASE_COMMITMENT_LENGTH + 1;
    blob[idx] ^= 0x01;
    assert_eq!(
        open_blob(&blob, "pw", &salt, 65536, 3, 1, &nonce, &hashes),
        PassphraseOpenResult::Rejected
    );
    let row = decrypt_passphrase_row(&record, blob, "pw");
    assert_eq!(row.code.map(|c| c.code()), Some("TAMPERED_CIPHERTEXT"));
}

#[test]
fn passphrase_normalization_equivalence_for_whitespace_variants() {
    let salt = fill(0x55, 16);
    let nonce = fill(0x66, 24);
    // Seal under a single-space-separated passphrase.
    let (record, blob, _hashes) =
        seal_passphrase("alpha beta", &salt, 65536, 3, 1, &nonce, b"normalized body");

    // Each of these collapses to "alpha beta" after the profile: an NBSP, a TAB,
    // an ideographic space (U+3000), and the NEL separator (U+0085) all map to a
    // single U+0020 interior space, and leading/trailing runs are trimmed.
    for variant in [
        "alpha\u{00a0}beta",     // NBSP
        "alpha\tbeta",           // TAB
        "alpha\u{3000}beta",     // ideographic space
        "alpha\u{0085}beta",     // NEL
        "  alpha   beta  ",      // multiple ASCII spaces + trim
        "alpha \t\u{00a0} beta", // mixed run collapses to one space
    ] {
        let row = decrypt_passphrase_row(&record, blob.clone(), variant);
        assert!(row.decrypted, "variant {variant:?} should decrypt");
        assert_eq!(
            row.plaintext_hash_ok,
            Some(true),
            "variant {variant:?} normalizes to the same CEK"
        );
    }

    // An interior U+200B (NOT White_Space) changes the CEK → the commitment
    // check rejects it.
    let row = decrypt_passphrase_row(&record, blob, "alpha\u{200b} beta");
    assert_eq!(
        row.code.map(|c| c.code()),
        Some("TAMPERED_CIPHERTEXT"),
        "U+200B is not collapsed, so it derives a different CEK"
    );
}

#[test]
fn passphrase_path_handles_empty_and_multi_chunk_plaintexts() {
    let salt = fill(0x55, 16);
    let nonce = fill(0x66, 24);

    // Empty plaintext: blob = 32-byte commitment + a lone 16-byte tag.
    let (_, blob, hashes) = seal_passphrase("pw", &salt, 65536, 3, 1, &nonce, b"");
    assert_eq!(blob.len(), PASSPHRASE_COMMITMENT_LENGTH + 16);
    assert_eq!(
        open_blob(&blob, "pw", &salt, 65536, 3, 1, &nonce, &hashes),
        PassphraseOpenResult::Opened { plaintext: vec![] }
    );

    // A plaintext crossing the 64 KiB chunk boundary.
    let big: Vec<u8> = (0..65536 + 333).map(|i| (i % 251) as u8).collect();
    let (_, blob, hashes) = seal_passphrase("pw", &salt, 65536, 3, 1, &nonce, &big);
    assert_eq!(
        blob.len(),
        PASSPHRASE_COMMITMENT_LENGTH + big.len() + 2 * 16
    );
    assert_eq!(
        open_blob(&blob, "pw", &salt, 65536, 3, 1, &nonce, &hashes),
        PassphraseOpenResult::Opened { plaintext: big }
    );
}

// --------------------------------------------------------------------------
// Behavioural pin: the slots transcript binds header + hashes
// --------------------------------------------------------------------------

#[test]
fn slots_hash_changes_when_a_header_field_or_the_hashes_change() {
    let slots = SealedSlots::X25519(vec![X25519Slot {
        epk: fill(0xab, 32),
        wrap: fill(0xcd, 48),
    }]);
    let hashes_hash = item_hashes_hash(&test_hashes()).expect("hashes");
    let aead = AEAD_CHACHA20_POLY1305_STREAM64K;
    let h1 = compute_slots_hash(aead, "x25519", &fill(0x00, 24), &slots, &hashes_hash);

    // The nonce is bound.
    let mut nonce2 = fill(0x00, 24);
    nonce2[23] = 0x10;
    let h2 = compute_slots_hash(aead, "x25519", &nonce2, &slots, &hashes_hash);
    assert_ne!(h1, h2, "the nonce is bound into the slots transcript");

    // The kem identifier is bound.
    let h3 = compute_slots_hash(
        aead,
        "mlkem768x25519",
        &fill(0x00, 24),
        &slots,
        &hashes_hash,
    );
    assert_ne!(
        h1, h3,
        "the kem identifier is bound into the slots transcript"
    );

    // The item's hashes map is bound.
    let mut other_hashes = BTreeMap::new();
    other_hashes.insert("sha2-256".to_string(), vec![0xEEu8; 32]);
    let h4 = compute_slots_hash(
        aead,
        "x25519",
        &fill(0x00, 24),
        &slots,
        &item_hashes_hash(&other_hashes).expect("hashes"),
    );
    assert_ne!(h1, h4, "hashes_hash is bound into the slots transcript");
}

// --------------------------------------------------------------------------
// Verifier resource bounds (MAX_SLOTS, MAX_DECODED_ENVELOPE_BYTES)
// --------------------------------------------------------------------------

const NONCE_LEN: usize = 24;
const SLOTS_MAC_LEN: usize = 32;
const EPK_LEN: usize = 32;
const WRAP_LEN: usize = 48;
const PER_SLOT_X25519: usize = EPK_LEN + WRAP_LEN; // 80

/// A distinct, well-formed epk per slot (the duplicate-KEM-material gate forbids
/// repeats). The bytes need not be valid points: the resource-bound checks run
/// before any KEM primitive, so a structurally-shaped envelope suffices.
fn distinct_x25519_slots(count: usize) -> Vec<X25519Slot> {
    (0..count)
        .map(|i| {
            let mut epk = vec![0u8; EPK_LEN];
            epk[0] = (i & 0xff) as u8;
            epk[1] = ((i >> 8) & 0xff) as u8;
            X25519Slot {
                epk,
                wrap: vec![0u8; WRAP_LEN],
            }
        })
        .collect()
}

fn x25519_envelope(slots: Vec<X25519Slot>) -> SealedEnvelope {
    SealedEnvelope {
        scheme: 1,
        aead: AEAD_CHACHA20_POLY1305_STREAM64K.to_string(),
        kem: "x25519".to_string(),
        nonce: vec![0u8; NONCE_LEN],
        slots: SealedSlots::X25519(slots),
        slots_mac: vec![0u8; SLOTS_MAC_LEN],
    }
}

#[test]
fn resource_bound_constants_are_pinned() {
    assert_eq!(MAX_SLOTS, 1024);
    assert_eq!(MAX_DECODED_ENVELOPE_BYTES, 65536);
}

#[test]
fn rejects_more_than_max_slots() {
    // MAX_SLOTS + 1 slots trips the slot-count cap (checked before the byte cap).
    let env = x25519_envelope(distinct_x25519_slots(MAX_SLOTS + 1));
    let err = ecies_sealed_poe_unwrap(
        &env,
        &fill(0u8, 16),
        &test_hashes(),
        UnwrapKeys::Single(&fill(0x11, 32)),
        None,
    )
    .expect_err("more than MAX_SLOTS slots must be a structural rejection");
    assert_eq!(err.code(), "ENC_SLOTS_TOO_MANY");
}

#[test]
fn rejects_decoded_envelope_over_byte_backstop() {
    // The smallest slot count whose decoded size exceeds the byte backstop but is
    // at or below MAX_SLOTS, so the byte backstop (not the slot cap) is the
    // tripping check. floor((65536 - 56) / 80) = 818 fit; 819 exceed it.
    let over = ((MAX_DECODED_ENVELOPE_BYTES - NONCE_LEN - SLOTS_MAC_LEN) / PER_SLOT_X25519) + 1;
    assert!(over <= MAX_SLOTS);
    let env = x25519_envelope(distinct_x25519_slots(over));
    let err = ecies_sealed_poe_unwrap(
        &env,
        &fill(0u8, 16),
        &test_hashes(),
        UnwrapKeys::Single(&fill(0x11, 32)),
        None,
    )
    .expect_err("a decoded envelope over the byte backstop must be rejected");
    assert_eq!(err.code(), "ENC_ENVELOPE_TOO_LARGE");
}

#[test]
fn accepts_envelope_just_below_the_byte_backstop() {
    // One slot fewer than the byte-bound trip: the resource checks pass, so the
    // unwrap proceeds to the trial-decrypt loop and returns a structured
    // non-match (the slots are not real wraps) rather than a resource error.
    let just_under = (MAX_DECODED_ENVELOPE_BYTES - NONCE_LEN - SLOTS_MAC_LEN) / PER_SLOT_X25519;
    let env = x25519_envelope(distinct_x25519_slots(just_under));
    let result = ecies_sealed_poe_unwrap(
        &env,
        &fill(0u8, 16),
        &test_hashes(),
        UnwrapKeys::Single(&fill(0x11, 32)),
        None,
    )
    .expect("just below the byte backstop must not be a resource error");
    assert!(matches!(result, UnwrapResult::NotMatched { .. }));
}

// --------------------------------------------------------------------------
// Canonical transcript bytes (transcript-bytes.json; fixture-driven)
// --------------------------------------------------------------------------

/// Load (nonce, slots, hashes) from a committed wrap fixture.
fn slots_from_wrap(name: &str, kem: &str) -> (Vec<u8>, SealedSlots, BTreeMap<String, Vec<u8>>) {
    let v = &fixture(name)["vector"];
    let nonce = b(v, "nonce_hex");
    let hashes = hashes_from(v);
    let arr = v["expected_slots"].as_array().expect("expected_slots");
    let slots = if kem == "x25519" {
        SealedSlots::X25519(
            arr.iter()
                .map(|sv| X25519Slot {
                    epk: b(sv, "epk_hex"),
                    wrap: b(sv, "wrap_hex"),
                })
                .collect(),
        )
    } else {
        SealedSlots::Mlkem768X25519(
            arr.iter()
                .map(|sv| Mlkem768X25519Slot {
                    kem_ct: b(sv, "kem_ct_hex"),
                    wrap: b(sv, "wrap_hex"),
                })
                .collect(),
        )
    };
    (nonce, slots, hashes)
}

#[test]
fn transcript_bytes_match_pinned_vectors() {
    // Pins the exact canonicalEncode output of SLOTS_TRANSCRIPT (both KEMs)
    // and PASSPHRASE_TRANSCRIPT, plus the item-hashes digest, so a
    // canonical-encoding divergence localises to the encoder rather than only
    // surfacing as a downstream slots_mac / commitment mismatch.
    let corpus = fixture("transcript-bytes.json");
    let mut saw_hashes = false;
    let mut saw_x25519 = false;
    let mut saw_hybrid = false;
    let mut saw_passphrase = false;
    for v in corpus["vectors"].as_array().expect("vectors") {
        let name = s(v, "name");
        // Three vector kinds, discriminated on field presence: item-hashes-only
        // pins, SLOTS_TRANSCRIPT pins (a `kem` field), and the
        // PASSPHRASE_TRANSCRIPT pin.
        if v.get("kem").is_none()
            && v.get("expected_passphrase_transcript_canonical_hex")
                .is_none()
        {
            let hashes = hashes_from(v);
            assert_eq!(
                hex::encode(item_hashes_hash(&hashes).expect("hashes").as_slice()),
                s(v, "expected_hashes_hash_hex"),
                "{name}: hashes_hash"
            );
            saw_hashes = true;
        } else if let Some(kem) = v.get("kem").and_then(|k| k.as_str()) {
            let source = s(v, "source_fixture");
            let (nonce, slots, hashes) = slots_from_wrap(source, kem);
            assert_eq!(hex::encode(&nonce), s(v, "nonce_hex"), "{name}");

            let hashes_hash = item_hashes_hash(&hashes).expect("hashes");
            assert_eq!(
                hex::encode(hashes_hash.as_slice()),
                s(v, "expected_hashes_hash_hex"),
                "{name}: hashes_hash"
            );

            let transcript = slots_transcript_bytes(
                AEAD_CHACHA20_POLY1305_STREAM64K,
                kem,
                &nonce,
                &slots,
                &hashes_hash,
            );
            assert_eq!(
                hex::encode(&transcript),
                s(v, "expected_slots_transcript_canonical_hex"),
                "{name}: raw SLOTS_TRANSCRIPT bytes"
            );

            let slots_hash = compute_slots_hash(
                AEAD_CHACHA20_POLY1305_STREAM64K,
                kem,
                &nonce,
                &slots,
                &hashes_hash,
            );
            assert_eq!(
                hex::encode(slots_hash.as_slice()),
                s(v, "expected_slots_hash_hex"),
                "{name}: slots_hash"
            );
            saw_x25519 = saw_x25519 || kem == "x25519";
            saw_hybrid = saw_hybrid || kem == "mlkem768x25519";
        } else {
            let nonce = b(v, "nonce_hex");
            let salt = b(v, "salt_hex");
            let m = v["params"]["m"].as_u64().unwrap();
            let t = v["params"]["t"].as_u64().unwrap();
            let p = v["params"]["p"].as_u64().unwrap();
            let hashes = hashes_from(v);
            let hashes_hash = item_hashes_hash(&hashes).expect("hashes");
            let transcript = passphrase_transcript_bytes(
                AEAD_CHACHA20_POLY1305_STREAM64K,
                &nonce,
                PASSPHRASE_KDF_ARGON2ID,
                &salt,
                m,
                t,
                p,
                &hashes_hash,
            );
            assert_eq!(
                hex::encode(&transcript),
                s(v, "expected_passphrase_transcript_canonical_hex"),
                "{name}: raw PASSPHRASE_TRANSCRIPT bytes"
            );
            let pw_hash = compute_passphrase_hash(
                AEAD_CHACHA20_POLY1305_STREAM64K,
                &nonce,
                PASSPHRASE_KDF_ARGON2ID,
                &salt,
                m,
                t,
                p,
                &hashes_hash,
            );
            assert_eq!(
                hex::encode(pw_hash.as_slice()),
                s(v, "expected_pw_hash_hex"),
                "{name}: pw_hash"
            );
            saw_passphrase = true;
        }
    }
    assert!(saw_hashes && saw_x25519 && saw_hybrid && saw_passphrase);
}
