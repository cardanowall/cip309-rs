//! Label 309 wire-format parity tests.
//!
//! These tests pin the Rust encoder, validator, and chunking helpers against the
//! same vectors the TypeScript and Python SDKs use:
//!
//! - the frozen maximal record vector (`cbor_hex` + `body_cbor_hex`) — the
//!   single most important record-level byte oracle;
//! - one positive KAT per wire surface, asserting acceptance + byte-exact
//!   re-encode round-trip;
//! - one negative KAT per structural error code, asserting the exact code;
//! - the hybrid (X-Wing) slot-shape negatives;
//! - the error-code catalogue invariants and the chunking helpers.

mod common;

use cardanowall::cbor::{encode_canonical_cbor, CborValue};
use cardanowall::hex;
use cardanowall::poe_standard::{
    bytes_chunk_array_concat, chunk_bytes, chunk_uri, encode_poe_record,
    encode_record_body_for_signing, is_valid_cid, reconstruct_chunked_uri, validate_poe_record,
    EncryptionEnvelope, ErrorCode, ItemEntry, MerkleCommit, PassphraseBlock, PoeRecord,
    ReconstructUriResult, Severity, SigEntry, Slot, ValidateResult, STRUCTURAL_ERROR_CODES,
    VERIFIER_ERROR_CODES,
};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hash32(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn repeat_byte(len: usize, byte: u8) -> Vec<u8> {
    vec![byte; len]
}

/// Chunk a flat byte string into <=64-byte chunks (the on-wire `kem_ct` shape).
fn chunk64(value: &[u8]) -> Vec<Vec<u8>> {
    value.chunks(64).map(<[u8]>::to_vec).collect()
}

const MLKEM768X25519_ENC_LENGTH: usize = 1120;

fn assert_emits(record_bytes: &[u8], code: ErrorCode) {
    let result = validate_poe_record(record_bytes);
    assert!(!result.is_ok(), "expected reject for {}", code.code());
    assert!(
        result.codes().contains(&code),
        "expected {} among emitted codes {:?}",
        code.code(),
        result.codes().iter().map(|c| c.code()).collect::<Vec<_>>()
    );
}

fn assert_sole_code(record_bytes: &[u8], code: ErrorCode) {
    let result = validate_poe_record(record_bytes);
    assert!(!result.is_ok(), "expected reject for {}", code.code());
    let codes = result.codes();
    assert!(codes.contains(&code), "missing {}", code.code());
    assert_eq!(
        codes.len(),
        1,
        "expected sole code {} but got {:?}",
        code.code(),
        codes.iter().map(|c| c.code()).collect::<Vec<_>>()
    );
}

/// Build a record whose single item carries the given `enc` envelope value.
/// `enc` is supplied as a raw `CborValue::Map` so the negative cases can craft
/// arbitrary (even malformed) envelope shapes the typed builder cannot express.
fn record_with_enc(enc: CborValue) -> Vec<u8> {
    let record = CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![
                (
                    CborValue::text("hashes"),
                    CborValue::Map(vec![(
                        CborValue::text("sha2-256"),
                        CborValue::Bytes(hash32(0xab)),
                    )]),
                ),
                (CborValue::text("enc"), enc),
            ])]),
        ),
    ]);
    encode_canonical_cbor(&record).expect("encode record_with_enc")
}

/// A well-formed classical (x25519) sealed envelope as a raw CBOR map; negative
/// cases mutate individual fields.
fn sealed_base_pairs() -> Vec<(CborValue, CborValue)> {
    vec![
        (CborValue::text("scheme"), CborValue::Unsigned(1)),
        (
            CborValue::text("aead"),
            CborValue::text("xchacha20-poly1305"),
        ),
        (CborValue::text("kem"), CborValue::text("x25519")),
        (
            CborValue::text("nonce"),
            CborValue::Bytes(repeat_byte(24, 0)),
        ),
        (
            CborValue::text("slots"),
            CborValue::Array(vec![CborValue::Map(vec![
                (CborValue::text("epk"), CborValue::Bytes(repeat_byte(32, 0))),
                (
                    CborValue::text("wrap"),
                    CborValue::Bytes(repeat_byte(48, 0)),
                ),
            ])]),
        ),
        (
            CborValue::text("slots_mac"),
            CborValue::Bytes(repeat_byte(32, 0)),
        ),
    ]
}

fn sealed_base() -> CborValue {
    CborValue::Map(sealed_base_pairs())
}

/// Replace (or insert) a key in a CBOR map's pair list.
fn map_set(pairs: &mut Vec<(CborValue, CborValue)>, key: &str, value: CborValue) {
    if let Some(slot) = pairs
        .iter_mut()
        .find(|(k, _)| matches!(k, CborValue::Text(t) if t == key))
    {
        slot.1 = value;
    } else {
        pairs.push((CborValue::text(key), value));
    }
}

fn map_remove(pairs: &mut Vec<(CborValue, CborValue)>, key: &str) {
    pairs.retain(|(k, _)| !matches!(k, CborValue::Text(t) if t == key));
}

fn sealed_hybrid_pairs() -> Vec<(CborValue, CborValue)> {
    vec![
        (CborValue::text("scheme"), CborValue::Unsigned(1)),
        (
            CborValue::text("aead"),
            CborValue::text("xchacha20-poly1305"),
        ),
        (CborValue::text("kem"), CborValue::text("mlkem768x25519")),
        (
            CborValue::text("nonce"),
            CborValue::Bytes(repeat_byte(24, 0)),
        ),
        (
            CborValue::text("slots"),
            CborValue::Array(vec![hybrid_slot(MLKEM768X25519_ENC_LENGTH)]),
        ),
        (
            CborValue::text("slots_mac"),
            CborValue::Bytes(repeat_byte(32, 0)),
        ),
    ]
}

fn hybrid_slot(kem_ct_len: usize) -> CborValue {
    CborValue::Map(vec![
        (
            CborValue::text("kem_ct"),
            CborValue::Array(
                chunk64(&repeat_byte(kem_ct_len, 0))
                    .into_iter()
                    .map(CborValue::Bytes)
                    .collect(),
            ),
        ),
        (
            CborValue::text("wrap"),
            CborValue::Bytes(repeat_byte(48, 0)),
        ),
    ])
}

/// Build a canonical COSE_Sign1 `[protected, {}, payload, sig64]`.
fn build_cose_sign1(alg: i64, kid: Option<Vec<u8>>, attached_payload: bool) -> Vec<u8> {
    let mut protected_pairs = vec![(CborValue::Unsigned(1), CborValue::int(alg))];
    if let Some(kid) = kid {
        protected_pairs.push((CborValue::Unsigned(4), CborValue::Bytes(kid)));
    }
    let protected_bytes =
        encode_canonical_cbor(&CborValue::Map(protected_pairs)).expect("encode protected");
    let payload = if attached_payload {
        CborValue::Bytes(Vec::new())
    } else {
        CborValue::Null
    };
    encode_canonical_cbor(&CborValue::Array(vec![
        CborValue::Bytes(protected_bytes),
        CborValue::Map(Vec::new()),
        payload,
        CborValue::Bytes(repeat_byte(64, 0x99)),
    ]))
    .expect("encode cose_sign1")
}

/// Build a `cbor<COSE_Key>` int-keyed map; `private` adds the forbidden -4 label.
fn build_cose_key(private: bool) -> Vec<u8> {
    let mut pairs = vec![
        (CborValue::Unsigned(1), CborValue::Unsigned(1)),
        (CborValue::int(-1), CborValue::Unsigned(6)),
        (CborValue::int(-2), CborValue::Bytes(hash32(0x55))),
    ];
    if private {
        pairs.push((CborValue::int(-4), CborValue::Bytes(hash32(0xaa))));
    }
    encode_canonical_cbor(&CborValue::Map(pairs)).expect("encode cose_key")
}

// ---------------------------------------------------------------------------
// Frozen record vector (the record-level byte oracle)
// ---------------------------------------------------------------------------

/// Reconstruct the typed `PoeRecord` from the fixture JSON, mirroring the
/// TypeScript `buildRecord` in `encoder.vector.test.ts`: `_hex` fields decode to
/// bytes, chunked-bytes arrays are arrays of hex strings, and every top-level
/// key the reconstructor does not consume is a verbatim extension key.
fn build_record_from_fixture(record_json: &Value) -> PoeRecord {
    let obj = record_json.as_object().expect("record is an object");
    let mut record = PoeRecord {
        v: obj["v"].as_u64().expect("v is uint"),
        ..PoeRecord::default()
    };

    if let Some(items) = obj.get("items").and_then(Value::as_array) {
        record.items = Some(items.iter().map(build_item_from_fixture).collect());
    }
    if let Some(merkle) = obj.get("merkle").and_then(Value::as_array) {
        record.merkle = Some(
            merkle
                .iter()
                .map(|m| MerkleCommit {
                    alg: m["alg"].as_str().unwrap().to_string(),
                    root: hex::decode(m["root_hex"].as_str().unwrap()).unwrap(),
                    leaf_count: m["leaf_count"].as_u64().unwrap(),
                    uris: None,
                })
                .collect(),
        );
    }
    if let Some(s) = obj.get("supersedes_hex").and_then(Value::as_str) {
        record.supersedes = Some(hex::decode(s).unwrap());
    }
    if let Some(sigs) = obj.get("sigs").and_then(Value::as_array) {
        record.sigs = Some(
            sigs.iter()
                .map(|s| SigEntry {
                    cose_sign1: hex_chunk_array(&s["cose_sign1_hex"]),
                    cose_key: s.get("cose_key_hex").map(hex_chunk_array),
                })
                .collect(),
        );
    }
    if let Some(crit) = obj.get("crit").and_then(Value::as_array) {
        record.crit = Some(
            crit.iter()
                .map(|c| c.as_str().unwrap().to_string())
                .collect(),
        );
    }

    // Extension keys: every top-level key the reconstructor did not consume.
    const CONSUMED: &[&str] = &["v", "items", "merkle", "supersedes_hex", "sigs", "crit"];
    for (key, value) in obj {
        if CONSUMED.contains(&key.as_str()) {
            continue;
        }
        record.extensions.push((key.clone(), json_to_cbor(value)));
    }
    record
}

fn build_item_from_fixture(item: &Value) -> ItemEntry {
    let hashes = item["hashes_hex"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(alg, digest_hex)| {
            (
                alg.clone(),
                hex::decode(digest_hex.as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    let uris = item.get("uris").and_then(Value::as_array).map(|uris| {
        uris.iter()
            .map(|chunks| {
                chunks
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| c.as_str().unwrap().to_string())
                    .collect()
            })
            .collect()
    });
    let enc = item.get("enc").map(|enc| {
        let slots = enc.get("slots").and_then(Value::as_array).map(|slots| {
            slots
                .iter()
                .map(|s| Slot {
                    epk: Some(hex::decode(s["epk_hex"].as_str().unwrap()).unwrap()),
                    kem_ct: None,
                    wrap: Some(hex::decode(s["wrap_hex"].as_str().unwrap()).unwrap()),
                })
                .collect()
        });
        EncryptionEnvelope {
            scheme: enc["scheme"].as_u64().unwrap(),
            aead: enc["aead"].as_str().unwrap().to_string(),
            nonce: hex::decode(enc["nonce_hex"].as_str().unwrap()).unwrap(),
            kem: enc.get("kem").and_then(Value::as_str).map(str::to_string),
            slots,
            slots_mac: enc
                .get("slots_mac_hex")
                .and_then(Value::as_str)
                .map(|s| hex::decode(s).unwrap()),
            passphrase: None,
        }
    });
    ItemEntry { hashes, uris, enc }
}

fn hex_chunk_array(value: &Value) -> Vec<Vec<u8>> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|c| hex::decode(c.as_str().unwrap()).unwrap())
        .collect()
}

/// Convert a JSON value into a `CborValue` for an extension key. JSON integers
/// become unsigned/negative ints, strings become text, objects become maps,
/// arrays become arrays. The fixture's extension keys are `x-note` (string) and
/// `x-meta` ({a:1, bb:2}).
fn json_to_cbor(value: &Value) -> CborValue {
    match value {
        Value::String(s) => CborValue::text(s.clone()),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                CborValue::Unsigned(u)
            } else if let Some(i) = n.as_i64() {
                CborValue::int(i)
            } else {
                panic!("non-integer JSON number in extension key");
            }
        }
        Value::Bool(b) => CborValue::Bool(*b),
        Value::Null => CborValue::Null,
        Value::Array(arr) => CborValue::Array(arr.iter().map(json_to_cbor).collect()),
        Value::Object(obj) => CborValue::Map(
            obj.iter()
                .map(|(k, v)| (CborValue::text(k.clone()), json_to_cbor(v)))
                .collect(),
        ),
    }
}

#[test]
fn frozen_record_vector_reproduces_full_and_body_cbor() {
    let path =
        common::crypto_core_fixtures().join("poe-record/maximal-record-with-extension-keys.json");
    let fixture = common::read_fixture_json(&path);
    let record = build_record_from_fixture(&fixture["record"]);

    let full = encode_poe_record(&record).unwrap();
    assert_eq!(
        hex::encode(&full),
        fixture["cbor_hex"].as_str().unwrap(),
        "full record CBOR (cbor_hex) must match byte-for-byte"
    );

    let body = encode_record_body_for_signing(&record).unwrap();
    assert_eq!(
        hex::encode(&body),
        fixture["body_cbor_hex"].as_str().unwrap(),
        "record body CBOR (body_cbor_hex, sigs stripped) must match byte-for-byte"
    );

    // The frozen vector is an ENCODE oracle, not a validation oracle: it carries
    // `crit: ["x-note"]`, and v1 implements zero extensions, so every shape-valid
    // crit entry is EXTENSION_UNSUPPORTED_CRITICAL (error-severity). The validator
    // therefore rejects this record by design — assert that exact verdict so the
    // crit-handling path stays pinned alongside the byte oracle.
    let result = validate_poe_record(&full);
    assert!(!result.is_ok());
    assert!(result
        .codes()
        .contains(&ErrorCode::ExtensionUnsupportedCritical));

    // Extension keys are the load-bearing case: assert the vector still pins
    // them so a future fixture edit cannot silently stop testing the path.
    assert!(record.extensions.iter().any(|(k, _)| k == "x-note"));
    assert!(record.extensions.iter().any(|(k, _)| k == "x-meta"));
}

// ---------------------------------------------------------------------------
// Positive KAT corpus
// ---------------------------------------------------------------------------

fn positive_corpus() -> Vec<(&'static str, PoeRecord)> {
    vec![
        (
            "minimal-items",
            PoeRecord {
                v: 1,
                items: Some(vec![ItemEntry {
                    hashes: vec![
                        ("sha2-256".to_string(), hash32(0xab)),
                        ("blake2b-256".to_string(), hash32(0xcd)),
                    ],
                    uris: None,
                    enc: None,
                }]),
                ..PoeRecord::default()
            },
        ),
        (
            "merkle-only",
            PoeRecord {
                v: 1,
                merkle: Some(vec![MerkleCommit {
                    alg: "rfc9162-sha256".to_string(),
                    root: hash32(0x77),
                    leaf_count: 8,
                    uris: None,
                }]),
                ..PoeRecord::default()
            },
        ),
        (
            "hybrid-items-merkle",
            PoeRecord {
                v: 1,
                items: Some(vec![ItemEntry {
                    hashes: vec![("sha2-256".to_string(), hash32(0xab))],
                    uris: None,
                    enc: None,
                }]),
                merkle: Some(vec![MerkleCommit {
                    alg: "rfc9162-sha256".to_string(),
                    root: hash32(0x88),
                    leaf_count: 16,
                    uris: None,
                }]),
                ..PoeRecord::default()
            },
        ),
        (
            "supersedence",
            PoeRecord {
                v: 1,
                items: Some(vec![ItemEntry {
                    hashes: vec![("sha2-256".to_string(), hash32(0xab))],
                    uris: None,
                    enc: None,
                }]),
                supersedes: Some(repeat_byte(32, 0x33)),
                ..PoeRecord::default()
            },
        ),
        (
            "sealed-slots-x25519",
            PoeRecord {
                v: 1,
                items: Some(vec![ItemEntry {
                    hashes: vec![
                        ("sha2-256".to_string(), hash32(0xab)),
                        ("blake2b-256".to_string(), hash32(0x22)),
                    ],
                    uris: None,
                    enc: Some(EncryptionEnvelope {
                        scheme: 1,
                        aead: "xchacha20-poly1305".to_string(),
                        nonce: repeat_byte(24, 0),
                        kem: Some("x25519".to_string()),
                        slots: Some(vec![
                            Slot {
                                epk: Some(repeat_byte(32, 0x01)),
                                kem_ct: None,
                                wrap: Some(repeat_byte(48, 0x02)),
                            },
                            Slot {
                                epk: Some(repeat_byte(32, 0x03)),
                                kem_ct: None,
                                wrap: Some(repeat_byte(48, 0x04)),
                            },
                        ]),
                        slots_mac: Some(repeat_byte(32, 0x07)),
                        passphrase: None,
                    }),
                }]),
                ..PoeRecord::default()
            },
        ),
        (
            "sealed-slots-hybrid",
            PoeRecord {
                v: 1,
                items: Some(vec![ItemEntry {
                    hashes: vec![("sha2-256".to_string(), hash32(0xab))],
                    uris: None,
                    enc: Some(EncryptionEnvelope {
                        scheme: 1,
                        aead: "xchacha20-poly1305".to_string(),
                        nonce: repeat_byte(24, 0),
                        kem: Some("mlkem768x25519".to_string()),
                        slots: Some(vec![Slot {
                            epk: None,
                            kem_ct: Some(chunk64(&repeat_byte(MLKEM768X25519_ENC_LENGTH, 0x11))),
                            wrap: Some(repeat_byte(48, 0x02)),
                        }]),
                        slots_mac: Some(repeat_byte(32, 0x07)),
                        passphrase: None,
                    }),
                }]),
                ..PoeRecord::default()
            },
        ),
        (
            "sealed-passphrase",
            PoeRecord {
                v: 1,
                items: Some(vec![ItemEntry {
                    hashes: vec![("sha2-256".to_string(), hash32(0xab))],
                    uris: None,
                    enc: Some(EncryptionEnvelope {
                        scheme: 1,
                        aead: "xchacha20-poly1305".to_string(),
                        nonce: repeat_byte(24, 0),
                        kem: None,
                        slots: None,
                        slots_mac: None,
                        passphrase: Some(PassphraseBlock {
                            alg: "argon2id".to_string(),
                            salt: repeat_byte(16, 0),
                            params: vec![
                                ("m".to_string(), 65_536),
                                ("t".to_string(), 3),
                                ("p".to_string(), 1),
                            ],
                        }),
                    }),
                }]),
                ..PoeRecord::default()
            },
        ),
        (
            "items-with-ar-uri",
            PoeRecord {
                v: 1,
                items: Some(vec![ItemEntry {
                    hashes: vec![("sha2-256".to_string(), hash32(0xab))],
                    uris: Some(vec![chunk_uri(&format!("ar://{}", "A".repeat(43)))]),
                    enc: None,
                }]),
                ..PoeRecord::default()
            },
        ),
        (
            "items-with-ipfs-cidv0-uri",
            PoeRecord {
                v: 1,
                items: Some(vec![ItemEntry {
                    hashes: vec![("sha2-256".to_string(), hash32(0xab))],
                    uris: Some(vec![chunk_uri(
                        "ipfs://QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH",
                    )]),
                    enc: None,
                }]),
                ..PoeRecord::default()
            },
        ),
    ]
}

#[test]
fn positive_corpus_accepts_and_round_trips() {
    for (name, record) in positive_corpus() {
        let encoded = encode_poe_record(&record).unwrap();
        let result = validate_poe_record(&encoded);
        assert!(result.is_ok(), "{name} should validate");
        let ValidateResult::Ok {
            record: decoded, ..
        } = result
        else {
            unreachable!();
        };
        // validate(encode(R)).record re-encodes to the same bytes.
        let reencoded = encode_poe_record(&decoded).unwrap();
        assert_eq!(reencoded, encoded, "{name} must round-trip byte-exactly");
    }
}

#[test]
fn signed_record_with_real_cose_sign1_validates() {
    let cose = build_cose_sign1(-8, None, false);
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), hash32(0xab))],
            uris: None,
            enc: None,
        }]),
        sigs: Some(vec![SigEntry {
            cose_sign1: chunk_bytes(&cose),
            cose_key: None,
        }]),
        ..PoeRecord::default()
    };
    let result = validate_poe_record(&encode_poe_record(&record).unwrap());
    assert!(result.is_ok());
}

#[test]
fn unsupported_sig_alg_is_info_not_failure() {
    // alg = -7 (ES256) is not in {-8, -19}; SIGNATURE_UNSUPPORTED is info-only.
    let cose = build_cose_sign1(-7, None, false);
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), hash32(0xab))],
            uris: None,
            enc: None,
        }]),
        sigs: Some(vec![SigEntry {
            cose_sign1: chunk_bytes(&cose),
            cose_key: None,
        }]),
        ..PoeRecord::default()
    };
    let result = validate_poe_record(&encode_poe_record(&record).unwrap());
    assert!(
        result.is_ok(),
        "unsupported sig alg must not fail the record"
    );
    assert!(result.codes().contains(&ErrorCode::SignatureUnsupported));
}

#[test]
fn extension_keys_are_accepted() {
    let record = CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![(
                CborValue::text("hashes"),
                CborValue::Map(vec![(
                    CborValue::text("sha2-256"),
                    CborValue::Bytes(hash32(0xab)),
                )]),
            )])]),
        ),
        (
            CborValue::text("x-vendor-flag"),
            CborValue::text("experiment"),
        ),
    ]);
    let bytes = encode_canonical_cbor(&record).unwrap();
    assert!(validate_poe_record(&bytes).is_ok());
}

// ---------------------------------------------------------------------------
// Negative KAT corpus (one per structural error code)
// ---------------------------------------------------------------------------

#[test]
fn negative_corpus_emits_expected_codes() {
    // MALFORMED_CBOR — a stray break byte sequence.
    assert_emits(&hex::decode("ffffffff").unwrap(), ErrorCode::MalformedCbor);

    // SCHEMA_TYPE_MISMATCH — items is a text string, not an array.
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (CborValue::text("items"), CborValue::text("not-an-array")),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::SchemaTypeMismatch);

    // SCHEMA_MISSING_REQUIRED — empty map (no v).
    let bytes = encode_canonical_cbor(&CborValue::Map(Vec::new())).unwrap();
    assert_emits(&bytes, ErrorCode::SchemaMissingRequired);

    // SCHEMA_UNKNOWN_FIELD — a non-extension typo key.
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (CborValue::text("items"), valid_items()),
        (
            CborValue::text("supersedess"),
            CborValue::Bytes(repeat_byte(32, 0)),
        ),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::SchemaUnknownField);

    // SCHEMA_INVALID_LITERAL — v = 2.
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(2)),
        (CborValue::text("items"), valid_items()),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::SchemaInvalidLiteral);

    // SCHEMA_EMPTY_RECORD — items=[] and merkle=[].
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (CborValue::text("items"), CborValue::Array(Vec::new())),
        (CborValue::text("merkle"), CborValue::Array(Vec::new())),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::SchemaEmptyRecord);

    // HASH_DIGEST_LENGTH_MISMATCH — 31-byte sha2-256.
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![(
                CborValue::text("hashes"),
                CborValue::Map(vec![(
                    CborValue::text("sha2-256"),
                    CborValue::Bytes(repeat_byte(31, 0)),
                )]),
            )])]),
        ),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::HashDigestLengthMismatch);

    // UNSUPPORTED_HASH_ALG — md5.
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![(
                CborValue::text("hashes"),
                CborValue::Map(vec![(
                    CborValue::text("md5"),
                    CborValue::Bytes(repeat_byte(16, 0)),
                )]),
            )])]),
        ),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::UnsupportedHashAlg);

    // UNSUPPORTED_MERKLE_COMMIT_ALG.
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("merkle"),
            CborValue::Array(vec![CborValue::Map(vec![
                (CborValue::text("alg"), CborValue::text("custom-merkle")),
                (CborValue::text("root"), CborValue::Bytes(hash32(0xab))),
                (CborValue::text("leaf_count"), CborValue::Unsigned(4)),
            ])]),
        ),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::UnsupportedMerkleCommitAlg);

    // INVALID_URI — https scheme.
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![
                (
                    CborValue::text("hashes"),
                    CborValue::Map(vec![(
                        CborValue::text("sha2-256"),
                        CborValue::Bytes(hash32(0xab)),
                    )]),
                ),
                (
                    CborValue::text("uris"),
                    CborValue::Array(vec![CborValue::Array(vec![CborValue::text(
                        "https://example.org/x",
                    )])]),
                ),
            ])]),
        ),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::InvalidUri);

    // UNAUTHENTICATED_CIPHER_FORBIDDEN.
    let mut enc = sealed_base_pairs();
    map_set(&mut enc, "aead", CborValue::text("aes-256-cbc"));
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::UnauthenticatedCipherForbidden,
    );

    // UNSUPPORTED_AEAD_ALG.
    let mut enc = sealed_base_pairs();
    map_set(&mut enc, "aead", CborValue::text("twofish-gcm"));
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::UnsupportedAeadAlg,
    );

    // NONCE_LENGTH_MISMATCH.
    let mut enc = sealed_base_pairs();
    map_set(&mut enc, "nonce", CborValue::Bytes(repeat_byte(12, 0)));
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::NonceLengthMismatch,
    );

    // UNSUPPORTED_ENVELOPE_SCHEME.
    let mut enc = sealed_base_pairs();
    map_set(&mut enc, "scheme", CborValue::Unsigned(2));
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::UnsupportedEnvelopeScheme,
    );

    // ENC_SLOTS_EMPTY.
    let mut enc = sealed_base_pairs();
    map_set(&mut enc, "slots", CborValue::Array(Vec::new()));
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::EncSlotsEmpty,
    );

    // ENC_SLOT_INVALID_SHAPE — slot missing wrap.
    let mut enc = sealed_base_pairs();
    map_set(
        &mut enc,
        "slots",
        CborValue::Array(vec![CborValue::Map(vec![(
            CborValue::text("epk"),
            CborValue::Bytes(repeat_byte(32, 0)),
        )])]),
    );
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::EncSlotInvalidShape,
    );

    // UNSUPPORTED_KEM_ALG.
    let mut enc = sealed_base_pairs();
    map_set(&mut enc, "kem", CborValue::text("x448"));
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::UnsupportedKemAlg,
    );

    // ENC_KEM_REQUIRED.
    let mut enc = sealed_base_pairs();
    map_remove(&mut enc, "kem");
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::EncKemRequired,
    );

    // KEM_EPK_LENGTH_MISMATCH.
    let mut enc = sealed_base_pairs();
    map_set(
        &mut enc,
        "slots",
        CborValue::Array(vec![CborValue::Map(vec![
            (CborValue::text("epk"), CborValue::Bytes(repeat_byte(31, 0))),
            (
                CborValue::text("wrap"),
                CborValue::Bytes(repeat_byte(48, 0)),
            ),
        ])]),
    );
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::KemEpkLengthMismatch,
    );

    // KEM_CT_LENGTH_MISMATCH — hybrid kem_ct reassembles to 1119.
    let mut enc = sealed_hybrid_pairs();
    map_set(
        &mut enc,
        "slots",
        CborValue::Array(vec![hybrid_slot(MLKEM768X25519_ENC_LENGTH - 1)]),
    );
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::KemCtLengthMismatch,
    );

    // WRAP_LENGTH_MISMATCH.
    let mut enc = sealed_base_pairs();
    map_set(
        &mut enc,
        "slots",
        CborValue::Array(vec![CborValue::Map(vec![
            (CborValue::text("epk"), CborValue::Bytes(repeat_byte(32, 0))),
            (
                CborValue::text("wrap"),
                CborValue::Bytes(repeat_byte(40, 0)),
            ),
        ])]),
    );
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::WrapLengthMismatch,
    );

    // ENC_SLOTS_MAC_INVALID_LENGTH.
    let mut enc = sealed_base_pairs();
    map_set(&mut enc, "slots_mac", CborValue::Bytes(repeat_byte(31, 0)));
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::EncSlotsMacInvalidLength,
    );

    // ENC_SLOTS_MAC_REQUIRED.
    let mut enc = sealed_base_pairs();
    map_remove(&mut enc, "slots_mac");
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::EncSlotsMacRequired,
    );

    // ENC_SLOTS_REQUIRED — slots_mac present, slots+kem absent.
    let mut enc = sealed_base_pairs();
    map_remove(&mut enc, "slots");
    map_remove(&mut enc, "kem");
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::EncSlotsRequired,
    );

    // ENC_EXCLUSIVITY_VIOLATION — slots AND passphrase.
    let mut enc = sealed_base_pairs();
    map_set(
        &mut enc,
        "passphrase",
        argon2id_passphrase(65_536, 3, 1, 16),
    );
    assert_emits(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::EncExclusivityViolation,
    );

    // ENC_NO_KEY_PATH — neither slots nor passphrase.
    let enc = CborValue::Map(vec![
        (CborValue::text("scheme"), CborValue::Unsigned(1)),
        (
            CborValue::text("aead"),
            CborValue::text("xchacha20-poly1305"),
        ),
        (
            CborValue::text("nonce"),
            CborValue::Bytes(repeat_byte(24, 0)),
        ),
    ]);
    assert_emits(&record_with_enc(enc), ErrorCode::EncNoKeyPath);

    // ENC_REQUIRES_CONTENT_HASH — an enc-bearing item whose hashes map has no
    // content-hash entry. The predicate is the absence of a content hash,
    // independent of whether the map is empty or merely non-content. A non-empty
    // {md5} map also co-fires UNSUPPORTED_HASH_ALG (v1 has no non-content alg);
    // an empty map also co-fires SCHEMA_TYPE_MISMATCH (the hashes-shape check).
    // assert_emits tolerates the co-fired code.
    let record_bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![
                (
                    CborValue::text("hashes"),
                    CborValue::Map(vec![(
                        CborValue::text("md5"),
                        CborValue::Bytes(repeat_byte(16, 0)),
                    )]),
                ),
                (CborValue::text("enc"), sealed_base()),
            ])]),
        ),
    ]))
    .unwrap();
    assert_emits(&record_bytes, ErrorCode::EncRequiresContentHash);

    // The empty-hashes-map variant must ALSO emit ENC_REQUIRES_CONTENT_HASH
    // (alongside SCHEMA_TYPE_MISMATCH from the hashes-shape check).
    let empty_hashes_bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![
                (CborValue::text("hashes"), CborValue::Map(vec![])),
                (CborValue::text("enc"), sealed_base()),
            ])]),
        ),
    ]))
    .unwrap();
    let empty_result = validate_poe_record(&empty_hashes_bytes);
    assert!(empty_result
        .codes()
        .contains(&ErrorCode::EncRequiresContentHash));
    assert!(empty_result
        .codes()
        .contains(&ErrorCode::SchemaTypeMismatch));

    // ENC_PASSPHRASE_ALG_UNSUPPORTED.
    let enc = CborValue::Map(vec![
        (CborValue::text("scheme"), CborValue::Unsigned(1)),
        (
            CborValue::text("aead"),
            CborValue::text("xchacha20-poly1305"),
        ),
        (
            CborValue::text("nonce"),
            CborValue::Bytes(repeat_byte(24, 0)),
        ),
        (
            CborValue::text("passphrase"),
            CborValue::Map(vec![
                (CborValue::text("alg"), CborValue::text("pbkdf2-sha-256")),
                (
                    CborValue::text("salt"),
                    CborValue::Bytes(repeat_byte(16, 0)),
                ),
                (
                    CborValue::text("params"),
                    CborValue::Map(vec![(CborValue::text("i"), CborValue::Unsigned(600_000))]),
                ),
            ]),
        ),
    ]);
    assert_emits(
        &record_with_enc(enc),
        ErrorCode::EncPassphraseAlgUnsupported,
    );

    // ENC_PASSPHRASE_SALT_TOO_SHORT.
    let enc = passphrase_only_enc(argon2id_passphrase(65_536, 3, 1, 15));
    assert_emits(&record_with_enc(enc), ErrorCode::EncPassphraseSaltTooShort);

    // ENC_PASSPHRASE_SALT_TOO_LONG.
    let enc = passphrase_only_enc(argon2id_passphrase(65_536, 3, 1, 65));
    assert_emits(&record_with_enc(enc), ErrorCode::EncPassphraseSaltTooLong);

    // ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW — m too low.
    let enc = passphrase_only_enc(argon2id_passphrase(1024, 3, 1, 16));
    assert_emits(
        &record_with_enc(enc),
        ErrorCode::EncPassphraseArgon2ParamsTooLow,
    );

    // MALFORMED_SIG_COSE_SIGN1 — garbage cose_sign1 chunk.
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (CborValue::text("items"), valid_items()),
        (
            CborValue::text("sigs"),
            CborValue::Array(vec![CborValue::Map(vec![(
                CborValue::text("cose_sign1"),
                CborValue::Array(vec![CborValue::Bytes(vec![0xff, 0xff, 0xff])]),
            )])]),
        ),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::MalformedSigCoseSign1);

    // SIG_ENTRY_INVALID_SHAPE — a sigs entry that is an array, not a map.
    // (A sigs entry carrying an EXTRA key instead yields SCHEMA_UNKNOWN_FIELD:
    // the sig entry is a closed map, so an unrecognised key is an unknown-field
    // violation rather than a shape violation.)
    let record_bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (CborValue::text("items"), valid_items()),
        (
            CborValue::text("sigs"),
            CborValue::Array(vec![CborValue::Array(vec![CborValue::Bytes(repeat_byte(
                10, 0,
            ))])]),
        ),
    ]))
    .unwrap();
    assert_emits(&record_bytes, ErrorCode::SigEntryInvalidShape);

    // SIG_ENTRY_INVALID_SHAPE also surfaces from a sigs entry with an extra
    // field. The sig entry is a closed map `{ cose_sign1, cose_key? }`, so an
    // unrecognised key is a shape violation — not the generic SCHEMA_UNKNOWN_FIELD
    // that item/enc/passphrase/merkle raise — matching the TS/Python reference.
    let record_bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (CborValue::text("items"), valid_items()),
        (
            CborValue::text("sigs"),
            CborValue::Array(vec![CborValue::Map(vec![
                (
                    CborValue::text("cose_sign1"),
                    CborValue::Array(vec![CborValue::Bytes(repeat_byte(64, 0))]),
                ),
                (
                    CborValue::text("extra_field"),
                    CborValue::Bytes(repeat_byte(8, 0)),
                ),
            ])]),
        ),
    ]))
    .unwrap();
    assert_emits(&record_bytes, ErrorCode::SigEntryInvalidShape);

    // SIG_ENTRY_KID_COSE_KEY_CONFLICT — both 32-byte kid and cose_key.
    let cose = build_cose_sign1(-8, Some(hash32(0x42)), false);
    let cose_key = build_cose_key(false);
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), hash32(0xab))],
            uris: None,
            enc: None,
        }]),
        sigs: Some(vec![SigEntry {
            cose_sign1: chunk_bytes(&cose),
            cose_key: Some(chunk_bytes(&cose_key)),
        }]),
        ..PoeRecord::default()
    };
    assert_emits(
        &encode_poe_record(&record).unwrap(),
        ErrorCode::SigEntryKidCoseKeyConflict,
    );

    // SIG_PRIVATE_KEY_LEAKED — cose_key carries label -4.
    let cose = build_cose_sign1(-8, None, false);
    let cose_key = build_cose_key(true);
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), hash32(0xab))],
            uris: None,
            enc: None,
        }]),
        sigs: Some(vec![SigEntry {
            cose_sign1: chunk_bytes(&cose),
            cose_key: Some(chunk_bytes(&cose_key)),
        }]),
        ..PoeRecord::default()
    };
    assert_emits(
        &encode_poe_record(&record).unwrap(),
        ErrorCode::SigPrivateKeyLeaked,
    );

    // CHUNK_TOO_LARGE — a 65-byte cose_sign1 chunk.
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (CborValue::text("items"), valid_items()),
        (
            CborValue::text("sigs"),
            CborValue::Array(vec![CborValue::Map(vec![(
                CborValue::text("cose_sign1"),
                CborValue::Array(vec![CborValue::Bytes(repeat_byte(65, 0))]),
            )])]),
        ),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::ChunkTooLarge);

    // SUPERSEDES_TX_INVALID_LENGTH — bytes of the wrong width.
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (CborValue::text("items"), valid_items()),
        (
            CborValue::text("supersedes"),
            CborValue::Bytes(repeat_byte(31, 0)),
        ),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::SupersedesTxInvalidLength);

    // SCHEMA_TYPE_MISMATCH — supersedes carries the wrong TYPE (text, not
    // bytes). A wrong type and a wrong length are distinct defects.
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (CborValue::text("items"), valid_items()),
        (CborValue::text("supersedes"), CborValue::text("not-bytes")),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::SchemaTypeMismatch);

    // CRIT_SHAPE_INVALID — crit names a base key.
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (CborValue::text("items"), valid_items()),
        (
            CborValue::text("crit"),
            CborValue::Array(vec![CborValue::text("v")]),
        ),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::CritShapeInvalid);

    // EXTENSION_UNSUPPORTED_CRITICAL — crit names a present extension key.
    let bytes = encode_canonical_cbor(&CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (CborValue::text("items"), valid_items()),
        (
            CborValue::text("crit"),
            CborValue::Array(vec![CborValue::text("x-foo")]),
        ),
        (CborValue::text("x-foo"), CborValue::text("bar")),
    ]))
    .unwrap();
    assert_emits(&bytes, ErrorCode::ExtensionUnsupportedCritical);
}

fn valid_items() -> CborValue {
    CborValue::Array(vec![CborValue::Map(vec![(
        CborValue::text("hashes"),
        CborValue::Map(vec![(
            CborValue::text("sha2-256"),
            CborValue::Bytes(hash32(0xab)),
        )]),
    )])])
}

fn argon2id_passphrase(m: u64, t: u64, p: u64, salt_len: usize) -> CborValue {
    CborValue::Map(vec![
        (CborValue::text("alg"), CborValue::text("argon2id")),
        (
            CborValue::text("salt"),
            CborValue::Bytes(repeat_byte(salt_len, 0)),
        ),
        (
            CborValue::text("params"),
            CborValue::Map(vec![
                (CborValue::text("m"), CborValue::Unsigned(m)),
                (CborValue::text("t"), CborValue::Unsigned(t)),
                (CborValue::text("p"), CborValue::Unsigned(p)),
            ]),
        ),
    ])
}

fn passphrase_only_enc(passphrase: CborValue) -> CborValue {
    CborValue::Map(vec![
        (CborValue::text("scheme"), CborValue::Unsigned(1)),
        (
            CborValue::text("aead"),
            CborValue::text("xchacha20-poly1305"),
        ),
        (
            CborValue::text("nonce"),
            CborValue::Bytes(repeat_byte(24, 0)),
        ),
        (CborValue::text("passphrase"), passphrase),
    ])
}

// ---------------------------------------------------------------------------
// Hybrid (mlkem768x25519) cross-KEM slot-shape negatives
// ---------------------------------------------------------------------------

#[test]
fn hybrid_slot_with_stray_epk_is_sole_invalid_shape() {
    let mut enc = sealed_hybrid_pairs();
    let mut slot = vec![
        (
            CborValue::text("kem_ct"),
            CborValue::Array(
                chunk64(&repeat_byte(MLKEM768X25519_ENC_LENGTH, 0))
                    .into_iter()
                    .map(CborValue::Bytes)
                    .collect(),
            ),
        ),
        (CborValue::text("epk"), CborValue::Bytes(repeat_byte(32, 0))),
        (
            CborValue::text("wrap"),
            CborValue::Bytes(repeat_byte(48, 0)),
        ),
    ];
    map_set(
        &mut enc,
        "slots",
        CborValue::Array(vec![CborValue::Map(std::mem::take(&mut slot))]),
    );
    assert_sole_code(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::EncSlotInvalidShape,
    );
}

#[test]
fn classical_slot_with_stray_kem_ct_is_sole_invalid_shape() {
    let mut enc = sealed_base_pairs();
    map_set(
        &mut enc,
        "slots",
        CborValue::Array(vec![CborValue::Map(vec![
            (CborValue::text("epk"), CborValue::Bytes(repeat_byte(32, 0))),
            (
                CborValue::text("kem_ct"),
                CborValue::Array(
                    chunk64(&repeat_byte(MLKEM768X25519_ENC_LENGTH, 0))
                        .into_iter()
                        .map(CborValue::Bytes)
                        .collect(),
                ),
            ),
            (
                CborValue::text("wrap"),
                CborValue::Bytes(repeat_byte(48, 0)),
            ),
        ])]),
    );
    assert_sole_code(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::EncSlotInvalidShape,
    );
}

#[test]
fn hybrid_slot_with_oversized_kem_ct_is_sole_length_mismatch() {
    let mut enc = sealed_hybrid_pairs();
    map_set(
        &mut enc,
        "slots",
        CborValue::Array(vec![hybrid_slot(MLKEM768X25519_ENC_LENGTH + 64)]),
    );
    assert_sole_code(
        &record_with_enc(CborValue::Map(enc)),
        ErrorCode::KemCtLengthMismatch,
    );
}

// ---------------------------------------------------------------------------
// CBOR decode mapping to MALFORMED_CBOR
// ---------------------------------------------------------------------------

#[test]
fn cbor_decode_failures_all_map_to_malformed_cbor() {
    // Duplicate keys, unsorted keys, indefinite-length, empty input, and garbage
    // all fold into the single MALFORMED_CBOR code.
    for hexstr in [
        "a2616101616102", // {"a":1,"a":2} duplicate keys
        "a2616201616102", // {"b":1,"a":2} unsorted keys
        "5fff",           // indefinite-length bytestring
        "ffffffff",       // garbage / stray break
    ] {
        assert_emits(&hex::decode(hexstr).unwrap(), ErrorCode::MalformedCbor);
    }
    // Empty input.
    assert_emits(&[], ErrorCode::MalformedCbor);
}

// ---------------------------------------------------------------------------
// Error-code catalogue invariants
// ---------------------------------------------------------------------------

#[test]
fn structural_codes_are_unique() {
    let mut codes: Vec<&str> = STRUCTURAL_ERROR_CODES.iter().map(|c| c.code()).collect();
    codes.sort_unstable();
    let len = codes.len();
    codes.dedup();
    assert_eq!(codes.len(), len, "STRUCTURAL_ERROR_CODES must be unique");
    // Pins the catalogue size (41 structural validator codes).
    assert_eq!(STRUCTURAL_ERROR_CODES.len(), 41);
}

#[test]
fn verifier_codes_are_disjoint_from_structural() {
    let structural: std::collections::BTreeSet<&str> =
        STRUCTURAL_ERROR_CODES.iter().map(|c| c.code()).collect();
    for code in VERIFIER_ERROR_CODES {
        assert!(
            !structural.contains(code.code()),
            "{} must not be in both lists",
            code.code()
        );
    }
    assert_eq!(VERIFIER_ERROR_CODES.len(), 25);
}

#[test]
fn severity_classification_matches_reference() {
    assert_eq!(ErrorCode::SignatureUnsupported.severity(), Severity::Info);
    assert_eq!(ErrorCode::UriFetchFailed.severity(), Severity::Warning);
    assert_eq!(ErrorCode::MerkleUnsupported.severity(), Severity::Info);
    assert_eq!(ErrorCode::OutOfProfileSkipped.severity(), Severity::Info);
    assert_eq!(
        ErrorCode::MerkleLeavesUnavailable.severity(),
        Severity::Warning
    );
    // Spot-check a default-error code.
    assert_eq!(ErrorCode::MalformedCbor.severity(), Severity::Error);
}

// ---------------------------------------------------------------------------
// Chunking helpers
// ---------------------------------------------------------------------------

#[test]
fn chunk_bytes_splits_on_64_byte_boundaries() {
    assert_eq!(
        chunk_bytes(&[]).iter().map(Vec::len).collect::<Vec<_>>(),
        [0]
    );
    assert_eq!(
        chunk_bytes(&repeat_byte(64, 0))
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        [64]
    );
    assert_eq!(
        chunk_bytes(&repeat_byte(65, 0))
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        [64, 1]
    );
    assert_eq!(
        chunk_bytes(&repeat_byte(128, 0))
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        [64, 64]
    );
    assert_eq!(
        chunk_bytes(&repeat_byte(73, 0))
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        [64, 9]
    );
}

#[test]
fn bytes_chunk_array_concat_is_inverse_of_chunk_bytes() {
    let original: Vec<u8> = (0..200u32).map(|i| (i & 0xff) as u8).collect();
    let chunks = chunk_bytes(&original);
    assert_eq!(bytes_chunk_array_concat(&chunks), original);
    assert_eq!(bytes_chunk_array_concat(&[]), Vec::<u8>::new());
}

#[test]
fn reconstruct_chunked_uri_round_trips() {
    assert_eq!(
        reconstruct_chunked_uri(&["ar://abcdef".to_string()]),
        ReconstructUriResult::Ok("ar://abcdef".to_string())
    );
    assert_eq!(
        reconstruct_chunked_uri(&[
            "ipfs://bafybeigdyrz".to_string(),
            "t5cfsdpaomk2lq".to_string(),
            "mhs4vqkrqu2ad34yz4nawtfprz4".to_string(),
        ]),
        ReconstructUriResult::Ok(
            "ipfs://bafybeigdyrzt5cfsdpaomk2lqmhs4vqkrqu2ad34yz4nawtfprz4".to_string()
        )
    );
}

#[test]
fn chunk_uri_collapses_short_and_splits_on_codepoint_boundaries() {
    assert_eq!(chunk_uri("ar://abc"), vec!["ar://abc".to_string()]);

    // A >64-byte URI with a multibyte codepoint near the boundary must rejoin
    // to the original, with every chunk ≤ 64 bytes and no codepoint split.
    let long = format!("{}\u{1F600}{}", "a".repeat(63), "b".repeat(40));
    let chunks = chunk_uri(&long);
    assert_eq!(chunks.concat(), long);
    for c in &chunks {
        assert!(c.len() <= 64);
    }
}

#[test]
fn cid_profile_accepts_cidv0_rejects_base64() {
    assert!(is_valid_cid(
        "QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH"
    ));
    assert!(!is_valid_cid("mAYIKsomethingbase64"));
    assert!(!is_valid_cid(""));
}

#[test]
fn cid_profile_rejects_qm_shaped_string_with_wrong_decoded_multihash() {
    // A 46-char all-base58btc `Qm…` string that DOES base58-decode to 34 bytes
    // but whose multihash length byte is 0x1e (30), not 0x20 (32). A regex-only
    // CIDv0 check (`Qm` + 44 base58 chars) would wrongly accept it; the profile
    // requires the DECODED bytes to start `[0x12, 0x20, …]`.
    assert!(!is_valid_cid(
        "Qm1FMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH"
    ));
    // A different `Qm…` string whose decode does begin `[0x12, 0x20, …]` is
    // accepted — the discriminator is the decoded prefix, not the shape.
    assert!(is_valid_cid(
        "QmZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
    ));
}

#[test]
fn cidv0_negative_in_ipfs_uri_yields_invalid_uri() {
    // The wrong-decode `Qm1…` CID inside an `ipfs://` URI surfaces as INVALID_URI
    // through the structural validator, not silent acceptance.
    let uri = "ipfs://Qm1FMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH";
    let record = CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![
                (
                    CborValue::text("hashes"),
                    CborValue::Map(vec![(
                        CborValue::text("sha2-256"),
                        CborValue::Bytes(hash32(0xab)),
                    )]),
                ),
                (
                    CborValue::text("uris"),
                    CborValue::Array(vec![CborValue::Array(
                        chunk_uri(uri).into_iter().map(CborValue::Text).collect(),
                    )]),
                ),
            ])]),
        ),
    ]);
    assert_emits(
        &encode_canonical_cbor(&record).unwrap(),
        ErrorCode::InvalidUri,
    );
}

// ---------------------------------------------------------------------------
// Python-reference regex/decode parity (extension key, unauthenticated cipher,
// URI scheme dispatch). The oracle verdicts below were produced by running the
// Python SDK's classifiers on the same inputs; the hand-rolled Rust port must
// reproduce each one. These pin the boundaries where the published TypeScript
// and Python references currently diverge.
// ---------------------------------------------------------------------------

/// Build a record whose only non-base top-level key is `key`, with otherwise
/// valid `items`. The extension-key classifier decides the verdict: a key that
/// matches the extension namespace yields an `OUT_OF_PROFILE_SKIPPED` info on an
/// otherwise-passing record; a key that does not yields SCHEMA_UNKNOWN_FIELD.
fn record_with_top_level_key(key: &str) -> Vec<u8> {
    let record = CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (CborValue::text("items"), valid_items()),
        (CborValue::text(key), CborValue::text("x")),
    ]);
    encode_canonical_cbor(&record).unwrap()
}

#[test]
fn extension_key_classifier_matches_python_oracle() {
    // (input, is_extension_key) — the Python `^(x-.+|[a-z]+-.+)$` oracle, where
    // `.` excludes U+000A and `$` tolerates a single trailing newline.
    let oracle: &[(&str, bool)] = &[
        ("x-note", true),
        ("x-meta", true),
        ("x-a", true),
        ("x-", false),
        ("x-\n", false),
        ("x-a\nb", false),
        ("a-\n", false),
        ("a-b", true),
        ("abc-def", true),
        ("a-", false),
        ("a--b", true),
        ("x--b", true),
        ("X-note", false),
        ("foo", false),
        ("foo-", false),
        ("-foo", false),
        ("x", false),
        ("cip-25-extra", true),
        ("x-note\n", true),
        ("abc-def\n", true),
        ("a-b\nc", false),
        ("1-foo", false),
        ("x-\r", true),
        ("x-\rb", true),
        ("abc-\ndef", false),
        ("x-é", true),
        ("é-x", false),
        ("a-b-c", true),
        ("x-note\n\n", false),
    ];
    for &(key, is_ext) in oracle {
        let result = validate_poe_record(&record_with_top_level_key(key));
        if is_ext {
            assert!(
                result.is_ok() && result.codes().contains(&ErrorCode::OutOfProfileSkipped),
                "key {key:?} should be an extension key (OUT_OF_PROFILE_SKIPPED, record ok)",
            );
        } else {
            assert!(
                !result.is_ok() && result.codes().contains(&ErrorCode::SchemaUnknownField),
                "key {key:?} should NOT be an extension key (SCHEMA_UNKNOWN_FIELD)",
            );
        }
    }
}

/// Build a record whose single item's `enc.aead` is `aead`, with otherwise
/// valid passphrase-path envelope fields. An unauthenticated cipher surfaces as
/// UNAUTHENTICATED_CIPHER_FORBIDDEN; any other unknown aead as UNSUPPORTED_AEAD_ALG.
fn record_with_aead(aead: &str) -> Vec<u8> {
    record_with_enc(CborValue::Map(vec![
        (CborValue::text("scheme"), CborValue::Unsigned(1)),
        (CborValue::text("aead"), CborValue::text(aead)),
        (
            CborValue::text("nonce"),
            CborValue::Bytes(repeat_byte(24, 0)),
        ),
        (
            CborValue::text("passphrase"),
            argon2id_passphrase(65_536, 3, 1, 16),
        ),
    ]))
}

#[test]
fn unauthenticated_cipher_classifier_matches_python_oracle() {
    // (aead, is_unauthenticated) — the Python regex oracle, where the `$` in
    // `([-_]|$)` tolerates a single trailing newline (so `aes-256-cbc\n` is
    // forbidden) but not a trailing `\r` or an interior newline.
    let unauthenticated: &[&str] = &[
        "aes-256-cbc",
        "aes-cbc",
        "des-ede3-cbc",
        "aes-256-ctr",
        "aes-ecb",
        "aes-cfb",
        "aes-ofb",
        "rc4",
        "des",
        "3des",
        "aes-256-cbc\n",
        "cbc",
        "cbc\n",
        "rc4\n",
        "des\n",
        "3des\n",
        "aes_256_cbc",
        "AES-256-CBC",
        "des-x",
        "rc4-x",
    ];
    for &aead in unauthenticated {
        assert_emits(
            &record_with_aead(aead),
            ErrorCode::UnauthenticatedCipherForbidden,
        );
    }
    // Not unauthenticated: an interior newline, a trailing `\r`, an undelimited
    // token, or a real authenticated cipher. The known AEAD validates; the
    // unknown-but-not-unauthenticated ones surface as UNSUPPORTED_AEAD_ALG.
    let not_unauthenticated_unknown: &[&str] = &[
        "aes-256-cbc\nx",
        "\ncbc",
        "cbcx",
        "aes-256-cbc\r",
        "aescbc",
        "aes-256-gcm",
        "chacha20-poly1305",
    ];
    for &aead in not_unauthenticated_unknown {
        assert_emits(&record_with_aead(aead), ErrorCode::UnsupportedAeadAlg);
    }
    // The single registered AEAD is accepted (no aead-level issue).
    let result = validate_poe_record(&record_with_aead("xchacha20-poly1305"));
    let codes = result.codes();
    assert!(
        !codes.contains(&ErrorCode::UnauthenticatedCipherForbidden)
            && !codes.contains(&ErrorCode::UnsupportedAeadAlg),
        "xchacha20-poly1305 must not trip an aead classifier; got {:?}",
        codes.iter().map(|c| c.code()).collect::<Vec<_>>()
    );
}

/// Build a record whose single item carries one `uris` entry = `uri`.
fn record_with_uri(uri: &str) -> Vec<u8> {
    let record = CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![
                (
                    CborValue::text("hashes"),
                    CborValue::Map(vec![(
                        CborValue::text("sha2-256"),
                        CborValue::Bytes(hash32(0xab)),
                    )]),
                ),
                (
                    CborValue::text("uris"),
                    CborValue::Array(vec![CborValue::Array(
                        chunk_uri(uri).into_iter().map(CborValue::Text).collect(),
                    )]),
                ),
            ])]),
        ),
    ]);
    encode_canonical_cbor(&record).unwrap()
}

#[test]
fn uri_scheme_dispatch_matches_python_oracle() {
    let arweave = format!("ar://{}", "A".repeat(43));
    let ipfs = "ipfs://QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH";

    // A correctly-cased permitted scheme has its body checked: valid bodies pass.
    assert!(validate_poe_record(&record_with_uri(&arweave)).is_ok());
    assert!(validate_poe_record(&record_with_uri(ipfs)).is_ok());

    // A correctly-cased scheme with an invalid body is rejected (body checked).
    assert_emits(&record_with_uri("ar://tooshort"), ErrorCode::InvalidUri);

    // An UPPER- or mixed-case scheme is case-folded per RFC 3986 §3.1, then its
    // body IS validated. A valid body under an upper/mixed scheme passes; a
    // malformed body is rejected exactly as under the lower-cased scheme. Only
    // the scheme is folded — the txid/CID body keeps its case.
    let upper_ar = format!("AR://{}", "A".repeat(43));
    assert!(validate_poe_record(&record_with_uri(&upper_ar)).is_ok());
    let upper_ipfs = format!("IPFS://{ipfs_rest}", ipfs_rest = &ipfs["ipfs://".len()..]);
    assert!(validate_poe_record(&record_with_uri(&upper_ipfs)).is_ok());
    assert_emits(&record_with_uri("AR://short"), ErrorCode::InvalidUri);
    let mixed_ar = format!("Ar://{}", "A".repeat(43));
    assert!(validate_poe_record(&record_with_uri(&mixed_ar)).is_ok());

    // An unpermitted scheme (any casing) is rejected by the gate.
    assert_emits(
        &record_with_uri("http://example.com"),
        ErrorCode::InvalidUri,
    );
}

// ---------------------------------------------------------------------------
// Typed-encoder byte oracles. The expected canonical bytes were produced by the
// Python encoder on the equivalent record; the Rust encoder must reproduce them
// byte-for-byte. These cover the `enc`/slot shapes the frozen vector does not.
// ---------------------------------------------------------------------------

/// A 32-byte `sha2-256` digest of `0xab`, matching the Python oracle inputs.
fn oracle_hashes() -> Vec<(String, Vec<u8>)> {
    vec![("sha2-256".to_string(), repeat_byte(32, 0xab))]
}

/// Wrap one sealed item into a full single-item record.
fn sealed_record(enc: EncryptionEnvelope) -> PoeRecord {
    PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: oracle_hashes(),
            uris: None,
            enc: Some(enc),
        }]),
        ..PoeRecord::default()
    }
}

#[test]
fn encoder_classical_slot_matches_python_bytes() {
    let enc = EncryptionEnvelope {
        scheme: 1,
        aead: "xchacha20-poly1305".to_string(),
        nonce: repeat_byte(24, 0x05),
        kem: Some("x25519".to_string()),
        slots: Some(vec![Slot {
            epk: Some(repeat_byte(32, 0x01)),
            kem_ct: None,
            wrap: Some(repeat_byte(48, 0x09)),
        }]),
        slots_mac: Some(repeat_byte(32, 0x07)),
        passphrase: None,
    };
    let expected = "a2617601656974656d7381a263656e63a6636b656d667832353531396461656164727863686163686132302d706f6c7931333035656e6f6e6365581805050505050505050505050505050505050505050505050565736c6f747381a26365706b582001010101010101010101010101010101010101010101010101010101010101016477726170583009090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090966736368656d650169736c6f74735f6d61635820070707070707070707070707070707070707070707070707070707070707070766686173686573a168736861322d3235365820abababababababababababababababababababababababababababababababab";
    assert_eq!(
        hex::encode(&encode_poe_record(&sealed_record(enc)).unwrap()),
        expected,
        "classical {{epk, wrap}} slot must encode to the Python oracle bytes"
    );
}

#[test]
fn encoder_hybrid_slot_matches_python_bytes() {
    let enc = EncryptionEnvelope {
        scheme: 1,
        aead: "xchacha20-poly1305".to_string(),
        nonce: repeat_byte(24, 0x05),
        kem: Some("mlkem768x25519".to_string()),
        slots: Some(vec![Slot {
            epk: None,
            kem_ct: Some(chunk64(&repeat_byte(MLKEM768X25519_ENC_LENGTH, 0x11))),
            wrap: Some(repeat_byte(48, 0x09)),
        }]),
        slots_mac: Some(repeat_byte(32, 0x07)),
        passphrase: None,
    };
    let expected = "a2617601656974656d7381a263656e63a6636b656d6e6d6c6b656d3736387832353531396461656164727863686163686132302d706f6c7931333035656e6f6e6365581805050505050505050505050505050505050505050505050565736c6f747381a264777261705830090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909666b656d5f6374925840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111115820111111111111111111111111111111111111111111111111111111111111111166736368656d650169736c6f74735f6d61635820070707070707070707070707070707070707070707070707070707070707070766686173686573a168736861322d3235365820abababababababababababababababababababababababababababababababab";
    assert_eq!(
        hex::encode(&encode_poe_record(&sealed_record(enc)).unwrap()),
        expected,
        "hybrid {{kem_ct, wrap}} slot must encode to the Python oracle bytes"
    );
}

#[test]
fn encoder_both_set_slot_is_kem_driven_two_key_map() {
    // A Slot carrying BOTH `epk` and `kem_ct` must encode to the KEM-driven
    // 2-key `{kem_ct, wrap}` map (the `epk` is dropped). The expected bytes are
    // therefore IDENTICAL to the hybrid-slot oracle above — the encoder must not
    // emit a 3-key map.
    let both = EncryptionEnvelope {
        scheme: 1,
        aead: "xchacha20-poly1305".to_string(),
        nonce: repeat_byte(24, 0x05),
        kem: Some("mlkem768x25519".to_string()),
        slots: Some(vec![Slot {
            epk: Some(repeat_byte(32, 0x01)),
            kem_ct: Some(chunk64(&repeat_byte(MLKEM768X25519_ENC_LENGTH, 0x11))),
            wrap: Some(repeat_byte(48, 0x09)),
        }]),
        slots_mac: Some(repeat_byte(32, 0x07)),
        passphrase: None,
    };
    let hybrid = EncryptionEnvelope {
        scheme: 1,
        aead: "xchacha20-poly1305".to_string(),
        nonce: repeat_byte(24, 0x05),
        kem: Some("mlkem768x25519".to_string()),
        slots: Some(vec![Slot {
            epk: None,
            kem_ct: Some(chunk64(&repeat_byte(MLKEM768X25519_ENC_LENGTH, 0x11))),
            wrap: Some(repeat_byte(48, 0x09)),
        }]),
        slots_mac: Some(repeat_byte(32, 0x07)),
        passphrase: None,
    };
    assert_eq!(
        encode_poe_record(&sealed_record(both)).unwrap(),
        encode_poe_record(&sealed_record(hybrid)).unwrap(),
        "a both-set slot must encode identically to the {{kem_ct, wrap}} hybrid slot"
    );
    // And the both-set record still validates (the encoder produced a clean
    // 2-key map, not the 3-key map the validator would reject).
    assert!(validate_poe_record(
        &encode_poe_record(&sealed_record(EncryptionEnvelope {
            scheme: 1,
            aead: "xchacha20-poly1305".to_string(),
            nonce: repeat_byte(24, 0x05),
            kem: Some("mlkem768x25519".to_string()),
            slots: Some(vec![Slot {
                epk: Some(repeat_byte(32, 0x01)),
                kem_ct: Some(chunk64(&repeat_byte(MLKEM768X25519_ENC_LENGTH, 0x11))),
                wrap: Some(repeat_byte(48, 0x09)),
            }]),
            slots_mac: Some(repeat_byte(32, 0x07)),
            passphrase: None,
        }))
        .unwrap()
    )
    .is_ok());
}

#[test]
fn encoder_passphrase_block_matches_python_bytes() {
    let enc = EncryptionEnvelope {
        scheme: 1,
        aead: "xchacha20-poly1305".to_string(),
        nonce: repeat_byte(24, 0x05),
        kem: None,
        slots: None,
        slots_mac: None,
        passphrase: Some(PassphraseBlock {
            alg: "argon2id".to_string(),
            salt: repeat_byte(16, 0x02),
            params: vec![
                ("m".to_string(), 65_536),
                ("t".to_string(), 3),
                ("p".to_string(), 1),
            ],
        }),
    };
    let expected = "a2617601656974656d7381a263656e63a46461656164727863686163686132302d706f6c7931333035656e6f6e6365581805050505050505050505050505050505050505050505050566736368656d65016a70617373706872617365a363616c67686172676f6e3269646473616c74500202020202020202020202020202020266706172616d73a3616d1a0001000061700161740366686173686573a168736861322d3235365820abababababababababababababababababababababababababababababababab";
    assert_eq!(
        hex::encode(&encode_poe_record(&sealed_record(enc)).unwrap()),
        expected,
        "passphrase block must encode to the Python oracle bytes"
    );
}

// ---------------------------------------------------------------------------
// Cross-SDK shared KAT — validator-negative
// ---------------------------------------------------------------------------

/// Resolve a `SCREAMING_SNAKE_CASE` code string to its [`ErrorCode`], searching
/// both catalogue arrays. Panics on an unknown string, which surfaces a fixture
/// that names a code the Rust catalogue does not carry.
fn error_code_from_str(name: &str) -> ErrorCode {
    STRUCTURAL_ERROR_CODES
        .iter()
        .chain(VERIFIER_ERROR_CODES.iter())
        .copied()
        .find(|c| c.code() == name)
        .unwrap_or_else(|| panic!("fixture names an unregistered error code: {name}"))
}

#[test]
fn validator_negative_shared_kat() {
    // Each vector pins the exact set of ERROR-severity codes the structural
    // validator must emit; an empty set means the record is valid. Info/warning
    // issues are not part of the contract, so the comparison filters to errors.
    let corpus = common::read_fixture_json(
        &common::crypto_core_fixtures().join("poe-record/validator-negative.json"),
    );
    for v in corpus["vectors"].as_array().expect("vectors array") {
        let name = v["name"].as_str().expect("vector name");
        let bytes = hex::decode(v["cbor_hex"].as_str().expect("cbor_hex")).expect("valid hex");
        let expected: std::collections::BTreeSet<ErrorCode> = v["expected_error_codes"]
            .as_array()
            .expect("expected_error_codes")
            .iter()
            .map(|c| error_code_from_str(c.as_str().expect("code string")))
            .collect();

        let result = validate_poe_record(&bytes);
        let actual: std::collections::BTreeSet<ErrorCode> = match &result {
            ValidateResult::Fail { issues } => issues.iter().map(|i| i.code).collect(),
            ValidateResult::Ok { .. } => std::collections::BTreeSet::new(),
        };

        assert_eq!(
            result.is_ok(),
            expected.is_empty(),
            "{name}: validity verdict (expected codes {:?})",
            expected.iter().map(|c| c.code()).collect::<Vec<_>>()
        );
        assert_eq!(
            actual,
            expected,
            "{name}: emitted error codes {:?} != expected {:?}",
            actual.iter().map(|c| c.code()).collect::<Vec<_>>(),
            expected.iter().map(|c| c.code()).collect::<Vec<_>>()
        );
    }
}
