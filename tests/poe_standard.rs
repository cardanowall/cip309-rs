//! Label 309 wire-format parity tests.
//!
//! These tests pin the Rust encoder and structural validator against the same
//! vectors the TypeScript and Python SDKs replay:
//!
//! - the shared validator conformance corpus — rejection vectors (one pinned
//!   distinct error-code set per failure mode), resource-bound rejections,
//!   acceptance vectors with their exact info-code sets, and the role-dependent
//!   unknown-envelope dispositions, each validated under the vector's
//!   `validator_options`;
//! - the frozen maximal record vector (`cbor_hex` + `body_cbor_hex`) — the
//!   single most important record-level byte oracle;
//! - catalogue invariants for the error-code registry projection (entry order
//!   is the cross-implementation sort key) and the issue-path ordering rules.

mod common;

use std::collections::BTreeSet;

use cardanowall::cbor::{encode_canonical_cbor, CborValue};
use cardanowall::hex;
use cardanowall::poe_standard::{
    encode_poe_record, encode_record_body_for_signing, validate_poe_record, Argon2ParamsCeiling,
    EncScheme1, EncryptionEnvelope, ErrorCode, ItemEntry, MerkleCommit, PassphraseBlock,
    PathSegment, PoeRecord, Severity, SigEntry, Slot, ValidateResult, ValidatorOptions,
    ValidatorRole, CARRIAGE_ERROR_CODES, ERROR_CODES, STRUCTURAL_ERROR_CODES, VERIFIER_ERROR_CODES,
};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Conformance corpus replay
// ---------------------------------------------------------------------------

fn load_vectors(file: &str) -> Vec<Value> {
    let path = common::crypto_core_fixtures().join(file);
    let corpus = common::read_fixture_json(&path);
    corpus["vectors"]
        .as_array()
        .unwrap_or_else(|| panic!("{file} carries a vectors array"))
        .clone()
}

/// Project a vector's `validator_options` onto [`ValidatorOptions`]. Absent
/// fields keep the defaults; `passphraseParamsCeiling: null` disables the
/// ceiling.
fn fixture_options(vector: &Value) -> ValidatorOptions {
    let mut options = ValidatorOptions::default();
    let Some(raw) = vector.get("validator_options") else {
        return options;
    };
    if let Some(extensions) = raw
        .get("supportedCriticalExtensions")
        .and_then(Value::as_array)
    {
        options.supported_critical_extensions = extensions
            .iter()
            .map(|e| e.as_str().expect("extension name is a string").to_string())
            .collect();
    }
    if let Some(max_slots) = raw.get("maxSlots").and_then(Value::as_u64) {
        options.max_slots = usize::try_from(max_slots).expect("maxSlots fits usize");
    }
    if let Some(max_bytes) = raw.get("maxEncEnvelopeBytes").and_then(Value::as_u64) {
        options.max_enc_envelope_bytes =
            usize::try_from(max_bytes).expect("maxEncEnvelopeBytes fits usize");
    }
    if let Some(ceiling) = raw.get("passphraseParamsCeiling") {
        options.passphrase_params_ceiling = if ceiling.is_null() {
            None
        } else {
            Some(Argon2ParamsCeiling {
                m: ceiling["m"].as_u64().expect("ceiling m"),
                t: ceiling["t"].as_u64().expect("ceiling t"),
                p: ceiling["p"].as_u64().expect("ceiling p"),
            })
        };
    }
    options
}

fn expected_code_set(vector: &Value, field: &str) -> BTreeSet<String> {
    vector[field]
        .as_array()
        .map(|codes| {
            codes
                .iter()
                .map(|c| c.as_str().expect("code is a string").to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn code_strings(codes: &BTreeSet<ErrorCode>) -> BTreeSet<String> {
    codes.iter().map(|c| c.code().to_string()).collect()
}

/// Replay one negative/bounds corpus file: the distinct error-severity code
/// set must equal the vector's `expected_error_codes` exactly (an empty
/// expected set pins an accepted record).
fn replay_negative_corpus(file: &str) {
    for vector in load_vectors(file) {
        let name = vector["name"].as_str().expect("vector name");
        let bytes = hex::decode(vector["cbor_hex"].as_str().expect("cbor_hex")).expect("hex");
        let options = fixture_options(&vector);
        let result = validate_poe_record(&bytes, &options);
        let expected = expected_code_set(&vector, "expected_error_codes");
        if expected.is_empty() {
            assert!(result.is_ok(), "{file}/{name}: expected acceptance");
            continue;
        }
        assert!(!result.is_ok(), "{file}/{name}: expected rejection");
        assert_eq!(
            code_strings(&result.error_codes()),
            expected,
            "{file}/{name}: distinct error-code set mismatch"
        );
    }
}

#[test]
fn validator_negative_corpus_replays() {
    replay_negative_corpus("validator/validator-negative.json");
}

#[test]
fn validator_bounds_negative_corpus_replays() {
    replay_negative_corpus("validator/validator-bounds-negative.json");
}

#[test]
fn validator_positive_corpus_replays() {
    for vector in load_vectors("validator/validator-positive.json") {
        let name = vector["name"].as_str().expect("vector name");
        let bytes = hex::decode(vector["cbor_hex"].as_str().expect("cbor_hex")).expect("hex");
        assert!(
            expected_code_set(&vector, "expected_error_codes").is_empty(),
            "{name}: a positive vector pins an empty error set"
        );
        let result = validate_poe_record(&bytes, &ValidatorOptions::default());
        let ValidateResult::Ok { warnings, info, .. } = result else {
            panic!("{name}: expected acceptance, got {result:?}");
        };
        let expected_info = expected_code_set(&vector, "expected_info_codes");
        let actual_info: BTreeSet<String> =
            info.iter().map(|i| i.code.code().to_string()).collect();
        assert_eq!(actual_info, expected_info, "{name}: info-code set mismatch");
        assert!(warnings.is_empty(), "{name}: unexpected warnings");
    }
}

#[test]
fn enc_unsupported_roles_corpus_replays_both_readings() {
    for vector in load_vectors("validator/enc-unsupported-roles.json") {
        let name = vector["name"].as_str().expect("vector name");
        let bytes = hex::decode(vector["cbor_hex"].as_str().expect("cbor_hex")).expect("hex");
        for (role_name, role) in [
            ("public", ValidatorRole::Public),
            ("recipient_or_strict", ValidatorRole::RecipientOrStrict),
        ] {
            let expectation = &vector["expected_by_role"][role_name];
            let options = ValidatorOptions {
                role,
                ..ValidatorOptions::default()
            };
            let result = validate_poe_record(&bytes, &options);
            assert_eq!(
                result.is_ok(),
                expectation["valid"].as_bool().expect("valid flag"),
                "{name} ({role_name}): verdict mismatch"
            );
            let expected_errors: BTreeSet<String> = expectation["error_codes"]
                .as_array()
                .expect("error_codes")
                .iter()
                .map(|c| c.as_str().expect("code").to_string())
                .collect();
            let expected_info: BTreeSet<String> = expectation["info_codes"]
                .as_array()
                .expect("info_codes")
                .iter()
                .map(|c| c.as_str().expect("code").to_string())
                .collect();
            assert_eq!(
                code_strings(&result.error_codes()),
                expected_errors,
                "{name} ({role_name}): error-code set mismatch"
            );
            assert_eq!(
                code_strings(&result.info_codes()),
                expected_info,
                "{name} ({role_name}): info-code set mismatch"
            );
        }
    }
}

#[test]
fn role_default_is_public() {
    let vectors = load_vectors("validator/enc-unsupported-roles.json");
    let vector = &vectors[0];
    let bytes = hex::decode(vector["cbor_hex"].as_str().expect("cbor_hex")).expect("hex");
    let result = validate_poe_record(&bytes, &ValidatorOptions::default());
    assert_eq!(
        result.is_ok(),
        vector["expected_by_role"]["public"]["valid"]
            .as_bool()
            .expect("valid flag")
    );
}

// ---------------------------------------------------------------------------
// Frozen record vector (the record-level byte oracle)
// ---------------------------------------------------------------------------

/// Reconstruct the typed `PoeRecord` from the fixture JSON: `_hex` fields
/// decode to bytes, `uris` are plain strings, `cose_sign1_hex` is a single hex
/// string, and every top-level key the reconstructor does not consume is a
/// verbatim extension key.
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
                    cose_sign1: hex::decode(s["cose_sign1_hex"].as_str().unwrap()).unwrap(),
                    cose_key: s
                        .get("cose_key_hex")
                        .and_then(Value::as_str)
                        .map(|k| hex::decode(k).unwrap()),
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
            .map(|u| u.as_str().unwrap().to_string())
            .collect()
    });
    let enc = item.get("enc").map(|enc| {
        let slots = enc.get("slots").and_then(Value::as_array).map(|slots| {
            slots
                .iter()
                .map(|s| Slot {
                    epk: s
                        .get("epk_hex")
                        .and_then(Value::as_str)
                        .map(|h| hex::decode(h).unwrap()),
                    kem_ct: s
                        .get("kem_ct_hex")
                        .and_then(Value::as_str)
                        .map(|h| hex::decode(h).unwrap()),
                    wrap: Some(hex::decode(s["wrap_hex"].as_str().unwrap()).unwrap()),
                })
                .collect()
        });
        EncryptionEnvelope::Scheme1(EncScheme1 {
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
        })
    });
    ItemEntry { hashes, uris, enc }
}

/// Convert a JSON value into a `CborValue` for an extension key. JSON integers
/// become unsigned/negative ints, strings become text, objects become maps,
/// arrays become arrays. The fixture's extension keys are `x-note` (string)
/// and `x-meta` ({a:1, bb:2}).
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

    // The vector validates clean only under the fixture's validator options
    // (the record carries `crit: ["x-note"]`); a default-configured validator
    // rejects it with EXTENSION_UNSUPPORTED_CRITICAL — by design.
    let result = validate_poe_record(&full, &fixture_options(&fixture));
    assert!(
        result.is_ok(),
        "the frozen vector validates under its pinned options: {result:?}"
    );

    let default_result = validate_poe_record(&full, &ValidatorOptions::default());
    assert!(!default_result.is_ok());
    assert!(default_result
        .error_codes()
        .contains(&ErrorCode::ExtensionUnsupportedCritical));

    // Extension keys are the load-bearing case: assert the vector still pins
    // them so a future fixture edit cannot silently stop testing the path.
    assert!(record.extensions.iter().any(|(k, _)| k == "x-note"));
    assert!(record.extensions.iter().any(|(k, _)| k == "x-meta"));

    // The accepted record re-encodes to the same bytes (the round-trip
    // property over the decoded record).
    let ValidateResult::Ok {
        record: decoded, ..
    } = validate_poe_record(&full, &fixture_options(&fixture))
    else {
        unreachable!();
    };
    assert_eq!(encode_poe_record(&decoded).unwrap(), full);
}

// ---------------------------------------------------------------------------
// Encoder round-trips (positive corpus over the typed builder)
// ---------------------------------------------------------------------------

fn hash32(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn repeat_byte(len: usize, byte: u8) -> Vec<u8> {
    vec![byte; len]
}

const AEAD_ID: &str = "chacha20-poly1305-stream64k";

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
                    uris: Some(vec![format!("ar://{}", "A".repeat(43))]),
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
                    hashes: vec![("sha2-256".to_string(), hash32(0xab))],
                    uris: None,
                    enc: Some(EncryptionEnvelope::Scheme1(EncScheme1 {
                        scheme: 1,
                        aead: AEAD_ID.to_string(),
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
                    })),
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
                    uris: Some(vec![
                        "ipfs://QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH".to_string(),
                    ]),
                    enc: Some(EncryptionEnvelope::Scheme1(EncScheme1 {
                        scheme: 1,
                        aead: AEAD_ID.to_string(),
                        nonce: repeat_byte(24, 0),
                        kem: Some("mlkem768x25519".to_string()),
                        slots: Some(vec![Slot {
                            epk: None,
                            kem_ct: Some(repeat_byte(1120, 0x11)),
                            wrap: Some(repeat_byte(48, 0x02)),
                        }]),
                        slots_mac: Some(repeat_byte(32, 0x07)),
                        passphrase: None,
                    })),
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
                    enc: Some(EncryptionEnvelope::Scheme1(EncScheme1 {
                        scheme: 1,
                        aead: AEAD_ID.to_string(),
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
                    })),
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
        let result = validate_poe_record(&encoded, &ValidatorOptions::default());
        let ValidateResult::Ok {
            record: decoded, ..
        } = result
        else {
            panic!("{name} should validate: {result:?}");
        };
        // validate(encode(R)).record re-encodes to the same bytes.
        let reencoded = encode_poe_record(&decoded).unwrap();
        assert_eq!(reencoded, encoded, "{name} must round-trip byte-exactly");
    }
}

#[test]
fn opaque_envelope_round_trips_verbatim() {
    // An envelope under an unsupported kem degrades to the opaque reading in
    // the public role: the record is accepted (ENC_UNSUPPORTED info) and the
    // decoded record preserves the envelope verbatim, so re-encoding
    // reproduces the original bytes (a signed body would re-verify).
    let record = CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![
                (
                    CborValue::text("enc"),
                    CborValue::Map(vec![
                        (CborValue::text("future"), CborValue::Bytes(vec![0x01; 8])),
                        (CborValue::text("scheme"), CborValue::Unsigned(2)),
                    ]),
                ),
                (
                    CborValue::text("hashes"),
                    CborValue::Map(vec![(
                        CborValue::text("sha2-256"),
                        CborValue::Bytes(hash32(0xab)),
                    )]),
                ),
            ])]),
        ),
    ]);
    let bytes = encode_canonical_cbor(&record).unwrap();
    let result = validate_poe_record(&bytes, &ValidatorOptions::default());
    let ValidateResult::Ok {
        record: decoded,
        info,
        ..
    } = result
    else {
        panic!("opaque envelope must be accepted in the public role: {result:?}");
    };
    assert!(info.iter().any(|i| i.code == ErrorCode::EncUnsupported));
    let item = &decoded.items.as_ref().unwrap()[0];
    assert!(matches!(item.enc, Some(EncryptionEnvelope::Opaque(_))));
    assert_eq!(encode_poe_record(&decoded).unwrap(), bytes);
}

#[test]
fn passphrase_ceiling_none_disables_the_policy_check() {
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), hash32(0xab))],
            uris: None,
            enc: Some(EncryptionEnvelope::Scheme1(EncScheme1 {
                scheme: 1,
                aead: AEAD_ID.to_string(),
                nonce: repeat_byte(24, 0),
                kem: None,
                slots: None,
                slots_mac: None,
                passphrase: Some(PassphraseBlock {
                    alg: "argon2id".to_string(),
                    salt: repeat_byte(16, 0),
                    // Above the default ceiling {m: 2097152, t: 16, p: 8} but
                    // inside the wire range.
                    params: vec![
                        ("m".to_string(), 4_194_304),
                        ("t".to_string(), 32),
                        ("p".to_string(), 16),
                    ],
                }),
            })),
        }]),
        ..PoeRecord::default()
    };
    let bytes = encode_poe_record(&record).unwrap();

    // Default options: the ceiling is enforced.
    let default_result = validate_poe_record(&bytes, &ValidatorOptions::default());
    assert!(default_result
        .error_codes()
        .contains(&ErrorCode::EncPassphraseParamsExceedPolicy));

    // Ceiling disabled: the same record passes.
    let no_ceiling = ValidatorOptions {
        passphrase_params_ceiling: None,
        ..ValidatorOptions::default()
    };
    assert!(validate_poe_record(&bytes, &no_ceiling).is_ok());
}

// ---------------------------------------------------------------------------
// Issue paths and deterministic ordering
// ---------------------------------------------------------------------------

fn key(s: &str) -> PathSegment {
    PathSegment::Key(s.to_string())
}

#[test]
fn issue_paths_land_on_the_offending_entry() {
    // One record, three defects at distinct paths: an unregistered hash alg
    // inside items[0], a leaf_count of zero inside merkle[0], and a stray
    // top-level key. The sorted issue list pins both the per-issue path and
    // the segment-wise order (integer segments before text segments, text by
    // UTF-8 bytes, prefix first).
    let record = CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![(
                CborValue::text("hashes"),
                CborValue::Map(vec![
                    (CborValue::text("md5"), CborValue::Bytes(vec![0u8; 16])),
                    (CborValue::text("sha2-256"), CborValue::Bytes(hash32(0xab))),
                ]),
            )])]),
        ),
        (
            CborValue::text("merkle"),
            CborValue::Array(vec![CborValue::Map(vec![
                (CborValue::text("alg"), CborValue::text("rfc9162-sha256")),
                (CborValue::text("leaf_count"), CborValue::Unsigned(0)),
                (CborValue::text("root"), CborValue::Bytes(hash32(0x77))),
            ])]),
        ),
        (
            CborValue::text("zz-typo"),
            CborValue::Unsigned(1), // "zz-typo" matches the companion namespace…
        ),
        (
            CborValue::text("ZZTYPO"),
            CborValue::Unsigned(1), // …but an uppercase key does not.
        ),
    ]);
    let bytes = encode_canonical_cbor(&record).unwrap();
    let ValidateResult::Fail { issues } = validate_poe_record(&bytes, &ValidatorOptions::default())
    else {
        panic!("expected rejection");
    };
    let flat: Vec<(Vec<PathSegment>, ErrorCode)> =
        issues.iter().map(|i| (i.path.clone(), i.code)).collect();
    assert_eq!(
        flat,
        vec![
            (vec![key("ZZTYPO")], ErrorCode::SchemaUnknownField),
            (
                vec![
                    key("items"),
                    PathSegment::Index(0),
                    key("hashes"),
                    key("md5")
                ],
                ErrorCode::UnsupportedHashAlg
            ),
            (
                vec![key("merkle"), PathSegment::Index(0), key("leaf_count")],
                ErrorCode::SchemaMerkleLeafCountInvalid
            ),
        ]
    );
}

#[test]
fn same_path_issues_tie_break_by_registry_order() {
    // slots_mac present without slots co-fires ENC_SLOTS_REQUIRED and
    // ENC_NO_KEY_PATH at the same `enc` path; the registry order pins
    // ENC_SLOTS_REQUIRED first.
    let record = CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![
                (
                    CborValue::text("enc"),
                    CborValue::Map(vec![
                        (CborValue::text("aead"), CborValue::text(AEAD_ID)),
                        (
                            CborValue::text("nonce"),
                            CborValue::Bytes(repeat_byte(24, 0x44)),
                        ),
                        (CborValue::text("scheme"), CborValue::Unsigned(1)),
                        (
                            CborValue::text("slots_mac"),
                            CborValue::Bytes(repeat_byte(32, 0xaa)),
                        ),
                    ]),
                ),
                (
                    CborValue::text("hashes"),
                    CborValue::Map(vec![(
                        CborValue::text("sha2-256"),
                        CborValue::Bytes(hash32(0xab)),
                    )]),
                ),
            ])]),
        ),
    ]);
    let bytes = encode_canonical_cbor(&record).unwrap();
    let ValidateResult::Fail { issues } = validate_poe_record(&bytes, &ValidatorOptions::default())
    else {
        panic!("expected rejection");
    };
    let codes: Vec<ErrorCode> = issues.iter().map(|i| i.code).collect();
    assert_eq!(
        codes,
        vec![ErrorCode::EncSlotsRequired, ErrorCode::EncNoKeyPath]
    );
    let enc_path = vec![key("items"), PathSegment::Index(0), key("enc")];
    assert!(issues.iter().all(|i| i.path == enc_path));
}

#[test]
fn failed_records_carry_info_issues_alongside_errors() {
    // A failing record with an info-severity disposition keeps the info issue
    // in the failure list — the per-severity views are projections of one
    // collected set, not separate channels.
    let record = CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![
                (
                    CborValue::text("enc"),
                    CborValue::Map(vec![(CborValue::text("scheme"), CborValue::Unsigned(2))]),
                ),
                (
                    CborValue::text("hashes"),
                    CborValue::Map(vec![(
                        CborValue::text("md5"),
                        CborValue::Bytes(vec![0u8; 16]),
                    )]),
                ),
            ])]),
        ),
    ]);
    let bytes = encode_canonical_cbor(&record).unwrap();
    let result = validate_poe_record(&bytes, &ValidatorOptions::default());
    assert!(!result.is_ok());
    let errors = code_strings(&result.error_codes());
    let info = code_strings(&result.info_codes());
    assert_eq!(
        errors,
        ["ENC_REQUIRES_CONTENT_HASH", "UNSUPPORTED_HASH_ALG"]
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        info,
        ["ENC_UNSUPPORTED"]
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>()
    );
}

// ---------------------------------------------------------------------------
// Error-code catalogue invariants
// ---------------------------------------------------------------------------

#[test]
fn catalogue_is_unique_and_indexed_in_registry_order() {
    let mut seen = BTreeSet::new();
    for (i, code) in ERROR_CODES.iter().enumerate() {
        assert!(seen.insert(code.code()), "duplicate code {}", code.code());
        assert_eq!(code.registry_index(), i);
        // SCREAMING_SNAKE_CASE.
        assert!(code
            .code()
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'));
    }
}

#[test]
fn per_layer_views_partition_the_catalogue_in_registry_order() {
    let union: Vec<ErrorCode> = STRUCTURAL_ERROR_CODES
        .iter()
        .chain(CARRIAGE_ERROR_CODES)
        .chain(VERIFIER_ERROR_CODES)
        .copied()
        .collect();
    assert_eq!(union.len(), ERROR_CODES.len());
    assert_eq!(
        union.iter().copied().collect::<BTreeSet<_>>().len(),
        ERROR_CODES.len()
    );
    for view in [
        STRUCTURAL_ERROR_CODES,
        CARRIAGE_ERROR_CODES,
        VERIFIER_ERROR_CODES,
    ] {
        let indices: Vec<usize> = view.iter().map(|c| c.registry_index()).collect();
        let mut sorted = indices.clone();
        sorted.sort_unstable();
        assert_eq!(indices, sorted, "view must preserve registry order");
    }
    // Each view's membership matches the per-code part projection.
    for code in ERROR_CODES {
        let in_structural = STRUCTURAL_ERROR_CODES.contains(code);
        let in_carriage = CARRIAGE_ERROR_CODES.contains(code);
        let in_verifier = VERIFIER_ERROR_CODES.contains(code);
        match code.part() {
            cardanowall::poe_standard::ErrorCodePart::A => assert!(in_structural),
            cardanowall::poe_standard::ErrorCodePart::Carriage => assert!(in_carriage),
            cardanowall::poe_standard::ErrorCodePart::B => assert!(in_verifier),
        }
    }
}

#[test]
fn severity_defaults_match_the_registry() {
    use ErrorCode::{
        EncUnsupported, InsufficientConfirmations, MerkleLeavesUnavailable, MerkleUnsupported,
        OutOfProfileSkipped, SignatureUnsupported, UriFetchFailed, UriProviderIntegrityMismatch,
    };
    for code in ERROR_CODES {
        let expected = match code {
            EncUnsupported
            | SignatureUnsupported
            | InsufficientConfirmations
            | MerkleUnsupported
            | OutOfProfileSkipped => Severity::Info,
            UriProviderIntegrityMismatch | UriFetchFailed | MerkleLeavesUnavailable => {
                Severity::Warning
            }
            _ => Severity::Error,
        };
        assert_eq!(code.severity(), expected, "{}", code.code());
    }
    // The dual-severity set.
    let dual: Vec<&ErrorCode> = ERROR_CODES
        .iter()
        .filter(|c| c.is_dual_severity())
        .collect();
    assert_eq!(
        dual.iter().map(|c| c.code()).collect::<Vec<_>>(),
        vec![
            "ENC_UNSUPPORTED",
            "MERKLE_LEAVES_UNAVAILABLE",
            "MERKLE_UNSUPPORTED",
            "OUT_OF_PROFILE_SKIPPED",
        ]
    );
}
