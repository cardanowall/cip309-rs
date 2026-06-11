//! Conformance replays for the verifier's carriage and Cardano-semantics
//! layers, plus the report-shape invariants of the published verify-report
//! JSON Schema.
//!
//! - `carriage/chunk-array-{positive,negative}.json` pin the label-309
//!   whole-body chunk-array reassembly and the carriage-error taxonomy.
//! - `carriage/aux-data-envelope-forms.json` pins the three Conway-era
//!   auxiliary-data envelope forms and the type/tag-only dispatch rule.
//! - `cardano/tx-binding.json` pins the transaction-reference integrity
//!   binding (body hash + `auxiliary_data_hash`, over the bytes as fetched).
//! - `cardano/confirmation-depth.json` pins `depth = tip − block + 1` and the
//!   threshold boundary, replayed through the full `verify_tx` pipeline.

mod common;

use cardanowall::cbor::{encode_canonical_cbor, CborValue};
use cardanowall::hash::blake2b256;
use cardanowall::poe_standard::{
    encode_poe_record, validate_poe_record, ItemEntry, PoeRecord, ValidatorOptions,
};
use cardanowall::verifier::fetch::{
    FetchOutboundOptions, FetchOutboundResult, FetchTransport, OutboundError,
};
use cardanowall::verifier::{
    bind_transaction, reassemble_label_309_value, unwrap_auxiliary_data, verify_report_to_dict,
    verify_tx, Verdict, VerifyTxInput,
};
use serde_json::Value;

fn carriage_fixture(name: &str) -> Value {
    common::read_fixture_json(&common::crypto_core_fixtures().join("carriage").join(name))
}

fn cardano_fixture(name: &str) -> Value {
    common::read_fixture_json(&common::label309_conformance().join("cardano").join(name))
}

fn vectors(fixture: &Value) -> &Vec<Value> {
    fixture["vectors"].as_array().expect("vectors is an array")
}

fn hex_field(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap_or_else(|| panic!("{key} is hex")))
        .unwrap_or_else(|e| panic!("{key} decodes: {e}"))
}

// ---------------------------------------------------------------------------
// carriage/chunk-array-{positive,negative}.json
// ---------------------------------------------------------------------------

#[test]
fn chunk_array_positive_vectors_reassemble() {
    let fixture = carriage_fixture("chunk-array-positive.json");
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let value = hex_field(v, "label_309_value_cbor_hex");
        let expected = hex_field(v, "expected_record_body_hex");
        let body = reassemble_label_309_value(&value)
            .unwrap_or_else(|e| panic!("vector {name} must reassemble: {e}"));
        assert_eq!(body, expected, "vector {name}: reassembled body mismatch");
    }
}

#[test]
fn chunk_array_negative_vectors_carry_pinned_codes() {
    let fixture = carriage_fixture("chunk-array-negative.json");
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let value = hex_field(v, "label_309_value_cbor_hex");
        let expected_code = v["expected_error_code"].as_str().unwrap();
        match reassemble_label_309_value(&value) {
            Err(err) => assert_eq!(
                err.code.code(),
                expected_code,
                "vector {name}: carriage code mismatch"
            ),
            Ok(body) => {
                // The empty-concatenation cases are tolerated at the transport
                // layer (chunk boundaries are semantics-free, including
                // degenerate ones); the pinned code then surfaces from the
                // record-body decode, not from reassembly.
                assert!(
                    body.is_empty(),
                    "vector {name}: only an empty concatenation may pass the transport layer"
                );
                let result = validate_poe_record(&body, &ValidatorOptions::default());
                assert!(
                    result
                        .error_codes()
                        .iter()
                        .any(|c| c.code() == expected_code),
                    "vector {name}: the record-body decode must surface {expected_code}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// carriage/aux-data-envelope-forms.json
// ---------------------------------------------------------------------------

#[test]
fn aux_data_envelope_forms_unwrap_per_fixture() {
    let fixture = carriage_fixture("aux-data-envelope-forms.json");
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let aux = hex_field(v, "auxiliary_data_cbor_hex");
        let expected = &v["expected"];

        match expected.get("error_code").and_then(Value::as_str) {
            Some("MALFORMED_CBOR") => {
                let err =
                    unwrap_auxiliary_data(&aux).expect_err(&format!("vector {name} must reject"));
                assert_eq!(err.code.code(), "MALFORMED_CBOR", "vector {name}");
            }
            Some("METADATA_NOT_FOUND") => {
                // METADATA_NOT_FOUND is the verifier-layer outcome for
                // well-formed auxiliary data with no label-309 entry: the
                // unwrap itself succeeds and reports no label-309 value.
                let unwrapped = unwrap_auxiliary_data(&aux)
                    .unwrap_or_else(|e| panic!("vector {name} must unwrap: {e}"));
                assert!(
                    unwrapped.label_309_value.is_none(),
                    "vector {name}: no label-309 value may be found"
                );
            }
            Some(other) => panic!("vector {name}: unexpected expected code {other}"),
            None => {
                let unwrapped = unwrap_auxiliary_data(&aux)
                    .unwrap_or_else(|e| panic!("vector {name} must unwrap: {e}"));
                let value = unwrapped
                    .label_309_value
                    .unwrap_or_else(|| panic!("vector {name} must carry label 309"));
                assert_eq!(
                    value,
                    hex_field(expected, "label_309_value_cbor_hex"),
                    "vector {name}: label-309 value mismatch"
                );
                let body = reassemble_label_309_value(&value)
                    .unwrap_or_else(|e| panic!("vector {name} must reassemble: {e}"));
                assert_eq!(
                    body,
                    hex_field(expected, "record_body_hex"),
                    "vector {name}: record body mismatch"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// cardano/tx-binding.json
// ---------------------------------------------------------------------------

#[test]
fn tx_binding_vectors_pin_the_integrity_binding() {
    let fixture = cardano_fixture("tx-binding.json");
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let requested = hex_field(v, "requested_tx_hash_hex");
        let body = hex_field(v, "transaction_body_cbor_hex");
        let aux = hex_field(v, "auxiliary_data_cbor_hex");
        let expected = &v["expected"];
        let expect_ok = expected["ok"].as_bool().unwrap();

        let binding = bind_transaction(&requested, &body, Some(&aux));
        if !expect_ok {
            match expected["error_code"].as_str().unwrap() {
                "TX_INTEGRITY_MISMATCH" => {
                    assert!(binding.is_err(), "vector {name}: binding must fail");
                    continue;
                }
                "METADATA_NOT_FOUND" => {
                    // Both bindings hold; the bound transaction simply carries
                    // no label 309.
                    binding.unwrap_or_else(|e| panic!("vector {name} must bind: {e}"));
                    let unwrapped = unwrap_auxiliary_data(&aux)
                        .unwrap_or_else(|e| panic!("vector {name} must unwrap: {e}"));
                    assert!(
                        unwrapped.label_309_value.is_none(),
                        "vector {name}: no label-309 value may be found"
                    );
                    continue;
                }
                other => panic!("vector {name}: unexpected expected code {other}"),
            }
        }

        binding.unwrap_or_else(|e| panic!("vector {name} must bind: {e}"));
        assert_eq!(
            hex::encode(blake2b256(&body)),
            expected["computed_tx_hash_hex"].as_str().unwrap(),
            "vector {name}: body hash"
        );
        assert_eq!(
            hex::encode(blake2b256(&aux)),
            expected["computed_auxiliary_data_hash_hex"]
                .as_str()
                .unwrap(),
            "vector {name}: auxiliary-data hash"
        );
        let unwrapped = unwrap_auxiliary_data(&aux).unwrap();
        let value = unwrapped.label_309_value.expect("label-309 value present");
        let record_body = reassemble_label_309_value(&value).unwrap();
        assert_eq!(
            record_body,
            hex_field(expected, "record_body_hex"),
            "vector {name}: record body"
        );
    }
}

// ---------------------------------------------------------------------------
// cardano/confirmation-depth.json — replayed through the full pipeline
// ---------------------------------------------------------------------------

/// A koios transport whose `tx_info` carries only `block_height`, so the
/// verifier derives depth from the `/tip` endpoint: depth = tip − block + 1.
struct HeightsTransport {
    tx_cbor: Vec<u8>,
    tx_info: Vec<u8>,
    tip: Vec<u8>,
}

impl FetchTransport for HeightsTransport {
    fn fetch(
        &self,
        url: &str,
        _opts: &FetchOutboundOptions,
    ) -> Result<FetchOutboundResult, OutboundError> {
        let bytes = if url.ends_with("/tx_cbor") {
            self.tx_cbor.clone()
        } else if url.ends_with("/tx_info") {
            self.tx_info.clone()
        } else if url.ends_with("/tip") {
            self.tip.clone()
        } else {
            return Err(OutboundError::Transport {
                url: url.to_string(),
                message: "unexpected url".to_string(),
            });
        };
        Ok(FetchOutboundResult {
            status: 200,
            bytes,
            duration_ms: 1,
        })
    }
}

/// Build a fully bound transaction around a minimal hash-only record.
fn bound_core_tx() -> (String, String) {
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![0x11u8; 32])],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let record_body = encode_poe_record(&record).unwrap();
    let chunks = CborValue::Array(
        record_body
            .chunks(64)
            .map(|c| CborValue::Bytes(c.to_vec()))
            .collect(),
    );
    let aux = CborValue::Map(vec![(CborValue::Unsigned(309), chunks)]);
    let aux_bytes = encode_canonical_cbor(&aux).unwrap();
    let body = CborValue::Map(vec![(
        CborValue::Unsigned(7),
        CborValue::Bytes(blake2b256(&aux_bytes).to_vec()),
    )]);
    let body_bytes = encode_canonical_cbor(&body).unwrap();
    let tx_hash = hex::encode(blake2b256(&body_bytes));
    let mut tx: Vec<u8> = vec![0x84];
    tx.extend_from_slice(&body_bytes);
    tx.push(0xa0);
    tx.push(0xf5);
    tx.extend_from_slice(&aux_bytes);
    (tx_hash, hex::encode(tx))
}

#[test]
fn confirmation_depth_vectors_replay_through_the_pipeline() {
    let fixture = cardano_fixture("confirmation-depth.json");
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty());
    let (tx_hash, tx_cbor_hex) = bound_core_tx();

    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let tip_height = v["tip_height"].as_u64().unwrap();
        let block_height = v["block_height"].as_u64().unwrap();
        let threshold = u32::try_from(v["threshold"].as_u64().unwrap()).unwrap();
        let expected_depth = v["expected_depth"].as_u64().unwrap();
        let expected_status = v["expected"]["status"].as_str().unwrap();

        let transport = HeightsTransport {
            tx_cbor: serde_json::to_vec(
                &serde_json::json!([{"tx_hash": tx_hash, "cbor": tx_cbor_hex}]),
            )
            .unwrap(),
            tx_info: serde_json::to_vec(&serde_json::json!([{
                "tx_hash": tx_hash,
                "block_height": block_height,
                "tx_timestamp": 1_700_000_000,
                "absolute_slot": 100_000_000,
            }]))
            .unwrap(),
            tip: serde_json::to_vec(&serde_json::json!([{"block_height": tip_height}])).unwrap(),
        };

        let mut input = VerifyTxInput::new(&tx_hash);
        input.cardano_gateway_chain = Some(vec!["https://api.koios.rest/api/v1".to_string()]);
        input.confirmation_depth_threshold = Some(threshold);
        input.fetch_outbound = Some(&transport);

        let report = verify_tx(&input);
        assert_eq!(
            report.confirmation_depth,
            Some(u32::try_from(expected_depth).unwrap()),
            "vector {name}: depth"
        );
        match expected_status {
            "pending" => {
                assert_eq!(report.verdict, Verdict::Pending, "vector {name}");
                assert_eq!(report.verdict.exit_code(), 3, "vector {name}");
                assert_eq!(
                    v["expected"]["code"].as_str().unwrap(),
                    "INSUFFICIENT_CONFIRMATIONS"
                );
                assert!(
                    report
                        .issues
                        .iter()
                        .any(|i| i.code.code() == "INSUFFICIENT_CONFIRMATIONS"),
                    "vector {name}: pending must carry INSUFFICIENT_CONFIRMATIONS"
                );
            }
            "confirmed" => {
                assert_eq!(report.verdict, Verdict::Valid, "vector {name}");
                assert_eq!(report.verdict.exit_code(), 0, "vector {name}");
            }
            other => panic!("vector {name}: unexpected status {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// verify-report schema invariants
// ---------------------------------------------------------------------------

/// Assert one serialised report against the load-bearing invariants of the
/// published verify-report JSON Schema: the required key set, the verdict /
/// exit-code pairing, the per-claim and audit entry shapes, and the
/// severity contract.
fn assert_report_schema_invariants(dict: &Value) {
    let obj = dict.as_object().expect("report is an object");
    for key in [
        "verdict",
        "exitCode",
        "issues",
        "items",
        "merkle",
        "auditTrail",
    ] {
        assert!(obj.contains_key(key), "schema-required key {key} missing");
    }

    let verdict = obj["verdict"].as_str().expect("verdict is a string");
    let exit_code = obj["exitCode"].as_u64().expect("exitCode is an integer");
    let expected_exit = match verdict {
        "valid" => 0,
        "failed" => 1,
        "unverifiable" => 2,
        "pending" => 3,
        other => panic!("verdict {other} outside the schema enum"),
    };
    assert_eq!(exit_code, expected_exit, "verdict/exitCode pairing");

    // A valid or pending verdict requires the resolved chain facts.
    if verdict == "valid" || verdict == "pending" {
        for key in ["confirmationDepth", "confirmationThreshold", "block_time"] {
            assert!(obj.contains_key(key), "{verdict} report must carry {key}");
        }
    }

    for issue in obj["issues"].as_array().expect("issues is an array") {
        let issue = issue.as_object().expect("issue is an object");
        for key in ["path", "code", "message"] {
            assert!(issue.contains_key(key), "issue key {key} missing");
        }
        let severity = issue["severity"].as_str().expect("severity is a string");
        assert!(
            ["error", "warning", "info"].contains(&severity),
            "severity {severity} outside the schema enum"
        );
        // The severity contract: a valid verdict cannot coexist with any
        // error-severity issue.
        if verdict == "valid" {
            assert_ne!(severity, "error", "valid verdict with an error issue");
        }
        for segment in issue["path"].as_array().expect("path is an array") {
            assert!(
                segment.is_string() || segment.as_u64().is_some(),
                "path segment outside the schema shape"
            );
        }
    }

    for entry in obj["items"].as_array().expect("items is an array") {
        let check = entry["contentCheck"].as_str().expect("contentCheck");
        assert!(["checked", "mismatched", "not_checked"].contains(&check));
        if let Some(decryption) = entry.get("decryption") {
            assert!(decryption["decrypted"].is_boolean(), "decrypted required");
        }
    }
    for entry in obj["merkle"].as_array().expect("merkle is an array") {
        let check = entry["contentCheck"].as_str().expect("contentCheck");
        assert!(["checked", "mismatched", "not_checked"].contains(&check));
    }

    for call in obj["auditTrail"]
        .as_array()
        .expect("auditTrail is an array")
    {
        let call = call.as_object().expect("audit entry is an object");
        for key in ["url", "method", "status", "bytes", "durationMs", "purpose"] {
            assert!(call.contains_key(key), "audit key {key} missing");
        }
        let purpose = call["purpose"].as_str().expect("purpose is a string");
        assert!(
            ["cardano", "arweave", "ipfs"].contains(&purpose),
            "purpose {purpose} outside the schema enum"
        );
    }
}

#[test]
fn emitted_reports_satisfy_the_schema_invariants() {
    // A valid run.
    let (tx_hash, tx_cbor_hex) = bound_core_tx();
    let transport = HeightsTransport {
        tx_cbor: serde_json::to_vec(
            &serde_json::json!([{"tx_hash": tx_hash, "cbor": tx_cbor_hex}]),
        )
        .unwrap(),
        tx_info: serde_json::to_vec(&serde_json::json!([{
            "tx_hash": tx_hash,
            "num_confirmations": 50,
            "tx_timestamp": 1_700_000_000,
            "absolute_slot": 100_000_000,
        }]))
        .unwrap(),
        tip: Vec::new(),
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec!["https://api.koios.rest/api/v1".to_string()]);
    input.fetch_outbound = Some(&transport);
    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Valid);
    assert_report_schema_invariants(&verify_report_to_dict(&report));

    // An unverifiable run (no provider reachable).
    struct FailTransport;
    impl FetchTransport for FailTransport {
        fn fetch(
            &self,
            url: &str,
            _opts: &FetchOutboundOptions,
        ) -> Result<FetchOutboundResult, OutboundError> {
            Err(OutboundError::Transport {
                url: url.to_string(),
                message: "connection refused".to_string(),
            })
        }
    }
    let fail = FailTransport;
    let mut input = VerifyTxInput::new("ab".repeat(32));
    input.cardano_gateway_chain = Some(vec!["https://api.koios.rest/api/v1".to_string()]);
    input.fetch_outbound = Some(&fail);
    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Unverifiable);
    assert_report_schema_invariants(&verify_report_to_dict(&report));

    // A pending run.
    let pending_transport = HeightsTransport {
        tx_cbor: serde_json::to_vec(
            &serde_json::json!([{"tx_hash": tx_hash, "cbor": tx_cbor_hex}]),
        )
        .unwrap(),
        tx_info: serde_json::to_vec(&serde_json::json!([{
            "tx_hash": tx_hash,
            "num_confirmations": 1,
            "tx_timestamp": 1_700_000_000,
            "absolute_slot": 100_000_000,
        }]))
        .unwrap(),
        tip: Vec::new(),
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec!["https://api.koios.rest/api/v1".to_string()]);
    input.fetch_outbound = Some(&pending_transport);
    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Pending);
    assert_report_schema_invariants(&verify_report_to_dict(&report));
}
