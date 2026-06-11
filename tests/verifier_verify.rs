//! Verifier pipeline tests.
//!
//! The capstone is the mainnet-corpus replay: for each captured record, a mock
//! transport returns the record's `captured_gateway_responses`, `verify_tx`
//! runs, the report serialises, and the result must equal the golden
//! `verify-reports/<tx_hash>.json` (compared as parsed JSON values, so key
//! order is irrelevant).
//!
//! Focused unit cases build byte-real bound transactions — body committed to
//! the requested hash, auxiliary data committed to the body's
//! `auxiliary_data_hash`, the record carried as the label-309 chunk array —
//! and assert on report verdicts, exit codes, issue codes, and per-claim
//! entries, never on log strings.

mod common;

use std::collections::HashMap;
use std::sync::Mutex;

use cardanowall::cbor::{encode_canonical_cbor, CborValue};
use cardanowall::hash::blake2b256;
use cardanowall::poe_standard::{encode_poe_record, ErrorCode, ItemEntry, PoeRecord};
use cardanowall::verifier::fetch::{
    FetchOutboundOptions, FetchOutboundResult, FetchTransport, OutboundError,
};
use cardanowall::verifier::{
    verify_report_to_dict, verify_tx, ContentCheck, Decryption, Profile, Verdict, VerifyTxInput,
};

use common::sdk_ts_fixtures;

const KOIOS_URL: &str = "https://api.koios.rest/api/v1";
const CONFORMANCE_DENY: [&str; 4] = [
    "operator.example",
    "*.operator.example",
    "localhost",
    "127.0.0.1",
];

// ---------------------------------------------------------------------------
// Bound-transaction construction
// ---------------------------------------------------------------------------

/// Split a record body into the label-309 whole-body chunk array (≤ 64-byte
/// byte-string elements).
fn chunk_array(body: &[u8]) -> CborValue {
    CborValue::Array(
        body.chunks(64)
            .map(|c| CborValue::Bytes(c.to_vec()))
            .collect(),
    )
}

/// A fully bound transaction: `[body, witness_set, true, aux]` where `aux` is
/// the metadata-map envelope `{309: <chunk array>}` and the body commits to it
/// under key 7. Returns `(tx_hash_hex, tx_cbor_hex)`.
fn bound_tx(record_body: &[u8]) -> (String, String) {
    let aux = CborValue::Map(vec![(CborValue::Unsigned(309), chunk_array(record_body))]);
    let aux_bytes = encode_canonical_cbor(&aux).expect("aux encodes");
    let body = CborValue::Map(vec![(
        CborValue::Unsigned(7),
        CborValue::Bytes(blake2b256(&aux_bytes).to_vec()),
    )]);
    let body_bytes = encode_canonical_cbor(&body).expect("body encodes");
    let tx_hash = hex::encode(blake2b256(&body_bytes));

    // Assemble the 4-element transaction byte-by-byte so the body and aux
    // spans are exactly the bytes hashed above.
    let mut tx: Vec<u8> = vec![0x84];
    tx.extend_from_slice(&body_bytes);
    tx.push(0xa0); // empty witness set
    tx.push(0xf5); // is_valid = true
    tx.extend_from_slice(&aux_bytes);
    (tx_hash, hex::encode(tx))
}

/// A minimal hash-only core record.
fn core_record(digest: &[u8; 32]) -> Vec<u8> {
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), digest.to_vec())],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    encode_poe_record(&record).expect("record encodes")
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

/// A transport that returns fixed bodies for the koios endpoints.
struct StaticTransport {
    tx_cbor: Vec<u8>,
    tx_info: Vec<u8>,
    tip: Option<Vec<u8>>,
}

impl FetchTransport for StaticTransport {
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
            match &self.tip {
                Some(b) => b.clone(),
                None => {
                    return Err(OutboundError::Transport {
                        url: url.to_string(),
                        message: "no tip body configured".to_string(),
                    });
                }
            }
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

/// Build a koios `tx_cbor` JSON array body for a single tx.
fn koios_tx_cbor_body(tx_hash: &str, cbor_hex: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([{"tx_hash": tx_hash, "cbor": cbor_hex}])).unwrap()
}

/// Build a koios `tx_info` JSON array body with the given confirmation depth.
fn koios_tx_info_body(tx_hash: &str, num_confirmations: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([{
        "tx_hash": tx_hash,
        "num_confirmations": num_confirmations,
        "tx_timestamp": 1_700_000_000,
        "absolute_slot": 100_000_000,
    }]))
    .unwrap()
}

/// A koios `tx_info` body WITHOUT `num_confirmations`, forcing the verifier to
/// derive depth from `block_height` and the `/tip` endpoint.
fn koios_tx_info_body_heights(tx_hash: &str, block_height: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([{
        "tx_hash": tx_hash,
        "block_height": block_height,
        "tx_timestamp": 1_700_000_000,
        "absolute_slot": 100_000_000,
    }]))
    .unwrap()
}

fn koios_tip_body(tip_height: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([{"block_height": tip_height}])).unwrap()
}

fn issue_codes(report: &cardanowall::verifier::VerifyReport) -> Vec<&'static str> {
    report.issues.iter().map(|i| i.code.code()).collect()
}

// ---------------------------------------------------------------------------
// Corpus replay (the capstone)
// ---------------------------------------------------------------------------

/// Build the recipient keyring for a corpus record from its
/// `recipient_secret_keys` field (absent for non-sealed records). The keyring
/// is global to the run; per-entry item indices in the corpus identify which
/// item the key was minted for but are not part of the input shape.
fn corpus_decryption_inputs(record: &serde_json::Value) -> Vec<Decryption> {
    record
        .get("recipient_secret_keys")
        .and_then(serde_json::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| {
                    let secret_key =
                        hex::decode(e.get("secret_key").and_then(serde_json::Value::as_str)?)
                            .ok()?;
                    Some(Decryption::Recipient {
                        recipient_secret_key: secret_key,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A deterministic transport that replays one corpus record's captured gateway
/// responses. Every response carries `duration_ms = 1` so the audit
/// `durationMs` / `bytes` are reproduced exactly. Two confirmation paths are
/// supported: Koios (`/tx_cbor` + `/tx_info` + `/tip`) and Blockfrost
/// (`/txs/{hash}/cbor` + `/txs/{hash}` + `/blocks/latest`). A URL with no
/// captured response yields a transport error (which surfaces in the report
/// rather than aborting the test).
struct MockTransport {
    tx_cbor_body: Option<Vec<u8>>,
    tx_info_body: Option<Vec<u8>>,
    tip_body: Option<Vec<u8>>,
    bf_tx_cbor_body: Option<Vec<u8>>,
    bf_tx_body: Option<Vec<u8>>,
    bf_blocks_latest_body: Option<Vec<u8>>,
    arweave: HashMap<String, Vec<u8>>,
    misses: Mutex<Vec<String>>,
}

impl MockTransport {
    fn from_corpus_record(record: &serde_json::Value) -> Self {
        let captures = &record["captured_gateway_responses"];
        let capture = |key: &str| captures.get(key).map(compact_json);
        let mut arweave = HashMap::new();
        if let Some(map) = captures
            .get("arweave_responses")
            .and_then(serde_json::Value::as_object)
        {
            for (ar_tx_id, hex_str) in map {
                if let Some(hex) = hex_str.as_str() {
                    if let Ok(bytes) = hex::decode(hex) {
                        arweave.insert(format!("https://arweave.net/{ar_tx_id}"), bytes);
                    }
                }
            }
        }
        Self {
            tx_cbor_body: capture("koios_tx_cbor"),
            tx_info_body: capture("koios_tx_info"),
            tip_body: capture("koios_tip"),
            bf_tx_cbor_body: capture("blockfrost_tx_cbor"),
            bf_tx_body: capture("blockfrost_tx"),
            bf_blocks_latest_body: capture("blockfrost_blocks_latest"),
            arweave,
            misses: Mutex::new(Vec::new()),
        }
    }

    fn ok(bytes: &[u8]) -> Result<FetchOutboundResult, OutboundError> {
        Ok(FetchOutboundResult {
            status: 200,
            bytes: bytes.to_vec(),
            duration_ms: 1,
        })
    }
}

/// Serialise a JSON value compactly (no spaces) — the byte length matches the
/// replay stub's compact form, which the golden `auditTrail[].bytes` pins.
fn compact_json(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("corpus capture re-serialises")
}

impl FetchTransport for MockTransport {
    fn fetch(
        &self,
        url: &str,
        _opts: &FetchOutboundOptions,
    ) -> Result<FetchOutboundResult, OutboundError> {
        // Koios confirmation path.
        if url.ends_with("/tx_cbor") {
            if let Some(b) = &self.tx_cbor_body {
                return Self::ok(b);
            }
        } else if url.ends_with("/tx_info") {
            if let Some(b) = &self.tx_info_body {
                return Self::ok(b);
            }
        } else if url.ends_with("/tip") {
            if let Some(b) = &self.tip_body {
                return Self::ok(b);
            }
        // Blockfrost confirmation path.
        } else if url.ends_with("/blocks/latest") {
            if let Some(b) = &self.bf_blocks_latest_body {
                return Self::ok(b);
            }
        } else if url.ends_with("/cbor") && url.contains("/txs/") {
            if let Some(b) = &self.bf_tx_cbor_body {
                return Self::ok(b);
            }
        } else if url.contains("/txs/") {
            if let Some(b) = &self.bf_tx_body {
                return Self::ok(b);
            }
        } else if let Some(bytes) = self.arweave.get(url) {
            return Self::ok(bytes);
        }
        self.misses.lock().unwrap().push(url.to_string());
        Err(OutboundError::Transport {
            url: url.to_string(),
            message: format!("no captured response for {url}"),
        })
    }
}

fn load_corpus() -> Vec<serde_json::Value> {
    // The corpus is a Python-only fixture (no TS twin), so it lives under the
    // sdk-py tree; reach it via the sdk-ts fixtures root's sibling.
    let path = common::sdk_py_fixtures().join("mainnet-corpus.json");
    let value = common::read_fixture_json(&path);
    value["records"]
        .as_array()
        .expect("corpus.records is an array")
        .clone()
}

#[test]
fn corpus_has_at_least_100_records() {
    let corpus = load_corpus();
    assert!(
        corpus.len() >= 100,
        "mainnet corpus has {} records; require >= 100",
        corpus.len()
    );
}

#[test]
fn corpus_replay_matches_golden_reports() {
    let corpus = load_corpus();
    assert!(
        corpus.len() >= 100,
        "corpus truncated: {} records",
        corpus.len()
    );

    let deny: Vec<String> = CONFORMANCE_DENY.iter().map(|s| (*s).to_string()).collect();
    let mut replayed = 0usize;

    for record in &corpus {
        let tx_hash = record["tx_hash"].as_str().expect("tx_hash is a string");
        let expected_verdict = record["expected_verdict"]
            .as_str()
            .expect("expected_verdict");
        let transport = MockTransport::from_corpus_record(record);

        // Route Blockfrost-provider records through the Blockfrost resolver,
        // and plumb any recipient secret keys into the keyring.
        let use_blockfrost =
            record.get("provider").and_then(serde_json::Value::as_str) == Some("blockfrost");
        let decryption = corpus_decryption_inputs(record);

        let mut input = VerifyTxInput::new(tx_hash);
        if use_blockfrost {
            // An empty Koios chain falls back to the configured Blockfrost path.
            input.cardano_gateway_chain = Some(vec![]);
            input.blockfrost_project_id = Some("corpus".to_string());
        } else {
            input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
        }
        if !decryption.is_empty() {
            input.decryption = Some(decryption);
        }
        input.deny_hosts = Some(deny.clone());
        input.fetch_outbound = Some(&transport);

        let report = verify_tx(&input);
        let actual = verify_report_to_dict(&report);

        let golden_path = sdk_ts_fixtures()
            .join("verify-reports")
            .join(format!("{tx_hash}.json"));
        let expected = common::read_fixture_json(&golden_path);

        assert_eq!(
            actual, expected,
            "VerifyReport diverged from golden for tx {tx_hash}"
        );
        assert_eq!(
            report.verdict.as_str(),
            expected_verdict,
            "verdict mismatch for tx {tx_hash}"
        );
        // Service-independence: no call ever reached the operator's own host.
        assert!(
            report
                .audit_trail
                .iter()
                .all(|c| !c.url.contains("operator.example")),
            "a call reached a deny-listed host for tx {tx_hash}"
        );
        replayed += 1;
    }

    assert!(replayed >= 100, "only replayed {replayed} corpus records");
}

// ---------------------------------------------------------------------------
// Focused unit cases (byte-real bound transactions)
// ---------------------------------------------------------------------------

#[test]
fn core_record_with_enough_confirmations_is_valid() {
    let digest = [0x11u8; 32];
    let (tx_hash, tx_cbor_hex) = bound_tx(&core_record(&digest));
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body(&tx_hash, 50),
        tip: None,
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(report.verdict.exit_code(), 0);
    assert_eq!(report.confirmation_depth, Some(50));
    assert_eq!(report.block_time, Some(1_700_000_000));
    assert_eq!(report.block_slot, Some(100_000_000));
    assert!(report.issues.is_empty());
    assert!(report.record.is_some());
    // One hash-only item: nothing to fetch, claim deliberately unchecked.
    assert_eq!(report.items.len(), 1);
    assert_eq!(report.items[0].content_check, ContentCheck::NotChecked);
    assert_eq!(report.metadata_labels.as_deref(), Some(&[309][..]));
    // Two resolve calls, both cardano-purpose, both 200.
    assert_eq!(report.audit_trail.len(), 2);
    assert!(report.audit_trail.iter().all(|c| c.status == Some(200)));
}

#[test]
fn record_below_threshold_is_pending_exit_3() {
    let digest = [0x22u8; 32];
    let (tx_hash, tx_cbor_hex) = bound_tx(&core_record(&digest));
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body(&tx_hash, 3),
        tip: None,
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Pending);
    assert_eq!(report.verdict.exit_code(), 3);
    assert_eq!(report.confirmation_depth, Some(3));
    // The record is still surfaced even when pending, and every content claim
    // is reported unchecked (the later steps are skipped).
    assert!(report.record.is_some());
    assert_eq!(report.items.len(), 1);
    assert_eq!(report.items[0].content_check, ContentCheck::NotChecked);
    assert!(issue_codes(&report).contains(&"INSUFFICIENT_CONFIRMATIONS"));
    // INSUFFICIENT_CONFIRMATIONS is info-severity: pending is not a failure.
    assert!(report
        .issues
        .iter()
        .all(|i| i.severity != cardanowall::poe_standard::Severity::Error));
}

#[test]
fn depth_is_derived_from_tip_when_confirmations_absent() {
    let digest = [0x23u8; 32];
    let (tx_hash, tx_cbor_hex) = bound_tx(&core_record(&digest));
    // tip 1014, block 1000 → depth 15 == default threshold → confirmed.
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body_heights(&tx_hash, 1000),
        tip: Some(koios_tip_body(1014)),
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.confirmation_depth, Some(15));
    assert_eq!(report.verdict, Verdict::Valid);
    // Three resolve calls this time: tx_cbor + tx_info + tip.
    assert_eq!(report.audit_trail.len(), 3);
}

#[test]
fn unreadable_tx_cbor_is_provider_unavailable_exit_2() {
    // A response that does not even walk as a transaction is unusable: the
    // binding cannot be evaluated, so this is unavailability — never a
    // record-attributable failure.
    let tx_hash = "cc".repeat(32);
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, "80"), // zero-element array
        tx_info: koios_tx_info_body(&tx_hash, 50),
        tip: None,
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Unverifiable);
    assert_eq!(report.verdict.exit_code(), 2);
    assert!(issue_codes(&report).contains(&"PROVIDER_UNAVAILABLE"));
}

#[test]
fn wrong_body_hash_is_tx_integrity_mismatch_unverifiable() {
    // A parseable transaction whose body does not hash to the requested
    // reference: the provider actively served wrong bytes. Provable against
    // the provider, never the record → unverifiable, exit 2.
    let digest = [0x33u8; 32];
    let (_real_hash, tx_cbor_hex) = bound_tx(&core_record(&digest));
    let wrong_hash = "ab".repeat(32);
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&wrong_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body(&wrong_hash, 50),
        tip: None,
    };
    let mut input = VerifyTxInput::new(&wrong_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Unverifiable);
    assert_eq!(report.verdict.exit_code(), 2);
    assert!(issue_codes(&report).contains(&"TX_INTEGRITY_MISMATCH"));
    assert!(report.record.is_none());
}

#[test]
fn no_label_309_metadata_is_metadata_not_found_failed() {
    // A bound transaction whose metadata carries label 674 only. The absence
    // of label 309 is proven by the integrity-bound transaction itself —
    // record-attributable, verdict failed.
    let aux = CborValue::Map(vec![(
        CborValue::Unsigned(674),
        CborValue::Array(vec![CborValue::text("not a poe record")]),
    )]);
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

    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &hex::encode(tx)),
        tx_info: koios_tx_info_body(&tx_hash, 50),
        tip: None,
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Failed);
    assert_eq!(report.verdict.exit_code(), 1);
    assert!(issue_codes(&report).contains(&"METADATA_NOT_FOUND"));
    // The co-published labels are still described.
    assert_eq!(report.metadata_labels.as_deref(), Some(&[674][..]));
}

#[test]
fn bare_map_label_309_value_is_malformed_cbor_failed() {
    // The record map stored directly under label 309 (no chunk array) violates
    // the carriage taxonomy: MALFORMED_CBOR, record-attributable.
    let record_body = core_record(&[0x44u8; 32]);
    let record_cbor = cardanowall::cbor::decode_canonical_cbor(&record_body).unwrap();
    let aux = CborValue::Map(vec![(CborValue::Unsigned(309), record_cbor)]);
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

    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &hex::encode(tx)),
        tx_info: koios_tx_info_body(&tx_hash, 50),
        tip: None,
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Failed);
    assert!(issue_codes(&report).contains(&"MALFORMED_CBOR"));
}

#[test]
fn deny_host_resolve_is_service_independence_violation() {
    let digest = [0x33u8; 32];
    let (tx_hash, tx_cbor_hex) = bound_tx(&core_record(&digest));
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body(&tx_hash, 50),
        tip: None,
    };
    // Point the explorer chain at the operator's own host: the deny-host short
    // circuit fires before any transport call and the whole run aborts —
    // rotating providers must not mask a service-independence violation.
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec!["https://api.operator.example/v1".to_string()]);
    input.deny_hosts = Some(CONFORMANCE_DENY.iter().map(|s| (*s).to_string()).collect());
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Failed);
    assert_eq!(report.verdict.exit_code(), 1);
    assert!(issue_codes(&report).contains(&"SERVICE_INDEPENDENCE_VIOLATION"));
}

#[test]
fn provider_unavailable_when_gateway_errors() {
    let tx_hash = "12".repeat(32);
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
    let transport = FailTransport;
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Unverifiable);
    assert_eq!(report.verdict.exit_code(), 2);
    assert!(issue_codes(&report).contains(&"PROVIDER_UNAVAILABLE"));
    // The failed call still lands on the audit trail, with the
    // schema-required status as null (no response was received).
    assert_eq!(report.audit_trail.len(), 1);
    assert_eq!(report.audit_trail[0].status, None);
}

#[test]
fn core_profile_skips_signed_record_with_out_of_profile_info() {
    use cardanowall::cose::{cose_sign1_label309_build, CoseHeader, Label309Signer};
    use cardanowall::poe_standard::{encode_record_body_for_signing, SigEntry};
    use cardanowall::seed_derive::derive_ed25519_keypair;

    // Build a STRUCTURALLY VALID signed record so structural validation
    // passes, then read it with a CORE-profile verifier: the signature surface
    // is skipped with OUT_OF_PROFILE_SKIPPED (info) and the record verifies
    // valid (the content claim does not depend on signer identity).
    let seed = [0x07u8; 32];
    let identity = derive_ed25519_keypair(&seed).unwrap();
    let pubkey = identity.public_key;

    let digest = [0x44u8; 32];
    let mut record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), digest.to_vec())],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let body = encode_record_body_for_signing(&record).unwrap();
    let protected = CoseHeader::new()
        .with_int(1, CborValue::int(-8))
        .with_int(4, CborValue::bytes(pubkey.to_vec()));
    let cose = cose_sign1_label309_build(
        &protected,
        &CoseHeader::new(),
        &body,
        Label309Signer::Seed(&identity.secret_key),
    )
    .unwrap();
    record.sigs = Some(vec![SigEntry {
        cose_sign1: cose,
        cose_key: None,
    }]);

    let (tx_hash, tx_cbor_hex) = bound_tx(&encode_poe_record(&record).unwrap());
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body(&tx_hash, 50),
        tip: None,
    };

    // CORE profile: skip the signature surface.
    let mut core_input = VerifyTxInput::new(&tx_hash);
    core_input.profile = Profile::Core;
    core_input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    core_input.fetch_outbound = Some(&transport);
    let core_report = verify_tx(&core_input);
    assert_eq!(core_report.verdict, Verdict::Valid);
    assert_eq!(core_report.verdict.exit_code(), 0);
    assert!(core_report.record_signatures.is_none());
    assert!(issue_codes(&core_report).contains(&"OUT_OF_PROFILE_SKIPPED"));

    // SIGNED profile: verify the signature → a valid in-signature-kid check.
    let mut signed_input = VerifyTxInput::new(&tx_hash);
    signed_input.profile = Profile::Signed;
    signed_input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    signed_input.fetch_outbound = Some(&transport);
    let signed_report = verify_tx(&signed_input);
    assert_eq!(signed_report.verdict, Verdict::Valid);
    let checks = signed_report
        .record_signatures
        .expect("signatures run at signed+");
    assert_eq!(checks.len(), 1);
    assert!(checks[0].valid, "the in-kid signature must verify");
    assert_eq!(
        checks[0].signer_pub.as_deref(),
        Some(hex::encode(pubkey).as_str())
    );
}

#[test]
fn tampered_signature_fails_the_record() {
    use cardanowall::cose::{cose_sign1_label309_build, CoseHeader, Label309Signer};
    use cardanowall::poe_standard::{encode_record_body_for_signing, SigEntry};
    use cardanowall::seed_derive::derive_ed25519_keypair;

    let identity = derive_ed25519_keypair(&[0x09u8; 32]).unwrap();
    let mut record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![0x55u8; 32])],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let body = encode_record_body_for_signing(&record).unwrap();
    let protected = CoseHeader::new()
        .with_int(1, CborValue::int(-8))
        .with_int(4, CborValue::bytes(identity.public_key.to_vec()));
    let mut cose = cose_sign1_label309_build(
        &protected,
        &CoseHeader::new(),
        &body,
        Label309Signer::Seed(&identity.secret_key),
    )
    .unwrap();
    // Flip one bit inside the trailing 64-byte signature field.
    let last = cose.len() - 1;
    cose[last] ^= 0x01;
    record.sigs = Some(vec![SigEntry {
        cose_sign1: cose,
        cose_key: None,
    }]);

    let (tx_hash, tx_cbor_hex) = bound_tx(&encode_poe_record(&record).unwrap());
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body(&tx_hash, 50),
        tip: None,
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Failed);
    assert_eq!(report.verdict.exit_code(), 1);
    assert!(issue_codes(&report).contains(&"SIGNATURE_INVALID"));
    let checks = report.record_signatures.expect("signature checks ran");
    assert!(!checks[0].valid);
    assert_eq!(
        checks[0].reason,
        Some(cardanowall::verifier::SigFailureReason::SignatureInvalid)
    );
    // The issue is located at the failing entry.
    let sig_issue = report
        .issues
        .iter()
        .find(|i| i.code == ErrorCode::SignatureInvalid)
        .expect("located issue");
    assert_eq!(
        sig_issue.path,
        vec![
            cardanowall::poe_standard::PathSegment::Key("sigs".to_string()),
            cardanowall::poe_standard::PathSegment::Index(0),
        ]
    );
}

#[test]
fn content_unavailable_is_unverifiable_and_claim_unchecked() {
    // An item committing to fetchable content whose every gateway fails: the
    // claim ends unchecked (not mismatched) and the verdict is unverifiable —
    // availability can never condemn a record.
    let plaintext = b"content bytes";
    let digest: [u8; 32] = cardanowall::hash::sha256(plaintext);
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), digest.to_vec())],
            uris: Some(vec![
                "ar://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
            ]),
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let (tx_hash, tx_cbor_hex) = bound_tx(&encode_poe_record(&record).unwrap());
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body(&tx_hash, 50),
        tip: None,
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Unverifiable);
    assert_eq!(report.verdict.exit_code(), 2);
    assert_eq!(report.items[0].content_check, ContentCheck::NotChecked);
    let codes = issue_codes(&report);
    assert!(codes.contains(&"CONTENT_UNAVAILABLE"));
    assert!(codes.contains(&"URI_FETCH_FAILED"));
}

#[test]
fn deny_host_content_is_per_attempt_violation_and_walk_continues() {
    use cardanowall::poe_standard::PathSegment;

    // A denied STORAGE gateway is per-attempt evidence at the claim's uris[]
    // path — unlike a resolve-path deny-hit, the run continues: the claim
    // ends unchecked (CONTENT_UNAVAILABLE), and the error-severity violation
    // forces the verdict to failed.
    let plaintext = b"never reachable";
    let digest: [u8; 32] = cardanowall::hash::sha256(plaintext);
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), digest.to_vec())],
            uris: Some(vec![
                "ar://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
            ]),
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let (tx_hash, tx_cbor_hex) = bound_tx(&encode_poe_record(&record).unwrap());
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body(&tx_hash, 50),
        tip: None,
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.arweave_gateway_chain = Some(vec!["https://arweave.gw.test".to_string()]);
    input.deny_hosts = Some(vec!["arweave.gw.test".to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Failed);
    let violations: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.code == ErrorCode::ServiceIndependenceViolation)
        .collect();
    assert_eq!(violations.len(), 1);
    assert_eq!(
        violations[0].path,
        vec![
            PathSegment::Key("items".to_string()),
            PathSegment::Index(0),
            PathSegment::Key("uris".to_string()),
            PathSegment::Index(0),
        ]
    );
    assert!(issue_codes(&report).contains(&"CONTENT_UNAVAILABLE"));
    assert_eq!(report.items[0].content_check, ContentCheck::NotChecked);
}

#[test]
fn ceiling_abort_ends_the_claim_with_one_issue() {
    use cardanowall::poe_standard::PathSegment;

    // Every URI of a claim addresses the same bytes, so the first ceiling
    // abort ends the claim: exactly one CONTENT_FETCH_LIMIT_EXCEEDED at the
    // claim's path, no other availability code, and the sibling URI is never
    // fetched.
    struct CeilingTransport {
        chain: StaticTransport,
        storage_urls: Mutex<Vec<String>>,
    }
    impl FetchTransport for CeilingTransport {
        fn fetch(
            &self,
            url: &str,
            opts: &FetchOutboundOptions,
        ) -> Result<FetchOutboundResult, OutboundError> {
            if url.contains("arweave.gw.test") {
                self.storage_urls.lock().unwrap().push(url.to_string());
                return Err(OutboundError::BodyTooLarge {
                    url: url.to_string(),
                    limit_bytes: 16,
                });
            }
            self.chain.fetch(url, opts)
        }
    }

    let plaintext = b"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
    let digest: [u8; 32] = cardanowall::hash::sha256(plaintext);
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), digest.to_vec())],
            uris: Some(vec![
                "ar://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                "ar://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            ]),
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let (tx_hash, tx_cbor_hex) = bound_tx(&encode_poe_record(&record).unwrap());
    let transport = CeilingTransport {
        chain: StaticTransport {
            tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
            tx_info: koios_tx_info_body(&tx_hash, 50),
            tip: None,
        },
        storage_urls: Mutex::new(Vec::new()),
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.arweave_gateway_chain = Some(vec!["https://arweave.gw.test".to_string()]);
    input.max_fetch_bytes = Some(16);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Unverifiable);
    let availability: Vec<_> = report
        .issues
        .iter()
        .filter(|i| {
            matches!(
                i.code,
                ErrorCode::ContentFetchLimitExceeded
                    | ErrorCode::ContentUnavailable
                    | ErrorCode::UriFetchFailed
            )
        })
        .collect();
    assert_eq!(availability.len(), 1);
    assert_eq!(availability[0].code, ErrorCode::ContentFetchLimitExceeded);
    assert_eq!(
        availability[0].path,
        vec![PathSegment::Key("items".to_string()), PathSegment::Index(0),]
    );
    assert_eq!(report.items[0].content_check, ContentCheck::NotChecked);
    // The walk ended at the first ceiling abort: one storage fetch only.
    assert_eq!(
        transport.storage_urls.lock().unwrap().as_slice(),
        ["https://arweave.gw.test/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()]
    );
}

#[test]
fn fetch_content_false_renders_offline_with_claims_unchecked() {
    let plaintext = b"content bytes";
    let digest: [u8; 32] = cardanowall::hash::sha256(plaintext);
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), digest.to_vec())],
            uris: Some(vec![
                "ar://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
            ]),
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let (tx_hash, tx_cbor_hex) = bound_tx(&encode_poe_record(&record).unwrap());
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body(&tx_hash, 50),
        tip: None,
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_content = false;
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    // Offline render: the claim is unchecked with no availability issue, and
    // the only outbound calls are the two resolve calls.
    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(report.items[0].content_check, ContentCheck::NotChecked);
    assert!(report.issues.is_empty());
    assert_eq!(report.audit_trail.len(), 2);
}

#[test]
fn verify_record_bytes_runs_the_pipeline_from_validation_onward() {
    use cardanowall::verifier::{verify_record_bytes, BlockInfo};

    // The caller (e.g. a server-rendered viewer) supplies the reassembled
    // record body plus the explorer-asserted block-info tuple; no chain fetch
    // is issued.
    struct PanicTransport;
    impl FetchTransport for PanicTransport {
        fn fetch(
            &self,
            url: &str,
            _opts: &FetchOutboundOptions,
        ) -> Result<FetchOutboundResult, OutboundError> {
            panic!("the record-bytes entry point must not fetch for a hash-only record: {url}");
        }
    }
    let transport = PanicTransport;
    let record_body = core_record(&[0x66u8; 32]);
    let mut input = VerifyTxInput::new("ef".repeat(32));
    input.fetch_outbound = Some(&transport);

    let report = verify_record_bytes(
        &record_body,
        BlockInfo {
            confirmation_depth: 42,
            block_time: 1_700_000_123,
            block_slot: Some(100_000_777),
        },
        &input,
    )
    .expect("a positive confirmation depth is valid input");
    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(report.confirmation_depth, Some(42));
    assert_eq!(report.block_time, Some(1_700_000_123));
    assert_eq!(report.block_slot, Some(100_000_777));
    assert!(report.record.is_some());
    assert_eq!(report.items.len(), 1);
    assert!(report.audit_trail.is_empty());

    // The same body below the threshold is pending.
    let pending = verify_record_bytes(
        &record_body,
        BlockInfo {
            confirmation_depth: 2,
            block_time: 1_700_000_123,
            block_slot: None,
        },
        &input,
    )
    .expect("a positive confirmation depth is valid input");
    assert_eq!(pending.verdict, Verdict::Pending);
    assert_eq!(pending.verdict.exit_code(), 3);
}

#[test]
fn zero_confirmation_depth_input_is_a_typed_error() {
    use cardanowall::verifier::{verify_record_bytes, BlockInfo, ZeroConfirmationDepthError};

    let record_body = core_record(&[0x67u8; 32]);
    let input = VerifyTxInput::new("ef".repeat(32));

    // Depth 0 asserts "in no block" against a tuple that carries block facts:
    // a caller-input error of the record-bytes entry point, never a report.
    let outcome = verify_record_bytes(
        &record_body,
        BlockInfo {
            confirmation_depth: 0,
            block_time: 1_700_000_123,
            block_slot: None,
        },
        &input,
    );
    assert_eq!(outcome.unwrap_err(), ZeroConfirmationDepthError);

    // Depth 1 — the tip block — is the floor and runs the pipeline.
    let report = verify_record_bytes(
        &record_body,
        BlockInfo {
            confirmation_depth: 1,
            block_time: 1_700_000_123,
            block_slot: None,
        },
        &input,
    )
    .expect("depth 1 is the floor of valid input");
    assert_eq!(report.verdict, Verdict::Pending);
    assert_eq!(report.confirmation_depth, Some(1));
    let dict = verify_report_to_dict(&report);
    assert_eq!(dict["confirmationDepth"], serde_json::json!(1));
}

#[test]
fn sub_floor_confirmation_depth_never_serialises() {
    use cardanowall::verifier::VerifyReport;

    // The verify-report schema admits `confirmationDepth` only at >= 1: a
    // report constructed below the floor omits the key on the wire rather
    // than emitting an out-of-domain value.
    let report = VerifyReport {
        tx_hash: "ab".repeat(32),
        verdict: Verdict::Unverifiable,
        profile: Profile::RecipientSealed,
        network: "cardano:mainnet",
        confirmation_threshold: 15,
        confirmation_depth: Some(0),
        block_time: None,
        block_slot: None,
        issues: Vec::new(),
        items: Vec::new(),
        merkle: Vec::new(),
        audit_trail: Vec::new(),
        record: None,
        record_signatures: None,
        tx_witnesses: None,
        tx_summary: None,
        metadata_labels: None,
    };
    let dict = verify_report_to_dict(&report);
    assert!(!dict.as_object().unwrap().contains_key("confirmationDepth"));

    let mut at_floor = report;
    at_floor.confirmation_depth = Some(1);
    let dict = verify_report_to_dict(&at_floor);
    assert_eq!(dict["confirmationDepth"], serde_json::json!(1));
}

// ---------------------------------------------------------------------------
// Chain-fact consistency (the explorer fallback depth computation)
// ---------------------------------------------------------------------------

#[test]
fn koios_tip_behind_block_height_is_inconsistent_not_depth_one() {
    // The provider reports the transaction in block 100 of a chain whose tip
    // it says is 99: an internally inconsistent snapshot. It must contribute
    // no chain facts — no fabricated "in the tip block" depth 1 — and with no
    // other provider the run ends PROVIDER_UNAVAILABLE with no depth at all.
    let digest = [0x24u8; 32];
    let (tx_hash, tx_cbor_hex) = bound_tx(&core_record(&digest));
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body_heights(&tx_hash, 100),
        tip: Some(koios_tip_body(99)),
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Unverifiable);
    assert_eq!(report.verdict.exit_code(), 2);
    assert!(issue_codes(&report).contains(&"PROVIDER_UNAVAILABLE"));
    assert_eq!(report.confirmation_depth, None);
    assert!(report.record.is_none());
    // The provider's evidence is recorded: all three calls are on the trail.
    assert_eq!(report.audit_trail.len(), 3);
    let dict = verify_report_to_dict(&report);
    assert!(!dict.as_object().unwrap().contains_key("confirmationDepth"));
}

#[test]
fn koios_served_zero_confirmations_is_inconsistent_not_depth_evidence() {
    // The provider serves `num_confirmations: 0` for a transaction the same
    // response reports as on-chain — the direct read is the same
    // self-contradiction as a tip behind the transaction's block, and must
    // contribute no chain facts.
    let digest = [0x25u8; 32];
    let (tx_hash, tx_cbor_hex) = bound_tx(&core_record(&digest));
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body(&tx_hash, 0),
        tip: None,
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Unverifiable);
    assert_eq!(report.verdict.exit_code(), 2);
    assert!(issue_codes(&report).contains(&"PROVIDER_UNAVAILABLE"));
    assert_eq!(report.confirmation_depth, None);
    // The direct read short-circuits before any tip call: two calls only.
    assert_eq!(report.audit_trail.len(), 2);
    let dict = verify_report_to_dict(&report);
    assert!(!dict.as_object().unwrap().contains_key("confirmationDepth"));
}

#[test]
fn blockfrost_tip_behind_block_height_is_inconsistent_not_depth_one() {
    struct BlockfrostTransport {
        cbor_body: Vec<u8>,
        tx_body: Vec<u8>,
        blocks_latest: Vec<u8>,
    }
    impl FetchTransport for BlockfrostTransport {
        fn fetch(
            &self,
            url: &str,
            _opts: &FetchOutboundOptions,
        ) -> Result<FetchOutboundResult, OutboundError> {
            let bytes = if url.contains("/txs/") && url.ends_with("/cbor") {
                self.cbor_body.clone()
            } else if url.ends_with("/blocks/latest") {
                self.blocks_latest.clone()
            } else if url.contains("/txs/") {
                self.tx_body.clone()
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

    // The same impossible snapshot through the Blockfrost fallback: discarded
    // identically, never saturated to depth 1.
    let digest = [0x25u8; 32];
    let (tx_hash, tx_cbor_hex) = bound_tx(&core_record(&digest));
    let transport = BlockfrostTransport {
        cbor_body: serde_json::to_vec(&serde_json::json!({"cbor": tx_cbor_hex})).unwrap(),
        tx_body: serde_json::to_vec(&serde_json::json!({
            "block_time": 1_700_000_000,
            "slot": 100_000_000,
            "block_height": 100,
        }))
        .unwrap(),
        blocks_latest: serde_json::to_vec(&serde_json::json!({"height": 99})).unwrap(),
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![]); // Blockfrost only
    input.blockfrost_project_id = Some("test-project".to_string());
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Unverifiable);
    assert_eq!(report.verdict.exit_code(), 2);
    assert!(issue_codes(&report).contains(&"PROVIDER_UNAVAILABLE"));
    assert_eq!(report.confirmation_depth, None);
    assert_eq!(report.audit_trail.len(), 3);
    let dict = verify_report_to_dict(&report);
    assert!(!dict.as_object().unwrap().contains_key("confirmationDepth"));
}

#[test]
fn inconsistent_provider_falls_through_to_the_next_in_chain() {
    // First provider: inconsistent snapshot (tip 99 behind block 100) — its
    // chain facts are discarded as that provider's failure. Second provider:
    // consistent (tip 199, block 100 → depth 100) — resolution continues per
    // the chain order and nothing of the first snapshot survives.
    struct RoutedTransport {
        bad: StaticTransport,
        good: StaticTransport,
    }
    impl FetchTransport for RoutedTransport {
        fn fetch(
            &self,
            url: &str,
            opts: &FetchOutboundOptions,
        ) -> Result<FetchOutboundResult, OutboundError> {
            if url.starts_with("https://koios-bad.test") {
                self.bad.fetch(url, opts)
            } else {
                self.good.fetch(url, opts)
            }
        }
    }

    let digest = [0x26u8; 32];
    let (tx_hash, tx_cbor_hex) = bound_tx(&core_record(&digest));
    let transport = RoutedTransport {
        bad: StaticTransport {
            tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
            tx_info: koios_tx_info_body_heights(&tx_hash, 100),
            tip: Some(koios_tip_body(99)),
        },
        good: StaticTransport {
            tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
            tx_info: koios_tx_info_body_heights(&tx_hash, 100),
            tip: Some(koios_tip_body(199)),
        },
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![
        "https://koios-bad.test/api/v1".to_string(),
        "https://koios-good.test/api/v1".to_string(),
    ]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(report.confirmation_depth, Some(100));
    // Both providers' evidence is on the trail: three calls each.
    assert_eq!(report.audit_trail.len(), 6);
}

// ---------------------------------------------------------------------------
// Unsupported signature algorithms (exactly-once reporting)
// ---------------------------------------------------------------------------

/// A hash-only record carrying one path-1 signature whose protected `alg` is
/// `alg` (the signature bytes themselves are well-formed Ed25519 output).
fn record_with_sig_alg(alg: i64) -> Vec<u8> {
    use cardanowall::cose::{cose_sign1_label309_build, CoseHeader, Label309Signer};
    use cardanowall::poe_standard::{encode_record_body_for_signing, SigEntry};
    use cardanowall::seed_derive::derive_ed25519_keypair;

    let identity = derive_ed25519_keypair(&[0x0bu8; 32]).unwrap();
    let mut record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![0x77u8; 32])],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let body = encode_record_body_for_signing(&record).unwrap();
    let protected = CoseHeader::new()
        .with_int(1, CborValue::int(alg))
        .with_int(4, CborValue::bytes(identity.public_key.to_vec()));
    let cose = cose_sign1_label309_build(
        &protected,
        &CoseHeader::new(),
        &body,
        Label309Signer::Seed(&identity.secret_key),
    )
    .unwrap();
    record.sigs = Some(vec![SigEntry {
        cose_sign1: cose,
        cose_key: None,
    }]);
    encode_poe_record(&record).unwrap()
}

fn verify_sig_alg_record(alg: i64) -> cardanowall::verifier::VerifyReport {
    let record_body = record_with_sig_alg(alg);
    let (tx_hash, tx_cbor_hex) = bound_tx(&record_body);
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body(&tx_hash, 50),
        tip: None,
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);
    verify_tx(&input)
}

/// The exactly-once contract: an `unsupported` per-signature verdict surfaces
/// as one SIGNATURE_UNSUPPORTED (info) at `["sigs", 0]` — never zero, never
/// duplicated — and the info never fails the record.
fn assert_unsupported_exactly_once(report: &cardanowall::verifier::VerifyReport) {
    use cardanowall::poe_standard::{PathSegment, Severity};

    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(report.verdict.exit_code(), 0);
    let unsupported: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.code == ErrorCode::SignatureUnsupported)
        .collect();
    assert_eq!(
        unsupported.len(),
        1,
        "exactly one SIGNATURE_UNSUPPORTED issue"
    );
    assert_eq!(unsupported[0].severity, Severity::Info);
    assert_eq!(
        unsupported[0].path,
        vec![PathSegment::Key("sigs".to_string()), PathSegment::Index(0)]
    );
    let checks = report
        .record_signatures
        .as_ref()
        .expect("signature checks ran");
    assert_eq!(checks.len(), 1);
    assert!(!checks[0].valid);
    assert_eq!(checks[0].verdict_str(), "unsupported");
}

#[test]
fn registered_unimplemented_sig_alg_surfaces_unsupported_exactly_once() {
    // alg -19 is in the registry (so the structural validator stays silent)
    // but is not implemented by this verifier: only the signature pass can
    // conclude `unsupported`, and the report must still carry the issue.
    assert_unsupported_exactly_once(&verify_sig_alg_record(-19));
}

#[test]
fn unregistered_sig_alg_surfaces_unsupported_exactly_once() {
    // alg -7 is outside the registry: the structural validator already
    // contributes SIGNATURE_UNSUPPORTED, and the signature pass's idempotent
    // add must not duplicate it.
    assert_unsupported_exactly_once(&verify_sig_alg_record(-7));
}

// ---------------------------------------------------------------------------
// Validator role vs profile (credentials alone never strict-validate)
// ---------------------------------------------------------------------------

#[test]
fn keyring_below_recipient_sealed_keeps_the_public_validator_role() {
    use cardanowall::poe_standard::{EncryptionEnvelope, Severity};

    // An envelope under an unregistered scheme: the public reading degrades
    // it to opaque metadata (ENC_UNSUPPORTED, info); the recipient reading
    // hard-rejects it (the same code escalated to error).
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![0x66u8; 32])],
            uris: None,
            enc: Some(EncryptionEnvelope::Opaque(CborValue::Map(vec![(
                CborValue::text("scheme"),
                CborValue::Unsigned(2),
            )]))),
        }]),
        ..PoeRecord::default()
    };
    let (tx_hash, tx_cbor_hex) = bound_tx(&encode_poe_record(&record).unwrap());
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &tx_cbor_hex),
        tx_info: koios_tx_info_body(&tx_hash, 50),
        tip: None,
    };
    let keyring = || {
        Some(vec![Decryption::Recipient {
            recipient_secret_key: vec![0x42u8; 32],
        }])
    };

    // profile=signed + credentials: the run can never decrypt, so the
    // validator keeps the public reading — the sealed surface is skipped as
    // out-of-profile, never strict-rejected.
    let mut signed_input = VerifyTxInput::new(&tx_hash);
    signed_input.profile = Profile::Signed;
    signed_input.decryption = keyring();
    signed_input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    signed_input.fetch_outbound = Some(&transport);
    let signed_report = verify_tx(&signed_input);
    assert_eq!(signed_report.verdict, Verdict::Valid);
    assert_eq!(signed_report.verdict.exit_code(), 0);
    let codes = issue_codes(&signed_report);
    assert!(codes.contains(&"ENC_UNSUPPORTED"));
    assert!(codes.contains(&"OUT_OF_PROFILE_SKIPPED"));
    assert!(signed_report
        .issues
        .iter()
        .all(|i| i.severity != Severity::Error));
    // The sealed item is reported, unchecked and undecrypted.
    assert_eq!(signed_report.items.len(), 1);
    assert_eq!(
        signed_report.items[0].content_check,
        ContentCheck::NotChecked
    );
    assert!(signed_report.items[0].decryption.is_none());

    // The same record and credentials at recipient-sealed WILL decrypt: the
    // strict reading applies and the unknown envelope hard-fails.
    let mut strict_input = VerifyTxInput::new(&tx_hash);
    strict_input.decryption = keyring();
    strict_input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    strict_input.fetch_outbound = Some(&transport);
    let strict_report = verify_tx(&strict_input);
    assert_eq!(strict_report.verdict, Verdict::Failed);
    assert!(strict_report
        .issues
        .iter()
        .any(|i| i.code == ErrorCode::EncUnsupported && i.severity == Severity::Error));
}
