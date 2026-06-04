//! Verifier pipeline parity tests.
//!
//! The capstone is the mainnet-corpus replay: for each of the ≥100 captured
//! records, a mock transport returns the record's `captured_gateway_responses`,
//! `verify_tx` runs, the report serialises, and the result must equal the golden
//! `verify-reports/<tx_hash>.json` (compared as parsed JSON values, so key order
//! is irrelevant). The mock returns `duration_ms = 1` on every response, exactly
//! as the Python harness's stub does, so the golden `duration_ms` is reproduced.
//!
//! Focused unit cases cover the cbor-walker shapes, profile gating, the
//! signature/decrypt/merkle verdicts, and the resolve error paths — asserting on
//! report values and verdicts, never on log strings.

mod common;

use std::collections::HashMap;
use std::sync::Mutex;

use cardanowall::verifier::fetch::{
    FetchOutboundOptions, FetchOutboundResult, FetchTransport, OutboundError,
};
use cardanowall::verifier::{
    verify_report_to_dict, verify_tx, Decryption, ExitCode, Profile, Verdict, VerifyTxInput,
};

use common::sdk_ts_fixtures;

/// Build the out-of-band recipient decryption inputs for a corpus record from its
/// `recipient_secret_keys` field (absent for non-sealed records).
fn corpus_decryption_inputs(record: &serde_json::Value) -> Vec<Decryption> {
    record
        .get("recipient_secret_keys")
        .and_then(serde_json::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| {
                    let item_index = e.get("item_index").and_then(serde_json::Value::as_i64)?;
                    let secret_key =
                        hex::decode(e.get("secret_key").and_then(serde_json::Value::as_str)?)
                            .ok()?;
                    Some(Decryption::Recipient {
                        item_index,
                        recipient_secret_key: secret_key,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

const KOIOS_URL: &str = "https://api.koios.rest/api/v1";
const CONFORMANCE_DENY: [&str; 4] = [
    "cardanowall.com",
    "*.cardanowall.com",
    "localhost",
    "127.0.0.1",
];

// ---------------------------------------------------------------------------
// Mock transport
// ---------------------------------------------------------------------------

/// A deterministic transport that replays one corpus record's captured gateway
/// responses. Every response carries `duration_ms = 1`, matching the golden-writer
/// (TS) replay stub so the audit `duration_ms` / `bytes` are reproduced exactly.
/// Two confirmation paths are supported: Koios (`/tx_cbor` + `/tx_info` +
/// `/tip`) and Blockfrost (`/txs/{hash}/cbor` + `/txs/{hash}` + `/blocks/latest`).
/// A URL with no captured response yields a transport error (which surfaces in
/// the report rather than aborting the test).
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
            .get("arweave_envelope_responses")
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
}

/// Serialise a JSON value compactly (no spaces) — the byte length matches the
/// Python stub's `json.dumps(..., separators=(",", ":"))`, which the golden
/// `http_calls[].bytes` pins. Object-key order does not affect the byte count.
fn compact_json(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("corpus capture re-serialises")
}

impl MockTransport {
    fn ok(bytes: &[u8]) -> Result<FetchOutboundResult, OutboundError> {
        Ok(FetchOutboundResult {
            status: 200,
            bytes: bytes.to_vec(),
            duration_ms: 1,
        })
    }
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

// ---------------------------------------------------------------------------
// Corpus replay (the capstone)
// ---------------------------------------------------------------------------

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

        // Replay exactly as the golden-writer (TS) does: route Blockfrost-provider
        // records through the Blockfrost resolver, and plumb any recipient secret
        // keys into `decryption`.
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
                .http_calls
                .iter()
                .all(|c| !c.url.contains("cardanowall.com")),
            "a call reached a deny-listed host for tx {tx_hash}"
        );
        replayed += 1;
    }

    assert!(replayed >= 100, "only replayed {replayed} corpus records");
}

// ---------------------------------------------------------------------------
// Focused unit cases
// ---------------------------------------------------------------------------

/// A transport that returns fixed bodies for the two koios endpoints.
struct StaticTransport {
    tx_cbor: Vec<u8>,
    tx_info: Vec<u8>,
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

/// A minimal core PoE tx: `[{"x":"body"}, {"x":"witness_set"}, true, {0: {309: <record>}}]`
/// where `<record>` is a bare canonical-CBOR map `{v:1, items:[{hashes:{sha2-256:<32B>}}]}`.
fn core_tx_cbor_hex(digest: &[u8; 32]) -> String {
    use cardanowall::cbor::{encode_canonical_cbor, CborValue};
    let record = CborValue::Map(vec![
        (CborValue::text("v"), CborValue::Unsigned(1)),
        (
            CborValue::text("items"),
            CborValue::Array(vec![CborValue::Map(vec![(
                CborValue::text("hashes"),
                CborValue::Map(vec![(
                    CborValue::text("sha2-256"),
                    CborValue::Bytes(digest.to_vec()),
                )]),
            )])]),
        ),
    ]);
    let metadata = CborValue::Map(vec![(
        CborValue::Unsigned(0),
        CborValue::Map(vec![(CborValue::Unsigned(309), record)]),
    )]);
    let tx = CborValue::Array(vec![
        CborValue::Map(vec![(CborValue::text("x"), CborValue::text("body"))]),
        CborValue::Map(vec![(CborValue::text("x"), CborValue::text("witness_set"))]),
        CborValue::Bool(true),
        metadata,
    ]);
    hex::encode(encode_canonical_cbor(&tx).unwrap())
}

#[test]
fn core_record_with_enough_confirmations_is_valid() {
    let tx_hash = "aa".repeat(32);
    let digest = [0x11u8; 32];
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &core_tx_cbor_hex(&digest)),
        tx_info: koios_tx_info_body(&tx_hash, 50),
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(report.exit_code, ExitCode::Ok);
    assert!(report.metadata_present);
    assert_eq!(report.num_confirmations, 50);
    assert!(report.validation.valid);
    assert!(report.record.is_some());
    // Two resolve calls, both cardano-purpose, both 200.
    assert_eq!(report.http_calls.len(), 2);
    assert!(report.http_calls.iter().all(|c| c.status == 200));
}

#[test]
fn record_below_threshold_is_pending_exit_3() {
    let tx_hash = "bb".repeat(32);
    let digest = [0x22u8; 32];
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &core_tx_cbor_hex(&digest)),
        tx_info: koios_tx_info_body(&tx_hash, 3),
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Pending);
    assert_eq!(report.exit_code, ExitCode::InsufficientDepth);
    assert_eq!(report.num_confirmations, 3);
    // The record is still surfaced even when pending.
    assert!(report.record.is_some());
    let codes: Vec<&str> = report
        .validation
        .issues
        .iter()
        .map(|i| i.code.code())
        .collect();
    assert!(codes.contains(&"INSUFFICIENT_CONFIRMATIONS"));
}

#[test]
fn empty_tx_cbor_array_is_malformed_cbor_exit_1() {
    // An empty `koios` `tx_cbor` array (no `tx_hash`/`cbor` entry) is a definitive
    // "tx not on chain" negative → METADATA_NOT_FOUND. A non-empty array whose
    // `cbor` decodes to a CBOR array with fewer than four elements is a malformed
    // post-Conway tx → MALFORMED_CBOR (matching the byte-faithful walker, which
    // requires `[body, witness_set, is_valid, auxiliary_data]`).
    let tx_hash = "cc".repeat(32);
    // `80` = a zero-element CBOR array, an invalid tx body.
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, "80"),
        tx_info: koios_tx_info_body(&tx_hash, 50),
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Failed);
    assert_eq!(report.exit_code, ExitCode::Integrity);
    let codes: Vec<&str> = report
        .validation
        .issues
        .iter()
        .map(|i| i.code.code())
        .collect();
    assert!(codes.contains(&"MALFORMED_CBOR"));
}

#[test]
fn no_label_309_metadata_is_metadata_not_found() {
    use cardanowall::cbor::{encode_canonical_cbor, CborValue};
    let tx_hash = "dd".repeat(32);
    // A tx whose aux carries metadata label 674 (not 309).
    let tx = CborValue::Array(vec![
        CborValue::Map(vec![(CborValue::text("x"), CborValue::text("body"))]),
        CborValue::Map(vec![(CborValue::text("x"), CborValue::text("ws"))]),
        CborValue::Bool(true),
        CborValue::Map(vec![(
            CborValue::Unsigned(0),
            CborValue::Map(vec![(
                CborValue::Unsigned(674),
                CborValue::text("not a poe record"),
            )]),
        )]),
    ]);
    let cbor_hex = hex::encode(encode_canonical_cbor(&tx).unwrap());
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &cbor_hex),
        tx_info: koios_tx_info_body(&tx_hash, 50),
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Failed);
    assert_eq!(report.exit_code, ExitCode::Integrity);
    assert!(!report.metadata_present);
    let codes: Vec<&str> = report
        .validation
        .issues
        .iter()
        .map(|i| i.code.code())
        .collect();
    assert!(codes.contains(&"METADATA_NOT_FOUND"));
}

#[test]
fn malformed_tx_cbor_is_malformed_cbor() {
    let tx_hash = "ee".repeat(32);
    // A CBOR scalar (not a 4-element array): integer 1.
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, "01"),
        tx_info: koios_tx_info_body(&tx_hash, 50),
    };
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Failed);
    assert_eq!(report.exit_code, ExitCode::Integrity);
    let codes: Vec<&str> = report
        .validation
        .issues
        .iter()
        .map(|i| i.code.code())
        .collect();
    assert!(codes.contains(&"MALFORMED_CBOR"));
}

#[test]
fn deny_host_resolve_is_service_independence_violation() {
    let tx_hash = "ff".repeat(32);
    let digest = [0x33u8; 32];
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &core_tx_cbor_hex(&digest)),
        tx_info: koios_tx_info_body(&tx_hash, 50),
    };
    // Point the gateway at the operator's own host: the deny-host short circuit
    // fires before any transport call.
    let mut input = VerifyTxInput::new(&tx_hash);
    input.cardano_gateway_chain = Some(vec!["https://api.cardanowall.com/v1".to_string()]);
    input.deny_hosts = Some(CONFORMANCE_DENY.iter().map(|s| (*s).to_string()).collect());
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(report.verdict, Verdict::Failed);
    assert_eq!(report.exit_code, ExitCode::Integrity);
    let codes: Vec<&str> = report
        .validation
        .issues
        .iter()
        .map(|i| i.code.code())
        .collect();
    assert!(codes.contains(&"SERVICE_INDEPENDENCE_VIOLATION"));
}

#[test]
fn provider_unavailable_when_gateway_errors() {
    let tx_hash = "12".repeat(32);
    // A transport that fails every call.
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
    assert_eq!(report.verdict, Verdict::Failed);
    assert_eq!(report.exit_code, ExitCode::Network);
    let codes: Vec<&str> = report
        .validation
        .issues
        .iter()
        .map(|i| i.code.code())
        .collect();
    assert!(codes.contains(&"PROVIDER_UNAVAILABLE"));
}

#[test]
fn core_profile_skips_signed_record_with_out_of_profile_info() {
    use cardanowall::cose::{cose_sign1_label309_build, CoseHeader, Label309Signer};
    use cardanowall::poe_standard::{
        chunk_bytes, encode_record_body_for_signing, ItemEntry, PoeRecord, SigEntry,
    };
    use cardanowall::seed_derive::derive_ed25519_keypair;

    // Build a STRUCTURALLY VALID signed record so structural validation passes,
    // then read it with a CORE-profile verifier: the signature surface is skipped
    // with OUT_OF_PROFILE_SKIPPED (info) and the record verifies valid (the
    // content claim does not depend on signer identity).
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
        .with_int(1, cardanowall::cbor::CborValue::int(-8))
        .with_int(4, cardanowall::cbor::CborValue::bytes(pubkey.to_vec()));
    let cose = cose_sign1_label309_build(
        &protected,
        &CoseHeader::new(),
        &body,
        Label309Signer::Seed(&identity.secret_key),
    )
    .unwrap();
    record.sigs = Some(vec![SigEntry {
        cose_sign1: chunk_bytes(&cose),
        cose_key: None,
    }]);

    // Box the signed record into a transaction CBOR.
    let cbor_hex = signed_tx_cbor_hex(&record);
    let tx_hash = "34".repeat(32);
    let transport = StaticTransport {
        tx_cbor: koios_tx_cbor_body(&tx_hash, &cbor_hex),
        tx_info: koios_tx_info_body(&tx_hash, 50),
    };

    // CORE profile: skip the signature surface.
    let mut core_input = VerifyTxInput::new(&tx_hash);
    core_input.profile = Profile::Core;
    core_input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    core_input.fetch_outbound = Some(&transport);
    let core_report = verify_tx(&core_input);
    assert_eq!(core_report.verdict, Verdict::Valid);
    assert_eq!(core_report.exit_code, ExitCode::Ok);
    assert!(core_report.record_signatures.is_none());
    let info_codes: Vec<&str> = core_report
        .validation
        .info
        .iter()
        .map(|i| i.code.code())
        .collect();
    assert!(info_codes.contains(&"OUT_OF_PROFILE_SKIPPED"));

    // SIGNED profile: actually verify the signature → a valid in-signature-kid check.
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

/// Box a record into the corpus-style transaction CBOR
/// `[{"x":"body"}, {"x":"ws"}, true, {0: {309: <record-canonical-cbor>}}]`.
fn signed_tx_cbor_hex(record: &cardanowall::poe_standard::PoeRecord) -> String {
    use cardanowall::cbor::{decode_canonical_cbor, encode_canonical_cbor, CborValue};
    use cardanowall::poe_standard::encode_poe_record;
    let record_cbor = decode_canonical_cbor(&encode_poe_record(record).unwrap()).unwrap();
    let tx = CborValue::Array(vec![
        CborValue::Map(vec![(CborValue::text("x"), CborValue::text("body"))]),
        CborValue::Map(vec![(CborValue::text("x"), CborValue::text("ws"))]),
        CborValue::Bool(true),
        CborValue::Map(vec![(
            CborValue::Unsigned(0),
            CborValue::Map(vec![(CborValue::Unsigned(309), record_cbor)]),
        )]),
    ]);
    hex::encode(encode_canonical_cbor(&tx).unwrap())
}
