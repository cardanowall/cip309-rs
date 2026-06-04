//! Canonical wire-form serialiser for [`VerifyReport`].
//!
//! [`verify_report_to_dict`] lowers a report to a [`serde_json::Value`] under the
//! exact rules the TypeScript and Python twins use, so the same transaction
//! produces byte-identical JSON across all three SDKs:
//!
//! - byte strings → lowercase hex (no `0x`),
//! - `None` values are omitted,
//! - empty lists are omitted at the report-field level (mirroring the twins'
//!   `compose_validation` / dataclass-field elision),
//! - the `record` is the CBOR→JSON projection of its canonical encoding (map keys
//!   as strings, byte values as hex).

use serde_json::{Map, Value};

use crate::cbor::{decode_canonical_cbor, CborValue};
use crate::poe_standard::{encode_poe_record, PoeRecord};

use crate::verifier::types::{
    DecryptResult, MerkleCheck, PathSegment, SignatureCheck, UriCheck, ValidationSummary, Verdict,
    VerifierIssue, VerifyReport, VerifyTxSummary, VerifyTxWitness,
};

/// Lower a [`VerifyReport`] to its canonical JSON object.
///
/// The result round-trips the `verify-reports/<tx_hash>.json` golden corpus: a
/// `serde_json::to_string` with sorted keys reproduces those fixtures byte-for-byte.
#[must_use]
pub fn verify_report_to_dict(report: &VerifyReport) -> Value {
    let mut out = Map::new();

    // Required scalar fields (always present).
    out.insert("tx_hash".into(), Value::String(report.tx_hash.clone()));
    out.insert(
        "verdict".into(),
        Value::String(report.verdict.as_str().into()),
    );
    out.insert("exit_code".into(), Value::from(report.exit_code.as_u8()));
    out.insert(
        "profile".into(),
        Value::String(report.profile.as_str().into()),
    );
    out.insert("network".into(), Value::String(report.network.into()));
    out.insert(
        "confirmation_depth_threshold".into(),
        Value::from(report.confirmation_depth_threshold),
    );
    out.insert("validation".into(), validation_to_value(&report.validation));
    insert_list_or_omit(&mut out, "http_calls", http_calls_to_values(report));
    out.insert(
        "metadata_present".into(),
        Value::Bool(report.metadata_present),
    );
    out.insert(
        "num_confirmations".into(),
        Value::from(report.num_confirmations),
    );

    // Optional fields, omitted when absent.
    if let Some(t) = report.block_time {
        out.insert("block_time".into(), Value::from(t));
    }
    if let Some(s) = report.block_slot {
        out.insert("block_slot".into(), Value::from(s));
    }
    if let Some(record) = &report.record {
        out.insert("record".into(), record_to_value(record));
    }
    if let Some(checks) = &report.record_signatures {
        out.insert(
            "record_signatures".into(),
            Value::Array(checks.iter().map(signature_check_to_value).collect()),
        );
    }
    if let Some(results) = &report.item_decryptions {
        out.insert(
            "item_decryptions".into(),
            Value::Array(results.iter().map(decrypt_result_to_value).collect()),
        );
    }
    // Transaction-level description. `tx_witnesses` and `metadata_labels` are
    // emitted even when empty (the carrying tx is described as having no vkey
    // witnesses / no co-published labels); they are omitted only when raw tx CBOR
    // was unavailable (the field stays `None`). `tx_summary` is omitted unless the
    // body decoded.
    if let Some(witnesses) = &report.tx_witnesses {
        out.insert(
            "tx_witnesses".into(),
            Value::Array(witnesses.iter().map(tx_witness_to_value).collect()),
        );
    }
    if let Some(summary) = &report.tx_summary {
        out.insert("tx_summary".into(), tx_summary_to_value(summary));
    }
    if let Some(labels) = &report.metadata_labels {
        out.insert(
            "metadata_labels".into(),
            Value::Array(labels.iter().copied().map(Value::from).collect()),
        );
    }
    if let Some(checks) = &report.uri_checks {
        insert_list_or_omit(
            &mut out,
            "uri_checks",
            checks.iter().map(uri_check_to_value).collect(),
        );
    }
    if let Some(checks) = &report.merkle_checks {
        insert_list_or_omit(
            &mut out,
            "merkle_checks",
            checks.iter().map(merkle_check_to_value).collect(),
        );
    }

    Value::Object(out)
}

/// `http_calls` is a required field but, like the dataclass-field elision in the
/// twins, an empty list is omitted; the verifier always issues at least the
/// resolve calls when it reaches the metadata stage, so the present case is the
/// norm.
fn insert_list_or_omit(out: &mut Map<String, Value>, key: &str, list: Vec<Value>) {
    if !list.is_empty() {
        out.insert(key.into(), Value::Array(list));
    }
}

fn http_calls_to_values(report: &VerifyReport) -> Vec<Value> {
    report
        .http_calls
        .iter()
        .map(|c| {
            let mut m = Map::new();
            m.insert("url".into(), Value::String(c.url.clone()));
            m.insert("method".into(), Value::String(c.method.as_str().into()));
            m.insert("status".into(), Value::from(c.status));
            m.insert("bytes".into(), Value::from(c.bytes));
            m.insert("duration_ms".into(), Value::from(c.duration_ms));
            m.insert("purpose".into(), Value::String(c.purpose.as_str().into()));
            Value::Object(m)
        })
        .collect()
}

fn validation_to_value(v: &ValidationSummary) -> Value {
    let mut m = Map::new();
    m.insert("valid".into(), Value::Bool(v.valid));
    if !v.issues.is_empty() {
        m.insert("issues".into(), issues_to_values(&v.issues));
    }
    if !v.warnings.is_empty() {
        m.insert("warnings".into(), issues_to_values(&v.warnings));
    }
    if !v.info.is_empty() {
        m.insert("info".into(), issues_to_values(&v.info));
    }
    Value::Object(m)
}

fn issues_to_values(issues: &[VerifierIssue]) -> Value {
    Value::Array(
        issues
            .iter()
            .map(|i| {
                let mut m = Map::new();
                m.insert("code".into(), Value::String(i.code.code().into()));
                m.insert("path".into(), Value::Array(path_to_values(&i.path)));
                m.insert("message".into(), Value::String(i.message.clone()));
                Value::Object(m)
            })
            .collect(),
    )
}

fn path_to_values(path: &[PathSegment]) -> Vec<Value> {
    path.iter()
        .map(|seg| match seg {
            PathSegment::Key(k) => Value::String(k.clone()),
            PathSegment::Index(i) => Value::from(*i),
        })
        .collect()
}

fn signature_check_to_value(c: &SignatureCheck) -> Value {
    let mut m = Map::new();
    m.insert("index".into(), Value::from(c.index));
    // The wire shape carries a 4-state `verdict` string, not a boolean.
    m.insert("verdict".into(), Value::String(c.verdict_str().into()));
    if let Some(pub_hex) = &c.signer_pub {
        m.insert("signer_pub".into(), Value::String(pub_hex.clone()));
    }
    if let Some(t) = c.signer_type {
        m.insert("signer_type".into(), Value::String(t.as_str().into()));
    }
    if let Some(r) = c.reason {
        m.insert("reason".into(), Value::String(r.as_str().into()));
    }
    Value::Object(m)
}

fn decrypt_result_to_value(d: &DecryptResult) -> Value {
    let mut m = Map::new();
    m.insert("item_index".into(), Value::from(d.item_index));
    // The wire shape carries a discriminated `verdict` string, not a boolean.
    m.insert("verdict".into(), Value::String(d.verdict_str().into()));
    if let Some(hash_ok) = d.plaintext_hash_ok {
        m.insert("plaintext_hash_ok".into(), Value::Bool(hash_ok));
    }
    if let Some(reason) = d.reason_str() {
        m.insert("reason".into(), Value::String(reason.into()));
    }
    Value::Object(m)
}

fn tx_witness_to_value(w: &VerifyTxWitness) -> Value {
    let mut m = Map::new();
    // The witness kind is fixed to "vkey"; bootstrap/script witnesses are summed
    // separately in `tx_summary.script_witness_count`.
    m.insert("type".into(), Value::String("vkey".into()));
    m.insert("vkey".into(), Value::String(w.vkey.clone()));
    m.insert("key_hash".into(), Value::String(w.key_hash.clone()));
    m.insert("signature_valid".into(), Value::Bool(w.signature_valid));
    Value::Object(m)
}

fn tx_summary_to_value(s: &VerifyTxSummary) -> Value {
    let mut m = Map::new();
    m.insert("fee_lovelace".into(), Value::String(s.fee_lovelace.clone()));
    m.insert("input_count".into(), Value::from(s.input_count));
    m.insert("output_count".into(), Value::from(s.output_count));
    m.insert(
        "outputs".into(),
        Value::Array(
            s.outputs
                .iter()
                .map(|o| {
                    let mut om = Map::new();
                    om.insert("address".into(), Value::String(o.address.clone()));
                    om.insert("lovelace".into(), Value::String(o.lovelace.clone()));
                    Value::Object(om)
                })
                .collect(),
        ),
    );
    m.insert(
        "total_output_lovelace".into(),
        Value::String(s.total_output_lovelace.clone()),
    );
    m.insert(
        "script_witness_count".into(),
        Value::from(s.script_witness_count),
    );
    if let Some(v) = s.invalid_before {
        m.insert("invalid_before".into(), Value::from(v));
    }
    if let Some(v) = s.invalid_hereafter {
        m.insert("invalid_hereafter".into(), Value::from(v));
    }
    if let Some(hashes) = &s.required_signer_key_hashes {
        m.insert(
            "required_signer_key_hashes".into(),
            Value::Array(hashes.iter().map(|h| Value::String(h.clone())).collect()),
        );
    }
    if let Some(v) = s.network_id {
        m.insert("network_id".into(), Value::from(v));
    }
    Value::Object(m)
}

fn uri_check_to_value(u: &UriCheck) -> Value {
    let mut m = Map::new();
    m.insert("item_index".into(), Value::from(u.item_index));
    m.insert("uri".into(), Value::String(u.uri.clone()));
    m.insert("ok".into(), Value::Bool(u.ok));
    if let Some(r) = u.reason {
        m.insert("reason".into(), Value::String(r.as_str().into()));
    }
    Value::Object(m)
}

fn merkle_check_to_value(c: &MerkleCheck) -> Value {
    let mut m = Map::new();
    m.insert("merkle_index".into(), Value::from(c.merkle_index));
    m.insert("alg".into(), Value::String(c.alg.clone()));
    // The wire shape carries a 5-state `verdict` string, not a boolean.
    m.insert("verdict".into(), Value::String(c.verdict_str().into()));
    if let Some(r) = c.reason {
        m.insert("reason".into(), Value::String(r.as_str().into()));
    }
    Value::Object(m)
}

/// Project a validated record to JSON via its canonical CBOR encoding.
///
/// The record re-encodes to the same canonical bytes the metadata carried, so the
/// projection (byte strings → hex, map keys → strings) matches the twins' record
/// shape exactly. On the impossible duplicate-extension-key encode failure the
/// record is rendered as an empty object rather than panicking.
fn record_to_value(record: &PoeRecord) -> Value {
    let Ok(bytes) = encode_poe_record(record) else {
        return Value::Object(Map::new());
    };
    let Ok(cbor) = decode_canonical_cbor(&bytes) else {
        return Value::Object(Map::new());
    };
    cbor_to_value(&cbor)
}

/// Project a decoded canonical [`CborValue`] to a [`serde_json::Value`].
///
/// Byte strings become lowercase hex; map keys are stringified (text keys
/// verbatim, integer keys as their decimal form); integers and booleans pass
/// through. A Label 309 record carries no floats, so none arise here.
fn cbor_to_value(value: &CborValue) -> Value {
    match value {
        CborValue::Unsigned(n) => Value::from(*n),
        CborValue::Negative(m) => {
            // CBOR negative integer is -1 - m; m fits in u64, so the signed value
            // fits in i128 and (for record fields) in i64.
            let signed = -1_i128 - i128::from(*m);
            i64::try_from(signed).map_or_else(|_| Value::String(signed.to_string()), Value::from)
        }
        CborValue::Bytes(b) => Value::String(crate::hex::encode(b)),
        CborValue::Text(s) => Value::String(s.clone()),
        CborValue::Bool(b) => Value::Bool(*b),
        CborValue::Null => Value::Null,
        CborValue::Array(items) => Value::Array(items.iter().map(cbor_to_value).collect()),
        CborValue::Map(pairs) => {
            let mut m = Map::new();
            for (k, v) in pairs {
                m.insert(cbor_key_to_string(k), cbor_to_value(v));
            }
            Value::Object(m)
        }
    }
}

/// Stringify a CBOR map key for the JSON projection.
fn cbor_key_to_string(key: &CborValue) -> String {
    match key {
        CborValue::Text(s) => s.clone(),
        CborValue::Unsigned(n) => n.to_string(),
        CborValue::Negative(m) => (-1_i128 - i128::from(*m)).to_string(),
        CborValue::Bytes(b) => crate::hex::encode(b),
        other => format!("{other:?}"),
    }
}

/// Convenience: whether a report serialised to its valid-pass shape.
#[must_use]
pub fn is_clean_pass(report: &VerifyReport) -> bool {
    report.verdict == Verdict::Valid
}
