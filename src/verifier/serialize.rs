//! Canonical wire-form serialiser for [`VerifyReport`].
//!
//! [`verify_report_to_dict`] lowers a report to a [`serde_json::Value`] whose
//! key names, enums, and entry shapes follow the published verify-report JSON
//! Schema — the cross-implementation contract — plus this implementation's
//! informational extras (`record`, `signatures`, the transaction description):
//!
//! - schema-required keys: `verdict`, `exitCode`, `issues`, `items`, `merkle`,
//!   `auditTrail`;
//! - chain facts: `network`, `confirmationDepth`, `confirmationThreshold`,
//!   and the spec-pinned snake_case `block_time` / `block_slot`;
//! - byte strings → lowercase hex (no `0x`);
//! - absent optional values are omitted;
//! - the `record` is the CBOR→JSON projection of its canonical encoding
//!   (map keys as strings, byte values as hex).

use serde_json::{Map, Value};

use crate::cbor::{decode_canonical_cbor, CborValue};
use crate::poe_standard::{encode_poe_record, PathSegment, PoeRecord, Severity};

use crate::verifier::fetch::HttpCallRecord;
use crate::verifier::types::{
    DecryptionOutcome, ItemReportEntry, MerkleReportEntry, SignatureCheck, VerifierIssue,
    VerifyReport, VerifyTxSummary, VerifyTxWitness,
};

/// Lower a [`VerifyReport`] to its canonical JSON object.
#[must_use]
pub fn verify_report_to_dict(report: &VerifyReport) -> Value {
    let mut out = Map::new();

    // Schema-required fields.
    out.insert(
        "verdict".into(),
        Value::String(report.verdict.as_str().into()),
    );
    out.insert("exitCode".into(), Value::from(report.verdict.exit_code()));
    out.insert(
        "issues".into(),
        Value::Array(report.issues.iter().map(issue_to_value).collect()),
    );
    out.insert(
        "items".into(),
        Value::Array(report.items.iter().map(item_entry_to_value).collect()),
    );
    out.insert(
        "merkle".into(),
        Value::Array(report.merkle.iter().map(merkle_entry_to_value).collect()),
    );
    out.insert(
        "auditTrail".into(),
        Value::Array(
            report
                .audit_trail
                .iter()
                .map(audit_entry_to_value)
                .collect(),
        ),
    );

    // Chain facts and run identity.
    out.insert("network".into(), Value::String(report.network.into()));
    out.insert("txHash".into(), Value::String(report.tx_hash.clone()));
    out.insert(
        "profile".into(),
        Value::String(report.profile.as_str().into()),
    );
    out.insert(
        "confirmationThreshold".into(),
        Value::from(report.confirmation_threshold),
    );
    // The schema admits `confirmationDepth` only at >= 1 (a transaction in
    // the tip block has depth exactly 1). The pipeline never resolves a lower
    // value, and a hand-constructed report carrying one omits the key rather
    // than serialising an out-of-domain claim.
    if let Some(depth) = report.confirmation_depth.filter(|d| *d >= 1) {
        out.insert("confirmationDepth".into(), Value::from(depth));
    }
    if let Some(t) = report.block_time {
        out.insert("block_time".into(), Value::from(t));
    }
    if let Some(s) = report.block_slot {
        out.insert("block_slot".into(), Value::from(s));
    }

    // Implementation extras (the schema is an open map).
    if let Some(record) = &report.record {
        out.insert("record".into(), record_to_value(record));
    }
    if let Some(checks) = &report.record_signatures {
        if !checks.is_empty() {
            out.insert(
                "signatures".into(),
                Value::Array(checks.iter().map(signature_check_to_value).collect()),
            );
        }
    }
    if let Some(witnesses) = &report.tx_witnesses {
        out.insert(
            "txWitnesses".into(),
            Value::Array(witnesses.iter().map(tx_witness_to_value).collect()),
        );
    }
    if let Some(summary) = &report.tx_summary {
        out.insert("txSummary".into(), tx_summary_to_value(summary));
    }
    if let Some(labels) = &report.metadata_labels {
        out.insert(
            "metadataLabels".into(),
            Value::Array(labels.iter().copied().map(Value::from).collect()),
        );
    }

    Value::Object(out)
}

fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "info",
    }
}

fn issue_to_value(issue: &VerifierIssue) -> Value {
    let mut m = Map::new();
    m.insert("code".into(), Value::String(issue.code.code().into()));
    m.insert("path".into(), Value::Array(path_to_values(&issue.path)));
    m.insert(
        "severity".into(),
        Value::String(severity_str(issue.severity).into()),
    );
    m.insert("message".into(), Value::String(issue.message.clone()));
    Value::Object(m)
}

fn path_to_values(path: &[PathSegment]) -> Vec<Value> {
    path.iter()
        .map(|seg| match seg {
            PathSegment::Key(k) => Value::String(k.clone()),
            PathSegment::Index(i) => Value::from(*i),
        })
        .collect()
}

fn item_entry_to_value(entry: &ItemReportEntry) -> Value {
    let mut m = Map::new();
    m.insert(
        "contentCheck".into(),
        Value::String(entry.content_check.as_str().into()),
    );
    if let Some(decryption) = &entry.decryption {
        m.insert("decryption".into(), decryption_to_value(decryption));
    }
    Value::Object(m)
}

fn decryption_to_value(outcome: &DecryptionOutcome) -> Value {
    let mut m = Map::new();
    m.insert("decrypted".into(), Value::Bool(outcome.decrypted));
    if let Some(ok) = outcome.plaintext_hash_ok {
        m.insert("plaintextHashOk".into(), Value::Bool(ok));
    }
    if let Some(code) = outcome.code {
        m.insert("code".into(), Value::String(code.code().into()));
    }
    Value::Object(m)
}

fn merkle_entry_to_value(entry: &MerkleReportEntry) -> Value {
    let mut m = Map::new();
    m.insert(
        "contentCheck".into(),
        Value::String(entry.content_check.as_str().into()),
    );
    Value::Object(m)
}

fn audit_entry_to_value(call: &HttpCallRecord) -> Value {
    let mut m = Map::new();
    m.insert("url".into(), Value::String(call.url.clone()));
    m.insert("method".into(), Value::String(call.method.as_str().into()));
    // The status is schema-required on every entry, with null as the
    // no-response reading: a refused call or transport failure serialises as
    // JSON null, never omits the key.
    m.insert(
        "status".into(),
        call.status.map_or(Value::Null, Value::from),
    );
    m.insert("bytes".into(), Value::from(call.bytes));
    m.insert("durationMs".into(), Value::from(call.duration_ms));
    m.insert(
        "purpose".into(),
        Value::String(call.purpose.as_str().into()),
    );
    Value::Object(m)
}

fn signature_check_to_value(check: &SignatureCheck) -> Value {
    let mut m = Map::new();
    m.insert("index".into(), Value::from(check.index));
    m.insert("verdict".into(), Value::String(check.verdict_str().into()));
    if let Some(pub_hex) = &check.signer_pub {
        m.insert("signerPub".into(), Value::String(pub_hex.clone()));
    }
    if let Some(t) = check.signer_type {
        m.insert("signerType".into(), Value::String(t.as_str().into()));
    }
    if let Some(r) = check.reason {
        m.insert("reason".into(), Value::String(r.as_str().into()));
    }
    Value::Object(m)
}

fn tx_witness_to_value(w: &VerifyTxWitness) -> Value {
    let mut m = Map::new();
    // The witness kind is fixed to "vkey"; bootstrap/script witnesses are
    // summed separately in `txSummary.script_witness_count`.
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

/// Project a validated record to JSON via its canonical CBOR encoding.
///
/// The record re-encodes to the same canonical bytes the metadata carried, so
/// the projection (byte strings → hex, map keys → strings) matches the wire
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
            // CBOR negative integer is -1 - m; m fits in u64, so the signed
            // value fits in i128 and (for record fields) in i64.
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
