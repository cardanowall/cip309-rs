//! Transaction-level decode for the Label 309 verifier.
//!
//! This module surfaces the Cardano TRANSACTION that carried a PoE record: which
//! wallet vkey(s) signed it, the fee, the outputs, and the co-published metadata
//! labels. It answers "who authorised and paid for this anchoring" — distinct
//! from the record-level COSE authorship signatures handled in [`super::signatures`].
//!
//! Unlike label-309 extraction, this decode is purely INFORMATIONAL: it is not
//! fed back into the structural validator, so it is not subject to the
//! canonical-CBOR byte-faithfulness concern that forces the cbor-walker to slice
//! rather than decode. We therefore decode the body + witness-set slices with the
//! permissive decoder. The slices themselves are still byte-faithful —
//! [`decode_tx_witnesses`] verifies each signature against `blake2b256(tx_body)`,
//! which only equals the on-chain transaction hash when the body bytes are
//! exactly as produced.

use crate::cbor::{decode_cbor_permissive, PermissiveValue};
use crate::cose::ed25519_verify;
use crate::hash::blake2b256;
use crate::recipient::bech32_encode_no_limit;

// `CardanoNetwork` governs the address bech32 encoding (the `_test` HRP suffix).
use crate::verifier::types::{CardanoNetwork, VerifyTxOutput, VerifyTxSummary, VerifyTxWitness};

const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
const ED25519_SIGNATURE_LENGTH: usize = 64;

// Conway-era transaction body map keys (integer keys).
const BODY_KEY_INPUTS: u64 = 0;
const BODY_KEY_OUTPUTS: u64 = 1;
const BODY_KEY_FEE: u64 = 2;
const BODY_KEY_INVALID_HEREAFTER: u64 = 3; // ttl
const BODY_KEY_INVALID_BEFORE: u64 = 8; // validity_interval_start
const BODY_KEY_REQUIRED_SIGNERS: u64 = 14;
const BODY_KEY_NETWORK_ID: u64 = 15;

// Witness-set map keys. Key 0 is the vkey witness set; every other key (native
// scripts, bootstrap witnesses, Plutus v1/v2/v3) is counted as a "script/other"
// witness without being deep-decoded.
const WITNESS_KEY_VKEY: u64 = 0;

/// Compute the 28-byte BLAKE2b-224 key hash of a vkey.
fn blake2b224(data: &[u8]) -> [u8; 28] {
    use blake2::digest::consts::U28;
    use blake2::digest::Digest;
    use blake2::Blake2b;
    Blake2b::<U28>::digest(data).into()
}

/// Look up an unsigned-integer key in a permissive map.
fn map_get(map: &[(PermissiveValue, PermissiveValue)], key: u64) -> Option<&PermissiveValue> {
    map.iter()
        .find(|(k, _)| matches!(k, PermissiveValue::Unsigned(n) if *n == key))
        .map(|(_, v)| v)
}

/// Borrow a value as a slice of array elements, treating non-arrays as empty.
fn as_array(v: &PermissiveValue) -> &[PermissiveValue] {
    match v {
        PermissiveValue::Array(items) => items,
        _ => &[],
    }
}

/// Borrow a value as a map's pairs, returning `None` for non-maps.
fn as_map(v: &PermissiveValue) -> Option<&[(PermissiveValue, PermissiveValue)]> {
    match v {
        PermissiveValue::Map(pairs) => Some(pairs),
        _ => None,
    }
}

/// Decode the vkey witnesses of a transaction and verify each signature against
/// the transaction body.
///
/// Each Cardano vkey witness is `[vkey(32B), signature(64B)]`; the signed message
/// is `blake2b256(tx_body)` (the transaction hash). A witness whose vkey or
/// signature is malformed, or whose signature does not verify, is reported with
/// `signature_valid: false` rather than dropped — the caller surfaces it
/// informationally and never fails the record on it.
///
/// Returns an empty vector when the witness set is not a CBOR map.
#[must_use]
pub fn decode_tx_witnesses(witness_set_bytes: &[u8], tx_body_bytes: &[u8]) -> Vec<VerifyTxWitness> {
    let Ok(decoded) = decode_cbor_permissive(witness_set_bytes) else {
        return Vec::new();
    };
    let Some(witness_set) = as_map(&decoded) else {
        return Vec::new();
    };
    let Some(vkey_value) = map_get(witness_set, WITNESS_KEY_VKEY) else {
        return Vec::new();
    };
    let tx_hash = blake2b256(tx_body_bytes);

    let mut out: Vec<VerifyTxWitness> = Vec::new();
    for entry in as_array(vkey_value) {
        let pair = as_array(entry);
        let vkey = pair.first();
        let signature = pair.get(1);
        let vkey_bytes = match vkey {
            Some(PermissiveValue::Bytes(b)) if b.len() == ED25519_PUBLIC_KEY_LENGTH => b.as_slice(),
            _ => continue,
        };
        let sig_bytes = match signature {
            Some(PermissiveValue::Bytes(b)) if b.len() == ED25519_SIGNATURE_LENGTH => {
                Some(b.as_slice())
            }
            _ => None,
        };
        // A structurally malformed witness (bad/absent signature) still describes
        // an attempted authorisation; surface the vkey and mark it invalid.
        let signature_valid = match sig_bytes {
            Some(sig) => ed25519_verify(vkey_bytes, &tx_hash, sig),
            None => false,
        };
        out.push(VerifyTxWitness {
            vkey: crate::hex::encode(vkey_bytes),
            key_hash: crate::hex::encode(&blake2b224(vkey_bytes)),
            signature_valid,
        });
    }
    out
}

/// Count the witness-set entries that are NOT vkey witnesses (native scripts,
/// bootstrap witnesses, Plutus v1/v2/v3), summed as a single count.
fn count_script_witnesses(witness_set_bytes: &[u8]) -> u64 {
    let Ok(decoded) = decode_cbor_permissive(witness_set_bytes) else {
        return 0;
    };
    let Some(witness_set) = as_map(&decoded) else {
        return 0;
    };
    let mut count: u64 = 0;
    for (key, value) in witness_set {
        if matches!(key, PermissiveValue::Unsigned(n) if *n == WITNESS_KEY_VKEY) {
            continue;
        }
        count += as_array(value).len() as u64;
    }
    count
}

/// A transaction body could not be decoded into a summary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxSummaryError {
    /// The decode hit a non-conforming shape (non-map body, non-integer coin, …).
    #[error("MALFORMED_CBOR: {0}")]
    Malformed(String),
}

/// Decode a transaction body into a JSON-safe summary: fee, input/output counts,
/// the output addresses + lovelace amounts, validity interval, required signer
/// key hashes, and network id.
///
/// Lovelace amounts are carried as DECIMAL STRINGS so they survive JSON
/// round-trips exactly (Cardano coin values can exceed `2^53`).
///
/// # Errors
///
/// Returns [`TxSummaryError::Malformed`] when the body is not a CBOR map, when an
/// output is neither an array nor a map, when an output address is not a byte
/// string, or when a coin value is not an integer.
pub fn decode_tx_summary(
    tx_body_bytes: &[u8],
    witness_set_bytes: &[u8],
    network: CardanoNetwork,
) -> Result<VerifyTxSummary, TxSummaryError> {
    let decoded = decode_cbor_permissive(tx_body_bytes)
        .map_err(|e| TxSummaryError::Malformed(e.to_string()))?;
    let body = as_map(&decoded)
        .ok_or_else(|| TxSummaryError::Malformed("tx body is not a CBOR map".to_string()))?;

    let inputs = map_get(body, BODY_KEY_INPUTS)
        .map(as_array)
        .unwrap_or_default();
    let outputs_raw = map_get(body, BODY_KEY_OUTPUTS)
        .map(as_array)
        .unwrap_or_default();

    let mut outputs: Vec<VerifyTxOutput> = Vec::with_capacity(outputs_raw.len());
    let mut total_output: u128 = 0;
    for o in outputs_raw {
        let (address_bytes, lovelace) = read_output(o)?;
        total_output = total_output.saturating_add(u128::from(lovelace));
        outputs.push(VerifyTxOutput {
            address: encode_cardano_address(&address_bytes, network)?,
            lovelace: lovelace.to_string(),
        });
    }

    let required_signers: Vec<String> = map_get(body, BODY_KEY_REQUIRED_SIGNERS)
        .map(as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|s| match s {
            PermissiveValue::Bytes(b) => Some(crate::hex::encode(b)),
            _ => None,
        })
        .collect();

    let fee_lovelace = coin_to_string(map_get(body, BODY_KEY_FEE))?;

    let invalid_before = map_get(body, BODY_KEY_INVALID_BEFORE).and_then(as_u64);
    let invalid_hereafter = map_get(body, BODY_KEY_INVALID_HEREAFTER).and_then(as_u64);
    let network_id = map_get(body, BODY_KEY_NETWORK_ID).and_then(as_u64);

    Ok(VerifyTxSummary {
        fee_lovelace,
        input_count: inputs.len() as u64,
        output_count: outputs.len() as u64,
        total_output_lovelace: total_output.to_string(),
        script_witness_count: count_script_witnesses(witness_set_bytes),
        outputs,
        invalid_before,
        invalid_hereafter,
        required_signer_key_hashes: if required_signers.is_empty() {
            None
        } else {
            Some(required_signers)
        },
        network_id,
    })
}

/// A transaction output is EITHER a legacy array `[address, amount]` OR a map
/// `{0: address, 1: amount}` (post-Babbage). `amount` is a bare coin or a
/// `[coin, multiasset]` pair — only the coin (lovelace) component is summarised.
fn read_output(output: &PermissiveValue) -> Result<(Vec<u8>, u64), TxSummaryError> {
    let (address, amount) = match output {
        PermissiveValue::Array(items) => (items.first(), items.get(1)),
        PermissiveValue::Map(pairs) => (map_get(pairs, 0), map_get(pairs, 1)),
        _ => {
            return Err(TxSummaryError::Malformed(
                "tx output is neither a CBOR array nor a CBOR map".to_string(),
            ))
        }
    };
    let address_bytes = match address {
        Some(PermissiveValue::Bytes(b)) => b.clone(),
        _ => {
            return Err(TxSummaryError::Malformed(
                "tx output address is not a byte string".to_string(),
            ))
        }
    };
    let lovelace = match amount {
        Some(PermissiveValue::Array(items)) => to_u64(items.first())?,
        other => to_u64(other)?,
    };
    Ok((address_bytes, lovelace))
}

fn coin_to_string(v: Option<&PermissiveValue>) -> Result<String, TxSummaryError> {
    Ok(to_u64(v)?.to_string())
}

fn to_u64(v: Option<&PermissiveValue>) -> Result<u64, TxSummaryError> {
    match v {
        Some(PermissiveValue::Unsigned(n)) => Ok(*n),
        _ => Err(TxSummaryError::Malformed(
            "expected a non-negative integer coin value".to_string(),
        )),
    }
}

/// Read a permissive value as a `u64`, for optional informational integer fields.
fn as_u64(v: &PermissiveValue) -> Option<u64> {
    match v {
        PermissiveValue::Unsigned(n) => Some(*n),
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Cardano address bech32 encoding (BIP-173, the CIP-19 bech32 form).
// -----------------------------------------------------------------------------
//
// The header byte's high nibble is the address type and its low nibble is the
// network id (0 = testnet, 1 = mainnet). Payment-address types 0–7 use the
// `addr` HRP; stake/reward types 14–15 use the `stake` HRP. The header's network
// nibble is authoritative for the `_test` suffix; the caller's `network` argument
// is the fallback when a header is ambiguous.

fn encode_cardano_address(
    address_bytes: &[u8],
    network: CardanoNetwork,
) -> Result<String, TxSummaryError> {
    let header = *address_bytes
        .first()
        .ok_or_else(|| TxSummaryError::Malformed("empty address byte string".to_string()))?;
    let address_type = header >> 4;
    let network_nibble = header & 0x0f;
    let is_stake = address_type == 14 || address_type == 15;
    // The header's network nibble is authoritative; fall back to the caller's
    // network only when the nibble is not the canonical 0 (testnet) / 1 (mainnet).
    let is_testnet = match network_nibble {
        0 => true,
        1 => false,
        _ => network == CardanoNetwork::Preprod,
    };
    let base = if is_stake { "stake" } else { "addr" };
    let hrp = if is_testnet {
        format!("{base}_test")
    } else {
        base.to_string()
    };
    bech32_encode_no_limit(&hrp, address_bytes)
        .map_err(|e| TxSummaryError::Malformed(format!("address bech32 encode failed: {e}")))
}
