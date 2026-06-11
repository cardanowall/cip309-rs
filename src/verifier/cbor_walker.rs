//! Position-aware CBOR walker: transaction slicing, the transaction-reference
//! integrity binding, auxiliary-data unwrapping, and label-309 chunk-array
//! reassembly.
//!
//! The verifier MUST operate on the raw transaction bytes exactly as fetched,
//! never on a decode-then-re-encode pass. A re-encode would silently launder a
//! non-conformant on-chain record into a conformant one (a canonical encoder
//! sorts map keys, collapses indefinite-length items, …) and would break both
//! hash bindings: `blake2b256(tx_body_bytes)` is the transaction id only over
//! the producer's original body bytes, and `blake2b256(auxiliary_data_bytes)`
//! matches the body's `auxiliary_data_hash` only over the auxiliary-data bytes
//! as serialised on chain. The walk therefore slices; it never re-encodes.
//!
//! Layer order, mirroring the verifier pipeline:
//!
//! 1. [`slice_tx`] — byte-faithful `[body, witness_set, is_valid, aux_data]`
//!    spans from the fetched transaction CBOR.
//! 2. [`bind_transaction`] — recompute `blake2b-256` over the body bytes
//!    against the requested transaction hash, and over the auxiliary-data
//!    bytes against the verified body's `auxiliary_data_hash` field. Nothing
//!    is read out of a fetched response before this binding holds.
//! 3. [`unwrap_auxiliary_data`] — accept all three Conway-era auxiliary-data
//!    envelope forms, dispatching on the top-level CBOR type and tag only
//!    (never on map-key inspection), and locate the label-309 value.
//! 4. [`reassemble_label_309_value`] — enforce the carriage-error taxonomy on
//!    the label-309 value (the whole-body chunk array is the only conformant
//!    shape) and byte-concatenate the chunks into the record body.

use crate::hash::blake2b256;
use crate::poe_standard::ErrorCode;

/// CBOR tag 259 wraps the keyed-map auxiliary-data form (CIP-29).
const CARDANO_AUX_DATA_TAG: u64 = 259;

/// The PoE metadata label.
const POE_LABEL: u64 = 309;

/// The ledger's per-metadatum string cap: the maximum transport chunk size.
pub const TRANSPORT_CHUNK_MAX_BYTES: usize = 64;

/// A carriage-layer rejection: the typed code plus a human-readable detail.
///
/// `code` is [`ErrorCode::MalformedCbor`] for every non-conformant shape except
/// an oversized transport chunk, which is [`ErrorCode::ChunkTooLarge`]. Both are
/// emitted by this pre-validator layer, never by the structural validator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}: {message}", code.code())]
pub struct CarriageError {
    /// The canonical taxonomy code (`MALFORMED_CBOR` or `CHUNK_TOO_LARGE`).
    pub code: ErrorCode,
    /// A human-readable description of the violation.
    pub message: String,
}

impl CarriageError {
    fn malformed(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::MalformedCbor,
            message: message.into(),
        }
    }

    fn chunk_too_large(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::ChunkTooLarge,
            message: message.into(),
        }
    }
}

/// A decoded CBOR head: major type, additional-info bits, the byte offset where
/// the payload begins, and the head's unsigned argument value.
struct CborHead {
    mt: u8,
    ai: u8,
    payload_start: usize,
    value_u64: u64,
}

/// Read one CBOR head at `pos`, rejecting indefinite-length and reserved
/// additional-info encodings (canonical CBOR forbids both).
fn read_head(bytes: &[u8], pos: usize) -> Result<CborHead, CarriageError> {
    let head = *bytes
        .get(pos)
        .ok_or_else(|| CarriageError::malformed("truncated input (no head byte)"))?;
    let mt = head >> 5;
    let ai = head & 0x1f;
    let mut p = pos + 1;
    let value_u64: u64;

    if ai < 24 {
        value_u64 = u64::from(ai);
    } else if ai == 24 {
        let b = *bytes
            .get(p)
            .ok_or_else(|| CarriageError::malformed("truncated 1-byte argument"))?;
        value_u64 = u64::from(b);
        p += 1;
    } else if ai == 25 {
        let slice = bytes
            .get(p..p + 2)
            .ok_or_else(|| CarriageError::malformed("truncated 2-byte argument"))?;
        value_u64 = u64::from(u16::from_be_bytes([slice[0], slice[1]]));
        p += 2;
    } else if ai == 26 {
        let slice = bytes
            .get(p..p + 4)
            .ok_or_else(|| CarriageError::malformed("truncated 4-byte argument"))?;
        value_u64 = u64::from(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]));
        p += 4;
    } else if ai == 27 {
        let slice = bytes
            .get(p..p + 8)
            .ok_or_else(|| CarriageError::malformed("truncated 8-byte argument"))?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(slice);
        value_u64 = u64::from_be_bytes(arr);
        p += 8;
    } else if ai == 31 {
        return Err(CarriageError::malformed(
            "indefinite-length encoding (ai=31) not allowed",
        ));
    } else {
        return Err(CarriageError::malformed(format!(
            "reserved additional info ai={ai}"
        )));
    }

    Ok(CborHead {
        mt,
        ai,
        payload_start: p,
        value_u64,
    })
}

/// Return the byte offset immediately past the CBOR item that begins at `pos`.
fn skip_cbor_item(bytes: &[u8], pos: usize) -> Result<usize, CarriageError> {
    let h = read_head(bytes, pos)?;
    let mut p = h.payload_start;
    match h.mt {
        0 | 1 => Ok(p),
        2 | 3 => {
            let len = usize::try_from(h.value_u64)
                .map_err(|_| CarriageError::malformed("string length out of range"))?;
            let end = p
                .checked_add(len)
                .ok_or_else(|| CarriageError::malformed("string length overflow"))?;
            if end > bytes.len() {
                return Err(CarriageError::malformed(format!(
                    "truncated {} string payload",
                    if h.mt == 2 { "byte" } else { "text" }
                )));
            }
            Ok(end)
        }
        4 => {
            for _ in 0..h.value_u64 {
                p = skip_cbor_item(bytes, p)?;
            }
            Ok(p)
        }
        5 => {
            for _ in 0..h.value_u64 {
                p = skip_cbor_item(bytes, p)?; // key
                p = skip_cbor_item(bytes, p)?; // value
            }
            Ok(p)
        }
        6 => skip_cbor_item(bytes, p),
        7 => {
            if h.ai < 24 {
                return Ok(p);
            }
            if h.ai == 24 {
                if p + 1 > bytes.len() {
                    return Err(CarriageError::malformed("truncated simple value"));
                }
                return Ok(p + 1);
            }
            if h.ai == 25 || h.ai == 26 || h.ai == 27 {
                return Ok(p);
            }
            Err(CarriageError::malformed(format!(
                "unsupported major-7 ai={}",
                h.ai
            )))
        }
        other => Err(CarriageError::malformed(format!(
            "unknown major type {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// 1. Transaction slicing
// ---------------------------------------------------------------------------

/// Byte-faithful slices of a fetched Cardano transaction.
///
/// `tx_body` and `witness_set` are EXACT on-chain byte spans:
/// `blake2b256(tx_body)` equals the transaction id, and each vkey witness
/// verifies against the sliced body. `aux_data` is the exact auxiliary-data
/// span, `None` when the transaction carries `null`/`undefined` there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSlices {
    /// The exact on-chain transaction-body bytes.
    pub tx_body: Vec<u8>,
    /// The exact on-chain witness-set bytes.
    pub witness_set: Vec<u8>,
    /// The exact on-chain auxiliary-data bytes, when present.
    pub aux_data: Option<Vec<u8>>,
}

/// Slice a fetched transaction into its byte-faithful components.
///
/// Accepts the four-element post-Alonzo shape
/// `[body, witness_set, is_valid, auxiliary_data]` and the three-element
/// pre-Alonzo shape `[body, witness_set, auxiliary_data]`.
///
/// # Errors
///
/// Returns a `MALFORMED_CBOR` [`CarriageError`] when the bytes do not walk as
/// such an array (wrong shape, truncation, indefinite-length items).
pub fn slice_tx(tx_cbor: &[u8]) -> Result<TxSlices, CarriageError> {
    let tx_head = read_head(tx_cbor, 0)?;
    if tx_head.mt != 4 {
        return Err(CarriageError::malformed(format!(
            "tx CBOR is not a CBOR array (major type {})",
            tx_head.mt
        )));
    }
    if tx_head.value_u64 != 3 && tx_head.value_u64 != 4 {
        return Err(CarriageError::malformed(format!(
            "tx CBOR array has {} elements; expected 3 ([body, witness_set, auxiliary_data]) or 4 ([body, witness_set, is_valid, auxiliary_data])",
            tx_head.value_u64
        )));
    }

    let body_start = tx_head.payload_start;
    let body_end = skip_cbor_item(tx_cbor, body_start)?;
    let witness_set_start = body_end;
    let witness_set_end = skip_cbor_item(tx_cbor, witness_set_start)?;
    let aux_start = if tx_head.value_u64 == 4 {
        skip_cbor_item(tx_cbor, witness_set_end)? // skip is_valid
    } else {
        witness_set_end
    };

    if aux_start >= tx_cbor.len() {
        return Err(CarriageError::malformed(
            "truncated tx (auxiliary_data missing)",
        ));
    }
    let aux_first_byte = tx_cbor[aux_start];
    let aux_data = if aux_first_byte == 0xf6 || aux_first_byte == 0xf7 {
        None
    } else {
        let aux_end = skip_cbor_item(tx_cbor, aux_start)?;
        Some(tx_cbor[aux_start..aux_end].to_vec())
    };

    Ok(TxSlices {
        tx_body: tx_cbor[body_start..body_end].to_vec(),
        witness_set: tx_cbor[witness_set_start..witness_set_end].to_vec(),
        aux_data,
    })
}

// ---------------------------------------------------------------------------
// 2. Transaction-reference integrity binding
// ---------------------------------------------------------------------------

/// The transaction body's `auxiliary_data_hash` field (body map key 7), exactly
/// as carried, or `None` when the body has no key 7.
///
/// Non-integer body-map keys are skipped rather than rejected: only the
/// integer key 7 is consulted, and the body bytes are already hash-bound to
/// the requested transaction before this read.
///
/// # Errors
///
/// Returns a `MALFORMED_CBOR` [`CarriageError`] when the body bytes do not walk
/// as a CBOR map.
pub fn extract_auxiliary_data_hash(tx_body: &[u8]) -> Result<Option<Vec<u8>>, CarriageError> {
    let body_head = read_head(tx_body, 0)?;
    if body_head.mt != 5 {
        return Err(CarriageError::malformed(format!(
            "transaction body is not a CBOR map (major type {})",
            body_head.mt
        )));
    }
    let mut pos = body_head.payload_start;
    for _ in 0..body_head.value_u64 {
        let key_head = read_head(tx_body, pos)?;
        let value_start = skip_cbor_item(tx_body, pos)?;
        let value_end = skip_cbor_item(tx_body, value_start)?;
        if key_head.mt == 0 && key_head.value_u64 == 7 {
            let value_head = read_head(tx_body, value_start)?;
            if value_head.mt != 2 {
                return Err(CarriageError::malformed(
                    "auxiliary_data_hash (body key 7) is not a byte string",
                ));
            }
            return Ok(Some(tx_body[value_head.payload_start..value_end].to_vec()));
        }
        pos = value_end;
    }
    Ok(None)
}

/// A failed transaction-reference integrity binding.
///
/// Every variant of this failure maps to the single verifier code
/// `TX_INTEGRITY_MISMATCH`: the response carries provably wrong bytes and MUST
/// be discarded before anything is read out of it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("TX_INTEGRITY_MISMATCH: {message}")]
pub struct TxBindingError {
    /// A human-readable description of which binding failed.
    pub message: String,
}

/// Bind fetched transaction bytes to the requested transaction reference.
///
/// Recomputes `blake2b-256` over `tx_body` — by ledger definition, the
/// transaction id — and rejects on any mismatch with `requested_tx_hash`; then
/// recomputes `blake2b-256` over the auxiliary-data bytes and rejects on any
/// mismatch with the verified body's `auxiliary_data_hash` field. Both digests
/// are computed over the bytes exactly as fetched. A body that commits to
/// auxiliary data the response does not carry — or carries auxiliary data
/// without committing to it — fails the same binding: such a transaction
/// cannot exist on chain.
///
/// # Errors
///
/// Returns [`TxBindingError`] when either binding fails or when the body bytes
/// cannot be walked to read the `auxiliary_data_hash` field.
pub fn bind_transaction(
    requested_tx_hash: &[u8],
    tx_body: &[u8],
    aux_data: Option<&[u8]>,
) -> Result<(), TxBindingError> {
    let computed_tx_hash = blake2b256(tx_body);
    if computed_tx_hash.as_slice() != requested_tx_hash {
        return Err(TxBindingError {
            message: format!(
                "transaction-body bytes hash to {}, not the requested {}",
                crate::hex::encode(&computed_tx_hash),
                crate::hex::encode(requested_tx_hash)
            ),
        });
    }

    let committed = extract_auxiliary_data_hash(tx_body).map_err(|e| TxBindingError {
        message: format!("transaction body is unreadable: {e}"),
    })?;

    match (aux_data, committed) {
        (None, None) => Ok(()),
        (Some(aux), Some(committed)) => {
            let computed = blake2b256(aux);
            if computed.as_slice() == committed.as_slice() {
                Ok(())
            } else {
                Err(TxBindingError {
                    message: format!(
                        "auxiliary-data bytes hash to {}, not the body's auxiliary_data_hash {}",
                        crate::hex::encode(&computed),
                        crate::hex::encode(&committed)
                    ),
                })
            }
        }
        (Some(_), None) => Err(TxBindingError {
            message: "auxiliary data is present but the verified body carries no \
                      auxiliary_data_hash; such a transaction cannot exist on chain"
                .to_string(),
        }),
        (None, Some(_)) => Err(TxBindingError {
            message: "the verified body commits to auxiliary data the response does not carry"
                .to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// 3. Auxiliary-data envelope forms
// ---------------------------------------------------------------------------

/// The unwrapped auxiliary data: the raw label-309 value bytes (still the
/// transport chunk array, not yet reassembled) and the full ascending-sorted
/// metadata label list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrappedAux {
    /// The raw CBOR bytes of the label-309 value, when label 309 is present.
    pub label_309_value: Option<Vec<u8>>,
    /// Every integer key of the metadata map, ascending.
    pub labels: Vec<u64>,
}

/// Unwrap auxiliary-data bytes down to the label-309 value.
///
/// Accepts all three Conway-era envelope forms, dispatching purely on the
/// top-level CBOR type and tag — never on map-key inspection:
///
/// - an **untagged map** is always the metadata map itself;
/// - an **untagged array** is the two-element `[metadata, scripts]` form, with
///   the metadata map at element 0;
/// - a **tag-259 map** carries the metadata map under integer key 0.
///
/// Any other top-level shape, and any tag other than 259, is rejected as
/// `MALFORMED_CBOR`. A tag-259 map with no key 0, and a metadata map with no
/// label-309 entry, are well-formed auxiliary data that simply carry no PoE
/// record (`label_309_value: None`).
///
/// # Errors
///
/// Returns a `MALFORMED_CBOR` [`CarriageError`] for a non-conformant top-level
/// shape, a foreign tag, a malformed metadata map, or trailing bytes.
pub fn unwrap_auxiliary_data(aux: &[u8]) -> Result<UnwrappedAux, CarriageError> {
    let head = read_head(aux, 0)?;
    let end = skip_cbor_item(aux, 0)?;
    if end != aux.len() {
        return Err(CarriageError::malformed(
            "trailing bytes after the auxiliary-data value",
        ));
    }

    let metadata_map_pos: Option<usize> = match head.mt {
        // Untagged map: the metadata map itself. Never key-sniffed.
        5 => Some(0),
        // Untagged array: the two-element [metadata, scripts] form.
        4 => {
            if head.value_u64 != 2 {
                return Err(CarriageError::malformed(format!(
                    "auxiliary-data array has {} elements; the metadata-with-scripts form has exactly 2",
                    head.value_u64
                )));
            }
            Some(head.payload_start)
        }
        // Tagged value: only tag 259, a map keyed by small integers, with the
        // metadata map under key 0.
        6 => {
            if head.value_u64 != CARDANO_AUX_DATA_TAG {
                return Err(CarriageError::malformed(format!(
                    "auxiliary data carries CBOR tag {}; only tag {CARDANO_AUX_DATA_TAG} is an auxiliary-data form",
                    head.value_u64
                )));
            }
            let inner_head = read_head(aux, head.payload_start)?;
            if inner_head.mt != 5 {
                return Err(CarriageError::malformed(
                    "tag-259 auxiliary data does not wrap a map",
                ));
            }
            let mut pos = inner_head.payload_start;
            let mut found: Option<usize> = None;
            for _ in 0..inner_head.value_u64 {
                let key_head = read_head(aux, pos)?;
                let value_start = skip_cbor_item(aux, pos)?;
                let value_end = skip_cbor_item(aux, value_start)?;
                if key_head.mt == 0 && key_head.value_u64 == 0 {
                    found = Some(value_start);
                }
                pos = value_end;
            }
            found
        }
        other => {
            return Err(CarriageError::malformed(format!(
                "auxiliary data has top-level major type {other}; expected a map, an array, or tag 259"
            )));
        }
    };

    let Some(metadata_map_pos) = metadata_map_pos else {
        // Well-formed auxiliary data with no metadata map (tag-259, no key 0).
        return Ok(UnwrappedAux {
            label_309_value: None,
            labels: Vec::new(),
        });
    };

    let meta_head = read_head(aux, metadata_map_pos)?;
    if meta_head.mt != 5 {
        return Err(CarriageError::malformed(format!(
            "metadata is not a CBOR map (major type {})",
            meta_head.mt
        )));
    }

    let mut labels: Vec<u64> = Vec::new();
    let mut label_309_value: Option<Vec<u8>> = None;
    let mut pos = meta_head.payload_start;
    for _ in 0..meta_head.value_u64 {
        let key_head = read_head(aux, pos)?;
        // Transaction-metadata labels are unsigned integers; any other key
        // type (including a negative integer) is not a metadata map.
        if key_head.mt != 0 {
            return Err(CarriageError::malformed(format!(
                "metadata map key has major type {}; metadata labels are unsigned integers",
                key_head.mt
            )));
        }
        let key = key_head.value_u64;
        labels.push(key);
        let value_start = skip_cbor_item(aux, pos)?;
        let value_end = skip_cbor_item(aux, value_start)?;
        if key == POE_LABEL {
            label_309_value = Some(aux[value_start..value_end].to_vec());
        }
        pos = value_end;
    }
    labels.sort_unstable();

    Ok(UnwrappedAux {
        label_309_value,
        labels,
    })
}

// ---------------------------------------------------------------------------
// 4. Label-309 chunk-array reassembly (the carriage-error taxonomy)
// ---------------------------------------------------------------------------

/// Reassemble a label-309 value into the record body, enforcing the
/// carriage-error taxonomy:
///
/// - a definite-length array of definite-length byte strings each ≤ 64 bytes
///   is accepted; the body is the in-order concatenation;
/// - zero-length elements are tolerated (chunk boundaries are semantics-free,
///   including degenerate ones) — an array whose concatenation is empty
///   reassembles to zero bytes, and the failure then surfaces from the
///   canonical decode of the empty body, not from this layer;
/// - an element longer than 64 bytes is `CHUNK_TOO_LARGE`;
/// - every other shape — a non-array value (bare map, bare byte string, …), a
///   non-byte-string element, an indefinite-length array or element — is
///   `MALFORMED_CBOR`.
///
/// The input is the raw CBOR bytes of the label-309 value exactly as carried
/// in the transaction's auxiliary data. The chunk-array form is required
/// regardless of body length.
///
/// # Errors
///
/// Returns a [`CarriageError`] carrying `CHUNK_TOO_LARGE` for an oversized
/// element and `MALFORMED_CBOR` for every other non-conformant shape.
pub fn reassemble_label_309_value(value: &[u8]) -> Result<Vec<u8>, CarriageError> {
    let head = read_head(value, 0)?;
    if head.mt != 4 {
        return Err(CarriageError::malformed(format!(
            "label-309 value has major type {}; the whole-body chunk array (a CBOR array of \
             byte strings) is required regardless of body length",
            head.mt
        )));
    }

    let mut body: Vec<u8> = Vec::new();
    let mut pos = head.payload_start;
    for i in 0..head.value_u64 {
        let chunk_head = read_head(value, pos)?;
        if chunk_head.mt != 2 {
            return Err(CarriageError::malformed(format!(
                "chunk array element {i} has major type {}; expected a byte string",
                chunk_head.mt
            )));
        }
        let len = usize::try_from(chunk_head.value_u64)
            .map_err(|_| CarriageError::malformed("chunk length out of range"))?;
        if len > TRANSPORT_CHUNK_MAX_BYTES {
            return Err(CarriageError::chunk_too_large(format!(
                "chunk array element {i} is {len} bytes; the ledger caps metadata byte strings \
                 at {TRANSPORT_CHUNK_MAX_BYTES}"
            )));
        }
        let start = chunk_head.payload_start;
        let end = start
            .checked_add(len)
            .filter(|e| *e <= value.len())
            .ok_or_else(|| CarriageError::malformed("truncated chunk payload"))?;
        body.extend_from_slice(&value[start..end]);
        pos = end;
    }
    if pos != value.len() {
        return Err(CarriageError::malformed(
            "trailing bytes after the chunk array",
        ));
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// Convenience
// ---------------------------------------------------------------------------

/// Extract the reassembled label-309 record body from raw transaction bytes.
///
/// A convenience composing [`slice_tx`], [`unwrap_auxiliary_data`], and
/// [`reassemble_label_309_value`]. It performs **no** integrity binding — the
/// verifier pipeline binds the slices with [`bind_transaction`] before
/// unwrapping; standalone callers that already trust their bytes may use this
/// directly. Returns `Ok(None)` when the transaction carries no auxiliary data
/// or no label-309 entry.
///
/// # Errors
///
/// Returns a [`CarriageError`] for a malformed transaction, malformed
/// auxiliary data, or a non-conformant label-309 value shape.
pub fn extract_label_309_metadata(tx_cbor: &[u8]) -> Result<Option<Vec<u8>>, CarriageError> {
    let slices = slice_tx(tx_cbor)?;
    let Some(aux) = &slices.aux_data else {
        return Ok(None);
    };
    let unwrapped = unwrap_auxiliary_data(aux)?;
    match unwrapped.label_309_value {
        Some(value) => Ok(Some(reassemble_label_309_value(&value)?)),
        None => Ok(None),
    }
}
