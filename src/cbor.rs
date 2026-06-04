//! Hand-rolled canonical CBOR encoder and strict canonical decoder.
//!
//! Label 309 records, signing bodies, and every embedded byte string that feeds a
//! signature or a MAC are serialised as canonical CBOR. "Canonical" here is RFC
//! 8949 §4.2.1 Core Deterministic Encoding: definite-length items only,
//! shortest-form integer and length arguments, and map keys sorted ascending by
//! the bytewise comparison of their *fully encoded* key bytes. Because the
//! leading header byte of a CBOR item encodes its length, that comparison is
//! automatically length-first — a shorter encoded key always sorts before a
//! longer one, and equal-length keys tie-break on their content bytes.
//!
//! Getting this byte-exact matters more than anything else in the SDK: the
//! record bytes, the signing body, and the slot bytes a MAC commits to all flow
//! from this module. A single mis-ordered map key or non-shortest length would
//! diverge every downstream record and break every signature. The encoder and
//! the strict decoder use the *same* comparator, so a record this encoder
//! produces is exactly what this decoder accepts.
//!
//! Three entry points mirror the TypeScript and Python SDKs:
//!
//! - [`encode_canonical_cbor`] — encode a [`CborValue`] to canonical bytes.
//! - [`decode_canonical_cbor`] — strict decode; rejects every non-canonical
//!   input (indefinite length, non-shortest integers, unsorted or duplicate map
//!   keys, floats, simple values, tags, trailing data, bad UTF-8).
//! - [`decode_cbor_permissive`] — a tolerant reader for the outer Cardano
//!   transaction envelope, which is not constrained to canonical form. Label 309
//!   records themselves MUST go through [`decode_canonical_cbor`].

use std::cmp::Ordering;

use thiserror::Error;

/// Canonical-CBOR decode error.
///
/// The Label 309 taxonomy folds every canonical-decode violation into the single
/// code [`MALFORMED_CBOR`](CanonicalCborError::MALFORMED_CBOR): indefinite-length
/// (streaming) items, non-shortest integers, unsorted or duplicate map keys,
/// floats, simple values, tags, trailing bytes, truncation, invalid UTF-8.
/// There is deliberately no finer-grained code — the structural validator
/// surfaces all of these as a single `MALFORMED_CBOR` record-level failure, and
/// a separate indefinite-length or duplicate-key code would split a distinction
/// the wire format does not make.
///
/// The enum keeps the [`IndefiniteLength`](CanonicalCborError::IndefiniteLength)
/// variant only so the specific cause survives in the human-readable `Display`
/// message; both variants report the same stable [`code`](Self::code).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CanonicalCborError {
    /// An indefinite-length (streaming) array, map, byte string, or text string
    /// was encountered. Canonical CBOR is definite-length only. Carries the
    /// `MALFORMED_CBOR` stable code; the variant exists only to keep the
    /// indefinite-length cause in the human-readable message.
    #[error("MALFORMED_CBOR: indefinite-length items are not permitted in canonical CBOR: {0}")]
    IndefiniteLength(String),

    /// Any other canonical-form violation: non-shortest integer or length
    /// argument, unsorted or duplicate map keys, a float, a non-`{false,true,
    /// null}` simple value, a tag, trailing bytes after the top-level item, a
    /// truncated item, or invalid UTF-8 in a text string.
    #[error("MALFORMED_CBOR: {0}")]
    Malformed(String),
}

impl CanonicalCborError {
    /// Stable code string for every canonical-form violation.
    pub const MALFORMED_CBOR: &'static str = "MALFORMED_CBOR";

    /// The stable code string this error carries.
    ///
    /// Matches the `code` field on the TypeScript `CanonicalCborError` and the
    /// Python `CanonicalCborError.code` byte-for-byte, so cross-implementation
    /// tests can assert the exact same string. Every variant — including
    /// `IndefiniteLength` — reports `MALFORMED_CBOR`; the specific cause lives in
    /// the `Display` message, not in the code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            CanonicalCborError::IndefiniteLength(_) | CanonicalCborError::Malformed(_) => {
                Self::MALFORMED_CBOR
            }
        }
    }
}

/// A CBOR value in the closed catalogue the canonical layer supports.
///
/// This is the exact value model the TypeScript and Python twins use: unsigned
/// and negative integers, byte strings, text strings, arrays, maps, and the
/// three permitted major-type-7 primitives `false`, `true`, and `null`. There
/// are deliberately no floats, no tags, and no other simple values — the
/// canonical surface forbids them, and the decoder rejects them outright.
///
/// Integers are split into two variants rather than a single signed type so the
/// full CBOR integer range (`-2^64 ..= 2^64 - 1`) is representable losslessly:
///
/// - [`Unsigned(n)`](CborValue::Unsigned) is the non-negative integer `n`
///   (major type 0).
/// - [`Negative(m)`](CborValue::Negative) is the negative integer `-1 - m`
///   (major type 1), where `m` is the raw CBOR argument. So `Negative(0)` is
///   `-1`, `Negative(9)` is `-10`, and `Negative(u64::MAX)` is `-2^64`.
///
/// Map keys are themselves `CborValue`s (text, integer, or byte-string keys all
/// appear in the wire format and its negative test vectors), which is why the
/// comparator operates on fully-encoded key bytes rather than on Rust strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborValue {
    /// A non-negative integer `n` (CBOR major type 0).
    Unsigned(u64),
    /// A negative integer `-1 - m` (CBOR major type 1); `m` is the CBOR argument.
    Negative(u64),
    /// A byte string (CBOR major type 2).
    Bytes(Vec<u8>),
    /// A UTF-8 text string (CBOR major type 3).
    Text(String),
    /// An array of values (CBOR major type 4).
    Array(Vec<CborValue>),
    /// A map of key/value pairs (CBOR major type 5). Stored as ordered pairs;
    /// the encoder re-sorts into canonical order regardless of insertion order.
    Map(Vec<(CborValue, CborValue)>),
    /// The boolean `false` or `true` (major type 7, simple value 20 / 21).
    Bool(bool),
    /// `null` (major type 7, simple value 22).
    Null,
}

impl CborValue {
    /// Construct a signed integer value, dispatching to the correct major type.
    ///
    /// Non-negative `n` becomes [`Unsigned`](CborValue::Unsigned); negative `n`
    /// becomes [`Negative`](CborValue::Negative) with argument `-1 - n`. This is
    /// a convenience for the `i64` range; values outside it (down to `-2^64` or
    /// up to `2^64 - 1`) are constructed with the variants directly.
    #[must_use]
    pub fn int(n: i64) -> Self {
        if n >= 0 {
            CborValue::Unsigned(n as u64)
        } else {
            // -1 - n is the CBOR argument; computed in unsigned space to avoid
            // overflow at i64::MIN.
            CborValue::Negative((-(n + 1)) as u64)
        }
    }

    /// Construct a text value from anything string-like.
    #[must_use]
    pub fn text(s: impl Into<String>) -> Self {
        CborValue::Text(s.into())
    }

    /// Construct a byte-string value from anything byte-vector-like.
    #[must_use]
    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        CborValue::Bytes(b.into())
    }
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// Encode a [`CborValue`] to canonical RFC 8949 §4.2.1 bytes.
///
/// Definite-length only, shortest-form integer and length arguments, map keys
/// sorted by encoded-key bytes (length-first). The encoder operates on the value
/// it is given: it does not invent or drop fields. Omitting absent optional
/// record fields is the record layer's job, not this layer's.
///
/// # Errors
///
/// Returns [`CanonicalCborError::Malformed`] if a map contains two keys whose
/// canonical encodings are byte-identical (a duplicate key), which the canonical
/// form forbids.
///
/// ```
/// use cardanowall::cbor::{encode_canonical_cbor, CborValue};
/// // {"b":1,"a":2} canonicalises to a2 6161 02 6162 01 (sorted a then b).
/// let map = CborValue::Map(vec![
///     (CborValue::text("b"), CborValue::Unsigned(1)),
///     (CborValue::text("a"), CborValue::Unsigned(2)),
/// ]);
/// assert_eq!(
///     cardanowall::hex::encode(&encode_canonical_cbor(&map).unwrap()),
///     "a2616102616201"
/// );
/// ```
pub fn encode_canonical_cbor(value: &CborValue) -> Result<Vec<u8>, CanonicalCborError> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// Write the CBOR header byte: `major << 5 | additional`.
fn write_header(out: &mut Vec<u8>, major: u8, additional: u8) {
    out.push((major << 5) | additional);
}

/// Write a major-type header plus its shortest-form argument.
///
/// The argument is the integer carried by the item (an unsigned magnitude, a
/// length, or an element count). RFC 8949 §4.2.1 requires the smallest encoding:
/// inline for `0..=23`, then 1, 2, 4, or 8 trailing big-endian bytes.
fn write_type_and_argument(out: &mut Vec<u8>, major: u8, argument: u64) {
    if argument <= 23 {
        write_header(out, major, argument as u8);
    } else if argument <= u8::MAX as u64 {
        write_header(out, major, 24);
        out.push(argument as u8);
    } else if argument <= u16::MAX as u64 {
        write_header(out, major, 25);
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= u32::MAX as u64 {
        write_header(out, major, 26);
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        write_header(out, major, 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

/// Recursively write one value in canonical form.
fn write_value(value: &CborValue, out: &mut Vec<u8>) -> Result<(), CanonicalCborError> {
    match value {
        CborValue::Unsigned(n) => write_type_and_argument(out, 0, *n),
        CborValue::Negative(m) => write_type_and_argument(out, 1, *m),
        CborValue::Bytes(b) => {
            write_type_and_argument(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        CborValue::Text(s) => {
            // Length is the UTF-8 byte length, not the char count.
            write_type_and_argument(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        CborValue::Array(items) => {
            write_type_and_argument(out, 4, items.len() as u64);
            for item in items {
                write_value(item, out)?;
            }
        }
        CborValue::Map(pairs) => write_map(pairs, out)?,
        CborValue::Bool(false) => write_header(out, 7, 20),
        CborValue::Bool(true) => write_header(out, 7, 21),
        CborValue::Null => write_header(out, 7, 22),
    }
    Ok(())
}

/// Write a map: sort pairs by encoded key bytes (length-first), reject duplicate
/// encoded keys, then emit the shortest-form header and the sorted pairs.
fn write_map(
    pairs: &[(CborValue, CborValue)],
    out: &mut Vec<u8>,
) -> Result<(), CanonicalCborError> {
    // Pre-encode each key once; the canonical order and the duplicate check both
    // operate on these exact bytes (RFC 8949 §4.2.1).
    let mut encoded: Vec<(Vec<u8>, &CborValue)> = Vec::with_capacity(pairs.len());
    for (key, val) in pairs {
        let mut key_bytes = Vec::new();
        write_value(key, &mut key_bytes)?;
        encoded.push((key_bytes, val));
    }

    // Sort ascending by the encoded key bytes. A plain byte-slice comparison is
    // length-first because the leading header byte carries the length, so a
    // shorter encoded key always wins the first differing byte against a longer
    // one. This is exactly the comparator the strict decoder enforces in-stream.
    encoded.sort_by(|a, b| compare_encoded_keys(&a.0, &b.0));

    // Reject duplicate keys: after sorting, byte-identical encoded keys are
    // adjacent, so a single linear pass catches every collision.
    for window in encoded.windows(2) {
        if window[0].0 == window[1].0 {
            return Err(CanonicalCborError::Malformed(
                "map contains a duplicate key".to_string(),
            ));
        }
    }

    write_type_and_argument(out, 5, encoded.len() as u64);
    for (key_bytes, val) in encoded {
        out.extend_from_slice(&key_bytes);
        write_value(val, out)?;
    }
    Ok(())
}

/// Bytewise-lexicographic comparison of two fully-encoded map keys.
///
/// Because each encoded key begins with a header byte that carries its length,
/// this single comparison is length-first: a shorter encoded key sorts before a
/// longer one, and equal-length keys tie-break on their content bytes. This is
/// the one comparator both the encoder (sort) and the strict decoder (in-stream
/// order check) use, so every record this crate produces round-trips through its
/// own decoder. (RFC 8949 §4.2.1.)
fn compare_encoded_keys(a: &[u8], b: &[u8]) -> Ordering {
    a.cmp(b)
}

// ---------------------------------------------------------------------------
// Strict canonical decoder
// ---------------------------------------------------------------------------

/// Strictly decode canonical RFC 8949 §4.2.1 bytes into a [`CborValue`].
///
/// Rejects every non-canonical input: indefinite-length items, non-shortest
/// integer or length arguments, unsorted or duplicate map keys, floats, simple
/// values other than `false`/`true`/`null`, tags, invalid UTF-8 text, truncated
/// input, and any trailing bytes after the single top-level item.
///
/// # Errors
///
/// Returns [`CanonicalCborError::IndefiniteLength`] for a streaming
/// (indefinite-length) item, and [`CanonicalCborError::Malformed`] for every
/// other violation. Both map to the single stable code `MALFORMED_CBOR`; the
/// `IndefiniteLength` variant exists only to keep the indefinite-length cause in
/// the human-readable message.
pub fn decode_canonical_cbor(bytes: &[u8]) -> Result<CborValue, CanonicalCborError> {
    let mut decoder = Decoder {
        data: bytes,
        pos: 0,
    };
    let value = decoder.read_value()?;
    if decoder.pos != bytes.len() {
        return Err(CanonicalCborError::Malformed(
            "trailing bytes after the top-level item".to_string(),
        ));
    }
    Ok(value)
}

/// Single-pass strict canonical decoder over a byte slice.
struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Decoder<'_> {
    /// Read the next byte, advancing the cursor.
    fn next_byte(&mut self) -> Result<u8, CanonicalCborError> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| CanonicalCborError::Malformed("unexpected end of input".to_string()))?;
        self.pos += 1;
        Ok(b)
    }

    /// Take `len` raw bytes, advancing the cursor.
    fn take(&mut self, len: usize) -> Result<&[u8], CanonicalCborError> {
        let end = self.pos.checked_add(len).ok_or_else(|| {
            CanonicalCborError::Malformed("length overflows the input".to_string())
        })?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| CanonicalCborError::Malformed("truncated item".to_string()))?;
        self.pos = end;
        Ok(slice)
    }

    /// Read the argument for `additional`, enforcing shortest-form encoding.
    ///
    /// Rejects indefinite length (`additional == 31`) and the reserved values
    /// 28..=30, and rejects any multi-byte argument that could have been written
    /// in fewer bytes (non-minimal integer encoding).
    fn read_argument(&mut self, additional: u8) -> Result<u64, CanonicalCborError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let v = u64::from(self.next_byte()?);
                if v <= 23 {
                    return Err(CanonicalCborError::Malformed(
                        "non-shortest integer encoding (1-byte argument < 24)".to_string(),
                    ));
                }
                Ok(v)
            }
            25 => {
                let raw = self.take(2)?;
                let v = u64::from(u16::from_be_bytes([raw[0], raw[1]]));
                if v <= u64::from(u8::MAX) {
                    return Err(CanonicalCborError::Malformed(
                        "non-shortest integer encoding (2-byte argument fits in fewer bytes)"
                            .to_string(),
                    ));
                }
                Ok(v)
            }
            26 => {
                let raw = self.take(4)?;
                let v = u64::from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]));
                if v <= u64::from(u16::MAX) {
                    return Err(CanonicalCborError::Malformed(
                        "non-shortest integer encoding (4-byte argument fits in fewer bytes)"
                            .to_string(),
                    ));
                }
                Ok(v)
            }
            27 => {
                let raw = self.take(8)?;
                let v = u64::from_be_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]);
                if v <= u64::from(u32::MAX) {
                    return Err(CanonicalCborError::Malformed(
                        "non-shortest integer encoding (8-byte argument fits in fewer bytes)"
                            .to_string(),
                    ));
                }
                Ok(v)
            }
            31 => Err(CanonicalCborError::IndefiniteLength(
                "indefinite-length item is not canonical".to_string(),
            )),
            // 28, 29, 30 are reserved.
            _ => Err(CanonicalCborError::Malformed(
                "reserved additional-information value".to_string(),
            )),
        }
    }

    /// Read one complete value, enforcing every canonical rule recursively.
    fn read_value(&mut self) -> Result<CborValue, CanonicalCborError> {
        let initial = self.next_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;

        match major {
            0 => Ok(CborValue::Unsigned(self.read_argument(additional)?)),
            1 => Ok(CborValue::Negative(self.read_argument(additional)?)),
            2 => {
                let len = self.read_length(additional)?;
                Ok(CborValue::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.read_length(additional)?;
                let raw = self.take(len)?;
                let s = std::str::from_utf8(raw).map_err(|_| {
                    CanonicalCborError::Malformed("text string is not valid UTF-8".to_string())
                })?;
                Ok(CborValue::Text(s.to_string()))
            }
            4 => {
                let len = self.read_length(additional)?;
                let mut items = Vec::with_capacity(len.min(self.data.len()));
                for _ in 0..len {
                    items.push(self.read_value()?);
                }
                Ok(CborValue::Array(items))
            }
            5 => self.read_map(additional),
            6 => Err(CanonicalCborError::Malformed(
                "tags are not permitted in canonical CBOR".to_string(),
            )),
            7 => self.read_simple(additional),
            // major is a 3-bit value, so 0..=7 is exhaustive.
            _ => unreachable!("major type is a 3-bit value"),
        }
    }

    /// Read a length argument for a byte/text string, array, or map, mapping it
    /// to a `usize` (rejecting indefinite length and non-shortest forms via
    /// [`read_argument`](Self::read_argument)).
    fn read_length(&mut self, additional: u8) -> Result<usize, CanonicalCborError> {
        let argument = self.read_argument(additional)?;
        usize::try_from(argument)
            .map_err(|_| CanonicalCborError::Malformed("length exceeds platform usize".to_string()))
    }

    /// Read a map, enforcing strictly-increasing encoded keys (which catches
    /// both unsorted keys and duplicates in one pass).
    fn read_map(&mut self, additional: u8) -> Result<CborValue, CanonicalCborError> {
        let len = self.read_length(additional)?;
        let mut pairs = Vec::with_capacity(len.min(self.data.len()));
        let mut prev_key_bytes: Option<&[u8]> = None;
        for _ in 0..len {
            let key_start = self.pos;
            let key = self.read_value()?;
            let key_bytes = &self.data[key_start..self.pos];
            if let Some(prev) = prev_key_bytes {
                // RFC 8949 §4.2.1 requires strictly-increasing encoded keys.
                // `Equal` is a duplicate; `Greater` is an out-of-order key.
                // Both are non-canonical and both collapse to MALFORMED_CBOR.
                match compare_encoded_keys(prev, key_bytes) {
                    Ordering::Less => {}
                    Ordering::Equal => {
                        return Err(CanonicalCborError::Malformed(
                            "duplicate map key".to_string(),
                        ))
                    }
                    Ordering::Greater => {
                        return Err(CanonicalCborError::Malformed(
                            "map keys are not in canonical order".to_string(),
                        ))
                    }
                }
            }
            prev_key_bytes = Some(key_bytes);
            let value = self.read_value()?;
            pairs.push((key, value));
        }
        Ok(CborValue::Map(pairs))
    }

    /// Read a major-type-7 value, accepting only `false`/`true`/`null`.
    ///
    /// Every other simple value, every float (half/single/double), the
    /// `undefined` value, and the indefinite-length break are rejected. This is
    /// the parity twin of the TypeScript decoder's `rejectFloats` /
    /// `rejectSimple` / `rejectUndefined` / `rejectNegativeZero` options: without
    /// it a float holding an integral value (e.g. `1.0`) would decode to an
    /// integer and let two non-identical byte strings canonicalise to the same
    /// record.
    fn read_simple(&mut self, additional: u8) -> Result<CborValue, CanonicalCborError> {
        match additional {
            20 => Ok(CborValue::Bool(false)),
            21 => Ok(CborValue::Bool(true)),
            22 => Ok(CborValue::Null),
            23 => Err(CanonicalCborError::Malformed(
                "the `undefined` simple value is not valid in a canonical record".to_string(),
            )),
            // additional 24 carries a one-byte simple value; 25/26/27 carry
            // float16/float32/float64. None are permitted on the record surface.
            24 => Err(CanonicalCborError::Malformed(
                "simple values other than false/true/null are not permitted".to_string(),
            )),
            25..=27 => Err(CanonicalCborError::Malformed(
                "floats are not permitted in a canonical record".to_string(),
            )),
            31 => Err(CanonicalCborError::IndefiniteLength(
                "indefinite-length break is not a value".to_string(),
            )),
            // additional 0..=19 and 28..=30 are unassigned/reserved simple values.
            _ => Err(CanonicalCborError::Malformed(
                "unassigned or reserved simple value".to_string(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Permissive decoder (outer Cardano-tx envelope only)
// ---------------------------------------------------------------------------

/// A value produced by the permissive decoder.
///
/// The outer Cardano transaction CBOR is not constrained to canonical form: it
/// uses indefinite-length items and unsorted maps freely. This model is
/// therefore looser than [`CborValue`] — it carries floats and tags, and its map
/// is an insertion-order list of arbitrary-keyed pairs — because its only job is
/// to peel the transaction structure so the label-309 byte string can be
/// re-encoded canonically and handed to the strict decoder.
///
/// Label 309 records themselves MUST NOT be read with this decoder; they go
/// through [`decode_canonical_cbor`].
#[derive(Debug, Clone, PartialEq)]
pub enum PermissiveValue {
    /// A non-negative integer `n`.
    Unsigned(u64),
    /// A negative integer `-1 - m`; `m` is the CBOR argument.
    Negative(u64),
    /// A byte string (definite- or indefinite-length, reassembled).
    Bytes(Vec<u8>),
    /// A UTF-8 text string (definite- or indefinite-length, reassembled).
    Text(String),
    /// An array of values.
    Array(Vec<PermissiveValue>),
    /// A map of key/value pairs in insertion order (no ordering or
    /// duplicate-key constraint is enforced).
    Map(Vec<(PermissiveValue, PermissiveValue)>),
    /// A tagged value: the tag number and the tagged content.
    Tag(u64, Box<PermissiveValue>),
    /// A boolean.
    Bool(bool),
    /// `null`.
    Null,
    /// `undefined`.
    Undefined,
    /// A simple value other than false/true/null/undefined, carried verbatim.
    Simple(u8),
    /// A floating-point value (half/single/double, widened to `f64`).
    Float(f64),
}

/// Permissively decode CBOR bytes for the outer Cardano transaction envelope.
///
/// Accepts indefinite-length items, unsorted and duplicate map keys, floats,
/// tags, and simple values — input the strict canonical decoder rejects. It
/// exists to peel the transaction structure
/// (`[body, witness_set, is_valid, auxiliary_data]`) so the embedded record byte
/// string can be re-encoded canonically. It still rejects genuinely malformed
/// (truncated) input.
///
/// # Errors
///
/// Returns [`CanonicalCborError::Malformed`] only for structurally broken input
/// (truncation, a dangling indefinite-length break, reserved additional-info,
/// invalid UTF-8 in a text chunk). Non-canonical-but-well-formed input is
/// accepted.
pub fn decode_cbor_permissive(bytes: &[u8]) -> Result<PermissiveValue, CanonicalCborError> {
    let mut decoder = PermissiveDecoder {
        data: bytes,
        pos: 0,
    };
    let value = decoder.read_value()?;
    if decoder.pos != bytes.len() {
        return Err(CanonicalCborError::Malformed(
            "trailing bytes after the top-level item".to_string(),
        ));
    }
    Ok(value)
}

/// Sentinel a permissive read returns when it hits an indefinite-length `break`.
enum PermissiveItem {
    Value(PermissiveValue),
    Break,
}

/// Tolerant CBOR reader for the outer transaction envelope.
struct PermissiveDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl PermissiveDecoder<'_> {
    fn next_byte(&mut self) -> Result<u8, CanonicalCborError> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| CanonicalCborError::Malformed("unexpected end of input".to_string()))?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, len: usize) -> Result<&[u8], CanonicalCborError> {
        let end = self.pos.checked_add(len).ok_or_else(|| {
            CanonicalCborError::Malformed("length overflows the input".to_string())
        })?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| CanonicalCborError::Malformed("truncated item".to_string()))?;
        self.pos = end;
        Ok(slice)
    }

    /// Read the argument for `additional` without the shortest-form constraint.
    fn read_argument(&mut self, additional: u8) -> Result<u64, CanonicalCborError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => Ok(u64::from(self.next_byte()?)),
            25 => {
                let raw = self.take(2)?;
                Ok(u64::from(u16::from_be_bytes([raw[0], raw[1]])))
            }
            26 => {
                let raw = self.take(4)?;
                Ok(u64::from(u32::from_be_bytes([
                    raw[0], raw[1], raw[2], raw[3],
                ])))
            }
            27 => {
                let raw = self.take(8)?;
                Ok(u64::from_be_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]))
            }
            _ => Err(CanonicalCborError::Malformed(
                "reserved additional-information value".to_string(),
            )),
        }
    }

    /// Read one top-level value, rejecting a stray indefinite-length break.
    fn read_value(&mut self) -> Result<PermissiveValue, CanonicalCborError> {
        match self.read_item()? {
            PermissiveItem::Value(v) => Ok(v),
            PermissiveItem::Break => Err(CanonicalCborError::Malformed(
                "unexpected indefinite-length break".to_string(),
            )),
        }
    }

    /// Read one item, which may be a value or an indefinite-length break.
    fn read_item(&mut self) -> Result<PermissiveItem, CanonicalCborError> {
        let initial = self.next_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;

        match major {
            0 => Ok(PermissiveItem::Value(PermissiveValue::Unsigned(
                self.read_argument(additional)?,
            ))),
            1 => Ok(PermissiveItem::Value(PermissiveValue::Negative(
                self.read_argument(additional)?,
            ))),
            2 => self.read_byte_or_text(additional, false),
            3 => self.read_byte_or_text(additional, true),
            4 => self.read_array(additional),
            5 => self.read_map(additional),
            6 => {
                let tag = self.read_argument(additional)?;
                let inner = self.read_value()?;
                Ok(PermissiveItem::Value(PermissiveValue::Tag(
                    tag,
                    Box::new(inner),
                )))
            }
            7 => self.read_simple(additional),
            _ => unreachable!("major type is a 3-bit value"),
        }
    }

    /// Read a byte or text string, definite or indefinite (reassembling chunks).
    fn read_byte_or_text(
        &mut self,
        additional: u8,
        is_text: bool,
    ) -> Result<PermissiveItem, CanonicalCborError> {
        if additional == 31 {
            // Indefinite-length string: concatenate definite-length chunks of
            // the same major type until the break.
            let mut buf = Vec::new();
            loop {
                let initial = self.next_byte()?;
                if initial == 0xFF {
                    break;
                }
                let chunk_major = initial >> 5;
                let chunk_additional = initial & 0x1F;
                let expected_major = if is_text { 3 } else { 2 };
                if chunk_major != expected_major || chunk_additional == 31 {
                    return Err(CanonicalCborError::Malformed(
                        "invalid chunk inside an indefinite-length string".to_string(),
                    ));
                }
                let len = self.read_length(chunk_additional)?;
                buf.extend_from_slice(self.take(len)?);
            }
            return Ok(PermissiveItem::Value(self.finish_string(buf, is_text)?));
        }
        let len = self.read_length(additional)?;
        let raw = self.take(len)?.to_vec();
        Ok(PermissiveItem::Value(self.finish_string(raw, is_text)?))
    }

    /// Turn reassembled bytes into a text or byte-string value.
    fn finish_string(
        &self,
        buf: Vec<u8>,
        is_text: bool,
    ) -> Result<PermissiveValue, CanonicalCborError> {
        if is_text {
            let s = String::from_utf8(buf).map_err(|_| {
                CanonicalCborError::Malformed("text string is not valid UTF-8".to_string())
            })?;
            Ok(PermissiveValue::Text(s))
        } else {
            Ok(PermissiveValue::Bytes(buf))
        }
    }

    /// Read an array, definite or indefinite.
    fn read_array(&mut self, additional: u8) -> Result<PermissiveItem, CanonicalCborError> {
        let mut items = Vec::new();
        if additional == 31 {
            loop {
                match self.read_item()? {
                    PermissiveItem::Break => break,
                    PermissiveItem::Value(v) => items.push(v),
                }
            }
        } else {
            let len = self.read_length(additional)?;
            for _ in 0..len {
                items.push(self.read_value()?);
            }
        }
        Ok(PermissiveItem::Value(PermissiveValue::Array(items)))
    }

    /// Read a map, definite or indefinite (no ordering/duplicate constraint).
    fn read_map(&mut self, additional: u8) -> Result<PermissiveItem, CanonicalCborError> {
        let mut pairs = Vec::new();
        if additional == 31 {
            loop {
                let key = match self.read_item()? {
                    PermissiveItem::Break => break,
                    PermissiveItem::Value(v) => v,
                };
                let value = self.read_value()?;
                pairs.push((key, value));
            }
        } else {
            let len = self.read_length(additional)?;
            for _ in 0..len {
                let key = self.read_value()?;
                let value = self.read_value()?;
                pairs.push((key, value));
            }
        }
        Ok(PermissiveItem::Value(PermissiveValue::Map(pairs)))
    }

    /// Read a major-type-7 item: bool, null, undefined, simple, float, or break.
    fn read_simple(&mut self, additional: u8) -> Result<PermissiveItem, CanonicalCborError> {
        match additional {
            0..=19 => Ok(PermissiveItem::Value(PermissiveValue::Simple(additional))),
            20 => Ok(PermissiveItem::Value(PermissiveValue::Bool(false))),
            21 => Ok(PermissiveItem::Value(PermissiveValue::Bool(true))),
            22 => Ok(PermissiveItem::Value(PermissiveValue::Null)),
            23 => Ok(PermissiveItem::Value(PermissiveValue::Undefined)),
            24 => {
                let v = self.next_byte()?;
                Ok(PermissiveItem::Value(PermissiveValue::Simple(v)))
            }
            25 => {
                let raw = self.take(2)?;
                Ok(PermissiveItem::Value(PermissiveValue::Float(decode_f16(
                    u16::from_be_bytes([raw[0], raw[1]]),
                ))))
            }
            26 => {
                let raw = self.take(4)?;
                Ok(PermissiveItem::Value(PermissiveValue::Float(f64::from(
                    f32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
                ))))
            }
            27 => {
                let raw = self.take(8)?;
                Ok(PermissiveItem::Value(PermissiveValue::Float(
                    f64::from_be_bytes([
                        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                    ]),
                )))
            }
            31 => Ok(PermissiveItem::Break),
            // 28, 29, 30 are reserved.
            _ => Err(CanonicalCborError::Malformed(
                "reserved additional-information value".to_string(),
            )),
        }
    }

    fn read_length(&mut self, additional: u8) -> Result<usize, CanonicalCborError> {
        let argument = self.read_argument(additional)?;
        usize::try_from(argument)
            .map_err(|_| CanonicalCborError::Malformed("length exceeds platform usize".to_string()))
    }
}

/// Decode an IEEE 754 half-precision (float16) bit pattern to an `f64`.
fn decode_f16(bits: u16) -> f64 {
    let sign = f64::from((bits >> 15) & 0x1);
    let exponent = (bits >> 10) & 0x1F;
    let mantissa = f64::from(bits & 0x3FF);
    let value = if exponent == 0 {
        // Subnormal: 2^-24 * mantissa.
        mantissa * 2f64.powi(-24)
    } else if exponent == 0x1F {
        // Infinity / NaN.
        if mantissa == 0.0 {
            f64::INFINITY
        } else {
            f64::NAN
        }
    } else {
        // Normalised: 2^(exp-25) * (1024 + mantissa).
        (1024.0 + mantissa) * 2f64.powi(i32::from(exponent) - 25)
    };
    if sign == 1.0 {
        -value
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_constructor_dispatches_major_type() {
        assert_eq!(CborValue::int(0), CborValue::Unsigned(0));
        assert_eq!(CborValue::int(23), CborValue::Unsigned(23));
        assert_eq!(CborValue::int(-1), CborValue::Negative(0));
        assert_eq!(CborValue::int(-10), CborValue::Negative(9));
        assert_eq!(CborValue::int(-100), CborValue::Negative(99));
        // i64::MIN must not overflow when computing -1 - n. The CBOR argument
        // for -2^63 is 2^63 - 1 = i64::MAX as u64.
        assert_eq!(
            CborValue::int(i64::MIN),
            CborValue::Negative(i64::MAX as u64)
        );
    }

    #[test]
    fn shortest_form_integer_boundaries() {
        let cases: [(CborValue, &str); 8] = [
            (CborValue::Unsigned(0), "00"),
            (CborValue::Unsigned(23), "17"),
            (CborValue::Unsigned(24), "1818"),
            (CborValue::Unsigned(255), "18ff"),
            (CborValue::Unsigned(256), "190100"),
            (CborValue::Unsigned(65535), "19ffff"),
            (CborValue::Unsigned(65536), "1a00010000"),
            (CborValue::Unsigned(u64::MAX), "1bffffffffffffffff"),
        ];
        for (value, expected) in cases {
            assert_eq!(
                crate::hex::encode(&encode_canonical_cbor(&value).unwrap()),
                expected
            );
        }
    }

    #[test]
    fn negative_full_range() {
        // -2^64 = Negative(u64::MAX): mt-1 argument is all-ones.
        assert_eq!(
            crate::hex::encode(&encode_canonical_cbor(&CborValue::Negative(u64::MAX)).unwrap()),
            "3bffffffffffffffff"
        );
    }

    #[test]
    fn encode_rejects_duplicate_keys() {
        let map = CborValue::Map(vec![
            (CborValue::text("a"), CborValue::Unsigned(1)),
            (CborValue::text("a"), CborValue::Unsigned(2)),
        ]);
        let err = encode_canonical_cbor(&map).unwrap_err();
        assert_eq!(err.code(), CanonicalCborError::MALFORMED_CBOR);
    }

    #[test]
    fn map_keys_sort_length_first() {
        // Encoded keys: "kem"->0x63.., "aead"->0x64.. ; length-first puts the
        // 3-char key (smaller header byte) before the 4-char key, even though
        // raw UTF-8 'a' < 'k'.
        let map = CborValue::Map(vec![
            (CborValue::text("aead"), CborValue::Unsigned(1)),
            (CborValue::text("kem"), CborValue::Unsigned(2)),
        ]);
        let encoded = encode_canonical_cbor(&map).unwrap();
        // a2 | 63 6b656d 02 | 64 61656164 01  (kem before aead)
        assert_eq!(crate::hex::encode(&encoded), "a2636b656d02646165616401");
    }

    #[test]
    fn decode_round_trips_a_nested_value() {
        let value = CborValue::Map(vec![
            (CborValue::text("v"), CborValue::Unsigned(1)),
            (
                CborValue::text("items"),
                CborValue::Array(vec![CborValue::Bytes(vec![0xde, 0xad])]),
            ),
        ]);
        let bytes = encode_canonical_cbor(&value).unwrap();
        let decoded = decode_canonical_cbor(&bytes).unwrap();
        // Re-encode the decoded value: canonical form is idempotent.
        assert_eq!(encode_canonical_cbor(&decoded).unwrap(), bytes);
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        // Two top-level items back to back; the second is trailing data.
        let err = decode_canonical_cbor(&[0x00, 0x00]).unwrap_err();
        assert_eq!(err.code(), CanonicalCborError::MALFORMED_CBOR);
    }

    #[test]
    fn permissive_accepts_indefinite_array() {
        // 9f 01 02 ff = [1, 2]
        let decoded = decode_cbor_permissive(&[0x9f, 0x01, 0x02, 0xff]).unwrap();
        assert_eq!(
            decoded,
            PermissiveValue::Array(vec![
                PermissiveValue::Unsigned(1),
                PermissiveValue::Unsigned(2)
            ])
        );
    }
}
