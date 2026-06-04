//! Crockford base32 and prefixed resource identifiers.
//!
//! Stripe-style prefixed resource IDs. The wire form is
//! `<prefix>_<26-char-crockford-base32>` over a 16-byte UUIDv7 payload. This
//! module is the only place that knows the byte-level encoding; everything else
//! consumes the helpers below.
//!
//! The Crockford alphabet is `0123456789abcdefghjkmnpqrstvwxyz` — the letters
//! `i`, `l`, `o`, `u` are excluded for visual disambiguation. Decoding is
//! case-insensitive and accepts the `I`/`L` → `1`, `O` → `0` aliases; `U` is
//! always invalid. Output is byte-identical to the TypeScript
//! (`@cardanowall/sdk-ts`) and Python (`cardanowall`) codecs.

use thiserror::Error;

/// The Crockford base32 alphabet (lowercase, value order, excludes `i l o u`).
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// The encoded length of a 16-byte UUID payload: 128 bits packs into exactly 26
/// base32 symbols (130 bits with 2 trailing zero-pad bits).
pub const CROCKFORD_ENCODED_LENGTH_FOR_UUID: usize = 26;

/// The proof-of-existence record id prefix the Label 309 standard defines.
///
/// The byte-level encode/decode helpers take an arbitrary prefix string, so any
/// gateway can mint Stripe-style `<prefix>_<base32>` ids for its own resource
/// types without an SDK bump. `poe` is the single prefix the standard itself
/// defines — the one prefixed id every Label 309 record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdPrefix {
    /// Proof-of-existence record id (`poe_…`).
    Poe,
}

impl IdPrefix {
    /// The wire prefix string for this resource type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            IdPrefix::Poe => "poe",
        }
    }
}

/// Errors raised by the Crockford base32 codec and the prefixed-id grammar.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdError {
    /// The encoder was given a payload that was not exactly 16 bytes.
    #[error("crockford-base32: expected 16 bytes, got {0}")]
    EncodeWrongByteLength(usize),

    /// The decoder was given a string that was not exactly 26 characters.
    #[error("crockford-base32: expected 26-char input, got {0}")]
    DecodeWrongLength(usize),

    /// A character was not in the Crockford alphabet (after alias mapping).
    /// Carries the character and its index.
    #[error("crockford-base32: invalid character {0:?} at index {1}")]
    InvalidCharacter(char, usize),

    /// The trailing pad bits of a 26-char input were not the canonical two zero
    /// bits the encoder emits.
    #[error("crockford-base32: non-zero pad bits at end of input")]
    NonZeroPadBits,

    /// A UUID string was not in canonical 8-4-4-4-12 hyphenated form. Carries
    /// the offending input.
    #[error("prefixed-id: not a canonical hyphenated UUID: {0:?}")]
    NotCanonicalUuid(String),

    /// A decoded payload was not 16 bytes. Carries the observed length.
    #[error("prefixed-id: expected 16 decoded bytes, got {0}")]
    DecodedNotSixteenBytes(usize),

    /// A prefixed id had no `_` separator. Carries the offending input.
    #[error("prefixed-id: missing prefix separator in {0:?}")]
    MissingSeparator(String),

    /// A prefixed id's prefix did not match the one expected. Carries the
    /// expected and actual prefixes.
    #[error("prefixed-id: expected prefix {0:?}, got {1:?}")]
    PrefixMismatch(String, String),
}

/// Map a single ASCII character to its Crockford 5-bit value, applying the
/// case-insensitive and `I`/`L` → `1`, `O` → `0` disambiguation aliases.
/// Returns `None` for any character outside the alphabet (including `u`/`U`).
fn decode_symbol(ch: char) -> Option<u8> {
    match ch {
        '0'..='9' => Some(ch as u8 - b'0'),
        'a'..='h' => Some(ch as u8 - b'a' + 10),
        'A'..='H' => Some(ch as u8 - b'A' + 10),
        'j' | 'k' => Some(ch as u8 - b'j' + 18),
        'J' | 'K' => Some(ch as u8 - b'J' + 18),
        'm' | 'n' => Some(ch as u8 - b'm' + 20),
        'M' | 'N' => Some(ch as u8 - b'M' + 20),
        'p'..='t' => Some(ch as u8 - b'p' + 22),
        'P'..='T' => Some(ch as u8 - b'P' + 22),
        'v'..='z' => Some(ch as u8 - b'v' + 27),
        'V'..='Z' => Some(ch as u8 - b'V' + 27),
        // Crockford disambiguation aliases.
        'i' | 'I' | 'l' | 'L' => Some(1),
        'o' | 'O' => Some(0),
        _ => None,
    }
}

/// Encode raw bytes as a lowercase Crockford base32 string (no padding).
///
/// Output length is `ceil(bytes.len() * 8 / 5)` with no `=` padding character.
/// For 16-byte UUIDs this produces 26 chars; for 32-byte secrets it produces 52.
#[must_use]
pub fn encode_bytes_variable_length(bytes: &[u8]) -> String {
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut out = String::new();
    for &byte in bytes {
        bits = (bits << 8) | u32::from(byte);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = ((bits >> bit_count) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bit_count > 0 {
        let idx = ((bits << (5 - bit_count)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

/// Encode exactly 16 raw bytes (a UUID payload) as a 26-char lowercase string.
///
/// # Errors
///
/// Returns [`IdError::EncodeWrongByteLength`] unless the input is exactly 16
/// bytes.
pub fn encode_bytes(bytes: &[u8]) -> Result<String, IdError> {
    if bytes.len() != 16 {
        return Err(IdError::EncodeWrongByteLength(bytes.len()));
    }
    Ok(encode_bytes_variable_length(bytes))
}

/// Decode a 26-char Crockford base32 string back to 16 raw bytes.
///
/// Case-insensitive; accepts the `I`/`L` → `1`, `O` → `0` disambiguation
/// mappings. This is the strict, wire-facing decoder: it enforces both the
/// exact 26-char length and that the two trailing pad bits are zero.
///
/// # Errors
///
/// Returns [`IdError::DecodeWrongLength`] for a wrong-length input,
/// [`IdError::InvalidCharacter`] for an out-of-alphabet character, or
/// [`IdError::NonZeroPadBits`] when the trailing pad bits are non-zero.
pub fn decode_bytes(encoded: &str) -> Result<[u8; 16], IdError> {
    if encoded.chars().count() != CROCKFORD_ENCODED_LENGTH_FOR_UUID {
        return Err(IdError::DecodeWrongLength(encoded.chars().count()));
    }
    let mut out = [0u8; 16];
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut out_idx = 0;
    for (i, ch) in encoded.chars().enumerate() {
        let value = decode_symbol(ch).ok_or(IdError::InvalidCharacter(ch, i))?;
        bits = (bits << 5) | u32::from(value);
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out[out_idx] = ((bits >> bit_count) & 0xff) as u8;
            out_idx += 1;
        }
    }
    // 26 symbols × 5 = 130 bits consumed, 16 bytes × 8 = 128 bits emitted, so
    // exactly 2 trailing zero pad bits should remain. Anything else means the
    // input was not produced by this encoder (or was tampered with).
    if bit_count != 2 || (bits & 0x3) != 0 {
        return Err(IdError::NonZeroPadBits);
    }
    Ok(out)
}

/// Convert a canonical 8-4-4-4-12 hyphenated UUID string to its 16 raw bytes.
///
/// Accepts the canonical hyphenated form only (case-insensitive): exactly four
/// hyphens and 32 hex characters after de-hyphenation.
fn uuid_string_to_bytes(uuid: &str) -> Result<[u8; 16], IdError> {
    let hyphen_count = uuid.bytes().filter(|&b| b == b'-').count();
    let stripped: String = uuid.chars().filter(|&c| c != '-').collect();
    let lowered = stripped.to_lowercase();
    let is_32_hex =
        lowered.len() == 32 && lowered.bytes().all(|b| b.is_ascii_hexdigit() && b != b'-');
    if !is_32_hex || hyphen_count != 4 {
        return Err(IdError::NotCanonicalUuid(uuid.to_string()));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&lowered[i * 2..i * 2 + 2], 16)
            .map_err(|_| IdError::NotCanonicalUuid(uuid.to_string()))?;
    }
    Ok(out)
}

/// Format 16 bytes as a canonical 8-4-4-4-12 hyphenated lowercase UUID string.
fn bytes_to_uuid_string(bytes: &[u8]) -> Result<String, IdError> {
    if bytes.len() != 16 {
        return Err(IdError::DecodedNotSixteenBytes(bytes.len()));
    }
    let h: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

/// Encode a canonical hyphenated UUID into the wire form `<prefix>_<crockford>`.
///
/// # Errors
///
/// Returns [`IdError::NotCanonicalUuid`] when `uuid` is not a canonical
/// 8-4-4-4-12 hyphenated UUID.
pub fn encode_prefixed_id(prefix: &str, uuid: &str) -> Result<String, IdError> {
    let bytes = uuid_string_to_bytes(uuid)?;
    let encoded = encode_bytes_variable_length(&bytes);
    Ok(format!("{prefix}_{encoded}"))
}

/// Decode a wire-format prefixed id back to the bare canonical UUID string.
///
/// # Errors
///
/// Returns [`IdError::MissingSeparator`] when there is no `_`,
/// [`IdError::PrefixMismatch`] when the prefix differs from `prefix`, or a
/// codec error ([`IdError::DecodeWrongLength`], [`IdError::InvalidCharacter`],
/// [`IdError::NonZeroPadBits`]) when the body is malformed.
pub fn decode_prefixed_id(prefix: &str, encoded: &str) -> Result<String, IdError> {
    let sep = encoded
        .find('_')
        .ok_or_else(|| IdError::MissingSeparator(encoded.to_string()))?;
    let actual_prefix = &encoded[..sep];
    if actual_prefix != prefix {
        return Err(IdError::PrefixMismatch(
            prefix.to_string(),
            actual_prefix.to_string(),
        ));
    }
    let body = &encoded[sep + 1..];
    let bytes = decode_bytes(body)?;
    bytes_to_uuid_string(&bytes)
}

/// Cheap strict-lowercase guard for a prefixed id (no `I`/`L`/`O`/`U` aliases,
/// no byte round-trip).
///
/// Matches the prefix and the strict lowercase Crockford alphabet but does NOT
/// validate the payload bytes round-trip. A trailing newline is rejected (the
/// body must be exactly 26 strict-lowercase Crockford characters). Use
/// [`decode_prefixed_id`] when full validation is required.
#[must_use]
pub fn is_prefixed_id(prefix: &str, candidate: &str) -> bool {
    let head = format!("{prefix}_");
    let Some(body) = candidate.strip_prefix(&head) else {
        return false;
    };
    body.len() == 26 && body.bytes().all(is_strict_crockford_lower)
}

/// True for a byte in the strict lowercase Crockford alphabet `[0-9a-hjkmnp-tv-z]`
/// (no `i l o u`, no uppercase, no aliases).
fn is_strict_crockford_lower(b: u8) -> bool {
    matches!(b,
        b'0'..=b'9'
        | b'a'..=b'h'
        | b'j' | b'k'
        | b'm' | b'n'
        | b'p'..=b't'
        | b'v'..=b'z'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poe_prefix_string_is_exact() {
        assert_eq!(IdPrefix::Poe.as_str(), "poe");
    }

    #[test]
    fn encodes_zero_and_ff_payloads() {
        assert_eq!(encode_bytes(&[0u8; 16]).unwrap(), "0".repeat(26));
        let ff = encode_bytes(&[0xffu8; 16]).unwrap();
        assert_eq!(&ff[..25], "z".repeat(25));
        assert_eq!(&ff[25..], "w");
    }

    #[test]
    fn encode_rejects_non_sixteen_bytes() {
        assert_eq!(
            encode_bytes(&[0u8; 15]),
            Err(IdError::EncodeWrongByteLength(15))
        );
        assert_eq!(
            encode_bytes(&[0u8; 17]),
            Err(IdError::EncodeWrongByteLength(17))
        );
    }

    #[test]
    fn decode_round_trips_and_accepts_aliases() {
        let bytes = [0xffu8; 16];
        let encoded = encode_bytes(&bytes).unwrap();
        assert_eq!(decode_bytes(&encoded).unwrap(), bytes);
        // Uppercase + I/L/O aliases decode to the same value.
        assert_eq!(decode_bytes(&encoded.to_uppercase()).unwrap(), bytes);
    }

    #[test]
    fn decode_rejects_u_and_wrong_length_and_pad_bits() {
        let zero = encode_bytes(&[0u8; 16]).unwrap();
        let bad = format!("u{}", &zero[1..]);
        assert!(matches!(
            decode_bytes(&bad),
            Err(IdError::InvalidCharacter('u', 0))
        ));
        assert_eq!(decode_bytes("0").err(), Some(IdError::DecodeWrongLength(1)));
        let tampered = format!("{}z", &zero[..25]);
        assert_eq!(decode_bytes(&tampered).err(), Some(IdError::NonZeroPadBits));
    }

    #[test]
    fn prefixed_id_round_trips() {
        let uuid = "01977c4a-0066-7777-aaaa-bbbbbbbbbbbb";
        let encoded = encode_prefixed_id("poe", uuid).unwrap();
        assert!(encoded.starts_with("poe_"));
        assert_eq!(decode_prefixed_id("poe", &encoded).unwrap(), uuid);
    }

    #[test]
    fn prefixed_id_rejects_bad_prefix_and_separator() {
        let encoded = encode_prefixed_id("poe", "01977c4a-0066-7777-aaaa-bbbbbbbbbbbb").unwrap();
        assert!(matches!(
            decode_prefixed_id("acct", &encoded),
            Err(IdError::PrefixMismatch(_, _))
        ));
        assert!(matches!(
            decode_prefixed_id("poe", "poenoseparatorhere00000000000000"),
            Err(IdError::MissingSeparator(_))
        ));
    }

    #[test]
    fn encode_rejects_malformed_uuid() {
        assert!(matches!(
            encode_prefixed_id("poe", "not-a-uuid"),
            Err(IdError::NotCanonicalUuid(_))
        ));
        assert!(matches!(
            encode_prefixed_id("poe", "01977c4a00667777aaaabbbbbbbbbbbb"),
            Err(IdError::NotCanonicalUuid(_))
        ));
    }

    #[test]
    fn is_prefixed_id_guard_behaviour() {
        let encoded = encode_prefixed_id("poe", "01977c4a-0066-7777-aaaa-bbbbbbbbbbbb").unwrap();
        assert!(is_prefixed_id("poe", &encoded));
        assert!(!is_prefixed_id("acct", &encoded));
        assert!(!is_prefixed_id("poe", &encoded.to_uppercase()));
        assert!(!is_prefixed_id("poe", &format!("{encoded}\n")));
        // Aliases are not the canonical wire form.
        let body = "0".repeat(26);
        assert!(!is_prefixed_id(
            "poe",
            &format!("poe_{}I{}", &body[..5], &body[6..])
        ));
        assert!(!is_prefixed_id(
            "poe",
            &format!("poe_{}u{}", &body[..5], &body[6..])
        ));
    }
}
