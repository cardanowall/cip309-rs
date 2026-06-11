//! The `cardano-poe-pw-norm-v1` passphrase normalization profile.
//!
//! Two implementations MUST derive a byte-identical CEK from the same
//! passphrase, and the only way to guarantee that is a pinned normalization.
//! The profile, applied in order:
//!
//! 1. Bound the raw UTF-8 input at [`MAX_PASSPHRASE_INPUT_BYTES`] — rejected
//!    before any normalization or hashing work, closing the pre-KDF
//!    denial-of-service hole an oversized passphrase would open.
//! 2. NFKC (UAX #15) under the pinned Unicode 16.0.0 tables
//!    ([`crate::unicode_nfkc16`]). Input the pinned tables cannot normalize
//!    stably — a code point Unicode 16.0 leaves unassigned, which a later
//!    Unicode version may give a decomposition and so silently change the
//!    derived key — is rejected.
//! 3. Collapse every maximal run of `White_Space` characters (the pinned
//!    Unicode 16.0 property) to a single U+0020.
//! 4. Trim a leading/trailing collapsed space.
//! 5. Reject a post-normalization empty result: a whitespace-only passphrase
//!    normalizes to zero bytes, which Argon2id would silently accept — keying
//!    the record to a CEK any party can derive.
//!
//! The UTF-8 encoding of the result is the Argon2id password input. Case is
//! deliberately NOT folded — the CEK derivation is case-sensitive.
//!
//! Every Unicode-sensitive step resolves against the pinned Unicode 16.0.0
//! data — the NFKC tables and the `White_Space` property both — never a
//! floating engine or language predicate, whose tables move with their
//! Unicode version.

use super::errors::{EciesSealedPoeError, EciesSealedPoeErrorCode};
use crate::unicode_nfkc16::{is_white_space16, nfkc16};

/// Maximum raw passphrase length, in UTF-8 bytes, enforced BEFORE
/// normalization and the Argon2id KDF.
///
/// The bound is byte length, not code-point count, so a short string of wide
/// multi-byte characters is still measured by its encoded size. 4096 bytes is
/// far above any human-chosen passphrase. A verifier-enforced,
/// deployment-pinned reference constant — not a wire field.
pub const MAX_PASSPHRASE_INPUT_BYTES: usize = 4096;

/// The 25 codepoints carrying the Unicode `White_Space` property under Unicode
/// 16.0. The normalization profile collapses every maximal run of these to a
/// single U+0020. The collapse itself consults the pinned
/// [`is_white_space16`] predicate; this constant enumerates the same set for
/// callers that need the list (a unit test pins the two against each other).
/// It is an explicit set on purpose: neither a regex `\s` class nor a
/// language `is_whitespace` predicate matches this set exactly, and the CEK
/// derivation must be byte-identical across implementations. In particular,
/// `char::is_whitespace` also matches the C0 information separators
/// U+001C–U+001F, which are NOT `White_Space` and must NOT collapse here.
pub const UNICODE_WHITE_SPACE: [char; 25] = [
    '\u{0009}', '\u{000a}', '\u{000b}', '\u{000c}', '\u{000d}', '\u{0020}', '\u{0085}', '\u{00a0}',
    '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}',
    '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}',
    '\u{3000}',
];

/// Apply the `cardano-poe-pw-norm-v1` profile and return the normalized
/// string; its UTF-8 bytes are the Argon2id password input.
///
/// # Errors
///
/// - [`EciesSealedPoeErrorCode::PassphraseInputTooLong`] when the raw input
///   exceeds [`MAX_PASSPHRASE_INPUT_BYTES`] UTF-8 bytes (checked before any
///   normalization work).
/// - [`EciesSealedPoeErrorCode::EncPassphraseUnnormalizable`] when the input
///   contains a code point that Unicode 16.0 leaves unassigned, so the pinned
///   tables cannot normalize it stably.
/// - [`EciesSealedPoeErrorCode::EncPassphraseEmpty`] when the result is the
///   empty string (a whitespace-only or otherwise vacuous passphrase).
pub fn normalize_passphrase(passphrase: &str) -> Result<String, EciesSealedPoeError> {
    if passphrase.len() > MAX_PASSPHRASE_INPUT_BYTES {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::PassphraseInputTooLong,
            format!(
                "raw passphrase is {} UTF-8 bytes; the maximum before normalization is {MAX_PASSPHRASE_INPUT_BYTES}",
                passphrase.len()
            ),
        ));
    }

    let normalized = nfkc16(passphrase).map_err(|cause| {
        EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncPassphraseUnnormalizable,
            cause.to_string(),
        )
    })?;

    // Collapse every maximal White_Space run to one U+0020, then trim a single
    // leading/trailing collapsed space (every run is already a single space).
    let mut collapsed = String::with_capacity(normalized.len());
    let mut in_run = false;
    for ch in normalized.chars() {
        if is_white_space16(ch as u32) {
            if !in_run {
                collapsed.push(' ');
                in_run = true;
            }
        } else {
            collapsed.push(ch);
            in_run = false;
        }
    }
    let trimmed = collapsed.strip_prefix(' ').unwrap_or(&collapsed);
    let trimmed = trimmed.strip_suffix(' ').unwrap_or(trimmed);

    if trimmed.is_empty() {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncPassphraseEmpty,
            "passphrase normalizes to the empty string",
        ));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_white_space_runs_and_trims() {
        assert_eq!(
            normalize_passphrase("  alpha \t\u{00a0} beta  ").unwrap(),
            "alpha beta"
        );
        assert_eq!(
            normalize_passphrase("alpha\u{3000}beta").unwrap(),
            "alpha beta"
        );
    }

    #[test]
    fn non_white_space_separators_survive_verbatim() {
        // U+200B ZERO WIDTH SPACE and the C0 information separators are not
        // White_Space and must not collapse.
        assert_eq!(normalize_passphrase("a\u{200b}b").unwrap(), "a\u{200b}b");
        for cp in 0x1cu32..=0x1f {
            let ch = char::from_u32(cp).unwrap();
            let input = format!("a{ch}b");
            assert_eq!(normalize_passphrase(&input).unwrap(), input);
        }
    }

    #[test]
    fn unicode_white_space_const_matches_pinned_predicate() {
        let from_predicate: Vec<char> = (0u32..=0x10FFFF)
            .filter_map(char::from_u32)
            .filter(|&ch| is_white_space16(ch as u32))
            .collect();
        assert_eq!(UNICODE_WHITE_SPACE.to_vec(), from_predicate);
    }

    #[test]
    fn rejects_post_normalization_empty() {
        for vacuous in ["", " ", "\t\u{00a0}\u{3000}", "\n\r"] {
            let err = normalize_passphrase(vacuous).unwrap_err();
            assert_eq!(err.code(), "ENC_PASSPHRASE_EMPTY", "input {vacuous:?}");
        }
    }

    #[test]
    fn rejects_raw_input_over_the_byte_cap() {
        let at_cap = "a".repeat(MAX_PASSPHRASE_INPUT_BYTES);
        assert!(normalize_passphrase(&at_cap).is_ok());
        let over = "a".repeat(MAX_PASSPHRASE_INPUT_BYTES + 1);
        assert_eq!(
            normalize_passphrase(&over).unwrap_err().code(),
            "PASSPHRASE_INPUT_TOO_LONG"
        );
        // Bytes, not code points: 1025 four-byte code points exceed the cap.
        let wide = "\u{1F680}".repeat(1025);
        assert!(wide.chars().count() < MAX_PASSPHRASE_INPUT_BYTES);
        assert_eq!(
            normalize_passphrase(&wide).unwrap_err().code(),
            "PASSPHRASE_INPUT_TOO_LONG"
        );
    }

    #[test]
    fn nfkc_maps_compatibility_forms() {
        // U+FB01 LATIN SMALL LIGATURE FI decomposes to "fi" under NFKC.
        assert_eq!(normalize_passphrase("\u{fb01}sh").unwrap(), "fish");
        // Full-width digits fold to ASCII.
        assert_eq!(
            normalize_passphrase("\u{ff11}\u{ff12}\u{ff13}").unwrap(),
            "123"
        );
        // L+V+T Hangul jamo compose to the precomposed syllable U+AC01.
        assert_eq!(
            normalize_passphrase("\u{1100}\u{1161}\u{11a8}").unwrap(),
            "\u{ac01}"
        );
    }

    #[test]
    fn rejects_unassigned_codepoints_as_unnormalizable() {
        // U+0378 (BMP) and U+1FFFF (supplementary) are unassigned in Unicode
        // 16.0; a later Unicode version could give them decompositions, so
        // accepting them would let the derived key drift across
        // implementations.
        for input in ["pass\u{0378}word", "tail\u{1FFFF}"] {
            let err = normalize_passphrase(input).unwrap_err();
            assert_eq!(
                err.code(),
                "ENC_PASSPHRASE_UNNORMALIZABLE",
                "input {input:?}"
            );
        }
    }

    #[test]
    fn unnormalizable_precedes_collapse_trim_and_empty() {
        // Whitespace-only apart from the unassigned code point: were
        // collapse/trim to run first, this would surface ENC_PASSPHRASE_EMPTY.
        assert_eq!(
            normalize_passphrase(" \u{0378} ").unwrap_err().code(),
            "ENC_PASSPHRASE_UNNORMALIZABLE"
        );
    }

    #[test]
    fn raw_byte_cap_precedes_the_unnormalizable_check() {
        // U+0378 is 2 UTF-8 bytes, so the raw input is 4098 bytes: over the
        // cap, which fires before the pinned normalizer ever sees the input.
        let input = format!("\u{0378}{}", "a".repeat(MAX_PASSPHRASE_INPUT_BYTES));
        assert_eq!(
            normalize_passphrase(&input).unwrap_err().code(),
            "PASSPHRASE_INPUT_TOO_LONG"
        );
    }
}
