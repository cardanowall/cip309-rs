//! Hash primitives: SHA-256, BLAKE2b-256, and dual-hash digests.
//!
//! These are the closed-catalogue content-hash primitives of the Label 309
//! standard. Both algorithms are registered under stable wire identifiers
//! ([`SHA2_256_ID`] / [`BLAKE2B_256_ID`]); a record may publish a content
//! digest under either, and [`dual_hash`] computes both at once for callers
//! that publish under both identifiers in the same record.
//!
//! Every output here is byte-identical to the TypeScript (`@cardanowall/sdk-ts`)
//! and Python (`cardanowall-sdk`) SDKs and is pinned against the shared
//! known-answer-test fixtures.

// SHA-256 and SHA-3 ride the `digest` 0.11 traits (re-exported by `sha2` /
// `sha3` 0.11). BLAKE2b rides the `digest` 0.10 traits (re-exported by
// `blake2` 0.10). The two trait generations are deliberately kept apart — they
// have incompatible `Digest`/`Update` traits, so we import each crate's own
// `Digest` under a local alias rather than trying to unify them.
use blake2::digest::consts::U32;
use blake2::digest::Digest as Blake2Digest;
use blake2::Blake2b;
use sha2::{Digest as Sha2Digest, Sha256};

/// Wire identifier for the SHA-256 content-hash algorithm.
///
/// Used as the key under which a SHA-256 digest is published in a Label 309
/// record's hash map.
pub const SHA2_256_ID: &str = "sha2-256";

/// Wire identifier for the BLAKE2b-256 content-hash algorithm.
///
/// Used as the key under which a BLAKE2b-256 digest is published in a Label 309
/// record's hash map.
pub const BLAKE2B_256_ID: &str = "blake2b-256";

/// True 32-byte parameterized BLAKE2b digest.
///
/// This is BLAKE2b with the output length parameter set to 32 (no key, salt,
/// or personalization), per RFC 7693. It is **not** BLAKE2b-512 truncated to
/// 32 bytes: the output-length parameter feeds the initial state, so the two
/// constructions produce different digests.
type Blake2b256 = Blake2b<U32>;

/// Compute the SHA-256 digest of `input`.
///
/// Returns the 32-byte digest. The empty input hashes to the well-known
/// `e3b0c442…` value.
///
/// ```
/// use cardanowall::hash::sha256;
/// assert_eq!(
///     cardanowall::hex::encode(&sha256(b"abc")),
///     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
/// );
/// ```
#[must_use]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(input);
    digest.into()
}

/// Compute the BLAKE2b-256 digest of `input`.
///
/// This is the true 32-byte parameterized BLAKE2b digest, not a truncation of
/// BLAKE2b-512. The empty input hashes to `0e5751c0…`.
///
/// ```
/// use cardanowall::hash::blake2b256;
/// assert_eq!(
///     cardanowall::hex::encode(&blake2b256(b"")),
///     "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
/// );
/// ```
#[must_use]
pub fn blake2b256(input: &[u8]) -> [u8; 32] {
    let digest = Blake2b256::digest(input);
    digest.into()
}

/// Both content-hash digests of the same bytes.
///
/// Carries an independent SHA-256 and BLAKE2b-256 digest of one input, for
/// callers publishing a record under both algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DualHashOutput {
    /// The SHA-256 digest, registered under [`SHA2_256_ID`].
    pub sha256: [u8; 32],
    /// The BLAKE2b-256 digest, registered under [`BLAKE2B_256_ID`].
    pub blake2b256: [u8; 32],
}

/// Compute both the SHA-256 and BLAKE2b-256 digests of `input` in one call.
///
/// The two digests are independent hashes of the same bytes; this is a
/// convenience over calling [`sha256`] and [`blake2b256`] separately.
///
/// ```
/// use cardanowall::hash::dual_hash;
/// let out = dual_hash(b"abc");
/// assert_eq!(out.sha256, cardanowall::hash::sha256(b"abc"));
/// assert_eq!(out.blake2b256, cardanowall::hash::blake2b256(b"abc"));
/// ```
#[must_use]
pub fn dual_hash(input: &[u8]) -> DualHashOutput {
    DualHashOutput {
        sha256: sha256(input),
        blake2b256: blake2b256(input),
    }
}

/// Compute both content-hash digests over a stream of byte chunks.
///
/// Equivalent to [`dual_hash`] over the concatenation of all chunks, but
/// without holding the whole input in memory. Hashing one large input or
/// streaming it in arbitrary chunk boundaries yields the same digests.
///
/// ```
/// use cardanowall::hash::{dual_hash, dual_hash_stream};
/// let whole = b"the quick brown fox";
/// let streamed = dual_hash_stream([&whole[..4], &whole[4..]]);
/// assert_eq!(streamed, dual_hash(whole));
/// ```
pub fn dual_hash_stream<I, C>(chunks: I) -> DualHashOutput
where
    I: IntoIterator<Item = C>,
    C: AsRef<[u8]>,
{
    let mut sha = Sha256::new();
    let mut blake = Blake2b256::new();
    for chunk in chunks {
        let bytes = chunk.as_ref();
        Sha2Digest::update(&mut sha, bytes);
        Blake2Digest::update(&mut blake, bytes);
    }
    DualHashOutput {
        sha256: sha.finalize().into(),
        blake2b256: blake.finalize().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty_is_well_known() {
        assert_eq!(
            crate::hex::encode(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    #[test]
    fn blake2b256_is_parameterized_not_truncated_512() {
        // The 32-byte parameterized digest of the empty input. A truncation of
        // BLAKE2b-512 would produce a different value, so this pins the
        // parameterization.
        assert_eq!(
            crate::hex::encode(&blake2b256(b"")),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
        );
    }

    #[test]
    fn dual_hash_matches_individual_digests() {
        let input = b"the quick brown fox";
        let out = dual_hash(input);
        assert_eq!(out.sha256, sha256(input));
        assert_eq!(out.blake2b256, blake2b256(input));
    }

    #[test]
    fn streaming_equals_one_shot_across_chunk_boundaries() {
        let input: Vec<u8> = (0u16..=300).map(|b| b as u8).collect();
        let one_shot = dual_hash(&input);
        for chunk_size in [1usize, 7, 64, 128, 256] {
            let chunks: Vec<&[u8]> = input.chunks(chunk_size).collect();
            assert_eq!(
                dual_hash_stream(chunks),
                one_shot,
                "chunk_size={chunk_size}"
            );
        }
    }

    #[test]
    fn wire_identifiers_are_stable() {
        assert_eq!(SHA2_256_ID, "sha2-256");
        assert_eq!(BLAKE2B_256_ID, "blake2b-256");
    }
}
