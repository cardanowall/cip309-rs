//! Binary Merkle tree root, inclusion proof, and verification (RFC 9162).
//!
//! This module reproduces the Label 309 Merkle subsystem byte-for-byte against the
//! TypeScript (`@cardanowall/sdk-ts`) and Python (`cardanowall`) SDKs. Two
//! surfaces live here:
//!
//! - The **tree primitives** ([`merkle_root`], [`merkle_inclusion_proof`],
//!   [`verify_inclusion`]) — the RFC 9162 §2.1.1 binary Merkle tree under
//!   SHA-256, identified on the wire by [`MERKLE_ALG_ID`].
//! - The **leaves-list codec** ([`encode_leaves_list`], [`decode_leaves_list`])
//!   — the canonical-CBOR off-chain artefact that pins the leaf set behind a
//!   record's `merkle[]` commitment, identified by [`LEAVES_LIST_FORMAT_V1`].
//!
//! ## Hashing rules (RFC 9162 §2.1.1)
//!
//! RFC 9162 §2.1.1 re-publishes RFC 6962 §2.1 with identical domain separation:
//!
//! - Leaf hash: `MTH({d}) = SHA-256(0x00 || d)`.
//! - Internal node: `MTH(D) = SHA-256(0x01 || MTH(left) || MTH(right))`, where
//!   the split point `k` is the largest power of two **strictly less than** the
//!   node count `n`, the left subtree is the first `k` leaves, and the right
//!   subtree is the remaining `n - k`.
//!
//! The distinct `0x00` leaf and `0x01` internal prefixes prevent the
//! CVE-2012-2459 leaf-versus-internal collision family. Empty trees (`n == 0`)
//! are forbidden: there is no canonical root for an empty list, so the
//! primitives return an error rather than a zero or sentinel digest.

use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::cbor::{decode_canonical_cbor, encode_canonical_cbor, CborValue};
use crate::hash::sha256;

/// On-wire algorithm identifier for the RFC 9162 §2.1.1 SHA-256 Merkle tree.
///
/// Carried in a record's `merkle[]` list-commitment and in the `tree_alg` field
/// of the leaves-list. Registered in the IANA COSE Verifiable Data Structure
/// Algorithms registry (codepoint 1).
pub const MERKLE_ALG_ID: &str = "rfc9162-sha256";

/// Literal `format` value bound to the leaves-list CDDL.
///
/// Future schema revisions bump the suffix; a v1 decoder MUST reject any other
/// value with [`MerkleLeavesListErrorCode::FormatUnsupported`].
pub const LEAVES_LIST_FORMAT_V1: &str = "cardano-poe-merkle-leaves-v1";

/// Length in bytes of every leaf digest and the Merkle root (SHA-256).
const DIGEST_LENGTH: usize = 32;

/// Leaf domain-separation prefix: `SHA-256(0x00 || d)`.
const LEAF_PREFIX: u8 = 0x00;

/// Internal-node domain-separation prefix: `SHA-256(0x01 || left || right)`.
const NODE_PREFIX: u8 = 0x01;

// ---------------------------------------------------------------------------
// Tree primitives
// ---------------------------------------------------------------------------

/// Structural rejection raised by [`merkle_root`] and [`merkle_inclusion_proof`].
///
/// [`verify_inclusion`] never raises this — verification is a Boolean predicate
/// that returns `false` on any inconsistency rather than erroring.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MerkleError {
    /// The leaf list was empty. RFC 9162 §2.1.1 defines no root for `n == 0`,
    /// so an empty tree is forbidden rather than collapsed to a sentinel digest.
    #[error("empty Merkle tree forbidden (n >= 1)")]
    EmptyTree,

    /// The inclusion-proof index was outside `[0, tree_size)`.
    #[error("index {index} out of range for tree_size {tree_size}")]
    IndexOutOfRange {
        /// The requested leaf index.
        index: usize,
        /// The number of leaves in the tree.
        tree_size: usize,
    },
}

/// Compute the canonical Merkle root per RFC 9162 §2.1.1 (SHA-256).
///
/// Each leaf is a bare 32-byte digest. For a single-leaf tree the root is
/// `SHA-256(0x00 || d_0)` — the leaf prefix means the root never equals the bare
/// leaf digest.
///
/// # Errors
///
/// Returns [`MerkleError::EmptyTree`] if `leaves` is empty.
pub fn merkle_root(leaves: &[[u8; DIGEST_LENGTH]]) -> Result<[u8; DIGEST_LENGTH], MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyTree);
    }
    Ok(root_unchecked(leaves))
}

/// Compute the inclusion proof (audit path) for the leaf at `index`.
///
/// The returned siblings are ordered leaf-to-root: element `0` is the sibling at
/// the leaf level and the last element is the top-level sibling. A single-leaf
/// tree has an empty proof (RFC 9162 §2.1.1).
///
/// # Errors
///
/// Returns [`MerkleError::EmptyTree`] if `leaves` is empty, or
/// [`MerkleError::IndexOutOfRange`] if `index >= leaves.len()`.
pub fn merkle_inclusion_proof(
    leaves: &[[u8; DIGEST_LENGTH]],
    index: usize,
) -> Result<Vec<[u8; DIGEST_LENGTH]>, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyTree);
    }
    if index >= leaves.len() {
        return Err(MerkleError::IndexOutOfRange {
            index,
            tree_size: leaves.len(),
        });
    }
    Ok(audit_path(leaves, index))
}

/// Verify an inclusion proof per RFC 9162 §2.1.3.2 (iterative form).
///
/// Returns `true` iff folding `proof` over `leaf` reconstructs a digest equal to
/// `root` (compared in constant time). Any structural inconsistency — a
/// wrong-length input, an out-of-range index, or a proof whose length does not
/// match the tree depth — returns `false`. Verification is a predicate, never a
/// parser, so it does not error.
///
/// `proof` is ordered leaf-to-root, matching [`merkle_inclusion_proof`]. The
/// fold tracks the leaf index `m` within the current subtree and the last index
/// `last = tree_size - 1`: at each step the current node is a right child (its
/// sibling on the left) when `m` is odd or `m == last`, otherwise a left child
/// (sibling on the right). This handles non-power-of-two trees, where a lone
/// right subtree is promoted without contributing a sibling.
#[must_use]
pub fn verify_inclusion(
    leaf: &[u8],
    index: usize,
    tree_size: usize,
    proof: &[[u8; DIGEST_LENGTH]],
    root: &[u8],
) -> bool {
    if leaf.len() != DIGEST_LENGTH || root.len() != DIGEST_LENGTH {
        return false;
    }
    if tree_size < 1 || index >= tree_size {
        return false;
    }

    if tree_size == 1 {
        // A single-leaf tree admits only the trivial empty-path proof at index 0.
        // The root MUST equal SHA-256(0x00 || leaf), never the bare leaf.
        if !proof.is_empty() || index != 0 {
            return false;
        }
        return ct_eq(&hash_leaf(leaf), root);
    }

    // `m` is the leaf index within the current subtree; `last` is the index of
    // the last leaf in that subtree. Both halve as the fold ascends a level.
    let mut m = index;
    let mut last = tree_size - 1;
    let mut h = hash_leaf(leaf);
    for sibling in proof {
        if last == 0 {
            // More siblings were supplied than the tree has levels.
            return false;
        }
        if (m & 1) == 1 || m == last {
            // Current node is the right child: its sibling is on the left.
            h = hash_node(sibling, &h);
            // A right-most carried node (even `m`, `m == last`) walks both
            // counters upward until it lands on a genuine right child.
            while (m & 1) == 0 && m != 0 {
                m >>= 1;
                last >>= 1;
            }
        } else {
            // Current node is the left child: its sibling is on the right.
            h = hash_node(&h, sibling);
        }
        m >>= 1;
        last >>= 1;
    }
    if last != 0 {
        // The proof was shorter than the tree's depth.
        return false;
    }
    ct_eq(&h, root)
}

/// Largest power of two strictly less than `n`; `n` MUST be `>= 2`.
fn largest_pow2_lt(n: usize) -> usize {
    debug_assert!(n >= 2, "largest_pow2_lt requires n >= 2");
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Leaf hash: `SHA-256(0x00 || d)`.
fn hash_leaf(d: &[u8]) -> [u8; DIGEST_LENGTH] {
    let mut buf = Vec::with_capacity(1 + d.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(d);
    sha256(&buf)
}

/// Internal-node hash: `SHA-256(0x01 || left || right)`.
fn hash_node(left: &[u8], right: &[u8]) -> [u8; DIGEST_LENGTH] {
    let mut buf = Vec::with_capacity(1 + left.len() + right.len());
    buf.push(NODE_PREFIX);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    sha256(&buf)
}

/// Recursive Merkle root over a non-empty leaf slice.
fn root_unchecked(leaves: &[[u8; DIGEST_LENGTH]]) -> [u8; DIGEST_LENGTH] {
    if leaves.len() == 1 {
        return hash_leaf(&leaves[0]);
    }
    let k = largest_pow2_lt(leaves.len());
    let left = root_unchecked(&leaves[..k]);
    let right = root_unchecked(&leaves[k..]);
    hash_node(&left, &right)
}

/// Recursive audit path (leaf-to-root) for the leaf at `index` within `leaves`.
fn audit_path(leaves: &[[u8; DIGEST_LENGTH]], index: usize) -> Vec<[u8; DIGEST_LENGTH]> {
    if leaves.len() == 1 {
        return Vec::new();
    }
    let k = largest_pow2_lt(leaves.len());
    if index < k {
        // Leaf is in the left subtree; the sibling is the right-subtree root.
        let mut path = audit_path(&leaves[..k], index);
        path.push(root_unchecked(&leaves[k..]));
        path
    } else {
        // Leaf is in the right subtree; the sibling is the left-subtree root.
        let mut path = audit_path(&leaves[k..], index - k);
        path.push(root_unchecked(&leaves[..k]));
        path
    }
}

/// Constant-time equality of two equal-length byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}

// ---------------------------------------------------------------------------
// Leaves-list codec
// ---------------------------------------------------------------------------

/// Stable discriminator for a [`MerkleLeavesListError`].
///
/// The string form (via [`code`](MerkleLeavesListErrorCode::code)) matches the
/// `code` carried by the Python SDK's `MerkleLeavesListError` byte-for-byte, so
/// cross-implementation tests can assert the exact same string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleLeavesListErrorCode {
    /// The payload is not a well-formed leaves-list: not a CBOR map, a
    /// wrong-typed or wrong-length field, an empty leaf array, or undecodable
    /// CBOR.
    Malformed,
    /// The `format` field is a string but not a registered leaves-list format.
    FormatUnsupported,
    /// The declared `leaf_count` does not equal the number of leaves present.
    LeafCountMismatch,
    /// The declared `root` does not match the root recomputed from the leaves.
    RootMismatch,
}

impl MerkleLeavesListErrorCode {
    /// The stable wire string for this code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            MerkleLeavesListErrorCode::Malformed => "SCHEMA_MERKLE_LEAVES_MALFORMED",
            MerkleLeavesListErrorCode::FormatUnsupported => {
                "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED"
            }
            MerkleLeavesListErrorCode::LeafCountMismatch => "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
            MerkleLeavesListErrorCode::RootMismatch => "MERKLE_ROOT_MISMATCH",
        }
    }
}

/// A structural or schema rejection from the leaves-list codec.
///
/// Carries a typed [`code`](MerkleLeavesListError::code) discriminator plus a
/// human-readable detail. The [`Display`](core::fmt::Display) form is
/// `"<CODE>: <detail>"`, mirroring the TypeScript and Python twins.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{}: {detail}", code.code())]
pub struct MerkleLeavesListError {
    code: MerkleLeavesListErrorCode,
    detail: String,
}

impl MerkleLeavesListError {
    /// The typed discriminator for this rejection.
    #[must_use]
    pub const fn code(&self) -> MerkleLeavesListErrorCode {
        self.code
    }

    /// The stable wire string for this rejection's code (e.g.
    /// `"MERKLE_ROOT_MISMATCH"`).
    #[must_use]
    pub const fn code_str(&self) -> &'static str {
        self.code.code()
    }

    fn new(code: MerkleLeavesListErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// A decoded leaves-list, returned by [`decode_leaves_list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLeavesList {
    /// The leaves-list `format` literal (always [`LEAVES_LIST_FORMAT_V1`]).
    pub format: String,
    /// The Merkle `tree_alg` identifier carried in the payload.
    pub tree_alg: String,
    /// The declared Merkle root (verified against the recomputed root).
    pub root: [u8; DIGEST_LENGTH],
    /// The leaf digests, in order.
    pub leaves: Vec<[u8; DIGEST_LENGTH]>,
    /// The number of leaves (equals `leaves.len()`).
    pub leaf_count: usize,
    /// The optional `leaf_alg` field, present only when the payload carried it.
    pub leaf_alg: Option<String>,
}

/// Encode a leaves-list to canonical CBOR (RFC 8949 §4.2.1).
///
/// `leaf_count` is set automatically to `leaves.len()`. The map keys are emitted
/// in canonical (length-first then bytewise) order, so the on-wire key order is
/// fixed regardless of construction order: `root` < `format` < `leaves` <
/// `leaf_alg` < `tree_alg` < `leaf_count`.
///
/// # Errors
///
/// Returns [`MerkleLeavesListErrorCode::Malformed`] if `leaves` is empty. (Leaf
/// and root lengths are guaranteed at the type level by the `[u8; 32]` element
/// type.)
pub fn encode_leaves_list(
    leaves: &[[u8; DIGEST_LENGTH]],
    root: &[u8; DIGEST_LENGTH],
    leaf_alg: Option<&str>,
) -> Result<Vec<u8>, MerkleLeavesListError> {
    if leaves.is_empty() {
        return Err(MerkleLeavesListError::new(
            MerkleLeavesListErrorCode::Malformed,
            "leaves must be a non-empty list",
        ));
    }

    let mut pairs = vec![
        (
            CborValue::text("format"),
            CborValue::text(LEAVES_LIST_FORMAT_V1),
        ),
        (CborValue::text("tree_alg"), CborValue::text(MERKLE_ALG_ID)),
        (CborValue::text("root"), CborValue::bytes(root.to_vec())),
        (
            CborValue::text("leaves"),
            CborValue::Array(
                leaves
                    .iter()
                    .map(|l| CborValue::bytes(l.to_vec()))
                    .collect(),
            ),
        ),
        (
            CborValue::text("leaf_count"),
            CborValue::Unsigned(leaves.len() as u64),
        ),
    ];
    if let Some(alg) = leaf_alg {
        pairs.push((CborValue::text("leaf_alg"), CborValue::text(alg)));
    }

    encode_canonical_cbor(&CborValue::Map(pairs)).map_err(|e| {
        MerkleLeavesListError::new(
            MerkleLeavesListErrorCode::Malformed,
            format!("canonical CBOR encode failed: {e}"),
        )
    })
}

/// Decode and validate a canonical-CBOR leaves-list.
///
/// The payload MUST be a CBOR map carrying a registered `format`, a string
/// `tree_alg`, a 32-byte `root`, a non-empty array of 32-byte `leaves`, and a
/// `leaf_count` equal to the number of leaves. As defence-in-depth the Merkle
/// root is recomputed from the decoded leaves and compared (constant time)
/// against the declared `root`.
///
/// # Errors
///
/// - [`Malformed`](MerkleLeavesListErrorCode::Malformed) — undecodable CBOR, a
///   non-map top level, or any wrong-typed / wrong-length field.
/// - [`FormatUnsupported`](MerkleLeavesListErrorCode::FormatUnsupported) — a
///   string `format` that is not registered.
/// - [`LeafCountMismatch`](MerkleLeavesListErrorCode::LeafCountMismatch) —
///   `leaf_count` does not equal `leaves.len()`.
/// - [`RootMismatch`](MerkleLeavesListErrorCode::RootMismatch) — the recomputed
///   root does not match the declared `root`.
pub fn decode_leaves_list(bytes: &[u8]) -> Result<DecodedLeavesList, MerkleLeavesListError> {
    let decoded = decode_canonical_cbor(bytes).map_err(|e| {
        MerkleLeavesListError::new(
            MerkleLeavesListErrorCode::Malformed,
            format!("CBOR decode failed: {e}"),
        )
    })?;

    let pairs = match &decoded {
        CborValue::Map(pairs) => pairs,
        _ => {
            return Err(MerkleLeavesListError::new(
                MerkleLeavesListErrorCode::Malformed,
                "top-level must be a CBOR map",
            ));
        }
    };

    let format = match map_get(pairs, "format") {
        Some(CborValue::Text(s)) => s.clone(),
        _ => {
            return Err(MerkleLeavesListError::new(
                MerkleLeavesListErrorCode::Malformed,
                "`format` must be a text string",
            ));
        }
    };
    if format != LEAVES_LIST_FORMAT_V1 {
        return Err(MerkleLeavesListError::new(
            MerkleLeavesListErrorCode::FormatUnsupported,
            format!("unsupported leaves-list format: {format:?}"),
        ));
    }

    let tree_alg = match map_get(pairs, "tree_alg") {
        Some(CborValue::Text(s)) => s.clone(),
        _ => {
            return Err(MerkleLeavesListError::new(
                MerkleLeavesListErrorCode::Malformed,
                "`tree_alg` must be a text string",
            ));
        }
    };
    if tree_alg != MERKLE_ALG_ID {
        return Err(MerkleLeavesListError::new(
            MerkleLeavesListErrorCode::Malformed,
            format!("unsupported leaves-list tree_alg: {tree_alg:?}"),
        ));
    }

    let root = match map_get(pairs, "root") {
        Some(CborValue::Bytes(b)) if b.len() == DIGEST_LENGTH => {
            let mut out = [0u8; DIGEST_LENGTH];
            out.copy_from_slice(b);
            out
        }
        _ => {
            return Err(MerkleLeavesListError::new(
                MerkleLeavesListErrorCode::Malformed,
                "`root` must be a 32-byte byte string",
            ));
        }
    };

    let leaves_raw = match map_get(pairs, "leaves") {
        Some(CborValue::Array(items)) if !items.is_empty() => items,
        _ => {
            return Err(MerkleLeavesListError::new(
                MerkleLeavesListErrorCode::Malformed,
                "`leaves` must be a non-empty array",
            ));
        }
    };
    let mut leaves: Vec<[u8; DIGEST_LENGTH]> = Vec::with_capacity(leaves_raw.len());
    for (i, item) in leaves_raw.iter().enumerate() {
        match item {
            CborValue::Bytes(b) if b.len() == DIGEST_LENGTH => {
                let mut out = [0u8; DIGEST_LENGTH];
                out.copy_from_slice(b);
                leaves.push(out);
            }
            _ => {
                return Err(MerkleLeavesListError::new(
                    MerkleLeavesListErrorCode::Malformed,
                    format!("`leaves[{i}]` must be a 32-byte byte string"),
                ));
            }
        }
    }

    let leaf_count = match map_get(pairs, "leaf_count") {
        Some(CborValue::Unsigned(n)) => *n,
        _ => {
            return Err(MerkleLeavesListError::new(
                MerkleLeavesListErrorCode::Malformed,
                "`leaf_count` must be a non-negative integer",
            ));
        }
    };
    if leaf_count != leaves.len() as u64 {
        return Err(MerkleLeavesListError::new(
            MerkleLeavesListErrorCode::LeafCountMismatch,
            format!(
                "`leaf_count` ({leaf_count}) does not match number of leaves ({})",
                leaves.len()
            ),
        ));
    }

    let leaf_alg = match map_get(pairs, "leaf_alg") {
        None => None,
        Some(CborValue::Text(s)) => Some(s.clone()),
        Some(_) => {
            return Err(MerkleLeavesListError::new(
                MerkleLeavesListErrorCode::Malformed,
                "`leaf_alg` (if present) must be a text string",
            ));
        }
    };

    // Defence-in-depth: recompute the root from the decoded leaves and compare
    // it (constant time) against the declared root.
    let recomputed = root_unchecked(&leaves);
    if !ct_eq(&recomputed, &root) {
        return Err(MerkleLeavesListError::new(
            MerkleLeavesListErrorCode::RootMismatch,
            "leaves recompute does not match declared root",
        ));
    }

    Ok(DecodedLeavesList {
        format,
        tree_alg,
        root,
        leaf_count: leaves.len(),
        leaves,
        leaf_alg,
    })
}

/// Look up a text-keyed entry in a decoded CBOR map.
fn map_get<'a>(pairs: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    pairs.iter().find_map(|(k, v)| match k {
        CborValue::Text(t) if t == key => Some(v),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_point_is_largest_power_of_two_strictly_less_than_n() {
        // RFC 9162 §2.1.1: k is the largest power of two STRICTLY below n, so a
        // power-of-two n splits into n/2 + n/2, not (n-1) + 1.
        assert_eq!(largest_pow2_lt(2), 1);
        assert_eq!(largest_pow2_lt(3), 2);
        assert_eq!(largest_pow2_lt(4), 2);
        assert_eq!(largest_pow2_lt(5), 4);
        assert_eq!(largest_pow2_lt(7), 4);
        assert_eq!(largest_pow2_lt(8), 4);
        assert_eq!(largest_pow2_lt(9), 8);
        assert_eq!(largest_pow2_lt(16), 8);
        assert_eq!(largest_pow2_lt(17), 16);
    }

    #[test]
    fn leaf_and_node_prefixes_differ() {
        // The 0x00 leaf and 0x01 node prefixes prevent the CVE-2012-2459
        // leaf-versus-internal collision: hashing the same 32 bytes as a leaf
        // and as the left half of a node must yield different digests.
        let d = [0x42u8; 32];
        assert_ne!(hash_leaf(&d), hash_node(&d, &d));
    }

    #[test]
    fn error_code_strings_are_stable() {
        assert_eq!(
            MerkleLeavesListErrorCode::Malformed.code(),
            "SCHEMA_MERKLE_LEAVES_MALFORMED"
        );
        assert_eq!(
            MerkleLeavesListErrorCode::FormatUnsupported.code(),
            "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED"
        );
        assert_eq!(
            MerkleLeavesListErrorCode::LeafCountMismatch.code(),
            "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH"
        );
        assert_eq!(
            MerkleLeavesListErrorCode::RootMismatch.code(),
            "MERKLE_ROOT_MISMATCH"
        );
    }

    #[test]
    fn leaves_list_error_display_is_code_colon_detail() {
        let err =
            MerkleLeavesListError::new(MerkleLeavesListErrorCode::RootMismatch, "boom".to_string());
        assert_eq!(err.to_string(), "MERKLE_ROOT_MISMATCH: boom");
        assert_eq!(err.code_str(), "MERKLE_ROOT_MISMATCH");
    }

    #[test]
    fn decode_rejects_unsupported_tree_alg() {
        // A well-formed leaves-list whose `tree_alg` is outside the v1 registry
        // must be rejected as SCHEMA_MERKLE_LEAVES_MALFORMED — the v1 tree
        // algorithm is the only one the leaf/node hashing reproduces.
        let leaves = [[0xa1u8; DIGEST_LENGTH], [0xa2u8; DIGEST_LENGTH]];
        let root = root_unchecked(&leaves);
        let pairs = vec![
            (
                CborValue::text("format"),
                CborValue::text(LEAVES_LIST_FORMAT_V1),
            ),
            (CborValue::text("root"), CborValue::bytes(root.to_vec())),
            (
                CborValue::text("leaves"),
                CborValue::Array(
                    leaves
                        .iter()
                        .map(|l| CborValue::bytes(l.to_vec()))
                        .collect(),
                ),
            ),
            (CborValue::text("tree_alg"), CborValue::text("not-rfc9162")),
            (
                CborValue::text("leaf_count"),
                CborValue::Unsigned(leaves.len() as u64),
            ),
        ];
        let bytes = encode_canonical_cbor(&CborValue::Map(pairs)).unwrap();
        let err = decode_leaves_list(&bytes).expect_err("wrong tree_alg must reject");
        assert_eq!(err.code(), MerkleLeavesListErrorCode::Malformed);
        assert_eq!(err.code_str(), "SCHEMA_MERKLE_LEAVES_MALFORMED");
    }
}
