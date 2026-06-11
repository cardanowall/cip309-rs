//! Merkle list-commitment verification.
//!
//! For each `record.merkle[i]` the verifier obtains the leaves-list document
//! (caller-supplied bytes, or fetched from `merkle[i].uris[]` under the same
//! first-success / attribution / fetch-ceiling semantics as item content),
//! validates it against the normative CBOR leaves-list container — the ONLY
//! accepted wire form — recomputes the RFC 9162 §2.1.1 root, and compares
//! byte-exact against the on-chain commitment.
//!
//! The record-attributable codes (`SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED` /
//! `SCHEMA_MERKLE_LEAVES_MALFORMED` / `SCHEMA_MERKLE_LEAF_COUNT_MISMATCH` /
//! `MERKLE_ROOT_MISMATCH`) hold the record to account only for an ATTRIBUTABLE
//! leaves-list — supplied out-of-band, or fetched with a verified
//! content-address binding. An unattributable fetched document failing them is
//! `URI_PROVIDER_INTEGRITY_MISMATCH` (warning) and the remaining sources are
//! tried.
//!
//! A claim left with no attributable leaves-list is `MERKLE_LEAVES_UNAVAILABLE`,
//! whose severity is context-dependent (the commitment floor): warning when at
//! least one other content commitment of the record was verified, error
//! (network class, verdict `unverifiable`) when the unavailability leaves the
//! record with no verified content commitment. Because the floor needs the
//! whole-record picture, this module returns the unavailability as a PENDING
//! marker and the report assembly emits the issue once every content check has
//! run.

use subtle::ConstantTimeEq;

use crate::merkle::{decode_leaves_list, MerkleLeavesListErrorCode};
use crate::poe_standard::{ErrorCode, MerkleCommit, PathSegment};

use crate::verifier::content::{
    provider_mismatch_path, walk_blob_sources, BlobWalkEnd, ContentFetchPolicy, SourceDecision,
};
use crate::verifier::egress::GatewayFetcher;
use crate::verifier::types::{ContentCheck, VerifierIssue};

/// The single registered Merkle list-commitment algorithm in v1. This
/// verifier implements it, so `MERKLE_UNSUPPORTED` never fires here (an
/// unregistered identifier is already rejected by the structural validator
/// with `UNSUPPORTED_MERKLE_COMMIT_ALG`).
const MERKLE_ALG: &str = "rfc9162-sha256";

/// The outcome of one commitment check.
pub struct MerkleCommitOutcome {
    /// The per-claim content-check status of the list commitment.
    pub content_check: ContentCheck,
    /// Set when the claim ended unchecked because no attributable leaves-list
    /// could be obtained; the report assembly emits `MERKLE_LEAVES_UNAVAILABLE`
    /// (or `CONTENT_FETCH_LIMIT_EXCEEDED`) with floor-resolved severity.
    pub unavailable: Option<MerkleUnavailable>,
}

/// The pending unavailability marker for the commitment floor.
pub struct MerkleUnavailable {
    /// The issue path (`["merkle", i]`).
    pub path: Vec<PathSegment>,
    /// Whether a leaves-list fetch aborted at the per-URI byte ceiling.
    pub limit_exceeded: bool,
}

/// A leaves-list document rejection against the on-chain commitment.
struct LeavesRejection {
    code: ErrorCode,
    message: String,
}

/// Validate one acquired leaves-list document against the on-chain commitment:
/// container grammar, document-internal consistency, the RFC 9162 root
/// recompute, and the leaf-count binding.
fn validate_leaves_document(bytes: &[u8], commit: &MerkleCommit) -> Result<(), LeavesRejection> {
    let decoded = decode_leaves_list(bytes).map_err(|e| {
        // Container codes pass through; every other rejection is the
        // not-the-container reading.
        let code = match e.code() {
            MerkleLeavesListErrorCode::FormatUnsupported => {
                ErrorCode::SchemaMerkleLeavesFormatUnsupported
            }
            MerkleLeavesListErrorCode::LeafCountMismatch => {
                ErrorCode::SchemaMerkleLeafCountMismatch
            }
            MerkleLeavesListErrorCode::RootMismatch => ErrorCode::MerkleRootMismatch,
            MerkleLeavesListErrorCode::Malformed => ErrorCode::SchemaMerkleLeavesMalformed,
        };
        LeavesRejection {
            code,
            message: e.to_string(),
        }
    })?;
    // The codec already recomputed the root from the decoded leaves and pinned
    // the document's own `root` to it, so the document root IS the recomputed
    // root here; compare it against the on-chain commitment.
    if decoded.root.len() != commit.root.len()
        || decoded.root.as_slice().ct_eq(&commit.root).unwrap_u8() != 1
    {
        return Err(LeavesRejection {
            code: ErrorCode::MerkleRootMismatch,
            message:
                "the RFC 9162 root recomputed from the leaves-list does not equal the on-chain root"
                    .to_string(),
        });
    }
    if decoded.leaf_count as u64 != commit.leaf_count {
        return Err(LeavesRejection {
            code: ErrorCode::SchemaMerkleLeafCountMismatch,
            message: format!(
                "leaves-list carries {} leaves but the on-chain commitment declares {}",
                decoded.leaf_count, commit.leaf_count
            ),
        });
    }
    Ok(())
}

/// Check one `merkle[i]` commitment.
pub fn check_merkle_commit(
    commit: &MerkleCommit,
    commit_index: usize,
    out_of_band: Option<&[u8]>,
    fetch_content: bool,
    policy: &ContentFetchPolicy<'_>,
    fetcher: &mut GatewayFetcher<'_>,
    issues: &mut Vec<VerifierIssue>,
) -> MerkleCommitOutcome {
    let base_path = vec![
        PathSegment::Key("merkle".to_string()),
        PathSegment::Index(commit_index),
    ];

    if commit.alg != MERKLE_ALG {
        // Defence-in-depth: the structural validator already rejected unknown
        // identifiers, so an unimplemented-but-registered algorithm cannot
        // occur in v1 (the registry has exactly one member).
        let mut alg_path = base_path.clone();
        alg_path.push(PathSegment::Key("alg".to_string()));
        issues.push(VerifierIssue::new(
            ErrorCode::UnsupportedMerkleCommitAlg,
            alg_path,
            format!(
                "merkle commitment algorithm {:?} is not implemented",
                commit.alg
            ),
        ));
        return MerkleCommitOutcome {
            content_check: ContentCheck::NotChecked,
            unavailable: None,
        };
    }

    let uris = commit.uris.as_deref().unwrap_or(&[]);
    // Offline with no out-of-band document: the claim is simply not checked —
    // the fetch was suppressed by policy, not unavailable.
    if !fetch_content && out_of_band.is_none() {
        return MerkleCommitOutcome {
            content_check: ContentCheck::NotChecked,
            unavailable: None,
        };
    }

    let walk = walk_blob_sources(
        out_of_band,
        uris,
        fetch_content,
        &base_path,
        policy,
        fetcher,
        issues,
        |blob, issues| match validate_leaves_document(blob.bytes, commit) {
            Ok(()) => SourceDecision::Accept(ContentCheck::Checked),
            Err(rejection) => {
                if blob.attributable() {
                    issues.push(VerifierIssue::new(
                        rejection.code,
                        base_path.clone(),
                        rejection.message,
                    ));
                    return SourceDecision::Accept(ContentCheck::Mismatched);
                }
                issues.push(VerifierIssue::new(
                    ErrorCode::UriProviderIntegrityMismatch,
                    provider_mismatch_path(&base_path, blob),
                    format!(
                        "leaves-list bytes fetched from {:?} fail validation ({}) and could not be attributed to the URI's content address; the serving provider is indicted, not the record",
                        blob.uri.unwrap_or("unknown source"),
                        rejection.code.code()
                    ),
                ));
                SourceDecision::NextSource
            }
        },
    );

    match walk {
        BlobWalkEnd::Done(content_check) => MerkleCommitOutcome {
            content_check,
            unavailable: None,
        },
        BlobWalkEnd::Exhausted { limit_exceeded } => MerkleCommitOutcome {
            content_check: ContentCheck::NotChecked,
            unavailable: Some(MerkleUnavailable {
                path: base_path,
                limit_exceeded,
            }),
        },
    }
}
