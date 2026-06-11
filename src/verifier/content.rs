//! Content acquisition with attribution — the shared engine behind the three
//! fetching consumers (plain-item digests, Merkle leaves-lists, sealed
//! ciphertext).
//!
//! Multiple URIs are alternative sources for the same bytes, processed
//! first-success-for-availability: sources are walked in order (caller-supplied
//! out-of-band bytes first, then each URI against its scheme's gateway chain)
//! and the consumer stops at the first source satisfying its claim. Every
//! walked blob knows its ATTRIBUTION — whether the bytes are bound to the URI's
//! content address (or were supplied out-of-band) — which decides whether a
//! mismatch condemns the record or merely indicts the serving provider:
//!
//! - out-of-band bytes → attributable;
//! - `ipfs://` raw-codec CIDv1 → attributable iff the multihash recompute over
//!   the fetched bytes verifies;
//! - everything else fetched → unattributable (no binding check implemented
//!   for `ar://` L1 / ANS-104 or DAG-form CIDs), so mismatches route through
//!   `URI_PROVIDER_INTEGRITY_MISMATCH`.
//!
//! Per-attempt diagnostics land in the issue list (`URI_FETCH_FAILED`
//! warnings, `URI_TARGET_FORBIDDEN` refusals, `SERVICE_INDEPENDENCE_VIOLATION`
//! on a denied host), each at the claim's `uris[j]` path; the per-claim END
//! state (`CONTENT_UNAVAILABLE` vs `CONTENT_FETCH_LIMIT_EXCEEDED` vs the
//! claim-specific availability code) is the consumer's to emit, with the
//! walk's `limit_exceeded` flag recording whether an attempt aborted at the
//! `max_fetch_bytes` ceiling. A ceiling abort ENDS the claim: every URI of a
//! claim addresses the same bytes, so any other honest source would abort at
//! the same ceiling.

use std::cell::Cell;

use subtle::ConstantTimeEq;

use crate::hash::{blake2b256, sha256};
use crate::poe_standard::{ErrorCode, ItemEntry, PathSegment};

use crate::verifier::egress::GatewayFetcher;
use crate::verifier::fetch::{FetchOutboundOptions, HttpMethod, HttpPurpose, OutboundError};
use crate::verifier::types::{ContentCheck, VerifierIssue};

/// The default Arweave gateway rotation, tried in order.
///
/// IPFS has NO baked-in default: IPFS gateways are not the producer's storage
/// provider, and a silent fallback would couple the verifier to an off-record
/// gateway — a deployment that fetches `ipfs://` must configure its own chain,
/// and one that does not is a deployment that declines IPFS
/// (`URI_TARGET_FORBIDDEN` at fetch time).
pub const ARWEAVE_GATEWAY_DEFAULTS: [&str; 3] = [
    "https://arweave.net",
    "https://ar-io.net",
    "https://g8way.io",
];

/// Gateway chains and fetch policy shared by every content consumer of a run.
pub struct ContentFetchPolicy<'a> {
    /// The Arweave gateway rotation (defaults applied by the caller).
    pub arweave_gateways: &'a [String],
    /// The IPFS gateway rotation; empty declines every `ipfs://` fetch.
    pub ipfs_gateways: &'a [String],
    /// The per-URI fetch ceiling in bytes (`None` → transport default).
    pub max_fetch_bytes: Option<u64>,
}

/// How a blob entered the run, for attribution and diagnostics.
enum BlobBinding<'x> {
    /// Caller-supplied bytes: attributable by definition.
    OutOfBand,
    /// Fetched from an `ipfs://` URI whose authority may bind the bytes.
    IpfsCid {
        /// The CID (the URI's authority component).
        cid: &'x str,
        /// Whether the URI carried a `/`-prefixed path component.
        has_path: bool,
    },
    /// Fetched under a scheme with no implemented binding check.
    Unsupported,
}

/// One candidate byte blob for a claim, with lazy content-address attribution.
pub struct AcquiredBlob<'x> {
    /// The blob bytes.
    pub bytes: &'x [u8],
    /// The source URI, absent for out-of-band bytes.
    pub uri: Option<&'x str>,
    /// The `uris[]` index of the source URI, absent for out-of-band bytes.
    pub uri_index: Option<usize>,
    binding: BlobBinding<'x>,
    // The binding check is memoized and runs only when a consumer actually
    // needs attribution (the mismatch path): bytes that satisfy the record's
    // own commitment never need it — the record's commitment is at least as
    // strong as the storage layer's.
    attribution: Cell<Option<bool>>,
}

impl AcquiredBlob<'_> {
    /// Whether the bytes are bound to their content address (or were supplied
    /// out-of-band). Attributable bytes failing a commitment condemn the
    /// record; unattributable ones indict only the serving provider.
    #[must_use]
    pub fn attributable(&self) -> bool {
        if let Some(memo) = self.attribution.get() {
            return memo;
        }
        let verified = match &self.binding {
            BlobBinding::OutOfBand => true,
            BlobBinding::Unsupported => false,
            BlobBinding::IpfsCid { cid, has_path } => {
                verify_ipfs_cid_binding(cid, *has_path, self.bytes) == CidBindingOutcome::Verified
            }
        };
        self.attribution.set(Some(verified));
        verified
    }
}

/// A consumer's decision over one walked blob.
pub enum SourceDecision<T> {
    /// Terminal outcome for the claim; the remaining sources are skipped.
    Accept(T),
    /// This blob did not settle the claim (an unattributable mismatch indicts
    /// the gateway, not the address); continue with the remaining sources.
    NextSource,
}

/// The end state of an exhausted source walk.
pub enum BlobWalkEnd<T> {
    /// A source produced a terminal outcome.
    Done(T),
    /// Every source was consumed without a terminal outcome.
    Exhausted {
        /// Whether any fetch attempt aborted at the per-URI byte ceiling.
        limit_exceeded: bool,
    },
}

/// One parsed fetchable URI.
enum FetchTarget<'x> {
    Arweave {
        txid: &'x str,
    },
    Ipfs {
        /// The CID plus any `/`-prefixed path, exactly as published.
        cid_and_path: &'x str,
        /// The bare CID (the authority component).
        cid: &'x str,
        /// Whether the URI carries a path component.
        has_path: bool,
    },
}

/// Walk a claim's candidate blobs in source order — caller-supplied
/// out-of-band bytes first, then (when `allow_fetch`) each URI in record order
/// against its scheme's gateway chain — handing each to `consume` until a
/// source is terminal.
///
/// Per-attempt diagnostics are recorded on `issues` at
/// `base_path + ["uris", j]`: `URI_FETCH_FAILED` for a failed gateway attempt,
/// `URI_TARGET_FORBIDDEN` for a refused target (a scheme outside the closed
/// fetch set, or an `ipfs://` URI under a deployment with no IPFS chain), and
/// `SERVICE_INDEPENDENCE_VIOLATION` for a call the egress hard-failed against
/// the deny-host list. A fetch aborted at the byte ceiling ENDS the claim —
/// every URI of a claim addresses the same bytes, so any other honest source
/// would abort at the same ceiling — surfaced via [`BlobWalkEnd::Exhausted`]'s
/// `limit_exceeded` so the consumer emits `CONTENT_FETCH_LIMIT_EXCEEDED` as
/// its end state.
#[allow(clippy::too_many_arguments)]
pub fn walk_blob_sources<T>(
    out_of_band: Option<&[u8]>,
    uris: &[String],
    allow_fetch: bool,
    base_path: &[PathSegment],
    policy: &ContentFetchPolicy<'_>,
    fetcher: &mut GatewayFetcher<'_>,
    issues: &mut Vec<VerifierIssue>,
    mut consume: impl FnMut(&AcquiredBlob<'_>, &mut Vec<VerifierIssue>) -> SourceDecision<T>,
) -> BlobWalkEnd<T> {
    if let Some(bytes) = out_of_band {
        let blob = AcquiredBlob {
            bytes,
            uri: None,
            uri_index: None,
            binding: BlobBinding::OutOfBand,
            attribution: Cell::new(None),
        };
        if let SourceDecision::Accept(t) = consume(&blob, issues) {
            return BlobWalkEnd::Done(t);
        }
    }
    if !allow_fetch {
        return BlobWalkEnd::Exhausted {
            limit_exceeded: false,
        };
    }

    for (uri_index, uri) in uris.iter().enumerate() {
        let uri_path = || {
            let mut p = base_path.to_vec();
            p.push(PathSegment::Key("uris".to_string()));
            p.push(PathSegment::Index(uri_index));
            p
        };

        let Some(target) = parse_fetch_target(uri) else {
            // Defence-in-depth: a target outside the closed fetch set can only
            // reach here by bypassing structural validation.
            issues.push(VerifierIssue::new(
                ErrorCode::UriTargetForbidden,
                uri_path(),
                format!(
                    "refusing to fetch {uri:?}: not a conformant ar:// or ipfs:// content address"
                ),
            ));
            continue;
        };

        let (gateways, purpose): (&[String], HttpPurpose) = match &target {
            FetchTarget::Arweave { .. } => (policy.arweave_gateways, HttpPurpose::Arweave),
            FetchTarget::Ipfs { .. } => {
                if policy.ipfs_gateways.is_empty() {
                    // This deployment declines every IPFS fetch — a policy
                    // statement about the verifier, never about the record.
                    issues.push(VerifierIssue::new(
                        ErrorCode::UriTargetForbidden,
                        uri_path(),
                        format!("refusing to fetch {uri:?}: no IPFS gateway chain is configured"),
                    ));
                    continue;
                }
                (policy.ipfs_gateways, HttpPurpose::Ipfs)
            }
        };

        for gateway in gateways {
            let url = match &target {
                FetchTarget::Arweave { txid } => join_gateway(gateway, txid),
                FetchTarget::Ipfs { cid_and_path, .. } => {
                    join_gateway(gateway, &format!("ipfs/{cid_and_path}"))
                }
            };
            let mut opts = FetchOutboundOptions::new(HttpMethod::Get, purpose);
            opts.max_bytes = policy.max_fetch_bytes;

            let bytes = match fetcher.fetch(&url, &opts) {
                Ok(res) if res.status == 200 => res.bytes,
                Ok(res) => {
                    issues.push(VerifierIssue::new(
                        ErrorCode::UriFetchFailed,
                        uri_path(),
                        format!(
                            "fetch of {uri:?} via {gateway} returned HTTP {}",
                            res.status
                        ),
                    ));
                    continue;
                }
                Err(OutboundError::BodyTooLarge { .. }) => {
                    // Aborted at the deployment's per-URI fetch ceiling. Every
                    // URI of a claim addresses the same bytes, so any other
                    // honest source would abort at the same ceiling: end the
                    // claim. The consumer's end state surfaces
                    // CONTENT_FETCH_LIMIT_EXCEEDED.
                    return BlobWalkEnd::Exhausted {
                        limit_exceeded: true,
                    };
                }
                Err(e @ OutboundError::DenyHost { .. }) => {
                    issues.push(VerifierIssue::new(
                        ErrorCode::ServiceIndependenceViolation,
                        uri_path(),
                        format!("outbound call to {url} targets a denyHosts entry: {e}"),
                    ));
                    continue;
                }
                Err(e) => {
                    issues.push(VerifierIssue::new(
                        ErrorCode::UriFetchFailed,
                        uri_path(),
                        format!("fetch of {uri:?} via {gateway} failed: {e}"),
                    ));
                    continue;
                }
            };

            let binding = match &target {
                FetchTarget::Ipfs { cid, has_path, .. } => BlobBinding::IpfsCid {
                    cid,
                    has_path: *has_path,
                },
                FetchTarget::Arweave { .. } => BlobBinding::Unsupported,
            };
            let blob = AcquiredBlob {
                bytes: &bytes,
                uri: Some(uri),
                uri_index: Some(uri_index),
                binding,
                attribution: Cell::new(None),
            };
            if let SourceDecision::Accept(t) = consume(&blob, issues) {
                return BlobWalkEnd::Done(t);
            }
        }
    }

    BlobWalkEnd::Exhausted {
        limit_exceeded: false,
    }
}

/// Join a gateway base URL and a path suffix with exactly one separator.
fn join_gateway(base: &str, suffix: &str) -> String {
    if base.ends_with('/') {
        format!("{base}{suffix}")
    } else {
        format!("{base}/{suffix}")
    }
}

/// Parse a `uris[]` entry into its fetch target. The scheme is case-folded per
/// RFC 3986 §3.1; the remainder is matched verbatim (content addresses are
/// case-sensitive). Returns `None` for a scheme outside the closed fetch set
/// or a shape the scheme cannot fetch.
fn parse_fetch_target(uri: &str) -> Option<FetchTarget<'_>> {
    let idx = uri.find("://")?;
    let scheme = &uri[..idx];
    if scheme.is_empty()
        || !scheme
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic())
    {
        return None;
    }
    let rest = &uri[idx + 3..];
    if scheme.eq_ignore_ascii_case("ar") {
        if is_arweave_txid(rest) {
            return Some(FetchTarget::Arweave { txid: rest });
        }
        return None;
    }
    if scheme.eq_ignore_ascii_case("ipfs") {
        let (cid, has_path) = match rest.find('/') {
            Some(slash) => (&rest[..slash], true),
            None => (rest, false),
        };
        if cid.is_empty() {
            return None;
        }
        return Some(FetchTarget::Ipfs {
            cid_and_path: rest,
            cid,
            has_path,
        });
    }
    None
}

fn is_arweave_txid(txid: &str) -> bool {
    txid.len() == 43
        && txid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// ---------------------------------------------------------------------------
// Item-hash recompute + the plain-item consumer
// ---------------------------------------------------------------------------

/// `true` iff every entry of an item's `hashes` map recomputes over `bytes`.
///
/// The structural validator guarantees registry membership of every key, so an
/// unknown algorithm reaching here is a defensive no-certify, not a wire case.
#[must_use]
pub fn recompute_item_hashes(hashes: &[(String, Vec<u8>)], bytes: &[u8]) -> bool {
    if hashes.is_empty() {
        return false;
    }
    for (alg, claimed) in hashes {
        let recomputed: Vec<u8> = match alg.as_str() {
            "sha2-256" => sha256(bytes).to_vec(),
            "blake2b-256" => blake2b256(bytes).to_vec(),
            _ => return false,
        };
        if recomputed.len() != claimed.len() || recomputed.ct_eq(claimed).unwrap_u8() != 1 {
            return false;
        }
    }
    true
}

/// Step-7 content check for one non-`enc` item: first-success across the URI
/// list, every digest in `item.hashes` recomputed, the attribution rule
/// applied to mismatching bytes.
///
/// - bytes satisfying every committed digest → `checked` (no binding check
///   needed);
/// - ATTRIBUTABLE bytes failing a digest → `URI_INTEGRITY_MISMATCH` (error,
///   record-attributable) — one provably mismatching URI condemns the record
///   even if a sibling URI matches, because the producer asserted at
///   publication that every listed URI resolves to committed bytes;
/// - UNATTRIBUTABLE bytes failing a digest → `URI_PROVIDER_INTEGRITY_MISMATCH`
///   (warning) and the remaining sources are tried;
/// - sources exhausted with nothing attributable → `CONTENT_UNAVAILABLE` (or
///   `CONTENT_FETCH_LIMIT_EXCEEDED` when an attempt aborted at the ceiling).
///
/// A hash-only item (no URIs) has nothing to fetch: its claim is `not_checked`
/// with no availability issue — nothing failed, nothing was expected to be
/// fetched. Sealed (`enc`-bearing) items never enter this step.
pub fn check_item_content(
    item: &ItemEntry,
    item_index: usize,
    fetch_content: bool,
    policy: &ContentFetchPolicy<'_>,
    fetcher: &mut GatewayFetcher<'_>,
    issues: &mut Vec<VerifierIssue>,
) -> ContentCheck {
    if !fetch_content {
        return ContentCheck::NotChecked;
    }
    let uris = item.uris.as_deref().unwrap_or(&[]);
    if uris.is_empty() {
        return ContentCheck::NotChecked;
    }

    let base_path = vec![
        PathSegment::Key("items".to_string()),
        PathSegment::Index(item_index),
    ];
    let walk = walk_blob_sources(
        None,
        uris,
        true,
        &base_path,
        policy,
        fetcher,
        issues,
        |blob, issues| {
            if recompute_item_hashes(&item.hashes, blob.bytes) {
                return SourceDecision::Accept(ContentCheck::Checked);
            }
            if blob.attributable() {
                issues.push(VerifierIssue::new(
                    ErrorCode::UriIntegrityMismatch,
                    base_path.clone(),
                    format!(
                        "attributable bytes fetched from {:?} do not satisfy the item's hashes commitment",
                        blob.uri.unwrap_or("out-of-band input")
                    ),
                ));
                return SourceDecision::Accept(ContentCheck::Mismatched);
            }
            issues.push(VerifierIssue::new(
                ErrorCode::UriProviderIntegrityMismatch,
                provider_mismatch_path(&base_path, blob),
                format!(
                    "bytes fetched from {:?} do not satisfy the item's hashes commitment and could not be attributed to the URI's content address; the serving provider is indicted, not the record",
                    blob.uri.unwrap_or("unknown source")
                ),
            ));
            SourceDecision::NextSource
        },
    );

    match walk {
        BlobWalkEnd::Done(check) => check,
        BlobWalkEnd::Exhausted { limit_exceeded } => {
            if limit_exceeded {
                issues.push(VerifierIssue::new(
                    ErrorCode::ContentFetchLimitExceeded,
                    base_path,
                    "a fetch for this item was aborted at the deployment's max-fetch-bytes ceiling; the claim is unchecked",
                ));
            } else {
                issues.push(VerifierIssue::new(
                    ErrorCode::ContentUnavailable,
                    base_path,
                    "the URI list was exhausted with no attributable bytes satisfying the commitment; the claim is unchecked",
                ));
            }
            ContentCheck::NotChecked
        }
    }
}

/// The issue path for an unattributable provider mismatch: the source URI when
/// the blob was fetched, the claim base path otherwise.
pub fn provider_mismatch_path(
    base_path: &[PathSegment],
    blob: &AcquiredBlob<'_>,
) -> Vec<PathSegment> {
    match blob.uri_index {
        Some(j) => {
            let mut p = base_path.to_vec();
            p.push(PathSegment::Key("uris".to_string()));
            p.push(PathSegment::Index(j));
            p
        }
        None => base_path.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Offline CID decoding (the minimum content-address binding check)
// ---------------------------------------------------------------------------

const CID_CODEC_RAW: u64 = 0x55;
const MULTIHASH_SHA2_256: u64 = 0x12;
const MULTIHASH_BLAKE2B_256: u64 = 0xb220;

/// A decoded CID: version, content codec, and the multihash fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCid {
    /// The CID version (0 or 1).
    pub version: u64,
    /// The content multicodec (`0x55` = raw, `0x70` = dag-pb, …).
    pub codec: u64,
    /// The multihash function code (`0x12` = sha2-256, `0xb220` = blake2b-256).
    pub multihash_code: u64,
    /// The multihash digest bytes.
    pub digest: Vec<u8>,
}

/// Decode the authority component of an `ipfs://` URI into its CID fields.
///
/// Returns `None` for anything outside the profile's multibase set or for
/// undecodable input — callers treat that exactly like an unsupported binding.
#[must_use]
pub fn parse_cid(cid: &str) -> Option<ParsedCid> {
    if cid.is_empty() {
        return None;
    }

    // CIDv0: the fixed base58btc "Qm…" shape — an implied dag-pb + sha2-256
    // multihash.
    if cid.starts_with("Qm") && cid.len() == 46 {
        let decoded = decode_base58btc(cid)?;
        if decoded.len() != 34 || decoded[0] != 0x12 || decoded[1] != 32 {
            return None;
        }
        return Some(ParsedCid {
            version: 0,
            codec: 0x70,
            multihash_code: MULTIHASH_SHA2_256,
            digest: decoded[2..].to_vec(),
        });
    }

    let prefix = cid.as_bytes()[0];
    let body = &cid[1..];
    let decoded = match prefix {
        b'b' => decode_base32_lower(body)?,
        b'B' => decode_base32_lower(&body.to_ascii_lowercase())?,
        b'f' => decode_base16_lower(body)?,
        b'F' => decode_base16_lower(&body.to_ascii_lowercase())?,
        b'z' => decode_base58btc(body)?,
        _ => return None,
    };

    let (version, pos) = read_varint(&decoded, 0)?;
    if version != 1 {
        return None;
    }
    let (codec, pos) = read_varint(&decoded, pos)?;
    let (multihash_code, pos) = read_varint(&decoded, pos)?;
    let (digest_len, pos) = read_varint(&decoded, pos)?;
    let digest = decoded.get(pos..)?;
    if digest.len() as u64 != digest_len {
        return None;
    }
    Some(ParsedCid {
        version,
        codec,
        multihash_code,
        digest: digest.to_vec(),
    })
}

/// The outcome of the CID binding check over fetched bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidBindingOutcome {
    /// The multihash recompute over the fetched bytes matched the CID digest.
    Verified,
    /// The recompute ran and did not match.
    Failed,
    /// No binding check applies: CIDv0, a DAG codec, a path component (which
    /// navigates a DAG the raw recompute cannot reproduce), or an
    /// out-of-profile multihash. The bytes stay unattributed.
    Unsupported,
}

/// The minimum binding check: for a raw-codec CIDv1 with no path component,
/// recompute the multihash directly over the fetched bytes and compare it to
/// the CID's digest.
#[must_use]
pub fn verify_ipfs_cid_binding(cid: &str, has_path: bool, bytes: &[u8]) -> CidBindingOutcome {
    if has_path {
        return CidBindingOutcome::Unsupported;
    }
    let Some(parsed) = parse_cid(cid) else {
        return CidBindingOutcome::Unsupported;
    };
    if parsed.version != 1 || parsed.codec != CID_CODEC_RAW {
        return CidBindingOutcome::Unsupported;
    }
    let computed: Vec<u8> = match parsed.multihash_code {
        MULTIHASH_SHA2_256 => sha256(bytes).to_vec(),
        MULTIHASH_BLAKE2B_256 => blake2b256(bytes).to_vec(),
        _ => return CidBindingOutcome::Unsupported,
    };
    if computed.len() == parsed.digest.len() && computed.ct_eq(&parsed.digest).unwrap_u8() == 1 {
        CidBindingOutcome::Verified
    } else {
        CidBindingOutcome::Failed
    }
}

fn read_varint(bytes: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut i = start;
    while i < bytes.len() {
        let b = bytes[i];
        if shift > 28 {
            return None;
        }
        value |= u64::from(b & 0x7f) << shift;
        i += 1;
        if b & 0x80 == 0 {
            return Some((value, i));
        }
        shift += 7;
    }
    None
}

/// RFC 4648 base32 (lowercase alphabet, no padding). Residual bits must be
/// zero padding only.
fn decode_base32_lower(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for ch in s.bytes() {
        let value = ALPHABET.iter().position(|&a| a == ch)? as u64;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

/// Lowercase base16 (multibase `f`).
fn decode_base16_lower(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = lower_hex_digit(bytes[i])?;
        let lo = lower_hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn lower_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn decode_base58btc(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if s.is_empty() {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    for ch in s.bytes() {
        let value = ALPHABET.iter().position(|&a| a == ch)? as u32;
        let mut carry = value;
        for byte in &mut out {
            let acc = u32::from(*byte) * 58 + carry;
            *byte = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            out.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Leading '1' characters encode leading zero bytes.
    for ch in s.bytes() {
        if ch == b'1' {
            out.push(0);
        } else {
            break;
        }
    }
    out.reverse();
    Some(out)
}
