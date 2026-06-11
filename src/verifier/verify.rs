//! The Label 309 standalone verifier — the public/recipient pipeline.
//!
//! [`verify_tx`] executes, in order; a step whose outcome forecloses the rest
//! short-circuits the pipeline:
//!
//! 1. Resolve the transaction via the explorer chain (raw tx CBOR, never a
//!    JSON projection). Negative outcomes split: `TX_NOT_FOUND` /
//!    `PROVIDER_UNAVAILABLE` → `unverifiable`.
//! 2. Bind the fetched bytes to the transaction reference — blake2b-256 over
//!    the body vs the requested hash, blake2b-256 over the auxiliary data vs
//!    the body's `auxiliary_data_hash`; no surviving response →
//!    `TX_INTEGRITY_MISMATCH`, `unverifiable` (provider-provable, never
//!    record-attributable).
//! 3. Unwrap the auxiliary data (all three Conway envelope forms, dispatch on
//!    type/tag only) and reassemble the label-309 chunk array. No label-309
//!    entry → `METADATA_NOT_FOUND`, `failed` (the absence is proven by the
//!    integrity-bound transaction itself).
//! 4. Structurally validate, with the validator role matching the verifier
//!    mode: a run that will actually decrypt — decryption credentials held
//!    AND the profile admits sealed decryption — is a RECIPIENT verifier
//!    (`recipient_or_strict`); otherwise `public`.
//! 5. Check confirmation depth — below threshold → `INSUFFICIENT_CONFIRMATIONS`,
//!    verdict `pending`, pipeline halts (results computed against a
//!    transaction that may yet be orphaned must not be presented as final).
//! 6. Verify record signatures (strict Ed25519, detached payload, verbatim
//!    protected bytes, wallet-address network binding).
//! 7. Fetch and hash-check plain-item content and Merkle leaves-lists
//!    (first-success-for-availability; the integrity / attribution /
//!    availability split; suppressed by `fetch_content: false`).
//! 8. Decrypt `enc`-bearing items with the keyring (recipient verifier),
//!    including the post-decryption plaintext-hash recheck.
//! 9. (`supersedes` is an advisory pointer; this implementation performs no
//!    existence hop.)
//! 10. Emit the report: verdict ∈ valid | pending | unverifiable | failed,
//!     exit codes 0 | 3 | 2 | 1 respectively, issues sorted by path then
//!     registry order, one per-claim entry per item / commitment, and the
//!     complete audit trail of every outbound call.
//!
//! [`verify_record_bytes`] runs the same pipeline from step 4 onward over
//! caller-supplied record-body bytes plus an explorer-asserted block-info
//! tuple.

use crate::poe_standard::{
    validate_poe_record, ErrorCode, PoeRecord, Severity, ValidateResult, ValidatorOptions,
    ValidatorRole,
};

use crate::verifier::cbor_walker::{reassemble_label_309_value, unwrap_auxiliary_data, TxSlices};
use crate::verifier::content::{check_item_content, ContentFetchPolicy, ARWEAVE_GATEWAY_DEFAULTS};
use crate::verifier::decrypt::decrypt_item;
use crate::verifier::egress::GatewayFetcher;
use crate::verifier::merkle::{check_merkle_commit, MerkleCommitOutcome};
use crate::verifier::profile::{out_of_profile_issues, profile_at_least};
use crate::verifier::resolve::resolve_cardano_tx;
use crate::verifier::signatures::verify_record_signatures;
use crate::verifier::tx_witnesses::{decode_tx_summary, decode_tx_witnesses};
use crate::verifier::types::{
    compare_verifier_issues, BlockInfo, ContentCheck, ItemReportEntry, MerkleReportEntry, Profile,
    SigFailureReason, SignatureCheck, TxDescription, Verdict, VerifierIssue, VerifyReport,
    VerifyTxInput,
};

/// Error-severity codes that are NOT record-attributable: network, policy, and
/// provider-integrity outcomes. They block a `valid` verdict but can never
/// condemn the record — the verdict they produce is `unverifiable`. Every
/// other error-severity code is record-attributable and produces `failed`.
const NETWORK_CLASS_CODES: [ErrorCode; 8] = [
    ErrorCode::TxNotFound,
    ErrorCode::ProviderUnavailable,
    ErrorCode::TxIntegrityMismatch,
    ErrorCode::ContentUnavailable,
    ErrorCode::ContentFetchLimitExceeded,
    ErrorCode::CiphertextUnavailable,
    ErrorCode::MerkleLeavesUnavailable,
    ErrorCode::UriTargetForbidden,
];

/// Derive the machine verdict from the run's issue list: any error-severity
/// record-attributable code → `failed`; only network/policy/provider-integrity
/// errors → `unverifiable`; no error-severity issue → `valid`.
fn verdict_from_issues(issues: &[VerifierIssue]) -> Verdict {
    let mut saw_network_error = false;
    for issue in issues {
        if issue.severity != Severity::Error {
            continue;
        }
        if !NETWORK_CLASS_CODES.contains(&issue.code) {
            return Verdict::Failed;
        }
        saw_network_error = true;
    }
    if saw_network_error {
        Verdict::Unverifiable
    } else {
        Verdict::Valid
    }
}

/// The chain facts a report carries once the transaction resolved.
#[derive(Clone, Copy)]
struct ChainFacts {
    confirmation_depth: u32,
    block_time: u64,
    block_slot: Option<u64>,
}

/// Everything a report shares regardless of which step emitted it.
struct ReportSkeleton {
    tx_hash: String,
    network: &'static str,
    profile: Profile,
    threshold: u32,
    chain_facts: Option<ChainFacts>,
    tx_description: TxDescription,
}

/// Assemble a report: sort the issues, derive the exit code from the verdict,
/// and attach the audit trail accumulated by the egress.
#[allow(clippy::too_many_arguments)]
fn assemble_report(
    skeleton: ReportSkeleton,
    mut issues: Vec<VerifierIssue>,
    verdict: Verdict,
    items: Vec<ItemReportEntry>,
    merkle: Vec<MerkleReportEntry>,
    record: Option<PoeRecord>,
    signatures: Option<Vec<SignatureCheck>>,
    audit_trail: Vec<crate::verifier::fetch::HttpCallRecord>,
) -> VerifyReport {
    issues.sort_by(compare_verifier_issues);
    let facts = skeleton.chain_facts;
    VerifyReport {
        tx_hash: skeleton.tx_hash,
        verdict,
        profile: skeleton.profile,
        network: skeleton.network,
        confirmation_threshold: skeleton.threshold,
        confirmation_depth: facts.map(|f| f.confirmation_depth),
        block_time: facts.map(|f| f.block_time),
        block_slot: facts.and_then(|f| f.block_slot),
        issues,
        items,
        merkle,
        audit_trail,
        record,
        record_signatures: signatures.filter(|s| !s.is_empty()),
        tx_witnesses: skeleton.tx_description.tx_witnesses,
        tx_summary: skeleton.tx_description.tx_summary,
        metadata_labels: skeleton.tx_description.metadata_labels,
    }
}

/// Verify a Cardano transaction's Label 309 record and produce a
/// [`VerifyReport`].
///
/// Routes every outbound call through `input.fetch_outbound`. With the
/// `client` feature (the default), an absent transport falls back to the
/// production reqwest transport; without it, the caller MUST supply a
/// [`FetchTransport`](crate::verifier::fetch::FetchTransport), and an absent
/// one yields a provider-unavailable report rather than reaching the network.
#[must_use]
pub fn verify_tx(input: &VerifyTxInput<'_>) -> VerifyReport {
    #[cfg(feature = "client")]
    let default_transport = crate::verifier::fetch::ReqwestTransport::new();

    #[cfg(feature = "client")]
    let transport: &dyn crate::verifier::fetch::FetchTransport =
        input.fetch_outbound.unwrap_or(&default_transport);

    // Without the `client` feature there is no built-in transport: the caller
    // is the sole source of outbound I/O, so an absent transport cannot reach
    // the chain and the verifier reports the provider as unavailable instead
    // of attempting (and silently skipping) the fetch.
    #[cfg(not(feature = "client"))]
    let Some(transport) = input.fetch_outbound
    else {
        let skeleton = ReportSkeleton {
            tx_hash: input.tx_hash.clone(),
            network: input.cardano_network.id(),
            profile: input.profile,
            threshold: input.threshold(),
            chain_facts: None,
            tx_description: TxDescription::default(),
        };
        let issues = vec![VerifierIssue::new(
            ErrorCode::ProviderUnavailable,
            Vec::new(),
            "no fetch transport supplied (build with the `client` feature or set \
             VerifyTxInput::fetch_outbound)",
        )];
        let verdict = verdict_from_issues(&issues);
        return assemble_report(
            skeleton,
            issues,
            verdict,
            Vec::new(),
            Vec::new(),
            None,
            None,
            Vec::new(),
        );
    };

    let mut fetcher = GatewayFetcher::new(transport, input.deny_hosts.as_deref());
    let threshold = input.threshold();
    let mut skeleton = ReportSkeleton {
        tx_hash: input.tx_hash.clone(),
        network: input.cardano_network.id(),
        profile: input.profile,
        threshold,
        chain_facts: None,
        tx_description: TxDescription::default(),
    };

    // Steps 1 + 2 — resolve via the explorer chain with the integrity binding
    // applied per response.
    let resolved = match resolve_cardano_tx(
        &input.tx_hash,
        input.cardano_gateway_chain.as_deref(),
        input.blockfrost_project_id.as_deref(),
        &mut fetcher,
    ) {
        Ok(r) => r,
        Err(failure) => {
            let issues = vec![VerifierIssue::new(
                failure.code,
                Vec::new(),
                failure.message,
            )];
            let verdict = verdict_from_issues(&issues);
            return assemble_report(
                skeleton,
                issues,
                verdict,
                Vec::new(),
                Vec::new(),
                None,
                None,
                fetcher.into_audit(),
            );
        }
    };
    skeleton.chain_facts = Some(ChainFacts {
        confirmation_depth: resolved.confirmation_depth,
        block_time: resolved.block_time,
        block_slot: Some(resolved.block_slot),
    });
    skeleton.tx_description = decode_tx_description(&resolved.slices, input);

    // Step 3 — unwrap the bound auxiliary data and reassemble the record body.
    let label_309_value = match &resolved.slices.aux_data {
        None => None,
        Some(aux) => match unwrap_auxiliary_data(aux) {
            Ok(unwrapped) => unwrapped.label_309_value,
            Err(e) => {
                let issues = vec![VerifierIssue::new(e.code, Vec::new(), e.message)];
                return assemble_report(
                    skeleton,
                    issues,
                    Verdict::Failed,
                    Vec::new(),
                    Vec::new(),
                    None,
                    None,
                    fetcher.into_audit(),
                );
            }
        },
    };
    let Some(label_309_value) = label_309_value else {
        let issues = vec![VerifierIssue::new(
            ErrorCode::MetadataNotFound,
            Vec::new(),
            "the integrity-bound transaction carries no metadata under label 309",
        )];
        return assemble_report(
            skeleton,
            issues,
            Verdict::Failed,
            Vec::new(),
            Vec::new(),
            None,
            None,
            fetcher.into_audit(),
        );
    };
    let record_body = match reassemble_label_309_value(&label_309_value) {
        Ok(body) => body,
        Err(e) => {
            let issues = vec![VerifierIssue::new(e.code, Vec::new(), e.message)];
            return assemble_report(
                skeleton,
                issues,
                Verdict::Failed,
                Vec::new(),
                Vec::new(),
                None,
                None,
                fetcher.into_audit(),
            );
        }
    };

    let block_info = BlockInfo {
        confirmation_depth: resolved.confirmation_depth,
        block_time: resolved.block_time,
        block_slot: Some(resolved.block_slot),
    };
    run_record_pipeline(&record_body, block_info, input, skeleton, fetcher)
}

/// The typed rejection of a caller-supplied [`BlockInfo`] whose
/// `confirmation_depth` is 0.
///
/// Depth counts blocks tip-inclusively — a transaction in the tip block has
/// depth exactly 1 — so a zero depth asserts the transaction is in no block,
/// contradicting the block facts the tuple itself carries. A caller-input bug
/// of this kind is an error of the call, never a report outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("BlockInfo.confirmation_depth must be >= 1 (a transaction in the tip block has depth 1)")]
pub struct ZeroConfirmationDepthError;

/// Sibling entry point: run the pipeline from the structural-validator step
/// onward over caller-supplied record-body bytes plus an explorer-asserted
/// block-info tuple — the path a server-rendered viewer uses to display
/// on-chain data without a render-time chain fetch.
///
/// `record_body` is the reassembled canonical record body (the chunk-array
/// transport already concatenated; see
/// [`reassemble_label_309_value`]).
/// The caller vouches that the bytes came from the label-309 metadata of a
/// real Cardano transaction and supplies the chain facts the resolve step
/// would have established. The chain-resolution fields of `input`
/// (`cardano_gateway_chain`, `blockfrost_project_id`) are unused.
///
/// # Errors
///
/// Returns [`ZeroConfirmationDepthError`] when `block_info.confirmation_depth`
/// is 0 — a transaction with block facts is in a block, whose floor depth is 1.
pub fn verify_record_bytes(
    record_body: &[u8],
    block_info: BlockInfo,
    input: &VerifyTxInput<'_>,
) -> Result<VerifyReport, ZeroConfirmationDepthError> {
    if block_info.confirmation_depth == 0 {
        return Err(ZeroConfirmationDepthError);
    }
    #[cfg(feature = "client")]
    let default_transport = crate::verifier::fetch::ReqwestTransport::new();

    #[cfg(feature = "client")]
    let transport: &dyn crate::verifier::fetch::FetchTransport =
        input.fetch_outbound.unwrap_or(&default_transport);

    // Without a transport, every content fetch is unavailable; the offline
    // checks still run.
    #[cfg(not(feature = "client"))]
    let transport: &dyn crate::verifier::fetch::FetchTransport = match input.fetch_outbound {
        Some(t) => t,
        None => &fetch_unavailable::NoTransport,
    };

    let fetcher = GatewayFetcher::new(transport, input.deny_hosts.as_deref());
    let skeleton = ReportSkeleton {
        tx_hash: input.tx_hash.clone(),
        network: input.cardano_network.id(),
        profile: input.profile,
        threshold: input.threshold(),
        chain_facts: Some(ChainFacts {
            confirmation_depth: block_info.confirmation_depth,
            block_time: block_info.block_time,
            block_slot: block_info.block_slot,
        }),
        tx_description: TxDescription::default(),
    };
    Ok(run_record_pipeline(
        record_body,
        block_info,
        input,
        skeleton,
        fetcher,
    ))
}

/// Steps 4–10, shared by both entry points.
fn run_record_pipeline(
    record_body: &[u8],
    block_info: BlockInfo,
    input: &VerifyTxInput<'_>,
    skeleton: ReportSkeleton,
    mut fetcher: GatewayFetcher<'_>,
) -> VerifyReport {
    // Step 4 — structural validation, with the role matching the verifier
    // mode: a run that will actually decrypt (credentials held AND the
    // profile implements decryption) is a recipient verifier, whose validator
    // hard-rejects envelopes it cannot fully validate (ENC_UNSUPPORTED
    // escalates to error) — a sealed delivery is never processed under a
    // half-validated envelope. A lower profile never decrypts, so it keeps
    // the public reading even when credentials were supplied.
    let will_decrypt =
        input.has_keyring() && profile_at_least(input.profile, Profile::RecipientSealed);
    let role = if will_decrypt {
        ValidatorRole::RecipientOrStrict
    } else {
        ValidatorRole::Public
    };
    let options = ValidatorOptions {
        role,
        ..ValidatorOptions::default()
    };
    let (record, mut issues) = match validate_poe_record(record_body, &options) {
        ValidateResult::Ok {
            record,
            warnings,
            info,
        } => {
            let mut issues: Vec<VerifierIssue> = warnings.iter().map(VerifierIssue::from).collect();
            issues.extend(info.iter().map(VerifierIssue::from));
            (*record, issues)
        }
        ValidateResult::Fail {
            issues: validator_issues,
        } => {
            let issues: Vec<VerifierIssue> =
                validator_issues.iter().map(VerifierIssue::from).collect();
            return assemble_report(
                skeleton,
                issues,
                Verdict::Failed,
                Vec::new(),
                Vec::new(),
                None,
                None,
                fetcher.into_audit(),
            );
        }
    };

    let item_count = record.items.as_ref().map_or(0, Vec::len);
    let merkle_count = record.merkle.as_ref().map_or(0, Vec::len);

    // Step 5 — confirmation depth. Below threshold the record is well-formed
    // but not final: verdict `pending`, and the signature / content / decrypt
    // steps are skipped so nothing computed against a possibly-orphaned
    // transaction can be presented as final.
    if block_info.confirmation_depth < skeleton.threshold {
        issues.push(VerifierIssue::new(
            ErrorCode::InsufficientConfirmations,
            Vec::new(),
            format!(
                "confirmation depth {} is below the threshold {}; signature, content, and \
                 decryption steps did not run",
                block_info.confirmation_depth, skeleton.threshold
            ),
        ));
        return assemble_report(
            skeleton,
            issues,
            Verdict::Pending,
            vec![ItemReportEntry::default(); item_count],
            vec![MerkleReportEntry::default(); merkle_count],
            Some(record),
            None,
            fetcher.into_audit(),
        );
    }

    // Profile gating: fields above the active profile are skipped with
    // OUT_OF_PROFILE_SKIPPED (info) — the record is never invalid solely
    // because this verifier does not implement a profile extension.
    issues.extend(out_of_profile_issues(&record, input.profile));
    let verify_signatures = profile_at_least(input.profile, Profile::Signed);

    // Step 6 — record-level signatures. Every `unsupported` per-signature
    // verdict puts SIGNATURE_UNSUPPORTED (info) at ["sigs", i] EXACTLY ONCE:
    // the structural validator contributes the identical issue for
    // UNREGISTERED algorithms, while a registered-but-unimplemented algorithm
    // is detected only here, so the add is idempotent against the merged
    // list. An unsupported algorithm never fails the record.
    let mut signatures: Option<Vec<SignatureCheck>> = None;
    let has_sigs = record.sigs.as_ref().is_some_and(|s| !s.is_empty());
    if verify_signatures && has_sigs {
        let checks = verify_record_signatures(&record, input.cardano_network);
        for check in &checks {
            if let Some(reason) = check.reason {
                let entry_issue = VerifierIssue::new(
                    reason.error_code(),
                    vec![
                        crate::poe_standard::PathSegment::Key("sigs".to_string()),
                        crate::poe_standard::PathSegment::Index(check.index),
                    ],
                    signature_failure_message(reason),
                );
                if reason == SigFailureReason::SignatureUnsupported {
                    push_issue_once(&mut issues, entry_issue);
                } else {
                    issues.push(entry_issue);
                }
            }
        }
        signatures = Some(checks);
    }

    // Steps 7 + 8 — content checks and sealed decryption.
    let default_arweave: Vec<String> = ARWEAVE_GATEWAY_DEFAULTS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let arweave_gateways: &[String] = match &input.arweave_gateway_chain {
        Some(g) if !g.is_empty() => g.as_slice(),
        _ => &default_arweave,
    };
    let empty_chain: Vec<String> = Vec::new();
    let ipfs_gateways: &[String] = input.ipfs_gateway_chain.as_ref().unwrap_or(&empty_chain);
    let policy = ContentFetchPolicy {
        arweave_gateways,
        ipfs_gateways,
        max_fetch_bytes: input.max_fetch_bytes,
    };
    let credentials = input.decryption.as_deref().unwrap_or(&[]);

    let mut item_entries: Vec<ItemReportEntry> = Vec::with_capacity(item_count);
    if let Some(items) = &record.items {
        for (i, item) in items.iter().enumerate() {
            if item.enc.is_some() {
                if will_decrypt {
                    let result = decrypt_item(
                        item,
                        i,
                        credentials,
                        input
                            .ciphertext_bytes
                            .as_ref()
                            .and_then(|m| m.get(&i))
                            .map(Vec::as_slice),
                        input.fetch_content,
                        &policy,
                        &mut fetcher,
                        &mut issues,
                    );
                    item_entries.push(ItemReportEntry {
                        content_check: result.content_check,
                        decryption: Some(result.decryption),
                    });
                } else {
                    // Public verifier (or a profile below recipient-sealed): a
                    // sealed item's plaintext claim cannot be checked without
                    // decrypting, and the URIs hold ciphertext, not the
                    // committed plaintext.
                    item_entries.push(ItemReportEntry::default());
                }
                continue;
            }
            let content_check = check_item_content(
                item,
                i,
                input.fetch_content,
                &policy,
                &mut fetcher,
                &mut issues,
            );
            item_entries.push(ItemReportEntry {
                content_check,
                decryption: None,
            });
        }
    }

    let mut merkle_outcomes: Vec<MerkleCommitOutcome> = Vec::with_capacity(merkle_count);
    if let Some(commits) = &record.merkle {
        for (i, commit) in commits.iter().enumerate() {
            merkle_outcomes.push(check_merkle_commit(
                commit,
                i,
                input
                    .merkle_leaves
                    .as_ref()
                    .and_then(|m| m.get(&i))
                    .map(Vec::as_slice),
                input.fetch_content,
                &policy,
                &mut fetcher,
                &mut issues,
            ));
        }
    }

    // The commitment floor resolves the dual severity of
    // MERKLE_LEAVES_UNAVAILABLE: warning when at least one other content
    // commitment of the record was verified in this run, error (network class,
    // verdict `unverifiable`) when the unavailability leaves the record with
    // no verified content commitment.
    let any_commitment_verified = item_entries
        .iter()
        .any(|e| e.content_check == ContentCheck::Checked)
        || merkle_outcomes
            .iter()
            .any(|o| o.content_check == ContentCheck::Checked);
    for outcome in &merkle_outcomes {
        let Some(unavailable) = &outcome.unavailable else {
            continue;
        };
        if unavailable.limit_exceeded {
            issues.push(VerifierIssue::new(
                ErrorCode::ContentFetchLimitExceeded,
                unavailable.path.clone(),
                "a leaves-list fetch was aborted at the max-fetch-bytes ceiling; the commitment \
                 is unchecked",
            ));
            continue;
        }
        issues.push(VerifierIssue::with_severity(
            ErrorCode::MerkleLeavesUnavailable,
            if any_commitment_verified {
                Severity::Warning
            } else {
                Severity::Error
            },
            unavailable.path.clone(),
            if any_commitment_verified {
                "no attributable leaves-list could be obtained; another content commitment of \
                 the record was verified"
            } else {
                "no attributable leaves-list could be obtained and no content commitment of the \
                 record was verified"
            },
        ));
    }
    let merkle_entries: Vec<MerkleReportEntry> = merkle_outcomes
        .iter()
        .map(|o| MerkleReportEntry {
            content_check: o.content_check,
        })
        .collect();

    // Step 10 — verdict + report.
    let verdict = verdict_from_issues(&issues);
    assemble_report(
        skeleton,
        issues,
        verdict,
        item_entries,
        merkle_entries,
        Some(record),
        signatures,
        fetcher.into_audit(),
    )
}

/// Append `issue` unless an identical `(code, path, severity)` issue is
/// already present. Used where two pipeline layers can legitimately conclude
/// the same fact about the same location — the structural validator and the
/// signature pass both finding a signature entry unsupported — and the report
/// must carry it exactly once.
fn push_issue_once(issues: &mut Vec<VerifierIssue>, issue: VerifierIssue) {
    let duplicate = issues.iter().any(|existing| {
        existing.code == issue.code
            && existing.severity == issue.severity
            && existing.path == issue.path
    });
    if !duplicate {
        issues.push(issue);
    }
}

fn signature_failure_message(reason: SigFailureReason) -> &'static str {
    match reason {
        SigFailureReason::MalformedSigCoseSign1 => {
            "the cose_sign1 blob is not a verifiable detached COSE_Sign1"
        }
        SigFailureReason::SignerKeyUnresolved => {
            "neither key-resolution path yielded a 32-byte Ed25519 public key"
        }
        SigFailureReason::WalletAddressMismatch => {
            "the wallet-path protected-header address does not equal the recomputed \
             network_header || Blake2b-224(pubkey)"
        }
        SigFailureReason::SignatureUnsupported => {
            "the COSE_Sign1 signature algorithm is not implemented by this verifier; the entry \
             is unsupported, not invalid"
        }
        SigFailureReason::SignatureInvalid => {
            "strict Ed25519 verification failed against the resolved public key"
        }
    }
}

/// Decode the transaction-level description (witnesses, summary, co-published
/// metadata labels) from the byte-faithful transaction slices.
///
/// Purely informational, so a decode failure must NOT propagate into the
/// verdict: it degrades to omitting the affected fields. The label-309 record
/// is validated separately; this view only describes the carrying transaction.
fn decode_tx_description(slices: &TxSlices, input: &VerifyTxInput<'_>) -> TxDescription {
    let metadata_labels = match &slices.aux_data {
        None => Some(Vec::new()),
        Some(aux) => unwrap_auxiliary_data(aux).ok().map(|u| u.labels),
    };
    TxDescription {
        tx_witnesses: Some(decode_tx_witnesses(&slices.witness_set, &slices.tx_body)),
        tx_summary: decode_tx_summary(&slices.tx_body, &slices.witness_set, input.cardano_network)
            .ok(),
        metadata_labels,
    }
}

// A no-network transport for the no-client build: every call fails as a
// transport error, which the pipeline surfaces as unavailability.
#[cfg(not(feature = "client"))]
mod fetch_unavailable {
    use crate::verifier::fetch::{
        FetchOutboundOptions, FetchOutboundResult, FetchTransport, OutboundError,
    };

    pub struct NoTransport;

    impl FetchTransport for NoTransport {
        fn fetch(
            &self,
            url: &str,
            _opts: &FetchOutboundOptions,
        ) -> Result<FetchOutboundResult, OutboundError> {
            Err(OutboundError::Transport {
                url: url.to_string(),
                message: "no fetch transport supplied".to_string(),
            })
        }
    }
}
