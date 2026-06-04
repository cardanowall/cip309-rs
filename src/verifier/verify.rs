//! The Label 309 standalone verifier entry point.
//!
//! `verify_tx` runs the pipeline sequentially; the verdict is the worst outcome
//! across the stages:
//!
//! 1. Resolve the Cardano gateway, raw tx CBOR, and confirmation depth.
//! 2. Extract the label-309 record metadata (re-encoded canonically).
//! 3. Structurally validate the record (never throws).
//! 4. Confirmation-depth gate → `pending` / exit 3 when below the threshold.
//! 5. Profile-gated signatures (signed+) and decryption (recipient-sealed+).
//! 6. Merkle list-commitment verification.
//! 7. Three-state verdict + exit-code emission.

use crate::poe_standard::{validate_poe_record, ErrorCode, PoeRecord, ValidateResult};

use crate::verifier::cbor_walker::extract_label_309_metadata;
use crate::verifier::cbor_walker::slice_tx_components;
use crate::verifier::decrypt::try_decryptions;
use crate::verifier::egress::GatewayFetcher;
use crate::verifier::fetch::{HttpCallRecord, ReqwestTransport};
use crate::verifier::merkle::check_merkle_commitments;
use crate::verifier::profile::{out_of_profile_issues, profile_at_least};
use crate::verifier::resolve::{resolve_cardano_tx, ResolveError, ResolvedTx};
use crate::verifier::signatures::verify_record_signatures;
use crate::verifier::tx_witnesses::{decode_tx_summary, decode_tx_witnesses};
use crate::verifier::types::{
    DecryptResult, ExitCode, Profile, SignatureCheck, TxDescription, ValidationSummary, Verdict,
    VerifierIssue, VerifyReport, VerifyTxInput, NETWORK_CARDANO_MAINNET,
};

/// Verify a Cardano transaction's Label 309 record and produce a [`VerifyReport`].
///
/// Routes every outbound call through `input.fetch_outbound` (or the default
/// reqwest transport when absent), so the report's `http_calls` audit and its
/// `duration_ms` values are fully determined by the injected transport in tests.
#[must_use]
pub fn verify_tx(input: &VerifyTxInput<'_>) -> VerifyReport {
    let default_transport = ReqwestTransport::new();
    let transport: &dyn crate::verifier::fetch::FetchTransport =
        input.fetch_outbound.unwrap_or(&default_transport);
    let mut fetcher = GatewayFetcher::new(transport, input.deny_hosts.as_deref());

    let report = run_pipeline(input, &mut fetcher);
    finalise_http_calls(report, fetcher.into_audit())
}

/// Replace the (placeholder) audit on a report with the fetcher's final trail.
fn finalise_http_calls(mut report: VerifyReport, audit: Vec<HttpCallRecord>) -> VerifyReport {
    report.http_calls = audit;
    report
}

fn run_pipeline(input: &VerifyTxInput<'_>, fetcher: &mut GatewayFetcher<'_>) -> VerifyReport {
    let threshold = input.threshold();

    // 1. Resolve.
    let resolved: ResolvedTx = match resolve_cardano_tx(
        &input.tx_hash,
        input.cardano_gateway_chain.as_deref(),
        input.blockfrost_project_id.as_deref(),
        fetcher,
    ) {
        Ok(r) => r,
        Err(e) => return resolve_failure_report(input, threshold, &e),
    };

    // Transaction-level description — who authorised/paid for the anchoring and
    // the co-published metadata labels, distinct from record-level authorship.
    // Decoded once from the raw tx CBOR and merged into every post-extract report
    // shape. This is pure description: it never gates on profile and never
    // changes the verdict. (The no-metadata / malformed-CBOR short-circuits below
    // run before extraction succeeds, so they carry no tx description — matching
    // the reference verifier, whose pre-validation error paths omit these fields.)
    let tx_description = decode_tx_description(&resolved.tx_cbor, input.cardano_network);

    // 2. Extract label-309 metadata.
    let metadata_bytes = match extract_label_309_metadata(&resolved.tx_cbor) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return base_report(
                input,
                threshold,
                Verdict::Failed,
                ExitCode::Integrity,
                BaseOverrides {
                    num_confirmations: resolved.num_confirmations,
                    block_time: Some(resolved.block_time),
                    block_slot: Some(resolved.block_slot),
                    metadata_present: false,
                    validation: issue_summary(
                        ErrorCode::MetadataNotFound,
                        "no label-309 metadata on this tx",
                    ),
                    ..Default::default()
                },
            );
        }
        Err(e) => {
            return base_report(
                input,
                threshold,
                Verdict::Failed,
                ExitCode::Integrity,
                BaseOverrides {
                    num_confirmations: resolved.num_confirmations,
                    block_time: Some(resolved.block_time),
                    block_slot: Some(resolved.block_slot),
                    metadata_present: false,
                    validation: issue_summary(ErrorCode::MalformedCbor, e.to_string()),
                    ..Default::default()
                },
            );
        }
    };

    // 3. Structural validation.
    let (record, validator_warnings, validator_info): (
        PoeRecord,
        Vec<VerifierIssue>,
        Vec<VerifierIssue>,
    ) = match validate_poe_record(&metadata_bytes) {
        ValidateResult::Ok {
            record,
            info,
            warnings,
        } => (
            *record,
            warnings.iter().map(VerifierIssue::from).collect(),
            info.iter().map(VerifierIssue::from).collect(),
        ),
        ValidateResult::Fail { issues } => {
            return base_report(
                input,
                threshold,
                Verdict::Failed,
                ExitCode::Integrity,
                BaseOverrides {
                    num_confirmations: resolved.num_confirmations,
                    block_time: Some(resolved.block_time),
                    block_slot: Some(resolved.block_slot),
                    metadata_present: true,
                    validation: ValidationSummary {
                        valid: false,
                        issues: issues.iter().map(VerifierIssue::from).collect(),
                        ..Default::default()
                    },
                    tx_description: tx_description.clone(),
                    ..Default::default()
                },
            );
        }
    };

    // 4. Confirmation depth gate.
    if resolved.num_confirmations < threshold {
        return base_report(
            input,
            threshold,
            Verdict::Pending,
            ExitCode::InsufficientDepth,
            BaseOverrides {
                num_confirmations: resolved.num_confirmations,
                block_time: Some(resolved.block_time),
                block_slot: Some(resolved.block_slot),
                metadata_present: true,
                record: Some(record),
                validation: issue_summary(
                    ErrorCode::InsufficientConfirmations,
                    format!("{} < threshold {threshold}", resolved.num_confirmations),
                ),
                tx_description,
            },
        );
    }

    // 5. Build the optimistic report; mutate verdict on any check failure.
    let mut combined_info = validator_info;
    combined_info.extend(out_of_profile_issues(&record, input.profile));
    let mut combined_warnings = validator_warnings;

    let mut verdict = Verdict::Valid;
    let mut exit_code = ExitCode::Ok;
    let mut record_signatures: Option<Vec<SignatureCheck>> = None;
    let mut item_decryptions: Option<Vec<DecryptResult>> = None;
    let mut merkle_checks = None;
    let mut uri_checks: Vec<crate::verifier::types::UriCheck> = Vec::new();

    // 5a. Record-level signatures (signed+ profile).
    let has_sigs = record.sigs.as_ref().is_some_and(|s| !s.is_empty());
    if profile_at_least(input.profile, Profile::Signed) && has_sigs {
        let checks = verify_record_signatures(&record, input);
        if has_hard_signature_failure(&checks) {
            verdict = Verdict::Failed;
            exit_code = ExitCode::Integrity;
        }
        record_signatures = Some(checks);
    }

    // 5b. Decryption (recipient-sealed+ profile and caller-supplied keys). The
    // ciphertext-fetch attempts surface as `uri_checks` on the report.
    let has_decryption = input.decryption.as_ref().is_some_and(|d| !d.is_empty());
    if profile_at_least(input.profile, Profile::RecipientSealed) && has_decryption {
        let (results, decrypt_uri_checks) = try_decryptions(&record, input, fetcher);
        uri_checks.extend(decrypt_uri_checks);
        if let Some(class) = decryption_failure_class(&results) {
            verdict = Verdict::Failed;
            exit_code = class;
        }
        item_decryptions = Some(results);
    }

    // 6. Merkle commitments (read structurally at every profile).
    let has_merkle = record.merkle.as_ref().is_some_and(|m| !m.is_empty());
    if has_merkle {
        let (checks, warnings) = check_merkle_commitments(&record, input, fetcher);
        combined_warnings.extend(warnings);
        if merkle_should_fail(&checks) {
            verdict = Verdict::Failed;
            exit_code = ExitCode::Integrity;
        }
        merkle_checks = Some(checks);
    }

    // Finalise the validation summary: a clean pass carries no issues; a failure
    // already pointed its issues at the root before this stage.
    let validation = ValidationSummary {
        valid: verdict == Verdict::Valid,
        issues: Vec::new(),
        warnings: combined_warnings,
        info: combined_info,
    };

    VerifyReport {
        tx_hash: input.tx_hash.clone(),
        verdict,
        exit_code,
        profile: input.profile,
        network: NETWORK_CARDANO_MAINNET,
        confirmation_depth_threshold: threshold,
        validation,
        http_calls: Vec::new(),
        metadata_present: true,
        num_confirmations: resolved.num_confirmations,
        block_time: Some(resolved.block_time),
        block_slot: Some(resolved.block_slot),
        record: Some(record),
        record_signatures,
        item_decryptions,
        tx_witnesses: tx_description.tx_witnesses,
        tx_summary: tx_description.tx_summary,
        metadata_labels: tx_description.metadata_labels,
        // Only present when at least one ciphertext/leaves fetch was attempted.
        uri_checks: if uri_checks.is_empty() {
            None
        } else {
            Some(uri_checks)
        },
        merkle_checks,
    }
}

/// Decode the transaction-level description (witnesses, summary, co-published
/// metadata labels) from raw tx CBOR.
///
/// Purely informational, so a decode failure must NOT propagate into the verdict:
/// it degrades to omitting the affected fields. The label-309 record is validated
/// separately; this view only describes the carrying transaction. When the outer
/// tx walk itself fails, every field is left absent (the report omits all three).
fn decode_tx_description(
    tx_cbor: &[u8],
    network: crate::verifier::types::CardanoNetwork,
) -> TxDescription {
    let Ok(components) = slice_tx_components(tx_cbor) else {
        return TxDescription::default();
    };
    TxDescription {
        metadata_labels: Some(components.aux_metadata_labels),
        tx_witnesses: Some(decode_tx_witnesses(
            &components.witness_set,
            &components.tx_body,
        )),
        tx_summary: decode_tx_summary(&components.tx_body, &components.witness_set, network).ok(),
    }
}

/// Build the report for a resolve-stage failure, mapping the error class to the
/// verdict / exit-code / issue-code triple the twins emit.
fn resolve_failure_report(
    input: &VerifyTxInput<'_>,
    threshold: u32,
    error: &ResolveError,
) -> VerifyReport {
    let (exit_code, code) = match error {
        ResolveError::NotALabel309Record(_) => (ExitCode::Integrity, ErrorCode::MetadataNotFound),
        ResolveError::ServiceIndependence(_) => {
            (ExitCode::Integrity, ErrorCode::ServiceIndependenceViolation)
        }
        ResolveError::ProviderUnavailable(_) => (ExitCode::Network, ErrorCode::ProviderUnavailable),
    };
    base_report(
        input,
        threshold,
        Verdict::Failed,
        exit_code,
        BaseOverrides {
            validation: issue_summary(code, error_message(error)),
            ..Default::default()
        },
    )
}

fn error_message(error: &ResolveError) -> String {
    match error {
        ResolveError::NotALabel309Record(m)
        | ResolveError::ServiceIndependence(m)
        | ResolveError::ProviderUnavailable(m) => m.clone(),
    }
}

/// Whether any signature check is a hard failure (every reason except the
/// info-severity `SIGNATURE_UNSUPPORTED` escalates the verdict).
fn has_hard_signature_failure(checks: &[SignatureCheck]) -> bool {
    use crate::verifier::types::SigFailureReason;
    checks
        .iter()
        .any(|c| !c.valid && c.reason != Some(SigFailureReason::SignatureUnsupported))
}

/// Classify the decryption outcome: `None` on success; otherwise the exit-code
/// class. A failure is any `!ok` row or a recovered-but-integrity-mismatched
/// plaintext. Network class (exit 2) applies only when at least one `!ok` row
/// carries a content/ciphertext-unavailability reason; otherwise integrity
/// (exit 1). Mirrors the Python twin's `has_network_class` test exactly.
fn decryption_failure_class(results: &[DecryptResult]) -> Option<ExitCode> {
    use crate::verifier::types::DecryptionFailureReason;
    let any_failure = results
        .iter()
        .any(|d| !d.ok || d.plaintext_hash_ok == Some(false));
    if !any_failure {
        return None;
    }
    let has_network_class = results.iter().any(|d| {
        !d.ok
            && matches!(
                d.reason,
                Some(DecryptionFailureReason::ContentUnavailable)
                    | Some(DecryptionFailureReason::CiphertextUnavailable)
            )
    });
    Some(if has_network_class {
        ExitCode::Network
    } else {
        ExitCode::Integrity
    })
}

/// Whether any Merkle check escalates the verdict (only error-severity reasons
/// do; an unavailable leaves blob stays warning-class).
fn merkle_should_fail(checks: &[crate::verifier::types::MerkleCheck]) -> bool {
    use crate::verifier::types::MerkleCheckReason;
    checks.iter().any(|c| {
        c.root_ok == Some(false)
            || matches!(
                c.reason,
                Some(MerkleCheckReason::MerkleRootMismatch)
                    | Some(MerkleCheckReason::SchemaMerkleLeafCountMismatch)
                    | Some(MerkleCheckReason::SchemaMerkleLeavesFormatUnsupported)
            )
    })
}

/// A single-issue validation summary helper for the short-circuit report paths.
fn issue_summary(code: ErrorCode, message: impl Into<String>) -> ValidationSummary {
    ValidationSummary {
        valid: false,
        issues: vec![VerifierIssue::new(code, Vec::new(), message)],
        ..Default::default()
    }
}

/// Optional overrides applied on top of the base report skeleton.
#[derive(Default)]
struct BaseOverrides {
    num_confirmations: u32,
    block_time: Option<u64>,
    block_slot: Option<u64>,
    metadata_present: bool,
    record: Option<PoeRecord>,
    validation: ValidationSummary,
    tx_description: TxDescription,
}

/// Build a report for a short-circuit (non-happy) path with the shared defaults.
fn base_report(
    input: &VerifyTxInput<'_>,
    threshold: u32,
    verdict: Verdict,
    exit_code: ExitCode,
    over: BaseOverrides,
) -> VerifyReport {
    VerifyReport {
        tx_hash: input.tx_hash.clone(),
        verdict,
        exit_code,
        profile: input.profile,
        network: NETWORK_CARDANO_MAINNET,
        confirmation_depth_threshold: threshold,
        validation: over.validation,
        http_calls: Vec::new(),
        metadata_present: over.metadata_present,
        num_confirmations: over.num_confirmations,
        block_time: over.block_time,
        block_slot: over.block_slot,
        record: over.record,
        record_signatures: None,
        item_decryptions: None,
        tx_witnesses: over.tx_description.tx_witnesses,
        tx_summary: over.tx_description.tx_summary,
        metadata_labels: over.tx_description.metadata_labels,
        uri_checks: None,
        merkle_checks: None,
    }
}
