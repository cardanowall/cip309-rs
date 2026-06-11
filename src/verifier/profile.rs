//! Conformance-profile gating.
//!
//! The four profiles form a strict superset ladder
//! `core ⊂ signed ⊂ sealed ⊂ recipient-sealed`. A verifier running at a lower
//! profile that meets a higher-profile field does not fail the record — it emits
//! one [`ErrorCode::OutOfProfileSkipped`] info issue per skipped surface and
//! continues. `merkle[]` is read structurally at every profile and never produces
//! a skip here.

use crate::poe_standard::{ErrorCode, PathSegment, PoeRecord};

use crate::verifier::types::{Profile, VerifierIssue};

/// `true` iff `actual` reads at least the surface of `required`.
#[must_use]
pub fn profile_at_least(actual: Profile, required: Profile) -> bool {
    actual.at_least(required)
}

/// Emit one `OUT_OF_PROFILE_SKIPPED` info issue per record field the active
/// profile does not read.
///
/// - below `signed`: a present `sigs[]` is skipped.
/// - below `sealed`: each `items[i].enc` is skipped (one issue per sealed item).
#[must_use]
pub fn out_of_profile_issues(record: &PoeRecord, profile: Profile) -> Vec<VerifierIssue> {
    let mut out = Vec::new();

    let has_sigs = record.sigs.as_ref().is_some_and(|s| !s.is_empty());
    if !profile_at_least(profile, Profile::Signed) && has_sigs {
        out.push(VerifierIssue::new(
            ErrorCode::OutOfProfileSkipped,
            vec![PathSegment::Key("sigs".to_string())],
            format!(
                "record carries sigs[] but verifier profile '{}' does not read \
                 record-level signatures (signed+ profile required)",
                profile.as_str()
            ),
        ));
    }

    if !profile_at_least(profile, Profile::Sealed) {
        if let Some(items) = &record.items {
            for (i, item) in items.iter().enumerate() {
                if item.enc.is_some() {
                    out.push(VerifierIssue::new(
                        ErrorCode::OutOfProfileSkipped,
                        vec![
                            PathSegment::Key("items".to_string()),
                            PathSegment::Index(i),
                            PathSegment::Key("enc".to_string()),
                        ],
                        format!(
                            "item carries enc envelope but verifier profile '{}' does not \
                             read sealed envelopes (sealed+ profile required)",
                            profile.as_str()
                        ),
                    ));
                }
            }
        }
    }

    out
}

/// The minimum conformance profile a verifier must implement to read this record
/// end-to-end, classified from record content only.
///
/// Returns `core`, `signed`, or `sealed` — never `recipient-sealed`, which is a
/// verifier capability (whether it decrypts), not record content.
#[must_use]
pub fn detect_conformance_profile(record: &PoeRecord) -> Profile {
    let has_sealed = record
        .items
        .as_ref()
        .is_some_and(|items| items.iter().any(|it| it.enc.is_some()));
    if has_sealed {
        return Profile::Sealed;
    }
    if record.sigs.as_ref().is_some_and(|s| !s.is_empty()) {
        return Profile::Signed;
    }
    Profile::Core
}
