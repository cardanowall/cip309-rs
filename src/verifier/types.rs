//! Public types for the Label 309 standalone verifier.
//!
//! The verifier is service-independent: it reads a Cardano transaction's
//! label-309 metadata, validates the record structurally, and runs profile-gated
//! signature, decryption, and Merkle checks — trusting no publisher and no
//! issuer server. The [`VerifyReport`] it produces is the wire body of a verify
//! response; it serialises (via [`super::serialize::verify_report_to_dict`]) to
//! the byte-identical JSON the TypeScript and Python SDKs emit for the same
//! transaction.

use std::collections::BTreeMap;

use crate::poe_standard::{ErrorCode, PoeRecord, Severity};

pub use crate::verifier::fetch::{
    FetchOutboundOptions, FetchOutboundResult, FetchTransport, HttpCallRecord, HttpMethod,
    HttpPurpose,
};

/// The wire-canonical network identifier surfaced on every report.
///
/// Label 309 product policy is Cardano mainnet only; the value is fixed so a
/// downstream consumer never has to infer which network a record was anchored
/// on. The `cardano_network` input governs only path-2 stake-byte derivation and
/// does not change this field.
pub const NETWORK_CARDANO_MAINNET: &str = "cardano:mainnet";

/// The default reorg-safety confirmation-depth floor.
///
/// A record with fewer confirmations is well-formed but not yet final, so the
/// verifier returns the [`Verdict::Pending`] / [`ExitCode::InsufficientDepth`]
/// pair rather than a failure.
pub const CONFIRMATION_DEPTH_THRESHOLD_DEFAULT: u32 = 15;

/// The three-state verifier verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every check passed.
    Valid,
    /// The record is well-formed but below the confirmation-depth threshold.
    Pending,
    /// A structural, cryptographic, or network check failed.
    Failed,
}

impl Verdict {
    /// The stable wire token for this verdict, identical across the SDKs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Verdict::Valid => "valid",
            Verdict::Pending => "pending",
            Verdict::Failed => "failed",
        }
    }
}

/// The verifier exit code, paired with [`Verdict`].
///
/// `0` is the only happy path; `3` fires exclusively on insufficient
/// confirmations; `1` is the record-attributable failure class; `2` is the
/// network failure class (a different gateway may succeed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// `0` — every check passed.
    Ok,
    /// `1` — integrity / structural / signature failure.
    Integrity,
    /// `2` — network failure (provider or content unavailable).
    Network,
    /// `3` — insufficient confirmations.
    InsufficientDepth,
}

impl ExitCode {
    /// The numeric wire value (`0..=3`).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            ExitCode::Ok => 0,
            ExitCode::Integrity => 1,
            ExitCode::Network => 2,
            ExitCode::InsufficientDepth => 3,
        }
    }
}

/// The four conformance profiles, in strict-superset order.
///
/// A verifier of a lower profile that meets a higher-profile field emits an
/// [`ErrorCode::OutOfProfileSkipped`] info issue and continues; it never reports
/// the record invalid. `recipient-sealed` is the union (the default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Profile {
    /// Hash-only: reads `items.hashes` / `uris` / `merkle` structurally.
    Core,
    /// `core` plus record-level `sigs[]`.
    Signed,
    /// `signed` plus the `enc` envelope structure.
    Sealed,
    /// `sealed` plus byte-level decryption with a recipient key.
    RecipientSealed,
}

impl Profile {
    /// The strict-superset rank (`core` = 0 … `recipient-sealed` = 3).
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Profile::Core => 0,
            Profile::Signed => 1,
            Profile::Sealed => 2,
            Profile::RecipientSealed => 3,
        }
    }

    /// `true` iff this profile reads at least the surface of `required`.
    #[must_use]
    pub const fn at_least(self, required: Profile) -> bool {
        self.rank() >= required.rank()
    }

    /// The stable wire token for this profile, identical across the SDKs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Profile::Core => "core",
            Profile::Signed => "signed",
            Profile::Sealed => "sealed",
            Profile::RecipientSealed => "recipient-sealed",
        }
    }
}

/// The verifier's default profile: the full pipeline.
pub const DEFAULT_PROFILE: Profile = Profile::RecipientSealed;

/// One verifier issue: a taxonomy code, its severity, a path, and a message.
///
/// `path` and `message` carry human diagnostics; the cross-implementation parity
/// surface is `code`. The `path` mirrors the Python `VerifierIssue.path` tuple so
/// the serialised report matches byte-for-byte where a path is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierIssue {
    /// The taxonomy code (its wire string is the stable identifier).
    pub code: ErrorCode,
    /// The dotted path into the record this issue concerns (may be empty).
    pub path: Vec<PathSegment>,
    /// A human-readable description (informational; not part of the contract).
    pub message: String,
    /// The issue severity.
    pub severity: Severity,
}

/// A single segment of a [`VerifierIssue`] path: either a map key or an index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    /// A textual key (e.g. `"sigs"`).
    Key(String),
    /// A numeric index (e.g. an `items[i]` position).
    Index(usize),
}

impl VerifierIssue {
    /// Build an issue, taking its severity from the code's catalogue default.
    #[must_use]
    pub fn new(code: ErrorCode, path: Vec<PathSegment>, message: impl Into<String>) -> Self {
        Self {
            code,
            path,
            message: message.into(),
            severity: code.severity(),
        }
    }
}

impl From<&crate::poe_standard::ValidationIssue> for VerifierIssue {
    /// Lift a structural-validator issue into a verifier issue.
    ///
    /// The structural validator's issues carry no structured path (their parity
    /// surface is the code), so the lifted issue has an empty path.
    fn from(issue: &crate::poe_standard::ValidationIssue) -> Self {
        Self {
            code: issue.code,
            path: Vec::new(),
            message: issue.message.clone(),
            severity: issue.severity,
        }
    }
}

/// The validation summary: a pass flag plus three severity-keyed issue lists.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidationSummary {
    /// `true` only when the verdict stayed [`Verdict::Valid`].
    pub valid: bool,
    /// Error-severity issues (drive a failed/pending verdict).
    pub issues: Vec<VerifierIssue>,
    /// Warning-severity issues (never fail the record).
    pub warnings: Vec<VerifierIssue>,
    /// Info-severity issues (out-of-profile skips, unsupported algorithms).
    pub info: Vec<VerifierIssue>,
}

/// The signer-key resolution path for a record signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerType {
    /// The 32-byte protected-header `kid` carried the raw Ed25519 pubkey.
    InSignatureKid,
    /// A `sigs[i].cose_key` COSE_Key blob carried the wallet pubkey.
    WalletInlineKey,
}

impl SignerType {
    /// The stable wire token for this signer type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SignerType::InSignatureKid => "in-signature-kid",
            SignerType::WalletInlineKey => "wallet-inline-key",
        }
    }
}

/// Per-entry signature failure reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigFailureReason {
    /// The COSE_Sign1 blob did not decode / had an attached payload.
    MalformedSigCoseSign1,
    /// The protected `alg` was not EdDSA (`-8`); info-severity, never fails.
    SignatureUnsupported,
    /// No 32-byte signer key could be resolved.
    SignerKeyUnresolved,
    /// The Ed25519 signature did not verify.
    SignatureInvalid,
    /// The path-2 wallet `address` did not bind to the resolved pubkey.
    WalletAddressMismatch,
}

impl SigFailureReason {
    /// The stable wire token for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SigFailureReason::MalformedSigCoseSign1 => "MALFORMED_SIG_COSE_SIGN1",
            SigFailureReason::SignatureUnsupported => "SIGNATURE_UNSUPPORTED",
            SigFailureReason::SignerKeyUnresolved => "SIGNER_KEY_UNRESOLVED",
            SigFailureReason::SignatureInvalid => "SIGNATURE_INVALID",
            SigFailureReason::WalletAddressMismatch => "WALLET_ADDRESS_MISMATCH",
        }
    }
}

/// One record-level signature verification outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureCheck {
    /// The `sigs[]` index.
    pub index: usize,
    /// Whether the signature verified (and, for path-2, bound its address).
    pub valid: bool,
    /// The resolved signer pubkey as lowercase hex, when resolution succeeded.
    pub signer_pub: Option<String>,
    /// The signer-key resolution path, when resolved.
    pub signer_type: Option<SignerType>,
    /// The failure reason, when `valid` is `false`.
    pub reason: Option<SigFailureReason>,
}

impl SignatureCheck {
    /// The 4-state wire `verdict` token, derived from the failure reason.
    ///
    /// A public hash-only PoE stays `"valid"` even when a signature is
    /// `"unsupported"`; `"unresolved"` is its own verdict; every other failure
    /// collapses to `"invalid"`. Identical across the SDKs.
    #[must_use]
    pub const fn verdict_str(&self) -> &'static str {
        match self.reason {
            None => "valid",
            Some(SigFailureReason::SignatureUnsupported) => "unsupported",
            Some(SigFailureReason::SignerKeyUnresolved) => "unresolved",
            Some(_) => "invalid",
        }
    }
}

/// Per-decryption failure reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptionFailureReason {
    /// The item has no `enc` envelope, an out-of-range index, or an unwrappable
    /// shape.
    NoEncEnvelope,
    /// A gateway returned a non-200 status for the ciphertext URI.
    UriFetchFailed,
    /// No ciphertext could be obtained from the record alone.
    CiphertextUnavailable,
    /// The reconstructed URI named no in-set retrieval scheme.
    UriTargetForbidden,
    /// Every configured gateway was exhausted.
    ContentUnavailable,
    /// No supplied recipient key opened any slot.
    WrongRecipientKey,
    /// A CEK was recovered but the slots MAC did not match.
    TamperedHeader,
    /// The content AEAD failed after a CEK was recovered.
    TamperedCiphertext,
    /// The decryption entry shape did not match the envelope's key path.
    WrongDecryptionInputShape,
    /// The passphrase KDF step failed.
    KdfDerivationFailed,
    /// The recovered plaintext did not match a committed content hash.
    UriIntegrityMismatch,
}

impl DecryptionFailureReason {
    /// The stable wire token for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            DecryptionFailureReason::NoEncEnvelope => "no_enc_envelope",
            DecryptionFailureReason::UriFetchFailed => "URI_FETCH_FAILED",
            DecryptionFailureReason::CiphertextUnavailable => "CIPHERTEXT_UNAVAILABLE",
            DecryptionFailureReason::UriTargetForbidden => "URI_TARGET_FORBIDDEN",
            DecryptionFailureReason::ContentUnavailable => "CONTENT_UNAVAILABLE",
            DecryptionFailureReason::WrongRecipientKey => "WRONG_RECIPIENT_KEY",
            DecryptionFailureReason::TamperedHeader => "TAMPERED_HEADER",
            DecryptionFailureReason::TamperedCiphertext => "TAMPERED_CIPHERTEXT",
            DecryptionFailureReason::WrongDecryptionInputShape => "WRONG_DECRYPTION_INPUT_SHAPE",
            DecryptionFailureReason::KdfDerivationFailed => "KDF_DERIVATION_FAILED",
            DecryptionFailureReason::UriIntegrityMismatch => "URI_INTEGRITY_MISMATCH",
        }
    }
}

/// One item-decryption outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptResult {
    /// The `items[]` index the entry targeted.
    pub item_index: i64,
    /// Whether decryption produced a plaintext (the integrity check may still
    /// have failed — see `plaintext_hash_ok`).
    pub ok: bool,
    /// Whether every committed content hash recomputed to the plaintext. Present
    /// only when `ok` is `true`.
    pub plaintext_hash_ok: Option<bool>,
    /// The failure reason, when one applies.
    pub reason: Option<DecryptionFailureReason>,
}

impl DecryptResult {
    /// The wire `verdict` token. `"decrypted"` on success; each failure reason
    /// projects to its distinct verdict, identical across the SDKs.
    #[must_use]
    pub const fn verdict_str(&self) -> &'static str {
        match self.reason {
            None => "decrypted",
            Some(DecryptionFailureReason::NoEncEnvelope) => "no-enc-envelope",
            Some(DecryptionFailureReason::WrongDecryptionInputShape) => "wrong-input-shape",
            Some(DecryptionFailureReason::CiphertextUnavailable)
            | Some(DecryptionFailureReason::UriTargetForbidden) => "ciphertext-unavailable",
            Some(DecryptionFailureReason::ContentUnavailable)
            | Some(DecryptionFailureReason::UriFetchFailed) => "content-unavailable",
            Some(DecryptionFailureReason::WrongRecipientKey) => "wrong-key",
            Some(DecryptionFailureReason::TamperedHeader) => "tampered-header",
            Some(DecryptionFailureReason::TamperedCiphertext)
            | Some(DecryptionFailureReason::UriIntegrityMismatch) => "tampered-ciphertext",
            Some(DecryptionFailureReason::KdfDerivationFailed) => "kdf-failed",
        }
    }

    /// The wire `reason` string, when a failure reason applies. The
    /// `NoEncEnvelope` (missing-envelope) case carries no reason, matching the
    /// reference verifier's bare `no-enc-envelope` row.
    #[must_use]
    pub fn reason_str(&self) -> Option<&'static str> {
        match self.reason {
            None | Some(DecryptionFailureReason::NoEncEnvelope) => None,
            Some(r) => Some(r.as_str()),
        }
    }
}

/// Per-commit Merkle outcome reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleCheckReason {
    /// The leaves payload could not be fetched; warning-severity.
    MerkleLeavesUnavailable,
    /// The recomputed root did not match the committed root.
    MerkleRootMismatch,
    /// The verifier does not implement this commitment algorithm.
    MerkleUnsupported,
    /// The leaves count did not match the committed count.
    SchemaMerkleLeafCountMismatch,
    /// The leaves payload used an unsupported format.
    SchemaMerkleLeavesFormatUnsupported,
}

impl MerkleCheckReason {
    /// The stable wire token for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            MerkleCheckReason::MerkleLeavesUnavailable => "MERKLE_LEAVES_UNAVAILABLE",
            MerkleCheckReason::MerkleRootMismatch => "MERKLE_ROOT_MISMATCH",
            MerkleCheckReason::MerkleUnsupported => "MERKLE_UNSUPPORTED",
            MerkleCheckReason::SchemaMerkleLeafCountMismatch => "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
            MerkleCheckReason::SchemaMerkleLeavesFormatUnsupported => {
                "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED"
            }
        }
    }
}

/// One Merkle list-commitment outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleCheck {
    /// The `merkle[]` index.
    pub merkle_index: usize,
    /// The commitment algorithm identifier.
    pub alg: String,
    /// Whether the recomputed root matched, when a fold was performed.
    pub root_ok: Option<bool>,
    /// The reason, for any non-`valid` outcome.
    pub reason: Option<MerkleCheckReason>,
}

impl MerkleCheck {
    /// The 5-state wire `verdict` token. `"valid"`/`"mismatch"` are root-bind
    /// outcomes; `"unavailable"`/`"format-unsupported"`/`"unsupported"` are
    /// warning/info-severity (they never fail the record). Identical across SDKs.
    #[must_use]
    pub const fn verdict_str(&self) -> &'static str {
        match self.reason {
            None => {
                if matches!(self.root_ok, Some(false)) {
                    "mismatch"
                } else {
                    "valid"
                }
            }
            Some(MerkleCheckReason::MerkleUnsupported) => "unsupported",
            Some(MerkleCheckReason::MerkleLeavesUnavailable) => "unavailable",
            Some(MerkleCheckReason::SchemaMerkleLeavesFormatUnsupported) => "format-unsupported",
            Some(MerkleCheckReason::MerkleRootMismatch)
            | Some(MerkleCheckReason::SchemaMerkleLeafCountMismatch) => "mismatch",
        }
    }
}

/// Per-attempt URI-fetch outcome reason (carried on `uri_checks`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriFailureReason {
    /// A gateway returned a non-200 status.
    UriFetchFailed,
    /// The fetched bytes did not match the committed hash.
    UriIntegrityMismatch,
    /// The URI named no in-set retrieval scheme.
    UriTargetForbidden,
    /// Every configured gateway was exhausted.
    ContentUnavailable,
}

impl UriFailureReason {
    /// The stable wire token for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            UriFailureReason::UriFetchFailed => "URI_FETCH_FAILED",
            UriFailureReason::UriIntegrityMismatch => "URI_INTEGRITY_MISMATCH",
            UriFailureReason::UriTargetForbidden => "URI_TARGET_FORBIDDEN",
            UriFailureReason::ContentUnavailable => "CONTENT_UNAVAILABLE",
        }
    }
}

/// One vkey witness on the carrying transaction.
///
/// Distinct from a record-level [`SignatureCheck`]: this describes who authorised
/// and paid for the anchoring transaction, not the optional Label 309 authorship
/// claim. A failed `signature_valid` is INFORMATIONAL — it never changes the
/// verifier's verdict (the content claim does not depend on who paid the fee).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyTxWitness {
    /// The 32-byte Ed25519 verification key, lowercase hex.
    pub vkey: String,
    /// The 28-byte BLAKE2b-224 key hash of the vkey, lowercase hex.
    pub key_hash: String,
    /// Whether `Ed25519.verify(sig, blake2b256(tx_body), vkey)` held.
    pub signature_valid: bool,
}

/// One transaction output: a bech32 address and its lovelace amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyTxOutput {
    /// The bech32-encoded (CIP-19) output address.
    pub address: String,
    /// The lovelace amount as a decimal string (coin values can exceed `2^53`).
    pub lovelace: String,
}

/// A JSON-safe description of the carrying transaction body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyTxSummary {
    /// The transaction fee in lovelace, as a decimal string.
    pub fee_lovelace: String,
    /// The number of transaction inputs.
    pub input_count: u64,
    /// The number of transaction outputs.
    pub output_count: u64,
    /// The output addresses and lovelace amounts.
    pub outputs: Vec<VerifyTxOutput>,
    /// The sum of output lovelace, as a decimal string.
    pub total_output_lovelace: String,
    /// The count of non-vkey (script/bootstrap/Plutus) witnesses.
    pub script_witness_count: u64,
    /// The validity-interval start slot, when present.
    pub invalid_before: Option<u64>,
    /// The TTL (validity-interval end) slot, when present.
    pub invalid_hereafter: Option<u64>,
    /// The required-signer key hashes (lowercase hex), when any are present.
    pub required_signer_key_hashes: Option<Vec<String>>,
    /// The transaction's network id, when present.
    pub network_id: Option<u64>,
}

/// The transaction-level description merged into a report when raw tx CBOR is
/// available: who authorised/paid for the anchoring, plus the co-published
/// metadata labels. Verdict-neutral.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxDescription {
    /// The vkey witnesses, when the witness set decoded.
    pub tx_witnesses: Option<Vec<VerifyTxWitness>>,
    /// The transaction body summary, when the body decoded.
    pub tx_summary: Option<VerifyTxSummary>,
    /// The ascending-sorted auxiliary metadata label keys, when aux decoded.
    pub metadata_labels: Option<Vec<i64>>,
}

/// One per-attempt URI-fetch diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriCheck {
    /// The `items[]` index the URI belongs to.
    pub item_index: i64,
    /// The reconstructed absolute URI.
    pub uri: String,
    /// Whether the attempt returned the content.
    pub ok: bool,
    /// The failure reason, when the attempt failed.
    pub reason: Option<UriFailureReason>,
}

/// One out-of-band decryption request.
///
/// The verifier dispatches on the on-wire `enc` shape (`slots[]` for the
/// recipient path, `passphrase` for the KDF path); a mismatched entry surfaces as
/// [`DecryptionFailureReason::WrongDecryptionInputShape`].
#[derive(Debug, Clone)]
pub enum Decryption {
    /// Sealed-recipient path: the 32-byte X25519 (or X-Wing) recipient secret.
    Recipient {
        /// The `items[]` index this entry targets.
        item_index: i64,
        /// The recipient secret key bytes.
        recipient_secret_key: Vec<u8>,
    },
    /// Passphrase path: the cleartext passphrase, normalised before KDF.
    Passphrase {
        /// The `items[]` index this entry targets.
        item_index: i64,
        /// The passphrase string.
        passphrase: String,
    },
}

impl Decryption {
    /// The targeted item index, regardless of path.
    #[must_use]
    pub const fn item_index(&self) -> i64 {
        match self {
            Decryption::Recipient { item_index, .. }
            | Decryption::Passphrase { item_index, .. } => *item_index,
        }
    }
}

/// The Cardano network governing path-2 stake-byte derivation.
///
/// This input never changes the report `network` field (always
/// [`NETWORK_CARDANO_MAINNET`]); it only selects the CIP-19 stake-address network
/// header used when binding a wallet signature's `address` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CardanoNetwork {
    /// Cardano mainnet (stake header `0xe1`). The default.
    #[default]
    Mainnet,
    /// Cardano preprod (stake header `0xe0`).
    Preprod,
}

/// The verifier input.
///
/// Mirrors the Python `VerifyTxInput`: a transaction hash, an optional profile
/// and gateway chains, optional out-of-band decryption material, and an
/// injectable [`FetchTransport`] for deterministic tests.
pub struct VerifyTxInput<'a> {
    /// Lowercase transaction hash (no `0x`).
    pub tx_hash: String,
    /// The verifier profile. Defaults to [`DEFAULT_PROFILE`].
    pub profile: Profile,
    /// Koios-compatible gateway URLs, tried in order.
    pub cardano_gateway_chain: Option<Vec<String>>,
    /// Enables the Blockfrost fallback when set.
    pub blockfrost_project_id: Option<String>,
    /// Arweave gateway rotation (defaults baked in when absent).
    pub arweave_gateway_chain: Option<Vec<String>>,
    /// IPFS gateway rotation (no baked-in default).
    pub ipfs_gateway_chain: Option<Vec<String>>,
    /// Confirmation-depth floor. Defaults to
    /// [`CONFIRMATION_DEPTH_THRESHOLD_DEFAULT`].
    pub confirmation_depth_threshold: Option<u32>,
    /// Service-independence deny-host patterns.
    pub deny_hosts: Option<Vec<String>>,
    /// Out-of-band decryption requests.
    pub decryption: Option<Vec<Decryption>>,
    /// Out-of-band ciphertext bytes, keyed by item index.
    pub ciphertext_bytes: Option<BTreeMap<i64, Vec<u8>>>,
    /// Out-of-band Merkle leaves-list bytes, keyed by `merkle[i]` index.
    pub merkle_leaves: Option<BTreeMap<usize, Vec<u8>>>,
    /// Network used for path-2 stake-byte derivation only.
    pub cardano_network: CardanoNetwork,
    /// Injectable transport (the single outbound egress point).
    pub fetch_outbound: Option<&'a dyn FetchTransport>,
}

impl<'a> VerifyTxInput<'a> {
    /// A minimal input: a transaction hash and the default profile/gateways.
    #[must_use]
    pub fn new(tx_hash: impl Into<String>) -> Self {
        Self {
            tx_hash: tx_hash.into(),
            profile: DEFAULT_PROFILE,
            cardano_gateway_chain: None,
            blockfrost_project_id: None,
            arweave_gateway_chain: None,
            ipfs_gateway_chain: None,
            confirmation_depth_threshold: None,
            deny_hosts: None,
            decryption: None,
            ciphertext_bytes: None,
            merkle_leaves: None,
            cardano_network: CardanoNetwork::Mainnet,
            fetch_outbound: None,
        }
    }

    /// The effective confirmation-depth threshold.
    #[must_use]
    pub fn threshold(&self) -> u32 {
        self.confirmation_depth_threshold
            .unwrap_or(CONFIRMATION_DEPTH_THRESHOLD_DEFAULT)
    }
}

/// The full verifier report.
///
/// Field names match the wire shape one-to-one. Serialisation rules (bytes →
/// lowercase hex, omission of `None` and empty lists) live in
/// [`super::serialize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// The transaction hash.
    pub tx_hash: String,
    /// The three-state verdict.
    pub verdict: Verdict,
    /// The exit code paired with the verdict.
    pub exit_code: ExitCode,
    /// The active verifier profile.
    pub profile: Profile,
    /// The wire-canonical network identifier.
    pub network: &'static str,
    /// The confirmation-depth threshold applied.
    pub confirmation_depth_threshold: u32,
    /// The validation summary.
    pub validation: ValidationSummary,
    /// The per-call outbound audit trail.
    pub http_calls: Vec<HttpCallRecord>,
    /// Whether label-309 metadata was present.
    pub metadata_present: bool,
    /// The transaction's confirmation depth.
    pub num_confirmations: u32,
    /// The block time (Unix seconds), when resolved.
    pub block_time: Option<u64>,
    /// The block slot, when resolved.
    pub block_slot: Option<u64>,
    /// The decoded record, projected to JSON, when validation passed.
    pub record: Option<PoeRecord>,
    /// Record-level signature checks, when run.
    pub record_signatures: Option<Vec<SignatureCheck>>,
    /// Item-decryption results, when run.
    pub item_decryptions: Option<Vec<DecryptResult>>,
    /// The carrying transaction's vkey witnesses, when raw tx CBOR was available.
    pub tx_witnesses: Option<Vec<VerifyTxWitness>>,
    /// The carrying transaction's body summary, when the body decoded.
    pub tx_summary: Option<VerifyTxSummary>,
    /// The co-published auxiliary metadata label keys, when aux decoded.
    pub metadata_labels: Option<Vec<i64>>,
    /// Per-attempt URI-fetch diagnostics, when any were emitted.
    pub uri_checks: Option<Vec<UriCheck>>,
    /// Merkle list-commitment checks, when run.
    pub merkle_checks: Option<Vec<MerkleCheck>>,
}
