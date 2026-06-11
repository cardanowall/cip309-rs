//! Public types for the Label 309 standalone verifier.
//!
//! The verifier is service-independent: it resolves a Cardano transaction
//! through public explorers, hash-binds the fetched bytes to the requested
//! transaction reference, validates the record structurally, and runs
//! profile-gated signature, content, Merkle, and decryption checks — trusting
//! no publisher and no issuer server. The [`VerifyReport`] it produces follows
//! the published verify-report JSON Schema: the schema's keys and enums are the
//! cross-implementation contract, and this module's types are their typed form.

use std::collections::BTreeMap;

use crate::poe_standard::{ErrorCode, PathSegment, PoeRecord, Severity, ValidationIssue};

pub use crate::verifier::fetch::{
    FetchOutboundOptions, FetchOutboundResult, FetchTransport, HttpCallRecord, HttpMethod,
    HttpPurpose,
};

/// The default reorg-safety confirmation-depth threshold, in blocks.
///
/// A transaction below the threshold is well-formed but not yet final, so the
/// verifier reports [`Verdict::Pending`] rather than a failure. Deployment
/// policy MAY raise it for high-value notarisation.
pub const CONFIRMATION_DEPTH_THRESHOLD_DEFAULT: u32 = 15;

/// The four-state machine verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every check that ran passed and no error-severity issue is present.
    Valid,
    /// On chain but below the confirmation-depth threshold
    /// (`INSUFFICIENT_CONFIRMATIONS`); no result is final.
    Pending,
    /// No record-attributable error, but a required check could not run — or
    /// could not be attributed — for network, policy, or provider-integrity
    /// reasons. The same record may verify `valid` on retry or under a
    /// different gateway configuration.
    Unverifiable,
    /// A record-attributable failure: integrity, structural, signature,
    /// Merkle-mismatch, or service-independence-violation class.
    Failed,
}

impl Verdict {
    /// The stable wire token for this verdict.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Verdict::Valid => "valid",
            Verdict::Pending => "pending",
            Verdict::Unverifiable => "unverifiable",
            Verdict::Failed => "failed",
        }
    }

    /// The four-state process exit code paired with this verdict:
    /// `valid` → 0, `failed` → 1, `unverifiable` → 2, `pending` → 3.
    /// Exit codes 4 and higher are reserved for verifier-host runtime failures
    /// that are not record-attributable and do not correspond to a verdict.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Verdict::Valid => 0,
            Verdict::Failed => 1,
            Verdict::Unverifiable => 2,
            Verdict::Pending => 3,
        }
    }
}

/// The four conformance profiles, in strict-superset order.
///
/// A verifier of a lower profile that meets a higher-profile field emits an
/// [`ErrorCode::OutOfProfileSkipped`] info issue and continues; it never
/// reports the record invalid on that ground. `recipient-sealed` is the union
/// (the default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Profile {
    /// Hash-only: structural validation plus content-hash checks.
    Core,
    /// `core` plus record-level signature verification.
    Signed,
    /// `signed` plus the structural surface of the encryption envelope.
    Sealed,
    /// `sealed` plus sealed-PoE decryption with held credentials.
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

    /// The stable wire token for this profile.
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

/// One report issue: a taxonomy code, its path, severity, and message.
///
/// The shape is shared by the structural validator and the verifier layer;
/// verifier-layer codes that concern the run rather than a record location
/// carry an empty path. The cross-implementation parity surface is
/// `(path, code, severity)`; `message` is human diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierIssue {
    /// Segments from the record root: text map keys and integer array indices.
    pub path: Vec<PathSegment>,
    /// The canonical taxonomy code.
    pub code: ErrorCode,
    /// The issue severity. Always emitted explicitly on the wire.
    pub severity: Severity,
    /// A human-readable explanation including the offending value.
    pub message: String,
}

impl VerifierIssue {
    /// Build an issue, taking its severity from the code's catalogue default.
    #[must_use]
    pub fn new(code: ErrorCode, path: Vec<PathSegment>, message: impl Into<String>) -> Self {
        Self {
            path,
            code,
            severity: code.severity(),
            message: message.into(),
        }
    }

    /// Build an issue with an explicit severity (the dual-severity escalations).
    #[must_use]
    pub fn with_severity(
        code: ErrorCode,
        severity: Severity,
        path: Vec<PathSegment>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            path,
            code,
            severity,
            message: message.into(),
        }
    }
}

impl From<&ValidationIssue> for VerifierIssue {
    /// Lift a structural-validator issue into the report's issue list, path
    /// and severity preserved.
    fn from(issue: &ValidationIssue) -> Self {
        Self {
            path: issue.path.clone(),
            code: issue.code,
            severity: issue.severity,
            message: issue.message.clone(),
        }
    }
}

/// Compare two issues by path (segment-wise) with the error-code-registry
/// order as the tie-break — the normative report ordering.
///
/// Paths are compared element by element from the root: two integer segments
/// compare numerically, two text segments by the bytewise order of their UTF-8
/// encodings, an integer segment orders before a text segment where the kinds
/// differ, and a path that is a strict prefix of another orders before it.
#[must_use]
pub fn compare_verifier_issues(a: &VerifierIssue, b: &VerifierIssue) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let n = a.path.len().min(b.path.len());
    for i in 0..n {
        let ord = match (&a.path[i], &b.path[i]) {
            (PathSegment::Index(x), PathSegment::Index(y)) => x.cmp(y),
            (PathSegment::Index(_), PathSegment::Key(_)) => Ordering::Less,
            (PathSegment::Key(_), PathSegment::Index(_)) => Ordering::Greater,
            (PathSegment::Key(x), PathSegment::Key(y)) => x.as_bytes().cmp(y.as_bytes()),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.path
        .len()
        .cmp(&b.path.len())
        .then_with(|| a.code.registry_index().cmp(&b.code.registry_index()))
}

/// The three-state per-claim content-check status, so an unchecked claim can
/// never masquerade as a verified one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContentCheck {
    /// Bytes were obtained and every committed digest matched.
    Checked,
    /// Attributable fetched (or decrypted) bytes failed a commitment — a
    /// record-attributable integrity outcome.
    Mismatched,
    /// The claim was not checked: `fetch_content` off, availability failure,
    /// unattributable fetched bytes, or the per-URI fetch ceiling.
    #[default]
    NotChecked,
}

impl ContentCheck {
    /// The stable wire token for this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ContentCheck::Checked => "checked",
            ContentCheck::Mismatched => "mismatched",
            ContentCheck::NotChecked => "not_checked",
        }
    }
}

/// The recipient-verifier outcome for one `enc`-bearing item after every
/// applicable keyring credential was attempted independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionOutcome {
    /// Whether an applicable credential recovered the content-encryption key
    /// and the ciphertext opened end-to-end.
    pub decrypted: bool,
    /// The post-decryption recheck: every digest in the item's `hashes` map
    /// recomputed over the recovered plaintext. Present whenever decryption ran
    /// to completion; `false` forces the record's verdict to `failed`.
    pub plaintext_hash_ok: Option<bool>,
    /// The typed code describing why decryption did not succeed; the same code
    /// also appears in the report's issue list.
    pub code: Option<ErrorCode>,
}

/// One per-item report entry, positionally aligned with the record's `items[]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ItemReportEntry {
    /// The per-claim content-check status.
    pub content_check: ContentCheck,
    /// The decryption outcome, for an `enc`-bearing item when the run's
    /// keyring is non-empty.
    pub decryption: Option<DecryptionOutcome>,
}

/// One per-commitment report entry, positionally aligned with `merkle[]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MerkleReportEntry {
    /// The per-claim content-check status of the list commitment (leaves-list
    /// acquisition, document validation, and root recompute).
    pub content_check: ContentCheck,
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
    /// The protected `alg` was outside the known set; info-severity, never
    /// fails the record.
    SignatureUnsupported,
    /// No 32-byte signer key could be resolved.
    SignerKeyUnresolved,
    /// Strict Ed25519 verification returned false.
    SignatureInvalid,
    /// The wallet-path `address` did not bind to the resolved pubkey under the
    /// containing transaction's network.
    WalletAddressMismatch,
}

impl SigFailureReason {
    /// The taxonomy code this reason carries in the issue list.
    #[must_use]
    pub const fn error_code(self) -> ErrorCode {
        match self {
            SigFailureReason::MalformedSigCoseSign1 => ErrorCode::MalformedSigCoseSign1,
            SigFailureReason::SignatureUnsupported => ErrorCode::SignatureUnsupported,
            SigFailureReason::SignerKeyUnresolved => ErrorCode::SignerKeyUnresolved,
            SigFailureReason::SignatureInvalid => ErrorCode::SignatureInvalid,
            SigFailureReason::WalletAddressMismatch => ErrorCode::WalletAddressMismatch,
        }
    }

    /// The stable wire token for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.error_code().code()
    }
}

/// One record-level signature verification outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureCheck {
    /// The `sigs[]` index.
    pub index: usize,
    /// Whether the signature verified (and, on the wallet path, bound its
    /// address).
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
    /// collapses to `"invalid"`.
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

/// One vkey witness on the carrying transaction.
///
/// Distinct from a record-level [`SignatureCheck`]: this describes who
/// authorised and paid for the anchoring transaction, not the optional Label
/// 309 authorship claim. A failed `signature_valid` is INFORMATIONAL — it never
/// changes the verifier's verdict (the content claim does not depend on who
/// paid the fee).
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
    pub metadata_labels: Option<Vec<u64>>,
}

/// One decryption credential of the run's keyring.
///
/// The keyring is **global to the run**, not positionally paired with
/// encrypted items: for each `enc`-bearing item the verifier attempts every
/// credential of the applicable shape independently — `Recipient` entries
/// against `enc.slots`-path items, `Passphrase` entries against
/// `enc.passphrase`-path items. One credential may open several items, and
/// different credentials may succeed on different items.
#[derive(Debug, Clone)]
pub enum Decryption {
    /// A recipient KEM private key: a 32-byte X25519 scalar or a 32-byte
    /// X-Wing decapsulation seed.
    Recipient {
        /// The recipient secret key bytes.
        recipient_secret_key: Vec<u8>,
    },
    /// A passphrase, normalised by the pinned profile before any KDF work.
    Passphrase {
        /// The passphrase string.
        passphrase: String,
    },
}

/// The Cardano network the verifier's explorer chain is configured against.
///
/// Names the report's `network` identifier and selects the expected CIP-19
/// network header byte for wallet-path signature address binding — both
/// derived from the containing transaction's network, never from any value in
/// the record body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CardanoNetwork {
    /// Cardano mainnet. The default; production deployments target mainnet.
    #[default]
    Mainnet,
    /// Cardano preprod (a test network).
    Preprod,
}

impl CardanoNetwork {
    /// The report's network identifier for this network.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            CardanoNetwork::Mainnet => "cardano:mainnet",
            CardanoNetwork::Preprod => "cardano:preprod",
        }
    }
}

/// The verifier input: a transaction reference plus deployment policy,
/// gateway chains, the decryption keyring, and out-of-band bytes.
pub struct VerifyTxInput<'a> {
    /// Lowercase transaction hash (64 hex characters, no `0x`).
    pub tx_hash: String,
    /// The verifier profile. Defaults to [`DEFAULT_PROFILE`].
    pub profile: Profile,
    /// Koios-compatible explorer URLs, tried in order.
    pub cardano_gateway_chain: Option<Vec<String>>,
    /// Enables the Blockfrost fallback explorer when set.
    pub blockfrost_project_id: Option<String>,
    /// Arweave gateway rotation (defaults baked in when absent).
    pub arweave_gateway_chain: Option<Vec<String>>,
    /// IPFS gateway rotation. No baked-in default: a deployment that supplies
    /// none declines every `ipfs://` fetch (`URI_TARGET_FORBIDDEN`).
    pub ipfs_gateway_chain: Option<Vec<String>>,
    /// Confirmation-depth threshold. Defaults to
    /// [`CONFIRMATION_DEPTH_THRESHOLD_DEFAULT`].
    pub confirmation_depth_threshold: Option<u32>,
    /// Service-independence deny-host patterns.
    pub deny_hosts: Option<Vec<String>>,
    /// The master content-fetch switch (default `true`). When `false`, every
    /// outbound content fetch — item URIs, Merkle leaves-lists, and ciphertext
    /// alike — is suppressed, so the record renders offline with every content
    /// claim reported as not checked. Out-of-band bytes are still consumed.
    pub fetch_content: bool,
    /// Per-URI fetch ceiling in bytes, enforced incrementally during
    /// streaming. A fetch that reaches it is aborted and surfaced as
    /// `CONTENT_FETCH_LIMIT_EXCEEDED` — a statement about the verifier's
    /// policy, never about the record. `None` applies the transport default.
    pub max_fetch_bytes: Option<u64>,
    /// The decryption keyring (see [`Decryption`]).
    pub decryption: Option<Vec<Decryption>>,
    /// Out-of-band ciphertext bytes, keyed by item index. Supplied bytes are
    /// attributable by definition.
    pub ciphertext_bytes: Option<BTreeMap<usize, Vec<u8>>>,
    /// Out-of-band Merkle leaves-list bytes, keyed by `merkle[i]` index.
    pub merkle_leaves: Option<BTreeMap<usize, Vec<u8>>>,
    /// The network of the configured explorer chain (see [`CardanoNetwork`]).
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
            fetch_content: true,
            max_fetch_bytes: None,
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

    /// Whether the keyring holds at least one credential. Necessary but not
    /// sufficient for the recipient-verifier reading: the run is a recipient
    /// verifier only when credentials are held AND the profile admits sealed
    /// decryption.
    #[must_use]
    pub fn has_keyring(&self) -> bool {
        self.decryption.as_ref().is_some_and(|d| !d.is_empty())
    }
}

/// Caller-supplied chain facts for the record-bytes entry point: the block-info
/// tuple a server-rendered viewer holds from its index, in the pinned
/// representations (integer POSIX seconds for `block_time`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockInfo {
    /// Confirmation depth in blocks: explorer tip height − including-block
    /// height + 1, so a transaction in the tip block has depth exactly 1.
    pub confirmation_depth: u32,
    /// The POSIX timestamp, in integer seconds UTC, of the slot of the block
    /// that includes the transaction.
    pub block_time: u64,
    /// The slot number of the including block, when available.
    pub block_slot: Option<u64>,
}

/// The full verifier report.
///
/// The schema-pinned surface is: `verdict`, `exitCode` (derived from the
/// verdict), `network`, `confirmationDepth` / `confirmationThreshold`,
/// `block_time` / `block_slot`, the flat `issues` list, the positional `items`
/// and `merkle` per-claim entries, and the `auditTrail`. The remaining fields
/// are implementation extras (the schema is an open map).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// The requested transaction hash.
    pub tx_hash: String,
    /// The four-state machine verdict ([`Verdict::exit_code`] pairs it with
    /// the process exit code).
    pub verdict: Verdict,
    /// The active verifier profile.
    pub profile: Profile,
    /// The network identifier of the resolved transaction, as established by
    /// the configured explorer chain.
    pub network: &'static str,
    /// The confirmation-depth threshold the resolved depth was compared
    /// against.
    pub confirmation_threshold: u32,
    /// The explorer-asserted confirmation depth, when the transaction
    /// resolved.
    pub confirmation_depth: Option<u32>,
    /// The block time in integer POSIX seconds UTC, when resolved.
    pub block_time: Option<u64>,
    /// The block slot, when resolved.
    pub block_slot: Option<u64>,
    /// Every issue of the run — structural-validation issues plus
    /// verifier-layer codes — sorted by path with the registry-order
    /// tie-break, each carrying an explicit severity.
    pub issues: Vec<VerifierIssue>,
    /// One entry per record `items[]` element, positionally aligned. Empty
    /// exactly when no validated record with an `items` array is in hand.
    pub items: Vec<ItemReportEntry>,
    /// One entry per record `merkle[]` element, positionally aligned.
    pub merkle: Vec<MerkleReportEntry>,
    /// Every outbound network call of the run — success, failure, retry —
    /// recorded by the single egress wrapper.
    pub audit_trail: Vec<HttpCallRecord>,
    /// The decoded record, when structural validation passed.
    pub record: Option<PoeRecord>,
    /// Record-level signature checks, when the signature step ran.
    pub record_signatures: Option<Vec<SignatureCheck>>,
    /// The carrying transaction's vkey witnesses, when raw tx CBOR decoded.
    pub tx_witnesses: Option<Vec<VerifyTxWitness>>,
    /// The carrying transaction's body summary, when the body decoded.
    pub tx_summary: Option<VerifyTxSummary>,
    /// The co-published auxiliary metadata label keys, when aux decoded.
    pub metadata_labels: Option<Vec<u64>>,
}
