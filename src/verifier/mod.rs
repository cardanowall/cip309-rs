//! Public and recipient verifiers over Cardano transaction metadata.
//!
//! The verifier validates a Label 309 record drawn from a Cardano transaction's
//! metadata without trusting the publisher, the operator, or any issuer server.
//! A record must verify only from the transaction bytes, an optional copy of the
//! content, and a public blockchain explorer.
//!
//! This module hosts the security-critical outbound-HTTP layer that the verify
//! pipeline relies on:
//!
//! - [`fetch`] — the canonical outbound fetcher. It enforces a protocol and
//!   method allowlist, a deny-host short circuit for service-independence, a
//!   bounded response-body cap, bounded timeouts, optional retry with jittered
//!   backoff, and a per-call audit trail. It also carries the IP-layer SSRF
//!   guard used for user-supplied (`webhook`) URLs: DNS resolution against an
//!   injectable resolver, a full private/special-purpose IP-range blocklist, and
//!   a resolved-IP return so the caller can pin the TCP connection against
//!   DNS-rebinding.

pub mod cbor_walker;
pub mod content;
pub mod decrypt;
pub mod egress;
pub mod fetch;
pub mod merkle;
pub mod profile;
pub mod resolve;
pub mod serialize;
pub mod signatures;
pub mod tx_witnesses;
pub mod types;
pub mod verify;

pub use cbor_walker::{
    bind_transaction, extract_auxiliary_data_hash, extract_label_309_metadata,
    reassemble_label_309_value, slice_tx, unwrap_auxiliary_data, CarriageError, TxBindingError,
    TxSlices, UnwrappedAux,
};
pub use content::{
    parse_cid, recompute_item_hashes, verify_ipfs_cid_binding, CidBindingOutcome,
    ContentFetchPolicy, ParsedCid, ARWEAVE_GATEWAY_DEFAULTS,
};
pub use decrypt::{decrypt_item, ItemDecryptionResult};
pub use egress::GatewayFetcher;
pub use merkle::{check_merkle_commit, MerkleCommitOutcome};
pub use profile::{detect_conformance_profile, out_of_profile_issues, profile_at_least};
pub use resolve::{
    resolve_cardano_tx, ResolveFailure, ResolvedTx, BLOCKFROST_MAINNET_HOST, KOIOS_MAINNET_URL,
};
pub use serialize::verify_report_to_dict;
pub use signatures::verify_record_signatures;
pub use tx_witnesses::{decode_tx_summary, decode_tx_witnesses};
pub use types::{
    compare_verifier_issues, BlockInfo, CardanoNetwork, ContentCheck, Decryption,
    DecryptionOutcome, ItemReportEntry, MerkleReportEntry, Profile, SigFailureReason,
    SignatureCheck, SignerType, TxDescription, Verdict, VerifierIssue, VerifyReport, VerifyTxInput,
    VerifyTxOutput, VerifyTxSummary, VerifyTxWitness, CONFIRMATION_DEPTH_THRESHOLD_DEFAULT,
    DEFAULT_PROFILE,
};
pub use verify::{verify_record_bytes, verify_tx, ZeroConfirmationDepthError};
