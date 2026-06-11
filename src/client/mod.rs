//! Gateway-agnostic HTTP client for the Label 309 service surface.
//!
//! The client targets any Label 309 gateway: the caller passes an explicit
//! `base_url` and an opaque bearer key, and every request is built through the
//! verifier's single outbound egress
//! ([`crate::verifier::fetch`]) so the deny-host policy, the protocol/method
//! allowlist, the bounded response-body cap, and the audit trail all apply.
//!
//! The surface mirrors the TypeScript and Python SDKs:
//!
//! - [`Label309Client`] — construction (required `base_url` + optional
//!   opaque bearer) and the three namespaces.
//! - [`PoeNamespace`] — quote, multipart uploads, publish, publish-batch, and
//!   the high-level [`publish_content`](PoeNamespace::publish_content) /
//!   `publish_prehashed` / `publish_sealed` / `publish_merkle` helpers.
//! - [`RecordsNamespace`] — record list, fetch, and verify.
//! - [`AccountNamespace`] — account balance read.
//! - The RFC 7807 / RFC 9457 [`ProblemDetails`] parser and the full typed
//!   [`Label309HttpError`] catalogue, with an unknown-code fallback to
//!   [`HttpErrorKind::Other`].
//! - The off-host signing helpers ([`prepare_sig_structure`] / `assemble_*`),
//!   which reuse [`crate::cose`] and never see the integrator's private key.

pub mod account;
pub mod errors;
pub mod http;
pub mod label309_client;
pub mod off_host_sign;
pub mod poe;
pub mod publish;
pub mod records;
pub mod resumable;
pub mod transport;
pub mod types;

pub use account::AccountNamespace;
pub use errors::{
    parse_http_error, HttpErrorKind, Label309HttpError, ParseHttpErrorArgs, ProblemDetails,
    ProblemErrorEntry,
};
pub use http::{ClientError, NamespaceConfig};
pub use label309_client::{InvalidClientConfigError, Label309Client, Label309ClientConfig};
pub use off_host_sign::{
    assemble_cose_sign1, assemble_cose_sign1_hashed, build_to_sign, prepare_sig_structure,
    prepare_sig_structure_hashed, AssembledCoseSign1, OffHostSignError, PreparedSigStructure,
    PreparedSigStructureHashed,
};
pub use poe::PoeNamespace;
pub use publish::{
    publish_content, publish_merkle, publish_prehashed, publish_sealed, PartialUploadError,
    PublishError, PublishHelperError, Signer, SignerError,
};
pub use records::RecordsNamespace;
pub use resumable::{
    upload_resumable, ResumableUploadError, DEFAULT_RESUMABLE_CHUNK_BYTES,
    DEFAULT_RESUMABLE_THRESHOLD_BYTES,
};
pub use transport::{
    ClientResponse, ClientTransport, MultipartField, RequestBody, ReqwestClientTransport,
    ResponseHeaders,
};
pub use types::{
    AccountBalance, ConformanceProfile, MerkleLeaf, PoeItemResponse, PoeStatus, PoeVerifyInput,
    PublishBatchEntry, PublishBatchFailureEntry, PublishBatchFailureError, PublishBatchInput,
    PublishBatchResponse, PublishBatchResultEntry, PublishBatchSuccessEntry, PublishContentInput,
    PublishInput, PublishMerkleInput, PublishMerkleResponse, PublishPrehashedInput,
    PublishResponse, PublishSealedInput, QuoteInput, QuoteResponse, RecordResource,
    RecordSignature, RecordsListInput, RecordsListResponse, ResumableSource, ResumableUploadInput,
    ResumableUploadResult, SealedKemChoice, SupportedHashAlg, UploadAttemptStatus, UploadEntry,
    UploadError, UploadSessionChunkAck, UploadSessionCreated, UploadSessionDeduplicated,
    UploadSessionStatus, UploadsInput, UploadsResponse,
};
