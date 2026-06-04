//! The gateway-agnostic HTTP client and its configuration.
//!
//! The client targets any Label 309 gateway. The caller supplies the target
//! directly, mirroring the reference SDKs:
//!
//! - `base_url` is required: it is used verbatim (one trailing slash stripped).
//!   The client never infers or defaults a host, so it is bound to no specific
//!   deployment.
//! - `api_key` is an optional opaque bearer. Any string is accepted as-is and
//!   forwarded as `Authorization: Bearer <key>`; it is never validated or
//!   parsed, because a third-party gateway may issue keys in its own format.
//!   With no key the client is anonymous and limited to read-only endpoints.
//!
//! The one illegal combination is a missing or empty `base_url`, which raises
//! [`InvalidClientConfigError`] from the constructor.

use crate::client::account::AccountNamespace;
use crate::client::http::NamespaceConfig;
use crate::client::poe::PoeNamespace;
use crate::client::records::RecordsNamespace;
use crate::client::transport::{ClientTransport, ReqwestClientTransport};

/// Raised synchronously from the client constructor when the config cannot be
/// resolved into a usable gateway target.
///
/// The single trigger: a missing or empty `base_url`. The client targets no
/// default host, so the caller must name the gateway explicitly.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidClientConfigError(pub String);

impl InvalidClientConfigError {
    /// The stable discriminator code for this error.
    pub const CODE: &'static str = "INVALID_CLIENT_CONFIG";
}

/// Configuration for [`Label309Client`].
#[derive(Debug, Clone, Default)]
pub struct Label309ClientConfig {
    /// The bearer credential, forwarded verbatim as `Authorization: Bearer …`.
    ///
    /// An opaque token: any string is accepted and never validated or parsed.
    /// Omit it for an anonymous, read-only client.
    pub api_key: Option<String>,
    /// The gateway base URL. Required; used verbatim with one trailing slash
    /// stripped.
    pub base_url: Option<String>,
}

/// Resolve the base URL from the config: `base_url` is required and non-empty.
fn resolve_base_url(config: &Label309ClientConfig) -> Result<String, InvalidClientConfigError> {
    match &config.base_url {
        Some(base_url) if !base_url.is_empty() => Ok(base_url.clone()),
        _ => Err(InvalidClientConfigError(
            "Label309Client: base_url is required. Pass the gateway base URL \
             (the api_key is an optional opaque bearer; omit it for read-only access)."
                .to_string(),
        )),
    }
}

/// Strip at most one trailing slash from a base URL.
fn strip_trailing_slash(url: &str) -> String {
    url.strip_suffix('/').unwrap_or(url).to_string()
}

/// The gateway-agnostic Label 309 HTTP client.
///
/// The client owns the outbound transport (the verifier's single egress) and
/// hands out the namespaces ([`poe`](Self::poe), [`records`](Self::records),
/// [`account`](Self::account)), each borrowing the client for the duration of a
/// call.
pub struct Label309Client {
    api_key: Option<String>,
    base_url: String,
    transport: Box<dyn ClientTransport>,
}

impl Label309Client {
    /// Construct a client from a config, using the production reqwest transport.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidClientConfigError`] when `base_url` is missing or empty.
    pub fn new(config: Label309ClientConfig) -> Result<Self, InvalidClientConfigError> {
        Self::with_transport(config, Box::new(ReqwestClientTransport::new()))
    }

    /// Construct a client with a caller-supplied transport (e.g. a test stub).
    ///
    /// # Errors
    ///
    /// Returns [`InvalidClientConfigError`] when `base_url` is missing or empty.
    pub fn with_transport(
        config: Label309ClientConfig,
        transport: Box<dyn ClientTransport>,
    ) -> Result<Self, InvalidClientConfigError> {
        let base_url = strip_trailing_slash(&resolve_base_url(&config)?);
        Ok(Self {
            api_key: config.api_key,
            base_url,
            transport,
        })
    }

    /// The resolved gateway base URL (one trailing slash stripped).
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Build the shared per-namespace config borrowing this client.
    fn namespace_config(&self) -> NamespaceConfig<'_> {
        NamespaceConfig {
            api_key: self.api_key.clone(),
            base_url: self.base_url.clone(),
            transport: self.transport.as_ref(),
        }
    }

    /// The `poe` namespace (quote / uploads / publish / publish-batch + the
    /// high-level helpers).
    #[must_use]
    pub fn poe(&self) -> PoeNamespace<'_> {
        PoeNamespace::new(self.namespace_config())
    }

    /// The `records` namespace (record list + fetch + verify).
    #[must_use]
    pub fn records(&self) -> RecordsNamespace<'_> {
        RecordsNamespace::new(self.namespace_config())
    }

    /// The `account` namespace (account balance read).
    #[must_use]
    pub fn account(&self) -> AccountNamespace<'_> {
        AccountNamespace::new(self.namespace_config())
    }
}
