//! The `client.records.*` namespace: the open-standard indexer read surface.
//!
//! - `GET  /api/v1/records` → [`list`](RecordsNamespace::list)
//! - `GET  /api/v1/records/{tx_hash}` → [`get`](RecordsNamespace::get)
//! - `POST /api/v1/records/{tx_hash}/verify` → [`verify`](RecordsNamespace::verify)
//!
//! Auth is optional — chain data is public. When an API key is configured it is
//! forwarded as `Authorization: Bearer …` so owner-only fields (currently
//! `account_id`) surface for the caller's own rows, and so the `sealed` list
//! filter can resolve records addressed to the caller.

use crate::client::http::{decode, json_headers, send, ClientError, NamespaceConfig};
use crate::client::transport::RequestBody;
use crate::client::types::{PoeVerifyInput, RecordResource, RecordsListInput, RecordsListResponse};
use crate::verifier::fetch::HttpMethod;

/// The `client.records.*` namespace.
pub struct RecordsNamespace<'t> {
    config: NamespaceConfig<'t>,
}

impl<'t> RecordsNamespace<'t> {
    /// Construct the namespace over a resolved config.
    #[must_use]
    pub fn new(config: NamespaceConfig<'t>) -> Self {
        Self { config }
    }

    /// List records as a paginated [`RecordsListResponse`] whose `data[]`
    /// entries are the same [`RecordResource`] projection [`get`](Self::get)
    /// returns.
    ///
    /// Pass `RecordsListInput { sealed: Some(true), .. }` to restrict the page
    /// to sealed records addressed to the authenticated caller (the gateway
    /// resolves the recipient from the bearer identity); omit it to list every
    /// record the caller may read. Page with `cursor = previous.next_cursor`
    /// until `has_more` is `false`.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ClientError`] on any non-2xx response.
    pub fn list(
        &self,
        input: Option<&RecordsListInput>,
    ) -> Result<RecordsListResponse, ClientError> {
        let mut query: Vec<(String, String)> = Vec::new();
        if let Some(input) = input {
            if input.sealed == Some(true) {
                query.push(("sealed".to_string(), "true".to_string()));
            }
            if let Some(limit) = input.limit {
                query.push(("limit".to_string(), limit.to_string()));
            }
            if let Some(cursor) = &input.cursor {
                query.push(("cursor".to_string(), cursor.clone()));
            }
        }
        let url = if query.is_empty() {
            format!("{}/api/v1/records", self.config.base_url)
        } else {
            format!(
                "{}/api/v1/records?{}",
                self.config.base_url,
                encode_query(&query)
            )
        };
        let headers = json_headers(self.config.api_key.as_deref(), None);
        let response = send(
            self.config.transport,
            &url,
            HttpMethod::Get,
            &headers,
            &RequestBody::None,
        )?;
        let mut page: RecordsListResponse = decode(&response.body)?;
        if page.tip_block_height.is_none() {
            page.tip_block_height = derive_tip_block_height(&page.data);
        }
        Ok(page)
    }

    /// Fetch a record by Cardano transaction hash.
    ///
    /// # Errors
    ///
    /// Returns [`HttpErrorKind::RecordNotFound`](crate::client::HttpErrorKind::RecordNotFound)
    /// for tx hashes the indexer has not seen (or un-anchored rows the caller
    /// does not own), and other typed errors on any non-2xx response.
    pub fn get(&self, tx_hash: &str) -> Result<RecordResource, ClientError> {
        let url = format!(
            "{}/api/v1/records/{}",
            self.config.base_url,
            encode_path_segment(tx_hash)
        );
        // The records namespace emits `content-type: application/json` on the GET
        // (matching the reference), unlike the inbox namespace which sends only
        // accept + bearer. `json_headers` produces content-type + accept + bearer.
        let headers = json_headers(self.config.api_key.as_deref(), None);
        let response = send(
            self.config.transport,
            &url,
            HttpMethod::Get,
            &headers,
            &RequestBody::None,
        )?;
        decode(&response.body)
    }

    /// Run the canonical Label 309 verifier against the record at `tx_hash`.
    ///
    /// Returns the verify report as a JSON value. The report is the serialized
    /// `VerifyReport` the standalone verifier emits — the gateway returns it
    /// verbatim. The client exposes the JSON document directly (rather than the
    /// in-process verifier type, which carries non-deserializable fields).
    ///
    /// This is the hosted PUBLIC verifier: it accepts no decryption
    /// credentials, and sealed items report as unverifiable without
    /// decryption. To verify as a recipient (decrypt + plaintext-hash
    /// recheck), run the `verifier` module locally with its `decryption`
    /// input — keys never leave the process. Optional
    /// `fetch_content: Some(false)` skips content re-fetching; affected
    /// claims report `not_checked`.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ClientError`] on any non-2xx response.
    pub fn verify(
        &self,
        tx_hash: &str,
        input: Option<&PoeVerifyInput>,
    ) -> Result<serde_json::Value, ClientError> {
        let body = verify_input_to_json(input);
        let url = format!(
            "{}/api/v1/records/{}/verify",
            self.config.base_url,
            encode_path_segment(tx_hash)
        );
        let headers = json_headers(self.config.api_key.as_deref(), None);
        let response = send(
            self.config.transport,
            &url,
            HttpMethod::Post,
            &headers,
            &RequestBody::Json(serde_json::to_string(&body).expect("verify body serialises")),
        )?;
        if response.body.is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_slice(&response.body).map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Derive the chain tip from a record page as `max(block_height +
/// num_confirmations - 1)` over the rows that carry a block height. Returns
/// `None` for an empty page or one with no anchored rows.
///
/// Saturating arithmetic keeps a hostile gateway row (e.g.
/// `{block_height: 0, num_confirmations: 0}`) from underflowing — it clamps to
/// `0` rather than panicking in debug or wrapping to `u64::MAX` in release.
fn derive_tip_block_height(records: &[RecordResource]) -> Option<u64> {
    records
        .iter()
        .filter_map(|r| {
            r.block_height
                .map(|bh| bh.saturating_add(r.num_confirmations).saturating_sub(1))
        })
        .max()
}

/// Lower a [`PoeVerifyInput`] to its JSON wire shape (`{}` when `None`).
fn verify_input_to_json(input: Option<&PoeVerifyInput>) -> serde_json::Value {
    let Some(input) = input else {
        return serde_json::Value::Object(serde_json::Map::new());
    };
    let mut map = serde_json::Map::new();
    if let Some(fetch_content) = input.fetch_content {
        map.insert(
            "fetch_content".to_string(),
            serde_json::Value::Bool(fetch_content),
        );
    }
    serde_json::Value::Object(map)
}

/// Encode an ordered query into a `key=value&…` string, percent-encoding values
/// the way `URLSearchParams` does (space → `+`, reserved chars escaped).
fn encode_query(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                encode_query_component(k),
                encode_query_component(v)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encode a query component (`URLSearchParams`-style: ` ` → `+`).
fn encode_query_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b' ' => out.push('+'),
            b if b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
                ) =>
            {
                out.push(b as char);
            }
            b => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

/// Percent-encode a path segment the way the reference's `encodeURIComponent`
/// does for the characters that occur in a tx hash (hex). Hex digits never
/// require escaping, but a defensive encoder keeps a non-hex caller safe.
fn encode_path_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        let unreserved = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            );
        if unreserved {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}
