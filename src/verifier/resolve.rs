//! Cardano gateway resolver: Koios first, Blockfrost fallback.
//!
//! The resolver fetches the producer's RAW on-chain transaction CBOR (never the
//! gateway's lossy JSON metadata projection — the verifier needs the original
//! bytes to peel label 309) plus the block-info tuple. Every outbound call routes
//! through the verifier's single egress point and lands on the report's
//! `http_calls` audit trail.

use serde_json::Value;

use crate::verifier::egress::GatewayFetcher;
use crate::verifier::fetch::{FetchOutboundOptions, HttpMethod, HttpPurpose, OutboundError};

/// The default Koios mainnet gateway base URL.
pub const KOIOS_MAINNET_URL: &str = "https://api.koios.rest/api/v1";

/// The Blockfrost mainnet host (used only when a project id is supplied).
pub const BLOCKFROST_MAINNET_HOST: &str = "https://cardano-mainnet.blockfrost.io/api/v0";

/// A resolved transaction: its raw CBOR plus the confirmation/block tuple.
#[derive(Debug, Clone)]
pub struct ResolvedTx {
    /// The raw on-chain transaction CBOR.
    pub tx_cbor: Vec<u8>,
    /// The confirmation depth.
    pub num_confirmations: u32,
    /// The block time (Unix seconds).
    pub block_time: u64,
    /// The block slot.
    pub block_slot: u64,
}

/// The terminal outcome of a resolve attempt.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ResolveError {
    /// A definitive "this tx carries no PoE record" response from a gateway.
    /// Maps to verdict `failed` / exit 1.
    #[error("NOT_A_CARDANOWALL_RECORD: {0}")]
    NotALabel309Record(String),
    /// A service-independence (deny-host) violation. Maps to verdict `failed` /
    /// exit 1.
    #[error("SERVICE_INDEPENDENCE_VIOLATION: {0}")]
    ServiceIndependence(String),
    /// Every gateway in the chain failed for a transient reason. Maps to verdict
    /// `failed` / exit 2.
    #[error("PROVIDER_UNAVAILABLE: {0}")]
    ProviderUnavailable(String),
}

/// Resolve a transaction through the Koios chain, then the Blockfrost fallback.
///
/// Iterates the configured Koios gateways in order; a definitive no-record or
/// deny-host response short-circuits the whole chain (rotating gateways cannot
/// turn a definitive negative into a positive). If every Koios gateway fails for
/// a transient reason and a Blockfrost project id is configured, the Blockfrost
/// path is tried. The final transient failure surfaces as
/// [`ResolveError::ProviderUnavailable`].
pub fn resolve_cardano_tx(
    tx_hash: &str,
    cardano_gateway_chain: Option<&[String]>,
    blockfrost_project_id: Option<&str>,
    fetcher: &mut GatewayFetcher<'_>,
) -> Result<ResolvedTx, ResolveError> {
    // `None` selects the default single-Koios chain; an explicit empty slice
    // means "no Koios gateways" (the caller routes straight to Blockfrost) — the
    // empty case must NOT fall back to the default, or a Blockfrost-only verify
    // would issue a doomed Koios call first.
    let default_chain = [KOIOS_MAINNET_URL.to_string()];
    let chain: &[String] = match cardano_gateway_chain {
        Some(c) => c,
        None => &default_chain,
    };

    let mut last_err: Option<String> = None;
    for koios_url in chain {
        match resolve_via_koios(tx_hash, koios_url, fetcher) {
            Ok(resolved) => return Ok(resolved),
            Err(e @ ResolveError::NotALabel309Record(_))
            | Err(e @ ResolveError::ServiceIndependence(_)) => return Err(e),
            Err(ResolveError::ProviderUnavailable(msg)) => last_err = Some(msg),
        }
    }

    if let Some(project_id) = blockfrost_project_id {
        match resolve_via_blockfrost(tx_hash, project_id, fetcher) {
            Ok(resolved) => return Ok(resolved),
            Err(e @ ResolveError::NotALabel309Record(_))
            | Err(e @ ResolveError::ServiceIndependence(_)) => return Err(e),
            Err(ResolveError::ProviderUnavailable(msg)) => last_err = Some(msg),
        }
    }

    Err(ResolveError::ProviderUnavailable(format!(
        "all_providers_failed: {}",
        last_err.unwrap_or_else(|| "unknown".to_string())
    )))
}

/// Classify an outbound error: a deny-host violation is service-independence,
/// every other transport error is a transient provider failure.
fn classify_outbound(e: &OutboundError) -> ResolveError {
    match e {
        OutboundError::DenyHost { .. } => ResolveError::ServiceIndependence(e.to_string()),
        _ => ResolveError::ProviderUnavailable(e.to_string()),
    }
}

fn json_post_options(body: String) -> FetchOutboundOptions {
    let mut opts = FetchOutboundOptions::new(HttpMethod::Post, HttpPurpose::Cardano);
    opts.headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("accept".to_string(), "application/json".to_string()),
    ];
    opts.body = Some(body);
    opts
}

fn resolve_via_koios(
    tx_hash: &str,
    koios_url: &str,
    fetcher: &mut GatewayFetcher<'_>,
) -> Result<ResolvedTx, ResolveError> {
    let body = format!("{{\"_tx_hashes\":[\"{}\"]}}", tx_hash);

    let cbor_res = fetcher
        .fetch(
            &format!("{koios_url}/tx_cbor"),
            &json_post_options(body.clone()),
        )
        .map_err(|e| classify_outbound(&e))?;
    if cbor_res.status != 200 {
        return Err(ResolveError::ProviderUnavailable(format!(
            "koios_tx_cbor_{}",
            cbor_res.status
        )));
    }
    let cbor_json = parse_json(&cbor_res.bytes)?;
    let arr = cbor_json.as_array().ok_or_else(|| {
        ResolveError::NotALabel309Record(
            "koios returned empty array for tx_cbor; tx may not exist".to_string(),
        )
    })?;
    if arr.is_empty() {
        return Err(ResolveError::NotALabel309Record(
            "koios returned empty array for tx_cbor; tx may not exist".to_string(),
        ));
    }
    let cbor_entry = arr[0].as_object().ok_or_else(|| {
        ResolveError::ProviderUnavailable("koios_tx_cbor_malformed_entry".to_string())
    })?;
    let cbor_field = cbor_entry
        .get("cbor")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ResolveError::ProviderUnavailable("koios_tx_cbor_missing_cbor_field".to_string())
        })?;
    if let Some(entry_hash) = cbor_entry.get("tx_hash").and_then(Value::as_str) {
        if entry_hash.to_lowercase() != tx_hash.to_lowercase() {
            return Err(ResolveError::ProviderUnavailable(format!(
                "koios_tx_cbor_hash_mismatch: requested {tx_hash} got {entry_hash}"
            )));
        }
    }
    let tx_cbor = hex_to_bytes(cbor_field)?;

    let info_res = fetcher
        .fetch(&format!("{koios_url}/tx_info"), &json_post_options(body))
        .map_err(|e| classify_outbound(&e))?;
    if info_res.status != 200 {
        return Err(ResolveError::ProviderUnavailable(format!(
            "koios_tx_info_{}",
            info_res.status
        )));
    }
    let info_json = parse_json(&info_res.bytes)?;
    let info_arr = info_json.as_array().ok_or_else(|| {
        ResolveError::NotALabel309Record("koios returned empty array for tx_info".to_string())
    })?;
    if info_arr.is_empty() {
        return Err(ResolveError::NotALabel309Record(
            "koios returned empty array for tx_info".to_string(),
        ));
    }
    let info_entry = info_arr[0].as_object().ok_or_else(|| {
        ResolveError::ProviderUnavailable("koios_tx_info_malformed_entry".to_string())
    })?;
    if let Some(entry_hash) = info_entry.get("tx_hash").and_then(Value::as_str) {
        if entry_hash.to_lowercase() != tx_hash.to_lowercase() {
            return Err(ResolveError::ProviderUnavailable(format!(
                "koios_tx_info_hash_mismatch: requested {tx_hash} got {entry_hash}"
            )));
        }
    }

    // Koios v1 `/tx_info` no longer returns `num_confirmations` — only
    // `block_height`. Confirmations are counted in BLOCKS, not slots (Cardano's
    // active-slot coefficient f=0.05 means only ~1 slot in 20 produces a block,
    // so a slot-difference count would inflate confirmations ~20x). Compute
    // `max(0, tip_height - tx_height + 1)` from the `/tip` block height. A
    // deprecated direct `num_confirmations` read stays as forward-compat for
    // older Koios deployments.
    let num_confirmations = match info_entry.get("num_confirmations") {
        Some(v) if !v.is_null() => require_non_negative_int(Some(v), "num_confirmations")?,
        _ => {
            let tx_block_height =
                require_non_negative_int(info_entry.get("block_height"), "block_height")?;
            let tip_height = fetch_koios_tip_height(koios_url, fetcher)?;
            tip_height.saturating_sub(tx_block_height).saturating_add(1)
        }
    };

    Ok(ResolvedTx {
        tx_cbor,
        num_confirmations,
        block_time: u64::from(require_non_negative_int(
            info_entry.get("tx_timestamp"),
            "tx_timestamp",
        )?),
        block_slot: u64::from(require_non_negative_int(
            info_entry.get("absolute_slot"),
            "absolute_slot",
        )?),
    })
}

/// Fetch the current tip's block height from Koios `/tip`.
fn fetch_koios_tip_height(
    koios_url: &str,
    fetcher: &mut GatewayFetcher<'_>,
) -> Result<u32, ResolveError> {
    let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Cardano);
    opts.headers = vec![("accept".to_string(), "application/json".to_string())];
    let tip_res = fetcher
        .fetch(&format!("{koios_url}/tip"), &opts)
        .map_err(|e| classify_outbound(&e))?;
    if tip_res.status != 200 {
        return Err(ResolveError::ProviderUnavailable(format!(
            "koios_tip_{}",
            tip_res.status
        )));
    }
    let tip_json = parse_json(&tip_res.bytes)?;
    let tip_arr = tip_json
        .as_array()
        .ok_or_else(|| ResolveError::ProviderUnavailable("koios_tip_empty".to_string()))?;
    let tip_entry = tip_arr
        .first()
        .and_then(Value::as_object)
        .ok_or_else(|| ResolveError::ProviderUnavailable("koios_tip_empty".to_string()))?;
    require_non_negative_int(tip_entry.get("block_height"), "tip.block_height")
}

fn resolve_via_blockfrost(
    tx_hash: &str,
    project_id: &str,
    fetcher: &mut GatewayFetcher<'_>,
) -> Result<ResolvedTx, ResolveError> {
    let base = BLOCKFROST_MAINNET_HOST;
    let header_opts = || {
        let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Cardano);
        opts.headers = vec![
            ("project_id".to_string(), project_id.to_string()),
            ("accept".to_string(), "application/json".to_string()),
        ];
        opts
    };

    let cbor_res = fetcher
        .fetch(&format!("{base}/txs/{tx_hash}/cbor"), &header_opts())
        .map_err(|e| classify_outbound(&e))?;
    if cbor_res.status != 200 {
        return Err(ResolveError::ProviderUnavailable(format!(
            "blockfrost_tx_cbor_{}",
            cbor_res.status
        )));
    }
    let cbor_json = parse_json(&cbor_res.bytes)?;
    let cbor_field = cbor_json
        .get("cbor")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ResolveError::ProviderUnavailable("blockfrost_tx_cbor_missing_cbor_field".to_string())
        })?;
    let tx_cbor = hex_to_bytes(cbor_field)?;

    let tx_res = fetcher
        .fetch(&format!("{base}/txs/{tx_hash}"), &header_opts())
        .map_err(|e| classify_outbound(&e))?;
    if tx_res.status != 200 {
        return Err(ResolveError::ProviderUnavailable(format!(
            "blockfrost_tx_{}",
            tx_res.status
        )));
    }
    let tx_json = parse_json(&tx_res.bytes)?;
    let block_time = u64::from(require_non_negative_int(
        tx_json.get("block_time"),
        "block_time",
    )?);
    let tx_slot = require_non_negative_int(tx_json.get("slot"), "slot")?;

    // Confirmations are counted in BLOCKS, not slots. Blockfrost may surface a
    // native `confirmations` field on `tx_content`; when present it is
    // authoritative. Otherwise compute `max(0, tip_height - tx_height + 1)` from
    // the tx's `block_height` and the tip's `height` (`/blocks/latest`). A
    // slot-difference count would inflate confirmations ~20x (active-slot
    // coefficient f=0.05), so slots are kept only for `block_slot`.
    let num_confirmations = match tx_json.get("confirmations") {
        Some(v) if !v.is_null() => require_non_negative_int(Some(v), "confirmations")?,
        _ => {
            let tx_block_height =
                require_non_negative_int(tx_json.get("block_height"), "block_height")?;
            let tip_res = fetcher
                .fetch(&format!("{base}/blocks/latest"), &header_opts())
                .map_err(|e| classify_outbound(&e))?;
            if tip_res.status != 200 {
                return Err(ResolveError::ProviderUnavailable(format!(
                    "blockfrost_blocks_latest_{}",
                    tip_res.status
                )));
            }
            let tip_json = parse_json(&tip_res.bytes)?;
            let tip_height = require_non_negative_int(tip_json.get("height"), "tip_height")?;
            tip_height.saturating_sub(tx_block_height).saturating_add(1)
        }
    };

    Ok(ResolvedTx {
        tx_cbor,
        num_confirmations,
        block_time,
        block_slot: u64::from(tx_slot),
    })
}

fn parse_json(bytes: &[u8]) -> Result<Value, ResolveError> {
    serde_json::from_slice(bytes)
        .map_err(|e| ResolveError::ProviderUnavailable(format!("gateway_json_invalid: {e}")))
}

/// Validate a JSON number is a non-negative integer that fits in `u32`.
///
/// Koios/Blockfrost block fields are well within the `u32` range; an absent,
/// non-integer, negative, or oversized value is a malformed gateway response.
fn require_non_negative_int(value: Option<&Value>, field: &str) -> Result<u32, ResolveError> {
    let n = value.and_then(Value::as_u64).ok_or_else(|| {
        ResolveError::ProviderUnavailable(format!(
            "gateway_field_invalid: {field} (got {})",
            value.map_or("absent".to_string(), std::string::ToString::to_string)
        ))
    })?;
    u32::try_from(n).map_err(|_| {
        ResolveError::ProviderUnavailable(format!("gateway_field_invalid: {field} (out of range)"))
    })
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, ResolveError> {
    let clean = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    crate::hex::decode(clean)
        .map_err(|e| ResolveError::ProviderUnavailable(format!("invalid hex: {e}")))
}
