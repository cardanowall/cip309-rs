//! Cardano explorer resolution with the transaction-reference integrity
//! binding.
//!
//! The resolver fetches the producer's RAW on-chain transaction CBOR (never an
//! explorer's lossy JSON metadata projection — re-encoding from JSON cannot
//! reproduce the byte-exact signing input) plus the explorer-asserted chain
//! facts (confirmation depth, block time, block slot). **Before anything is
//! read out of a fetched response**, the response is hash-bound to the
//! requested transaction reference: `blake2b-256` over the fetched body bytes
//! must equal the requested transaction hash, and `blake2b-256` over the
//! fetched auxiliary-data bytes must equal the verified body's
//! `auxiliary_data_hash`. A response failing either binding carries provably
//! wrong bytes and is discarded; the next provider in the chain is tried.
//!
//! Three negative outcomes are distinguished across the provider chain:
//!
//! - `TX_NOT_FOUND` — a provider definitively answered that it knows no
//!   transaction under the requested hash, and no other provider yielded one.
//!   A single provider's negative answer is not chain-authoritative, so every
//!   remaining provider is consulted first.
//! - `TX_INTEGRITY_MISMATCH` — at least one provider actively served bytes
//!   that fail the binding, and no provider's response survived it. Provable
//!   against the providers, never the record.
//! - `PROVIDER_UNAVAILABLE` — every provider was unreachable or returned no
//!   usable response.
//!
//! Every outbound call routes through the verifier's single egress point and
//! lands on the report's audit trail.

use serde_json::Value;

use crate::poe_standard::ErrorCode;
use crate::verifier::cbor_walker::{bind_transaction, slice_tx, TxSlices};
use crate::verifier::egress::GatewayFetcher;
use crate::verifier::fetch::{FetchOutboundOptions, HttpMethod, HttpPurpose, OutboundError};

/// The default Koios mainnet explorer base URL.
pub const KOIOS_MAINNET_URL: &str = "https://api.koios.rest/api/v1";

/// The Blockfrost mainnet host (used only when a project id is supplied).
pub const BLOCKFROST_MAINNET_HOST: &str = "https://cardano-mainnet.blockfrost.io/api/v0";

/// A resolved, integrity-bound transaction plus its explorer-asserted facts.
#[derive(Debug, Clone)]
pub struct ResolvedTx {
    /// The raw on-chain transaction CBOR, exactly as fetched.
    pub tx_cbor: Vec<u8>,
    /// The byte-faithful body / witness-set / auxiliary-data slices, already
    /// bound to the requested transaction hash.
    pub slices: TxSlices,
    /// Explorer-asserted confirmation depth in blocks (tip block = 1).
    pub confirmation_depth: u32,
    /// Explorer-asserted block time (integer POSIX seconds UTC).
    pub block_time: u64,
    /// Explorer-asserted block slot.
    pub block_slot: u64,
}

/// The terminal outcome of an exhausted resolve.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{}: {message}", code.code())]
pub struct ResolveFailure {
    /// `TX_NOT_FOUND`, `PROVIDER_UNAVAILABLE`, `TX_INTEGRITY_MISMATCH`, or
    /// `SERVICE_INDEPENDENCE_VIOLATION`.
    pub code: ErrorCode,
    /// A human-readable description of the terminal failure.
    pub message: String,
}

/// One provider's non-success outcome, aggregated across the chain.
enum ProviderFailure {
    /// The provider definitively answered "no such transaction".
    NotFound(String),
    /// The provider was unreachable or returned no usable response.
    Unavailable(String),
    /// The provider served bytes that failed the integrity binding.
    IntegrityMismatch(String),
    /// The call targeted a deny-listed host: a hard stop for the whole run.
    Deny(String),
}

/// Resolve a transaction through the configured explorer chain.
///
/// Iterates the Koios-compatible explorers in order, then the Blockfrost
/// fallback when a project id is configured. Each provider's response is
/// integrity-bound before acceptance; a provider whose bytes fail the binding
/// is discarded and the next is tried. A deny-host violation aborts the whole
/// chain immediately (rotating providers must not mask a service-independence
/// violation).
///
/// # Errors
///
/// Returns [`ResolveFailure`] when no provider yields a bound transaction,
/// with the code aggregated across the chain: a deny-host hit dominates, then
/// `TX_INTEGRITY_MISMATCH` (a provider actively served wrong bytes), then
/// `TX_NOT_FOUND` (a definitive negative answer), then `PROVIDER_UNAVAILABLE`.
pub fn resolve_cardano_tx(
    tx_hash: &str,
    cardano_gateway_chain: Option<&[String]>,
    blockfrost_project_id: Option<&str>,
    fetcher: &mut GatewayFetcher<'_>,
) -> Result<ResolvedTx, ResolveFailure> {
    // The requested reference must be a 32-byte hash for any binding to be
    // possible; a malformed reference can match no transaction on any chain.
    let Ok(requested_hash) = crate::hex::decode(tx_hash) else {
        return Err(ResolveFailure {
            code: ErrorCode::TxNotFound,
            message: format!("transaction hash {tx_hash:?} is not hex"),
        });
    };
    if requested_hash.len() != 32 {
        return Err(ResolveFailure {
            code: ErrorCode::TxNotFound,
            message: format!(
                "transaction hash must be 32 bytes (64 hex chars); got {} bytes",
                requested_hash.len()
            ),
        });
    }

    // `None` selects the default single-Koios chain; an explicit empty slice
    // means "no Koios explorers" (the caller routes straight to Blockfrost) —
    // the empty case must NOT fall back to the default, or a Blockfrost-only
    // verify would issue a doomed Koios call first.
    let default_chain = [KOIOS_MAINNET_URL.to_string()];
    let chain: &[String] = match cardano_gateway_chain {
        Some(c) => c,
        None => &default_chain,
    };

    let mut not_found: Option<String> = None;
    let mut integrity_mismatch: Option<String> = None;
    let mut unavailable: Option<String> = None;

    let mut absorb = |failure: ProviderFailure| -> Option<ResolveFailure> {
        match failure {
            ProviderFailure::Deny(message) => Some(ResolveFailure {
                code: ErrorCode::ServiceIndependenceViolation,
                message,
            }),
            ProviderFailure::NotFound(m) => {
                not_found.get_or_insert(m);
                None
            }
            ProviderFailure::IntegrityMismatch(m) => {
                integrity_mismatch.get_or_insert(m);
                None
            }
            ProviderFailure::Unavailable(m) => {
                unavailable.get_or_insert(m);
                None
            }
        }
    };

    for koios_url in chain {
        match resolve_via_koios(tx_hash, &requested_hash, koios_url, fetcher) {
            Ok(resolved) => return Ok(resolved),
            Err(failure) => {
                if let Some(terminal) = absorb(failure) {
                    return Err(terminal);
                }
            }
        }
    }

    if let Some(project_id) = blockfrost_project_id {
        match resolve_via_blockfrost(tx_hash, &requested_hash, project_id, fetcher) {
            Ok(resolved) => return Ok(resolved),
            Err(failure) => {
                if let Some(terminal) = absorb(failure) {
                    return Err(terminal);
                }
            }
        }
    }

    if let Some(message) = integrity_mismatch {
        return Err(ResolveFailure {
            code: ErrorCode::TxIntegrityMismatch,
            message,
        });
    }
    if let Some(message) = not_found {
        return Err(ResolveFailure {
            code: ErrorCode::TxNotFound,
            message,
        });
    }
    Err(ResolveFailure {
        code: ErrorCode::ProviderUnavailable,
        message: unavailable.unwrap_or_else(|| "no provider was configured".to_string()),
    })
}

/// Slice and bind one provider's fetched transaction CBOR.
fn bind_fetched_tx(
    requested_hash: &[u8],
    tx_cbor: Vec<u8>,
    provider: &str,
) -> Result<(Vec<u8>, TxSlices), ProviderFailure> {
    // A response that does not even walk as a transaction is unusable — the
    // binding cannot be evaluated, so this is unavailability, not provable
    // provider misbehaviour.
    let slices = slice_tx(&tx_cbor).map_err(|e| {
        ProviderFailure::Unavailable(format!("{provider}: fetched tx CBOR is unreadable: {e}"))
    })?;
    bind_transaction(requested_hash, &slices.tx_body, slices.aux_data.as_deref())
        .map_err(|e| ProviderFailure::IntegrityMismatch(format!("{provider}: {}", e.message)))?;
    Ok((tx_cbor, slices))
}

/// Classify an outbound error: a deny-host violation is a hard stop; every
/// other transport error is this provider's unavailability.
fn classify_outbound(e: &OutboundError) -> ProviderFailure {
    match e {
        OutboundError::DenyHost { .. } => ProviderFailure::Deny(e.to_string()),
        _ => ProviderFailure::Unavailable(e.to_string()),
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
    requested_hash: &[u8],
    koios_url: &str,
    fetcher: &mut GatewayFetcher<'_>,
) -> Result<ResolvedTx, ProviderFailure> {
    let body = format!("{{\"_tx_hashes\":[\"{tx_hash}\"]}}");

    let cbor_res = fetcher
        .fetch(
            &format!("{koios_url}/tx_cbor"),
            &json_post_options(body.clone()),
        )
        .map_err(|e| classify_outbound(&e))?;
    if cbor_res.status != 200 {
        return Err(ProviderFailure::Unavailable(format!(
            "koios_tx_cbor_{}",
            cbor_res.status
        )));
    }
    let cbor_json = parse_json(&cbor_res.bytes)?;
    let arr = cbor_json
        .as_array()
        .ok_or_else(|| ProviderFailure::Unavailable("koios_tx_cbor_not_an_array".to_string()))?;
    // An empty result set is Koios's definitive "I know no such transaction".
    if arr.is_empty() {
        return Err(ProviderFailure::NotFound(format!(
            "koios at {koios_url} knows no transaction {tx_hash}"
        )));
    }
    let cbor_entry = arr[0]
        .as_object()
        .ok_or_else(|| ProviderFailure::Unavailable("koios_tx_cbor_malformed_entry".to_string()))?;
    let cbor_field = cbor_entry
        .get("cbor")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderFailure::Unavailable("koios_tx_cbor_missing_cbor_field".to_string())
        })?;
    let tx_cbor = hex_to_bytes(cbor_field)?;

    // Bind BEFORE reading chain facts: nothing is consumed from an unbound
    // response. (An entry-level tx_hash echo needs no separate check — the
    // body-hash recomputation subsumes it.)
    let (tx_cbor, slices) = bind_fetched_tx(requested_hash, tx_cbor, koios_url)?;

    let info_res = fetcher
        .fetch(&format!("{koios_url}/tx_info"), &json_post_options(body))
        .map_err(|e| classify_outbound(&e))?;
    if info_res.status != 200 {
        return Err(ProviderFailure::Unavailable(format!(
            "koios_tx_info_{}",
            info_res.status
        )));
    }
    let info_json = parse_json(&info_res.bytes)?;
    let info_arr = info_json
        .as_array()
        .ok_or_else(|| ProviderFailure::Unavailable("koios_tx_info_not_an_array".to_string()))?;
    if info_arr.is_empty() {
        return Err(ProviderFailure::NotFound(format!(
            "koios at {koios_url} knows no transaction {tx_hash}"
        )));
    }
    let info_entry = info_arr[0]
        .as_object()
        .ok_or_else(|| ProviderFailure::Unavailable("koios_tx_info_malformed_entry".to_string()))?;

    // Confirmation depth is counted in BLOCKS: tip height − including-block
    // height + 1 (tip block = depth 1). A provider-supplied
    // `num_confirmations` field is the same explorer-asserted quantity and is
    // accepted when present; otherwise the tip height is fetched and the
    // formula applied. Slots are never used for depth (the active-slot
    // coefficient would inflate a slot-difference count ~20x).
    let confirmation_depth = match info_entry.get("num_confirmations") {
        Some(v) if !v.is_null() => served_depth(
            require_non_negative_int(Some(v), "num_confirmations")?,
            koios_url,
            "num_confirmations",
        )?,
        _ => {
            let tx_block_height =
                require_non_negative_int(info_entry.get("block_height"), "block_height")?;
            let tip_height = fetch_koios_tip_height(koios_url, fetcher)?;
            depth_from_heights(tip_height, tx_block_height, koios_url)?
        }
    };

    Ok(ResolvedTx {
        tx_cbor,
        slices,
        confirmation_depth,
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
) -> Result<u32, ProviderFailure> {
    let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Cardano);
    opts.headers = vec![("accept".to_string(), "application/json".to_string())];
    let tip_res = fetcher
        .fetch(&format!("{koios_url}/tip"), &opts)
        .map_err(|e| classify_outbound(&e))?;
    if tip_res.status != 200 {
        return Err(ProviderFailure::Unavailable(format!(
            "koios_tip_{}",
            tip_res.status
        )));
    }
    let tip_json = parse_json(&tip_res.bytes)?;
    let tip_entry = tip_json
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(Value::as_object)
        .ok_or_else(|| ProviderFailure::Unavailable("koios_tip_empty".to_string()))?;
    require_non_negative_int(tip_entry.get("block_height"), "tip.block_height")
}

fn resolve_via_blockfrost(
    tx_hash: &str,
    requested_hash: &[u8],
    project_id: &str,
    fetcher: &mut GatewayFetcher<'_>,
) -> Result<ResolvedTx, ProviderFailure> {
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
    // Blockfrost's 404 is its definitive "no such transaction".
    if cbor_res.status == 404 {
        return Err(ProviderFailure::NotFound(format!(
            "blockfrost knows no transaction {tx_hash}"
        )));
    }
    if cbor_res.status != 200 {
        return Err(ProviderFailure::Unavailable(format!(
            "blockfrost_tx_cbor_{}",
            cbor_res.status
        )));
    }
    let cbor_json = parse_json(&cbor_res.bytes)?;
    let cbor_field = cbor_json
        .get("cbor")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderFailure::Unavailable("blockfrost_tx_cbor_missing_cbor_field".to_string())
        })?;
    let tx_cbor = hex_to_bytes(cbor_field)?;

    let (tx_cbor, slices) = bind_fetched_tx(requested_hash, tx_cbor, "blockfrost")?;

    let tx_res = fetcher
        .fetch(&format!("{base}/txs/{tx_hash}"), &header_opts())
        .map_err(|e| classify_outbound(&e))?;
    if tx_res.status == 404 {
        return Err(ProviderFailure::NotFound(format!(
            "blockfrost knows no transaction {tx_hash}"
        )));
    }
    if tx_res.status != 200 {
        return Err(ProviderFailure::Unavailable(format!(
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

    // Depth in blocks (see the Koios path). Blockfrost surfaces a native
    // `confirmations` field on some deployments; otherwise tip height − block
    // height + 1 from `/blocks/latest`.
    let confirmation_depth = match tx_json.get("confirmations") {
        Some(v) if !v.is_null() => served_depth(
            require_non_negative_int(Some(v), "confirmations")?,
            base,
            "confirmations",
        )?,
        _ => {
            let tx_block_height =
                require_non_negative_int(tx_json.get("block_height"), "block_height")?;
            let tip_res = fetcher
                .fetch(&format!("{base}/blocks/latest"), &header_opts())
                .map_err(|e| classify_outbound(&e))?;
            if tip_res.status != 200 {
                return Err(ProviderFailure::Unavailable(format!(
                    "blockfrost_blocks_latest_{}",
                    tip_res.status
                )));
            }
            let tip_json = parse_json(&tip_res.bytes)?;
            let tip_height = require_non_negative_int(tip_json.get("height"), "tip_height")?;
            depth_from_heights(tip_height, tx_block_height, "blockfrost")?
        }
    };

    Ok(ResolvedTx {
        tx_cbor,
        slices,
        confirmation_depth,
        block_time,
        block_slot: u64::from(tx_slot),
    })
}

/// Confirmation depth from a provider's own tip/height snapshot: tip height −
/// including-block height + 1, counted in blocks, the tip block having depth
/// exactly 1.
///
/// A snapshot whose tip is behind the block the provider itself reported for
/// the transaction is internally inconsistent: no depth can honestly be
/// computed from it, so the provider's chain facts are discarded as that
/// provider's failure and resolution continues down the chain. Inventing a
/// depth from impossible facts would present a possibly-deep reorg or a
/// confused provider as a freshly confirmed transaction.
fn depth_from_heights(
    tip_height: u32,
    tx_block_height: u32,
    provider: &str,
) -> Result<u32, ProviderFailure> {
    if tip_height < tx_block_height {
        return Err(ProviderFailure::Unavailable(format!(
            "{provider}: inconsistent chain snapshot: tip height {tip_height} is behind the \
             transaction's block height {tx_block_height}"
        )));
    }
    Ok((tip_height - tx_block_height).saturating_add(1))
}

// A provider-served confirmation count below 1 for a transaction the same
// response places in a block is the same self-contradiction as a tip behind
// the transaction's block: the snapshot is unusable, never depth evidence
// (a transaction in a block has depth >= 1 by definition).
fn served_depth(depth: u32, provider: &str, field: &str) -> Result<u32, ProviderFailure> {
    if depth < 1 {
        return Err(ProviderFailure::Unavailable(format!(
            "{provider}: inconsistent chain snapshot: served {field} {depth} for a transaction \
             the same response reports as on-chain"
        )));
    }
    Ok(depth)
}

fn parse_json(bytes: &[u8]) -> Result<Value, ProviderFailure> {
    serde_json::from_slice(bytes)
        .map_err(|e| ProviderFailure::Unavailable(format!("gateway_json_invalid: {e}")))
}

/// Validate a JSON number is a non-negative integer that fits in `u32`.
///
/// Explorer block fields are well within the `u32` range; an absent,
/// non-integer, negative, or oversized value is a malformed explorer response.
fn require_non_negative_int(value: Option<&Value>, field: &str) -> Result<u32, ProviderFailure> {
    let n = value.and_then(Value::as_u64).ok_or_else(|| {
        ProviderFailure::Unavailable(format!(
            "gateway_field_invalid: {field} (got {})",
            value.map_or("absent".to_string(), std::string::ToString::to_string)
        ))
    })?;
    u32::try_from(n).map_err(|_| {
        ProviderFailure::Unavailable(format!("gateway_field_invalid: {field} (out of range)"))
    })
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, ProviderFailure> {
    let clean = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    crate::hex::decode(clean).map_err(|e| ProviderFailure::Unavailable(format!("invalid hex: {e}")))
}
