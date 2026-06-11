//! Shared test helpers: resolve the cross-implementation fixture trees by path.
//!
//! These fixtures are the canonical cross-implementation conformance vectors,
//! vendored under `tests/fixtures/` so this crate verifies byte-parity entirely
//! on its own. They are byte-identical to the vectors the TypeScript and Python
//! SDKs load, so passing them proves cross-implementation agreement.
//!
//! This is a shared support module included by multiple integration-test
//! binaries. Each binary uses only the subset of helpers it needs, so the
//! unused-on-this-build helpers are expected; the allow keeps the shared API
//! whole without per-binary noise.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Absolute path to the `crypto-core` fixture tree (the source of truth).
pub fn crypto_core_fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crypto-core")
}

/// Absolute path to the Python SDK fixture tree (a byte-identical mirror).
pub fn sdk_py_fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sdk-py")
}

/// Absolute path to the TypeScript SDK fixture tree (additional goldens).
pub fn sdk_ts_fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sdk-ts")
}

/// Absolute path to the standard's conformance tree, for fixture areas that
/// have no package-local mirror.
pub fn label309_conformance() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../label-309/conformance")
}

/// Read and parse a JSON fixture file.
///
/// Panics with a path-tagged message if the file cannot be read or parsed,
/// which surfaces a missing or malformed vector immediately in the failing test.
pub fn read_fixture_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("failed to parse fixture {}: {e}", path.display()))
}
