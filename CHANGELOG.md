# Changelog

All notable changes to the Label 309 Rust SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** `cardanowall` is pre-1.0. The API, wire format, and
> conformance vectors may change in backward-incompatible ways until a 1.0
> release. Pre-1.0 versions do not carry the stability guarantees of
> [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-06-04

### Changed

- **BREAKING:** Public API renamed `Cip309*` → `Label309*` (`Cip309Client` → `Label309Client`, `build_cip309_sig_structure` → `build_label309_sig_structure`, `cose_sign1_cip309_*` → `cose_sign1_label309_*`), matching the standard's rename to **Label 309**. No wire-format changes.

## [0.1.0] - 2026-06-02

### Added

- Initial public release of the Label 309 Rust SDK (crate `cardanowall`).
- Byte-parity with the TypeScript and Python SDKs against the shared conformance vectors.
