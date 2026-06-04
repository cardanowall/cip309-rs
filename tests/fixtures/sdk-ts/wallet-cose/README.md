# wallet-cose fixtures

Per-wallet `COSE_Sign1` verification fixtures driving the TS KAT test at
`tests/wallet-cose/verify-fixtures.kat.test.ts` and its Python parity
counterpart in the Python SDK. Six wallets (Eternl, Lace, Nami, Typhon, Yoroi,
NuFi) × four variants (`positive`, `tampered-address`, `missing-address`,
`wrong-network-header`) = **24 byte-pinned JSON fixtures** per tree.

## Layout

| File                                      | Purpose                                                                                                                                                                         |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `<wallet>-cose.json`                      | Real-capture positive fixture from the wallet's `signData`. Byte-faithful — never re-canonicalised.                                                                             |
| `<wallet>-cose-tampered-address.json`     | Synthetic tamper: COSE_Sign1 signed by `seed_signer` whose address claim binds to a DIFFERENT pubkey. Verifier MUST emit `WALLET_ADDRESS_MISMATCH`.                             |
| `<wallet>-cose-missing-address.json`      | Synthetic tamper: COSE_Sign1 protected-header omits the `"address"` field entirely. Verifier MUST emit `WALLET_ADDRESS_MISMATCH`.                                               |
| `<wallet>-cose-wrong-network-header.json` | Synthetic tamper: address claim binds to the correct signer pubkey but carries a `0xe0` (testnet) network byte instead of `0xe1`. Verifier MUST emit `WALLET_ADDRESS_MISMATCH`. |
| `_build-tampered-fixtures.test.ts`        | Regenerator script (vitest-runnable); writes the 18 tamper variants to this TS canonical tree. The Python mirror is synced separately (see below).                                                |
| `README.md`                               | This file.                                                                                                                                                                      |

The Python SDK keeps a byte-identical mirror of this directory. The regenerator
writes only this TS tree; after regenerating, copy the changed JSON files across
to the Python SDK's matching directory. `pnpm check:vendored-fixtures` enforces
byte-equality between the two trees.

## Capture protocol (positive fixtures)

Positive fixtures are real wallet captures. To (re-)capture:

1. Start the dev server with the capture-page flag set:
   ```bash
   CARDANOWALL_ENABLE_WALLET_FIXTURE_CAPTURE=true pnpm --filter @cardanowall/web dev
   ```
2. In a mainnet-configured browser with the relevant wallet extension
   installed and connected to a real Cardano mainnet stake account, navigate
   to `/en/dev/wallet-capture`.
3. Pick the wallet → enter the wallet's human-readable version (read from
   the extension UI; CIP-30 does not expose it) → click **Capture**.
4. Confirm the wallet-extension prompt. The page renders a JSON preview and
   green/red sanity-invariant badges (the five capture sanity invariants).
   All five badges MUST read green; if any badge is red the wallet has a bug —
   re-capture from a fresh wallet session, do NOT mutate the JSON to satisfy
   the invariant.
5. Click **Copy to clipboard** and paste the JSON into this directory as
   `<wallet>-cose.json`.
6. Copy the same file to the matching path in the Python SDK's fixtures tree.
7. Re-run the regenerator (default mode, read-only) to confirm the
   downstream tamper variants still match:
   ```bash
   pnpm vitest run tests/fixtures/wallet-cose/_build-tampered-fixtures.test.ts
   ```
8. Run `pnpm check:vendored-fixtures` to confirm the TS and Python trees are
   byte-identical.

The dev-capture page pins a **deterministic record body**
(`{v: 1, items: [{hashes: {'sha2-256': <32 × 0x00>}}]}`) so all six positive
fixtures share `record_body_cbor_hex` and `to_sign_bytes_hex`; only
`cose_sign1_bytes_hex`, `cose_key_bytes_hex`, `stake_addr_hex`, and
`expected_signer_pubkey_hex` vary across the six wallets.

## Fixture JSON schema

Canonical schema briefly:

```jsonc
{
  "wallet": "eternl", // one of the six supported lowercase wallet names
  "captured_at": "<ISO-8601>",
  "wallet_version": "<human-readable>",
  "wallet_api_version": "<CIP-30 apiVersion>",
  "browser_user_agent": "<navigator.userAgent>",
  "cardano_network": "mainnet", // mainnet only — there is no testnet path
  "record_body_cbor_hex": "<lowercase hex>",
  "to_sign_bytes_hex": "<lowercase hex; first 25 bytes = utf8('cardano-poe-record-sig-v1')>",
  "stake_addr_hex": "<29 bytes; first byte 0xe1>",
  "stake_addr_bech32": "stake1...",
  "cose_sign1_bytes_hex": "<wallet-returned bytes, byte-faithful>",
  "cose_key_bytes_hex": "<wallet-returned bytes, byte-faithful>",
  "expected_signer_pubkey_hex": "<32 bytes; output of parseCoseKeyEd25519(cose_key)>",
  "expected_normalized_verdict": {
    "index": 0,
    "signer_pub_hex": "<same as expected_signer_pubkey_hex>",
    "signer_type": "wallet-inline-key",
    "ok": true,
    "reason": null,
  },
}
```

Tamper-variant fixtures use a similar schema with `tamper_variant`,
`captured_from_positive_fixture`, `tamper_signer_pubkey_hex`, and an
`expected_normalized_verdict` carrying `ok: false`, `reason: "WALLET_ADDRESS_MISMATCH"`.

## Synthetic-tamper construction rules

The tamper variants are NOT byte-mutations of real captures (that would
trigger `SIGNATURE_INVALID` because the Ed25519 signature was computed over
the original `Sig_structure`, see `_build-tampered-fixtures.test.ts` for the
byte-level rationale). Instead they are deterministically synthesised from
HKDF-derived seeds:

```text
seed = HKDF-SHA-256(
  ikm  = utf8("cardanowall-wallet-cose-tamper-v1"),
  salt = utf8(wallet),                  // e.g. utf8("eternl")
  info = utf8(<variant info string>),   // see table below
  length = 32,
)
pub  = Ed25519.getPublicKey(seed)
```

| Variant                            | info strings used                                                         |
| ---------------------------------- | ------------------------------------------------------------------------- |
| `tampered-address`                 | `tamper-signer` (signs), `tamper-address` (Blake2b-224 → claimed address) |
| `missing-address`                  | `missing-signer` (only — no address claim)                                |
| `wrong-network-header`             | `wrong-network-signer` (signs + Blake2b-224 with `0xe0` prefix)           |
| (bootstrap-only) `positive-signer` | autonomous-mode synthetic positive fixture                                |

### Freeze rule

Once the fixtures land on `dev`, the HKDF IKM string, the per-wallet salts,
and the per-variant info strings are **frozen**. Changing any of them
changes every committed tamper-fixture byte and breaks the cross-language
parity check. A
deliberate rotation requires re-running `UPDATE=1 ... _build-tampered-fixtures.test.ts`
and re-committing all 36 mirrored files in one commit.

## Regenerator (`_build-tampered-fixtures.test.ts`)

Two-mode vitest-runnable script.

```bash
# Default — read-only validation. Recomputes tamper bytes, asserts byte-equality
# against the on-disk fixtures in both trees. Runs in CI on every push.
pnpm vitest run tests/fixtures/wallet-cose/_build-tampered-fixtures.test.ts

# UPDATE=1 — writes the 18 tamper-variant JSON files byte-identically to this
# package's fixtures directory AND the Python SDK's mirror. Run locally after
# a freeze rotation; commit all 36 files atomically.
UPDATE=1 pnpm vitest run tests/fixtures/wallet-cose/_build-tampered-fixtures.test.ts

# BOOTSTRAP_POSITIVE=1 — one-time autonomous-mode bootstrap that ALSO writes
# the 6 positive fixtures synthetically. NEVER run after real wallet
# captures land; doing so overwrites real-capture bytes with synthetic
# placeholders. The autonomous-mode placeholders ship with
# `captured_at: "1970-01-01T00:00:00Z"` and `wallet_version: "synthetic-placeholder"`
# as a grep flag.
BOOTSTRAP_POSITIVE=1 UPDATE=1 pnpm vitest run \
  tests/fixtures/wallet-cose/_build-tampered-fixtures.test.ts
```

The cross-language parity check skips the `_build-tampered-fixtures.test.ts`
file via its existing `*.test.ts` skip rule, so the regenerator can live
inside the parity-gated tree without breaking the byte-equality check.

## Re-capture workflow on wallet update

When a wallet ships a new version that changes its `COSE_Sign1` canonical
encoding (label sort order, indefinite-length CBOR, non-shortest integer
form, etc.), the KAT test surfaces the regression as
`MALFORMED_SIG_COSE_SIGN1` and CI fails — asserted by the strictness of
`decodeCoseSign1` / `parseCoseKeyEd25519`.

The reviewer either:

1. Pushes the wallet vendor to fix and rolls back the wallet version; OR
2. Amends Label 309 to accommodate the new encoding (a normative spec
   change); OR
3. Re-captures the positive fixture from the new wallet build using the
   protocol above, and re-runs `UPDATE=1` to regenerate the tamper variants
   (the tamper bytes depend on `record_body_cbor_hex`, which is pinned, so
   tamper variants do NOT change on a wallet update unless the pinned
   record body itself rotates).
