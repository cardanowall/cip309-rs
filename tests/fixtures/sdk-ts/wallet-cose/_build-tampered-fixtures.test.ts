// Wallet-cose fixture regenerator.
//
// This .test.ts file lives inside `tests/fixtures/wallet-cose/` so it is
// auto-skipped by the cross-language parity check (which skips *.test.ts),
// while still being picked up by vitest.
//
// This regenerator writes ONLY the TS canonical tree (its own package). The
// Python mirror under the Python SDK is synced by copying the regenerated files
// across, and byte-equality between the two trees is enforced by a separate
// cross-language fixture check — the regenerator never reaches into a sibling
// package.
//
// Two modes:
//   * default (no env)        — read-only validation. Recomputes every tamper
//                               variant deterministically from the per-wallet
//                               positive fixture's `record_body_cbor_hex` and
//                               asserts byte-equality with the on-disk
//                               `<wallet>-cose-<variant>.json` files in the TS
//                               canonical tree.
//   * `UPDATE=1`              — writes the 18 tamper-variant JSON files to the
//                               TS canonical tree.
//   * `BOOTSTRAP_POSITIVE=1`  — additionally synthesises the 6 positive
//                               fixtures and writes them to the TS tree. This
//                               is the autonomous-mode placeholder path; in
//                               normal operation positive fixtures come from
//                               the dev-only `/<locale>/dev/wallet-capture`
//                               page driving real CIP-30 wallets and are
//                               byte-faithful captures. The dev replaces the
//                               synthetic placeholders by re-capturing.
//
// Determinism inputs (FROZEN once the fixtures land on `dev`; changing any
// of these breaks every committed tamper-fixture byte and fails the parity
// gate):
//   * HKDF-SHA-256 IKM (UTF-8): `cardanowall-wallet-cose-tamper-v1`
//   * Per-wallet salt (UTF-8):   the lowercase wallet name
//                                (`eternl`, `lace`, `nami`, `typhon`, `yoroi`,
//                                `nufi`)
//   * Per-variant info (UTF-8): `tamper-signer`, `tamper-address`,
//                                `missing-signer`, `wrong-network-signer`,
//                                `positive-signer` (bootstrap only)
//   * Record body: canonical CBOR of
//                  `{ v: 1, items: [{ hashes: { 'sha2-256': <32 × 0x00> } }] }`
//                  — pinned across all six wallet captures so
//                  `record_body_cbor_hex` and `to_sign_bytes_hex` are
//                  byte-identical across the six positive fixtures and only
//                  `cose_sign1_bytes_hex` / `cose_key_bytes_hex` /
//                  `stake_addr_hex` / `expected_signer_pubkey_hex` vary.
//   * Ed25519 signing: deterministic per RFC 8032 §5.1.6 via
//                       `signEd25519({ seed, message })`.
//   * Canonical CBOR: `encodeCanonicalCbor` is byte-deterministic per RFC
//                      8949 §4.2.1.
//
// Layout: this regenerator writes each `<wallet>-cose-<variant>.json` to BOTH
// this package's `tests/fixtures/wallet-cose/` directory and the mirrored path
// in the Python SDK, keeping the cross-language parity check's byte-equality
// assertion green.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, it } from 'vitest';

import { encodeCanonicalCbor, type CanonicalCborValue } from '@cardanowall/crypto-core/cbor';
import {
  CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES,
  coseSign1Label309Build,
  parseCoseKeyEd25519,
  type CoseHeader,
} from '@cardanowall/crypto-core/cose';
import { blake2b224 } from '@cardanowall/crypto-core/hash';
import { hkdfSha256 } from '@cardanowall/crypto-core/kdf';
import { getPublicKeyEd25519 } from '@cardanowall/crypto-core/sig';
import { hexToBytes } from '@cardanowall/crypto-core/util';
import { encodeRecordBodyForSigning, type PoeRecord } from '@cardanowall/poe-standard';

const UPDATE = process.env['UPDATE'] === '1' || process.env['UPDATE'] === 'true';
const BOOTSTRAP_POSITIVE =
  process.env['BOOTSTRAP_POSITIVE'] === '1' || process.env['BOOTSTRAP_POSITIVE'] === 'true';

const HKDF_IKM = new TextEncoder().encode('cardanowall-wallet-cose-tamper-v1');

const WALLETS = ['eternl', 'lace', 'nami', 'typhon', 'yoroi', 'nufi'] as const;
type Wallet = (typeof WALLETS)[number];

const MAINNET_STAKE_NETWORK_BYTE = 0xe1;
const TESTNET_STAKE_NETWORK_BYTE = 0xe0;
const STAKE_ADDRESS_LENGTH = 29;
const ED25519_PUBLIC_KEY_LENGTH = 32;
const BLAKE2B_224_LENGTH = 28;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TS_FIXTURE_DIR = HERE;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function deriveSeed(wallet: Wallet, info: string): Uint8Array {
  return hkdfSha256({ ikm: HKDF_IKM, salt: utf8(wallet), info: utf8(info), length: 32 });
}

function buildCoseKey(pub: Uint8Array): Uint8Array {
  // RFC 9053 §7.2 OKP / Ed25519 COSE_Key.
  return encodeCanonicalCbor(
    new Map<number, unknown>([
      [1, 1],
      [3, -8],
      [-1, 6],
      [-2, pub],
    ]) as unknown as CanonicalCborValue,
  );
}

function buildRecordBodyCbor(): Uint8Array {
  // Pinned trivial record body shared across all wallet captures.
  const record: PoeRecord = {
    v: 1,
    items: [{ hashes: { 'sha2-256': new Uint8Array(32) } }],
  };
  return encodeRecordBodyForSigning(record);
}

function buildToSignBytes(recordBodyCbor: Uint8Array): Uint8Array {
  const out = new Uint8Array(CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length + recordBodyCbor.length);
  out.set(CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES, 0);
  out.set(recordBodyCbor, CARDANO_POE_SIG_DOMAIN_PREFIX_BYTES.length);
  return out;
}

function stakeAddressFor(pub: Uint8Array, networkByte: number): Uint8Array {
  const hash = blake2b224(pub);
  const out = new Uint8Array(STAKE_ADDRESS_LENGTH);
  out[0] = networkByte;
  out.set(hash, 1);
  return out;
}

interface PositiveFixture {
  readonly wallet: Wallet;
  readonly captured_at: string;
  readonly wallet_version: string;
  readonly wallet_api_version: string;
  readonly browser_user_agent: string;
  readonly cardano_network: 'mainnet';
  readonly record_body_cbor_hex: string;
  readonly to_sign_bytes_hex: string;
  readonly stake_addr_hex: string;
  readonly stake_addr_bech32: string;
  readonly cose_sign1_bytes_hex: string;
  readonly cose_key_bytes_hex: string;
  readonly expected_signer_pubkey_hex: string;
  readonly expected_normalized_verdict: {
    readonly index: 0;
    readonly signer_pub_hex: string;
    readonly signer_type: 'wallet-inline-key';
    readonly ok: true;
    readonly reason: null;
  };
}

function buildSyntheticPositive(wallet: Wallet): PositiveFixture {
  const recordBodyCbor = buildRecordBodyCbor();
  const toSignBytes = buildToSignBytes(recordBodyCbor);
  const seed = deriveSeed(wallet, 'positive-signer');
  const pub = getPublicKeyEd25519({ seed });
  const stakeAddr = stakeAddressFor(pub, MAINNET_STAKE_NETWORK_BYTE);
  const stakeBech32 = encodeStakeAddressBech32(stakeAddr);
  const protectedHeader: CoseHeader = new Map<number | string, unknown>([
    [1, -8],
    ['address', stakeAddr],
  ]);
  const cose = coseSign1Label309Build({
    protectedHeader,
    unprotectedHeader: new Map(),
    recordBodyCbor,
    signerSecretKey: seed,
  });
  const coseKey = buildCoseKey(pub);
  const pubHex = bytesToHex(pub);
  return {
    wallet,
    captured_at: SYNTHETIC_CAPTURED_AT,
    wallet_version: SYNTHETIC_WALLET_VERSION,
    wallet_api_version: SYNTHETIC_WALLET_API_VERSION,
    browser_user_agent: SYNTHETIC_BROWSER_USER_AGENT,
    cardano_network: 'mainnet',
    record_body_cbor_hex: bytesToHex(recordBodyCbor),
    to_sign_bytes_hex: bytesToHex(toSignBytes),
    stake_addr_hex: bytesToHex(stakeAddr),
    stake_addr_bech32: stakeBech32,
    cose_sign1_bytes_hex: bytesToHex(cose),
    cose_key_bytes_hex: bytesToHex(coseKey),
    expected_signer_pubkey_hex: pubHex,
    expected_normalized_verdict: {
      index: 0,
      signer_pub_hex: pubHex,
      signer_type: 'wallet-inline-key',
      ok: true,
      reason: null,
    },
  };
}

// Synthetic placeholders used ONLY for the autonomous-mode bootstrap. When a
// dev re-captures from a real wallet via /<locale>/dev/wallet-capture, the
// captured fixture overwrites these values with real provenance. The strings
// are deliberately marked synthetic so a casual grep flags them.
const SYNTHETIC_CAPTURED_AT = '1970-01-01T00:00:00Z';
const SYNTHETIC_WALLET_VERSION = 'synthetic-placeholder';
const SYNTHETIC_WALLET_API_VERSION = 'synthetic-placeholder';
const SYNTHETIC_BROWSER_USER_AGENT = 'synthetic-placeholder';

interface TamperedAddressFixture {
  readonly wallet: Wallet;
  readonly tamper_variant: 'tampered-address';
  readonly captured_from_positive_fixture: string;
  readonly record_body_cbor_hex: string;
  readonly to_sign_bytes_hex: string;
  readonly tamper_signer_pubkey_hex: string;
  readonly tamper_address_pubkey_hex: string;
  readonly stake_addr_hex: string;
  readonly cose_sign1_bytes_hex: string;
  readonly cose_key_bytes_hex: string;
  readonly expected_normalized_verdict: {
    readonly index: 0;
    readonly signer_pub_hex: string;
    readonly signer_type: 'wallet-inline-key';
    readonly ok: false;
    readonly reason: 'WALLET_ADDRESS_MISMATCH';
  };
}

function buildTamperedAddress(wallet: Wallet, positive: PositiveFixture): TamperedAddressFixture {
  const recordBodyCbor = hexToBytes(positive.record_body_cbor_hex);
  const seedSigner = deriveSeed(wallet, 'tamper-signer');
  const pubSigner = getPublicKeyEd25519({ seed: seedSigner });
  const seedAddress = deriveSeed(wallet, 'tamper-address');
  const pubAddress = getPublicKeyEd25519({ seed: seedAddress });
  const addressClaim = stakeAddressFor(pubAddress, MAINNET_STAKE_NETWORK_BYTE);
  const protectedHeader: CoseHeader = new Map<number | string, unknown>([
    [1, -8],
    ['address', addressClaim],
  ]);
  const cose = coseSign1Label309Build({
    protectedHeader,
    unprotectedHeader: new Map(),
    recordBodyCbor,
    signerSecretKey: seedSigner,
  });
  const coseKey = buildCoseKey(pubSigner);
  const pubSignerHex = bytesToHex(pubSigner);
  return {
    wallet,
    tamper_variant: 'tampered-address',
    captured_from_positive_fixture: `${wallet}-cose.json`,
    record_body_cbor_hex: positive.record_body_cbor_hex,
    to_sign_bytes_hex: positive.to_sign_bytes_hex,
    tamper_signer_pubkey_hex: pubSignerHex,
    tamper_address_pubkey_hex: bytesToHex(pubAddress),
    stake_addr_hex: bytesToHex(addressClaim),
    cose_sign1_bytes_hex: bytesToHex(cose),
    cose_key_bytes_hex: bytesToHex(coseKey),
    expected_normalized_verdict: {
      index: 0,
      signer_pub_hex: pubSignerHex,
      signer_type: 'wallet-inline-key',
      ok: false,
      reason: 'WALLET_ADDRESS_MISMATCH',
    },
  };
}

interface MissingAddressFixture {
  readonly wallet: Wallet;
  readonly tamper_variant: 'missing-address';
  readonly captured_from_positive_fixture: string;
  readonly record_body_cbor_hex: string;
  readonly to_sign_bytes_hex: string;
  readonly tamper_signer_pubkey_hex: string;
  readonly cose_sign1_bytes_hex: string;
  readonly cose_key_bytes_hex: string;
  readonly expected_normalized_verdict: {
    readonly index: 0;
    readonly signer_pub_hex: string;
    readonly signer_type: 'wallet-inline-key';
    readonly ok: false;
    readonly reason: 'WALLET_ADDRESS_MISMATCH';
  };
}

function buildMissingAddress(wallet: Wallet, positive: PositiveFixture): MissingAddressFixture {
  const recordBodyCbor = hexToBytes(positive.record_body_cbor_hex);
  const seedSigner = deriveSeed(wallet, 'missing-signer');
  const pubSigner = getPublicKeyEd25519({ seed: seedSigner });
  // No 'address' key in the protected header — the verifier in
  // `src/verifier/signatures.ts` collapses the missing-address case to
  // WALLET_ADDRESS_MISMATCH.
  const protectedHeader: CoseHeader = new Map<number | string, unknown>([[1, -8]]);
  const cose = coseSign1Label309Build({
    protectedHeader,
    unprotectedHeader: new Map(),
    recordBodyCbor,
    signerSecretKey: seedSigner,
  });
  const coseKey = buildCoseKey(pubSigner);
  const pubSignerHex = bytesToHex(pubSigner);
  return {
    wallet,
    tamper_variant: 'missing-address',
    captured_from_positive_fixture: `${wallet}-cose.json`,
    record_body_cbor_hex: positive.record_body_cbor_hex,
    to_sign_bytes_hex: positive.to_sign_bytes_hex,
    tamper_signer_pubkey_hex: pubSignerHex,
    cose_sign1_bytes_hex: bytesToHex(cose),
    cose_key_bytes_hex: bytesToHex(coseKey),
    expected_normalized_verdict: {
      index: 0,
      signer_pub_hex: pubSignerHex,
      signer_type: 'wallet-inline-key',
      ok: false,
      reason: 'WALLET_ADDRESS_MISMATCH',
    },
  };
}

interface WrongNetworkHeaderFixture {
  readonly wallet: Wallet;
  readonly tamper_variant: 'wrong-network-header';
  readonly captured_from_positive_fixture: string;
  readonly record_body_cbor_hex: string;
  readonly to_sign_bytes_hex: string;
  readonly tamper_signer_pubkey_hex: string;
  readonly stake_addr_hex: string;
  readonly cose_sign1_bytes_hex: string;
  readonly cose_key_bytes_hex: string;
  readonly expected_normalized_verdict: {
    readonly index: 0;
    readonly signer_pub_hex: string;
    readonly signer_type: 'wallet-inline-key';
    readonly ok: false;
    readonly reason: 'WALLET_ADDRESS_MISMATCH';
  };
}

function buildWrongNetworkHeader(
  wallet: Wallet,
  positive: PositiveFixture,
): WrongNetworkHeaderFixture {
  const recordBodyCbor = hexToBytes(positive.record_body_cbor_hex);
  const seedSigner = deriveSeed(wallet, 'wrong-network-signer');
  const pubSigner = getPublicKeyEd25519({ seed: seedSigner });
  // Testnet network byte 0xe0 + correct Blake2b-224(pub_signer) — the
  // (signer_pub, hash-of-pub_signer) pair is internally coherent; only the
  // network byte fails the mainnet guard at signatures.ts:220.
  const addressClaim = stakeAddressFor(pubSigner, TESTNET_STAKE_NETWORK_BYTE);
  const protectedHeader: CoseHeader = new Map<number | string, unknown>([
    [1, -8],
    ['address', addressClaim],
  ]);
  const cose = coseSign1Label309Build({
    protectedHeader,
    unprotectedHeader: new Map(),
    recordBodyCbor,
    signerSecretKey: seedSigner,
  });
  const coseKey = buildCoseKey(pubSigner);
  const pubSignerHex = bytesToHex(pubSigner);
  return {
    wallet,
    tamper_variant: 'wrong-network-header',
    captured_from_positive_fixture: `${wallet}-cose.json`,
    record_body_cbor_hex: positive.record_body_cbor_hex,
    to_sign_bytes_hex: positive.to_sign_bytes_hex,
    tamper_signer_pubkey_hex: pubSignerHex,
    stake_addr_hex: bytesToHex(addressClaim),
    cose_sign1_bytes_hex: bytesToHex(cose),
    cose_key_bytes_hex: bytesToHex(coseKey),
    expected_normalized_verdict: {
      index: 0,
      signer_pub_hex: pubSignerHex,
      signer_type: 'wallet-inline-key',
      ok: false,
      reason: 'WALLET_ADDRESS_MISMATCH',
    },
  };
}

function serializeFixture(obj: unknown): string {
  return JSON.stringify(obj, null, 2) + '\n';
}

function writeFixture(filename: string, content: string): void {
  fs.writeFileSync(path.join(TS_FIXTURE_DIR, filename), content, 'utf8');
}

function readFixture(filename: string): string {
  return fs.readFileSync(path.join(TS_FIXTURE_DIR, filename), 'utf8');
}

function readPositive(wallet: Wallet): PositiveFixture {
  const raw = JSON.parse(readFixture(`${wallet}-cose.json`)) as PositiveFixture;
  return raw;
}

// CIP-19 §7 stake (reward) addresses are bech32-encoded with HRP `stake` on
// mainnet. Encoding 29 raw bytes → 47-character bech32 string; round-trips
// the wallet-returned reward address shape (e.g. `stake1u...`).
function encodeStakeAddressBech32(stakeAddr: Uint8Array): string {
  return bech32Encode('stake', stakeAddr);
}

// Inline bech32 encoder — used only for the synthetic-positive bootstrap
// path. We avoid pulling @scure/base into the crypto-core test layer; the
// helper here implements BIP-173 / RFC-9527 bech32 (NOT bech32m) which is
// the encoding CIP-19 specifies for stake addresses.
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Encode(hrp: string, data: Uint8Array): string {
  const fiveBitWords = to5BitWords(data);
  const checksum = bech32CreateChecksum(hrp, fiveBitWords);
  const combined = [...fiveBitWords, ...checksum];
  let out = `${hrp}1`;
  for (const w of combined) out += BECH32_CHARSET[w];
  return out;
}

function to5BitWords(bytes: Uint8Array): number[] {
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push((acc >> bits) & 0x1f);
    }
  }
  if (bits > 0) out.push((acc << (5 - bits)) & 0x1f);
  return out;
}

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i]!;
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 0x1f);
  return out;
}

function bech32CreateChecksum(hrp: string, data: number[]): number[] {
  const values = [...bech32HrpExpand(hrp), ...data];
  const polymod = bech32Polymod([...values, 0, 0, 0, 0, 0, 0]) ^ 1;
  const out: number[] = [];
  for (let i = 0; i < 6; i++) out.push((polymod >> (5 * (5 - i))) & 0x1f);
  return out;
}

// Module-level: on BOOTSTRAP_POSITIVE, synthesise the 6 positive fixtures. The
// synthesis is deterministic so a re-run reproduces identical bytes.
// BOOTSTRAP_POSITIVE writes positives and is only meaningful as a paired write
// op — require UPDATE=1 so a stray BOOTSTRAP_POSITIVE=1 alone cannot quietly
// desync positives from the tamper variants that are re-derived from them.
if (BOOTSTRAP_POSITIVE) {
  if (!UPDATE) {
    throw new Error(
      'BOOTSTRAP_POSITIVE=1 requires UPDATE=1 (it writes positive fixtures, and the tamper variants must be rewritten in the same run). Re-run with `BOOTSTRAP_POSITIVE=1 UPDATE=1`.',
    );
  }
  for (const wallet of WALLETS) {
    const fixture = buildSyntheticPositive(wallet);
    writeFixture(`${wallet}-cose.json`, serializeFixture(fixture));
  }
}

// Sanity invariant: every positive fixture's `expected_signer_pubkey_hex`
// must equal `parseCoseKeyEd25519(cose_key)`, and `stake_addr_hex` must equal
// `0xe1 || Blake2b-224(signer_pub)`. Asserted at module-load time so the
// regenerator self-validates the positive fixtures before computing tamper
// variants (which DEPEND on the positive fixture's record_body_cbor_hex).
const positives = new Map<Wallet, PositiveFixture>();
for (const wallet of WALLETS) {
  const positive = readPositive(wallet);
  const coseKeyBytes = hexToBytes(positive.cose_key_bytes_hex);
  const pub = parseCoseKeyEd25519(coseKeyBytes);
  if (pub === null || pub.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new Error(
      `positive fixture ${wallet}-cose.json: parseCoseKeyEd25519 returned ${pub === null ? 'null' : `${pub.length} bytes`} (expected 32). Re-capture required.`,
    );
  }
  if (bytesToHex(pub) !== positive.expected_signer_pubkey_hex) {
    throw new Error(
      `positive fixture ${wallet}-cose.json: expected_signer_pubkey_hex !== parseCoseKeyEd25519(cose_key). Re-capture required.`,
    );
  }
  const stakeAddr = hexToBytes(positive.stake_addr_hex);
  if (stakeAddr.length !== STAKE_ADDRESS_LENGTH) {
    throw new Error(
      `positive fixture ${wallet}-cose.json: stake_addr_hex must encode to 29 bytes, got ${stakeAddr.length}. Re-capture required.`,
    );
  }
  if (stakeAddr[0] !== MAINNET_STAKE_NETWORK_BYTE) {
    throw new Error(
      `positive fixture ${wallet}-cose.json: stake_addr_hex[0] !== 0xe1 (mainnet). Re-capture required.`,
    );
  }
  const derivedHash = blake2b224(pub);
  if (derivedHash.length !== BLAKE2B_224_LENGTH) {
    throw new Error(
      `positive fixture ${wallet}-cose.json: blake2b224(pub) length ${derivedHash.length} !== 28.`,
    );
  }
  const stakeHashOnRecord = stakeAddr.slice(1);
  for (let i = 0; i < BLAKE2B_224_LENGTH; i++) {
    if (derivedHash[i] !== stakeHashOnRecord[i]) {
      throw new Error(
        `positive fixture ${wallet}-cose.json: Blake2b-224(signer_pub) does not bind to stake_addr_hex[1:29]. Re-capture required.`,
      );
    }
  }
  positives.set(wallet, positive);
}

type TamperVariantName = 'tampered-address' | 'missing-address' | 'wrong-network-header';
const TAMPER_VARIANTS: readonly TamperVariantName[] = [
  'tampered-address',
  'missing-address',
  'wrong-network-header',
];

function buildTamperVariant(variant: TamperVariantName, wallet: Wallet, positive: PositiveFixture) {
  if (variant === 'tampered-address') return buildTamperedAddress(wallet, positive);
  if (variant === 'missing-address') return buildMissingAddress(wallet, positive);
  return buildWrongNetworkHeader(wallet, positive);
}

describe('wallet-cose tamper-fixture regenerator', () => {
  for (const wallet of WALLETS) {
    describe(wallet, () => {
      for (const variant of TAMPER_VARIANTS) {
        const filename = `${wallet}-cose-${variant}.json`;
        it(filename, () => {
          const positive = positives.get(wallet)!;
          const expected = buildTamperVariant(variant, wallet, positive);
          const expectedJson = serializeFixture(expected);
          if (UPDATE) {
            writeFixture(filename, expectedJson);
            return;
          }
          const tsOnDisk = readFixture(filename);
          if (tsOnDisk !== expectedJson) {
            throw new Error(
              `Tamper fixture ${filename} has drifted. Run \`UPDATE=1 pnpm vitest run tests/fixtures/wallet-cose/_build-tampered-fixtures.test.ts\` to regenerate.`,
            );
          }
        });
      }
    });
  }
});
