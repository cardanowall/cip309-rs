// Regenerator for multi-priv sealed-PoE unwrap KAT fixtures.
// Runs only when BUILD_FIXTURES=1 is set:
//
//   BUILD_FIXTURES=1 pnpm exec vitest run packages/crypto-core/tests/fixtures/sealed-poe/_build-multipriv-fixtures.test.ts
//
// Pinned inputs: deterministic priv-byte arrays (fill-byte patterns) following
// the sealed-PoE fixture-generation conventions. Wraps via eciesSealedPoeWrap with
// skipShuffle=true so slot positions are deterministic across regenerations.
// The Python parity twin mirrors these JSON files byte-for-byte.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, it } from 'vitest';

import { x25519PublicKey } from '../../../src/kem/x25519';
import type { ItemHashes } from '../../../src/sealed-poe/transcript';
import { eciesSealedPoeWrap, SEALED_POE_AEAD } from '../../../src/sealed-poe/wrap';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PY_MIRROR = path.resolve(HERE, '../../../../sdk-py/tests/fixtures/sealed-poe');

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function fillPriv(b: number): Uint8Array {
  const out = new Uint8Array(32);
  out.fill(b & 0xff);
  return out;
}

function fillBytes(b: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  out.fill(b & 0xff);
  return out;
}

function sequentialBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = i & 0xff;
  return out;
}

function writeJson(filePath: string, value: unknown): void {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

// The honest hash claim: the real sha2-256 of the plaintext.
function honestHashes(plaintext: Uint8Array): ItemHashes {
  return { 'sha2-256': sha256(plaintext) };
}

function hashesToHex(hashes: ItemHashes): Record<string, string> {
  return Object.fromEntries(Object.entries(hashes).map(([alg, d]) => [alg, bytesToHex(d)]));
}

interface MultiPrivFixture {
  version: 1;
  primitive: string;
  source: string;
  vector: {
    name: string;
    recipient_privs_hex: string[];
    hashes: Record<string, string>;
    envelope: {
      scheme: 1;
      aead: typeof SEALED_POE_AEAD;
      kem: 'x25519';
      nonce_hex: string;
      slots: Array<{ epk_hex: string; wrap_hex: string }>;
      slots_mac_hex: string;
    };
    ciphertext_hex: string;
    expected_plaintext_hex: string;
    expected_matching_priv_index: number | null;
    expected_outer_loop_count: number;
    expected_inner_loop_count_per_priv: number;
  };
}

function buildFixture(args: {
  name: string;
  recipientPrivs: Uint8Array[];
  // index into recipientPrivs whose pubkey is used to seal the envelope; null
  // for the no-match case (uses an outsider pub).
  matchPrivIndex: number | null;
  plaintext: Uint8Array;
  nNonMatchSlots: number; // total slots = nNonMatchSlots (+ 1 if matchPrivIndex !== null)
  cek: Uint8Array;
  nonce: Uint8Array;
  // Ephemeral secrets for all wrap slots (length = total slots).
  ephemeralSecrets: Uint8Array[];
  expectedOuterLoopCount: number;
  expectedInnerLoopCountPerPriv: number;
  expectedMatchingPrivIndex: number | null;
  outsiderPub?: Uint8Array;
  // Explicit slot position for the matching recipient pub.
  // Default 0 (preserves the builder behaviour). When set, the
  // match pub is inserted at index `matchSlotIdx` and fillers occupy the
  // remaining slots (preserving the total slot count =
  // 1 + nNonMatchSlots). Ignored when matchPrivIndex is null.
  matchSlotIdx?: number;
}): MultiPrivFixture {
  const recipientPubs: Uint8Array[] = [];
  const fillerPubs: Uint8Array[] = [];
  for (let s = 0; s < args.nNonMatchSlots; s++) {
    // Distinct outsider pubs derived from sequential fill privs that do NOT
    // collide with the recipient set.
    const filler = fillPriv(0xd0 + s);
    fillerPubs.push(x25519PublicKey({ secretKey: filler }));
  }
  if (args.matchPrivIndex !== null) {
    const matchPriv = args.recipientPrivs[args.matchPrivIndex]!;
    const matchPub = x25519PublicKey({ secretKey: matchPriv });
    const idx = args.matchSlotIdx ?? 0;
    const total = args.nNonMatchSlots + 1;
    if (idx < 0 || idx >= total) {
      throw new Error(`matchSlotIdx=${idx} out of range [0, ${total - 1}]`);
    }
    for (let s = 0; s < idx; s++) recipientPubs.push(fillerPubs[s]!);
    recipientPubs.push(matchPub);
    for (let s = idx; s < args.nNonMatchSlots; s++) recipientPubs.push(fillerPubs[s]!);
  } else {
    const outsider = args.outsiderPub!;
    recipientPubs.push(outsider);
    for (const p of fillerPubs) recipientPubs.push(p);
  }

  const hashes = honestHashes(args.plaintext);
  const out = eciesSealedPoeWrap({
    plaintext: args.plaintext,
    hashes,
    recipientPublicKeys: recipientPubs,
    cek: args.cek,
    nonce: args.nonce,
    ephemeralSecrets: args.ephemeralSecrets,
    skipShuffle: true,
  });

  return {
    version: 1,
    primitive: 'sealed-poe-unwrap-multipriv',
    source: 'multi-priv trial-decrypt iterator extension',
    vector: {
      name: args.name,
      recipient_privs_hex: args.recipientPrivs.map(bytesToHex),
      hashes: hashesToHex(hashes),
      envelope: {
        scheme: 1,
        aead: SEALED_POE_AEAD,
        kem: 'x25519',
        nonce_hex: bytesToHex(out.envelope.nonce),
        slots: out.envelope.slots.map((s) => ({
          epk_hex: bytesToHex(s.epk),
          wrap_hex: bytesToHex(s.wrap),
        })),
        slots_mac_hex: bytesToHex(out.envelope.slots_mac),
      },
      ciphertext_hex: bytesToHex(out.ciphertext),
      expected_plaintext_hex: bytesToHex(args.plaintext),
      expected_matching_priv_index: args.expectedMatchingPrivIndex,
      expected_outer_loop_count: args.expectedOuterLoopCount,
      expected_inner_loop_count_per_priv: args.expectedInnerLoopCountPerPriv,
    },
  };
}

function mirror(filename: string, value: unknown): void {
  const tsPath = path.resolve(HERE, filename);
  const pyPath = path.resolve(PY_MIRROR, filename);
  writeJson(tsPath, value);
  // Byte-copy from TS canonical to Python mirror (parity gate enforces SHA-256
  // identity).
  fs.copyFileSync(tsPath, pyPath);
}

function buildCurrentMatchFixture(): void {
  const privs = [fillPriv(0x11), fillPriv(0x22), fillPriv(0x33), fillPriv(0x44)];
  // N=1 slot sealed to priv[0] (current).
  const fx = buildFixture({
    name: 'multipriv-current-match-n1-k4',
    recipientPrivs: privs,
    matchPrivIndex: 0,
    plaintext: sequentialBytes(32),
    nNonMatchSlots: 0,
    cek: fillBytes(0xa0, 32),
    nonce: fillBytes(0xb0, 24),
    ephemeralSecrets: [fillPriv(0xc0)],
    expectedOuterLoopCount: 1,
    expectedInnerLoopCountPerPriv: 1,
    expectedMatchingPrivIndex: 0,
  });
  mirror('unwrap-multipriv-current-match.json', fx);
}

function buildArchivedMatchFixture(): void {
  const privs = [fillPriv(0x11), fillPriv(0x22), fillPriv(0x33), fillPriv(0x44)];
  // N=3 slots sealed to priv[2] (archived_mid). Two additional outsider slots
  // pad to N=3.
  const fx = buildFixture({
    name: 'multipriv-archived-match-n3-k4',
    recipientPrivs: privs,
    matchPrivIndex: 2,
    plaintext: sequentialBytes(32),
    nNonMatchSlots: 2,
    cek: fillBytes(0xa1, 32),
    nonce: fillBytes(0xb1, 24),
    ephemeralSecrets: [fillPriv(0xc1), fillPriv(0xc2), fillPriv(0xc3)],
    expectedOuterLoopCount: 3,
    expectedInnerLoopCountPerPriv: 3,
    expectedMatchingPrivIndex: 2,
  });
  mirror('unwrap-multipriv-archived-match.json', fx);
}

function buildNoMatchFixture(): void {
  const privs = [fillPriv(0x11), fillPriv(0x22), fillPriv(0x33), fillPriv(0x44)];
  // N=3 slots sealed to an outsider pub.
  const outsiderPriv = fillPriv(0xff);
  const outsiderPub = x25519PublicKey({ secretKey: outsiderPriv });
  const fx = buildFixture({
    name: 'multipriv-no-match-n3-k4',
    recipientPrivs: privs,
    matchPrivIndex: null,
    plaintext: sequentialBytes(32),
    nNonMatchSlots: 2,
    cek: fillBytes(0xa2, 32),
    nonce: fillBytes(0xb2, 24),
    ephemeralSecrets: [fillPriv(0xc4), fillPriv(0xc5), fillPriv(0xc6)],
    expectedOuterLoopCount: 4,
    expectedInnerLoopCountPerPriv: 3,
    expectedMatchingPrivIndex: null,
    outsiderPub,
  });
  mirror('unwrap-multipriv-no-match.json', fx);
}

function buildWorstCaseFixture(): void {
  const privs: Uint8Array[] = [];
  for (let i = 0; i < 10; i++) privs.push(fillPriv(0x11 + i));
  // N=32 slots sealed to priv[9] (last archived). 31 outsider slots pad to N=32.
  const ephemerals: Uint8Array[] = [];
  for (let i = 0; i < 32; i++) ephemerals.push(fillPriv(0x80 + i));
  const fx = buildFixture({
    name: 'multipriv-n32-k10-worst-case',
    recipientPrivs: privs,
    matchPrivIndex: 9,
    plaintext: sequentialBytes(32),
    nNonMatchSlots: 31,
    cek: fillBytes(0xa3, 32),
    nonce: fillBytes(0xb3, 24),
    ephemeralSecrets: ephemerals,
    expectedOuterLoopCount: 10,
    expectedInnerLoopCountPerPriv: 32,
    expectedMatchingPrivIndex: 9,
  });
  mirror('unwrap-multipriv-n32-k10-worst-case.json', fx);
}

// Multi-priv MAC-fail (bit-flipped wrap) — handcrafted negative
// fixture appended into unwrap-negative.json. We build a valid envelope sealed
// to priv[1], then bit-flip slots[0].wrap byte 0. The recovered CEK from
// priv[1]'s match on slot[1] is the legitimate CEK so MAC matches —
// uninteresting. Instead, bit-flip the slots_mac so the recovered CEK fails MAC
// verification — this exercises the multi-priv TAMPERED_HEADER path because
// SOME priv recovered a CEK but the MAC failed.
function buildNegativeAdditions(): void {
  const fxPath = path.resolve(HERE, 'unwrap-negative.json');
  const corpus = JSON.parse(fs.readFileSync(fxPath, 'utf8')) as {
    version: number;
    primitive: string;
    source: string;
    matched_false_vectors: Array<Record<string, unknown>>;
    raise_vectors: Array<Record<string, unknown>>;
  };

  // Build a valid envelope sealed to priv[1] of a K=3 set; then bit-flip the
  // on-wire slots_mac so the legitimate CEK's MAC fails. Recipient holds K=3
  // privs including the genuine one — multi-priv path SHOULD recover the CEK
  // (priv[1] matches slot[0]) but slots_mac comparison fails → TAMPERED_HEADER.
  const privs = [fillPriv(0x55), fillPriv(0x66), fillPriv(0x77)];
  const matchPub = x25519PublicKey({ secretKey: privs[1]! });
  const macFailPlaintext = sequentialBytes(16);
  const macFailHashes = honestHashes(macFailPlaintext);
  const out = eciesSealedPoeWrap({
    plaintext: macFailPlaintext,
    hashes: macFailHashes,
    recipientPublicKeys: [matchPub],
    cek: fillBytes(0xa4, 32),
    nonce: fillBytes(0xb4, 24),
    ephemeralSecrets: [fillPriv(0xc7)],
    skipShuffle: true,
  });
  const tamperedMac = new Uint8Array(out.envelope.slots_mac);
  tamperedMac[0] = tamperedMac[0]! ^ 0xff;
  const macFailVector = {
    name: 'multipriv-mac-fail',
    envelope: {
      scheme: 1,
      aead: SEALED_POE_AEAD,
      kem: 'x25519',
      nonce_hex: bytesToHex(out.envelope.nonce),
      slots: out.envelope.slots.map((s) => ({
        epk_hex: bytesToHex(s.epk),
        wrap_hex: bytesToHex(s.wrap),
      })),
      slots_mac_hex: bytesToHex(tamperedMac),
    },
    hashes: hashesToHex(macFailHashes),
    ciphertext_hex: bytesToHex(out.ciphertext),
    recipient_secret_keys_hex: privs.map(bytesToHex),
    expected_reason: 'TAMPERED_HEADER',
  };
  const existingIdx = corpus.matched_false_vectors.findIndex(
    (v) => v['name'] === 'multipriv-mac-fail',
  );
  if (existingIdx >= 0) {
    corpus.matched_false_vectors[existingIdx] = macFailVector;
  } else {
    corpus.matched_false_vectors.push(macFailVector);
  }

  // raise_vectors additions — empty/both/neither/wrong-length on the new
  // recipient_secret_keys form. We carry a single sentinel envelope to satisfy
  // the existing shape; the raise fires before any envelope-shape work.
  const sentinel = {
    scheme: 1,
    aead: SEALED_POE_AEAD,
    kem: 'x25519',
    nonce_hex: bytesToHex(fillBytes(0x00, 24)),
    slots: [
      {
        epk_hex: bytesToHex(fillBytes(0x00, 32)),
        wrap_hex: bytesToHex(fillBytes(0x00, 48)),
      },
    ],
    slots_mac_hex: bytesToHex(fillBytes(0x00, 32)),
  };
  const sentinelCiphertext = bytesToHex(fillBytes(0x00, 16));
  const sentinelHashes = hashesToHex(honestHashes(new Uint8Array(0)));
  const validPrivHex = bytesToHex(fillPriv(0x11));
  const shortPrivHex = bytesToHex(fillBytes(0x11, 31));

  const newRaises: Array<Record<string, unknown>> = [
    {
      name: 'empty-recipient-secret-keys',
      envelope: sentinel,
      hashes: sentinelHashes,
      ciphertext_hex: sentinelCiphertext,
      recipient_secret_keys_hex: [],
      expected_error_code: 'INVALID_RECIPIENT_KEY',
    },
    {
      name: 'both-forms-supplied',
      envelope: sentinel,
      hashes: sentinelHashes,
      ciphertext_hex: sentinelCiphertext,
      recipient_secret_hex: validPrivHex,
      recipient_secret_keys_hex: [validPrivHex],
      expected_error_code: 'INVALID_RECIPIENT_KEY',
    },
    {
      name: 'neither-form-supplied',
      envelope: sentinel,
      hashes: sentinelHashes,
      ciphertext_hex: sentinelCiphertext,
      expected_error_code: 'INVALID_RECIPIENT_KEY',
    },
    {
      name: 'multipriv-element-wrong-length',
      envelope: sentinel,
      hashes: sentinelHashes,
      ciphertext_hex: sentinelCiphertext,
      recipient_secret_keys_hex: [validPrivHex, shortPrivHex, validPrivHex],
      expected_error_code: 'INVALID_RECIPIENT_KEY',
    },
  ];
  for (const v of newRaises) {
    const idx = corpus.raise_vectors.findIndex((existing) => existing['name'] === v['name']);
    if (idx >= 0) corpus.raise_vectors[idx] = v;
    else corpus.raise_vectors.push(v);
  }

  writeJson(fxPath, corpus);
  fs.copyFileSync(fxPath, path.resolve(PY_MIRROR, 'unwrap-negative.json'));
}

const SHOULD_BUILD = process.env['BUILD_FIXTURES'] === '1';

// Constant-time-N matrix fixtures (K=5 privs, N=32 slots).
// Five scenarios pin the per-priv constant-time-N invariant against the
// matching priv index (0 vs 4) and the matching slot position (0 vs 31).
function buildAc9MatrixFixture(args: {
  name: string;
  matchPrivIndex: number | null;
  matchSlotIdx?: number;
  expectedOuterLoopCount: number;
  expectedMatchingPrivIndex: number | null;
  ephemeralSeedByte: number;
  cekByte: number;
  nonceByte: number;
  outsiderPub?: Uint8Array;
}): MultiPrivFixture {
  // K=5 user privs (current first + 4 archived).
  const privs: Uint8Array[] = [
    fillPriv(0x51),
    fillPriv(0x52),
    fillPriv(0x53),
    fillPriv(0x54),
    fillPriv(0x55),
  ];
  // N=32 slots total: 1 match (when matchPrivIndex !== null) + 31 fillers.
  const ephemerals: Uint8Array[] = [];
  for (let i = 0; i < 32; i++) ephemerals.push(fillPriv((args.ephemeralSeedByte + i) & 0xff));
  return buildFixture({
    name: args.name,
    recipientPrivs: privs,
    matchPrivIndex: args.matchPrivIndex,
    plaintext: sequentialBytes(32),
    // 32 total slots in every scenario: 1 match (when matchPrivIndex !== null)
    // + 31 fillers; OR 1 outsider + 31 fillers in the no-match case.
    nNonMatchSlots: 31,
    cek: fillBytes(args.cekByte, 32),
    nonce: fillBytes(args.nonceByte, 24),
    ephemeralSecrets: ephemerals,
    expectedOuterLoopCount: args.expectedOuterLoopCount,
    expectedInnerLoopCountPerPriv: 32,
    expectedMatchingPrivIndex: args.expectedMatchingPrivIndex,
    ...(args.matchSlotIdx !== undefined ? { matchSlotIdx: args.matchSlotIdx } : {}),
    ...(args.outsiderPub !== undefined ? { outsiderPub: args.outsiderPub } : {}),
  });
}

function buildAc9MatrixFixtures(): void {
  // Scenario (a): match at priv 0 + slot 0.
  mirror(
    'unwrap-multipriv-ac9-priv0-slot0.json',
    buildAc9MatrixFixture({
      name: 'multipriv-ac9-priv0-slot0-n32-k5',
      matchPrivIndex: 0,
      matchSlotIdx: 0,
      expectedOuterLoopCount: 1,
      expectedMatchingPrivIndex: 0,
      ephemeralSeedByte: 0x60,
      cekByte: 0xa5,
      nonceByte: 0xb5,
    }),
  );
  // Scenario (b): match at priv 0 + slot 31.
  mirror(
    'unwrap-multipriv-ac9-priv0-slot31.json',
    buildAc9MatrixFixture({
      name: 'multipriv-ac9-priv0-slot31-n32-k5',
      matchPrivIndex: 0,
      matchSlotIdx: 31,
      expectedOuterLoopCount: 1,
      expectedMatchingPrivIndex: 0,
      ephemeralSeedByte: 0x70,
      cekByte: 0xa6,
      nonceByte: 0xb6,
    }),
  );
  // Scenario (c): match at priv 4 + slot 0.
  mirror(
    'unwrap-multipriv-ac9-priv4-slot0.json',
    buildAc9MatrixFixture({
      name: 'multipriv-ac9-priv4-slot0-n32-k5',
      matchPrivIndex: 4,
      matchSlotIdx: 0,
      expectedOuterLoopCount: 5,
      expectedMatchingPrivIndex: 4,
      ephemeralSeedByte: 0x40,
      cekByte: 0xa7,
      nonceByte: 0xb7,
    }),
  );
  // Scenario (d): match at priv 4 + slot 31.
  mirror(
    'unwrap-multipriv-ac9-priv4-slot31.json',
    buildAc9MatrixFixture({
      name: 'multipriv-ac9-priv4-slot31-n32-k5',
      matchPrivIndex: 4,
      matchSlotIdx: 31,
      expectedOuterLoopCount: 5,
      expectedMatchingPrivIndex: 4,
      ephemeralSeedByte: 0x30,
      cekByte: 0xa8,
      nonceByte: 0xb8,
    }),
  );
  // Scenario (e): no match. All 5 privs entered + all 32 slots per priv.
  const outsiderPub = x25519PublicKey({ secretKey: fillPriv(0xfe) });
  mirror(
    'unwrap-multipriv-ac9-no-match.json',
    buildAc9MatrixFixture({
      name: 'multipriv-ac9-no-match-n32-k5',
      matchPrivIndex: null,
      expectedOuterLoopCount: 5,
      expectedMatchingPrivIndex: null,
      ephemeralSeedByte: 0x20,
      cekByte: 0xa9,
      nonceByte: 0xb9,
      outsiderPub,
    }),
  );
}

describe('crypto-core sealed-poe multi-priv fixture builder (BUILD_FIXTURES=1 to enable)', () => {
  it.runIf(SHOULD_BUILD)('regenerates multi-priv KAT + negative fixtures', () => {
    buildCurrentMatchFixture();
    buildArchivedMatchFixture();
    buildNoMatchFixture();
    buildWorstCaseFixture();
    buildNegativeAdditions();
    buildAc9MatrixFixtures();
  });

  it.skipIf(SHOULD_BUILD)('is gated; set BUILD_FIXTURES=1 to regenerate', () => {});
});
