// Regenerator for hybrid (mlkem768x25519 / X-Wing) sealed-PoE KAT fixtures.
// Runs only when BUILD_FIXTURES=1 is set:
//
//   BUILD_FIXTURES=1 pnpm exec vitest run packages/crypto-core/tests/fixtures/sealed-poe/_build-hybrid-fixtures.test.ts
//
// Pinned inputs: deterministic recipient keypair seeds, per-slot 64-byte X-Wing
// encapsulation randomness (eseed), CEK, content nonce, and the item's hashes
// map (the honest sha2-256 of the plaintext). Wraps via eciesSealedPoeWrap with
// kem='mlkem768x25519' + skipShuffle=true so slot positions are deterministic
// across regenerations. The Python parity twin mirrors these JSON files
// byte-for-byte.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@noble/hashes/sha2.js';
import { describe, it } from 'vitest';

import { mlkem768x25519Keygen } from '../../../src/kem/mlkem768x25519';
import type { ItemHashes } from '../../../src/sealed-poe/transcript';
import { eciesSealedPoeWrap, type Mlkem768X25519Slot } from '../../../src/sealed-poe/wrap';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PY_MIRROR = path.resolve(HERE, '../../../../sdk-py/tests/fixtures/sealed-poe');

const RUN = process.env.BUILD_FIXTURES === '1';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
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

function mirror(filename: string, value: unknown): void {
  const tsPath = path.resolve(HERE, filename);
  const pyPath = path.resolve(PY_MIRROR, filename);
  writeJson(tsPath, value);
  fs.copyFileSync(tsPath, pyPath);
}

// The honest hash claim: the real sha2-256 of the plaintext.
function honestHashes(plaintext: Uint8Array): ItemHashes {
  return { 'sha2-256': sha256(plaintext) };
}

function hashesToHex(hashes: ItemHashes): Record<string, string> {
  return Object.fromEntries(Object.entries(hashes).map(([alg, d]) => [alg, bytesToHex(d)]));
}

interface HybridSlotHex {
  // Single 1120-byte X-Wing ciphertext, hex.
  kem_ct_hex: string;
  wrap_hex: string;
}

interface HybridFixture {
  version: 1;
  primitive: string;
  source: string;
  vector: {
    name: string;
    // 32-byte X-Wing keygen seeds, one per recipient (the secret material).
    recipient_seeds_hex: string[];
    // 1216-byte X-Wing public keys derived from the seeds.
    recipient_publics_hex: string[];
    // 64-byte per-slot encapsulation randomness.
    eseeds_hex: string[];
    cek_hex: string;
    nonce_hex: string;
    plaintext_hex: string;
    hashes: Record<string, string>;
    expected_slots: HybridSlotHex[];
    expected_slots_mac_hex: string;
    expected_ciphertext_hex: string;
    expected_plaintext_hex: string;
  };
}

function buildHybridFixture(args: {
  name: string;
  recipientSeeds: Uint8Array[];
  eseeds: Uint8Array[];
  cek: Uint8Array;
  nonce: Uint8Array;
  plaintext: Uint8Array;
}): HybridFixture {
  const keys = args.recipientSeeds.map((s) => mlkem768x25519Keygen(s));
  const recipientPublicKeys = keys.map((k) => k.publicKey);
  const hashes = honestHashes(args.plaintext);

  const out = eciesSealedPoeWrap({
    plaintext: args.plaintext,
    hashes,
    recipientPublicKeys,
    kem: 'mlkem768x25519',
    cek: args.cek,
    nonce: args.nonce,
    eseeds: args.eseeds,
    skipShuffle: true,
  });
  if (out.envelope.kem !== 'mlkem768x25519') {
    throw new Error('expected mlkem768x25519 envelope');
  }
  const slots = out.envelope.slots as ReadonlyArray<Mlkem768X25519Slot>;

  return {
    version: 1,
    primitive: 'sealed-poe-wrap-hybrid',
    source: 'X-Wing (ML-KEM-768 + X25519) hybrid KEM sealed-PoE',
    vector: {
      name: args.name,
      recipient_seeds_hex: args.recipientSeeds.map(bytesToHex),
      recipient_publics_hex: recipientPublicKeys.map(bytesToHex),
      eseeds_hex: args.eseeds.map(bytesToHex),
      cek_hex: bytesToHex(args.cek),
      nonce_hex: bytesToHex(args.nonce),
      plaintext_hex: bytesToHex(args.plaintext),
      hashes: hashesToHex(hashes),
      expected_slots: slots.map((s) => ({
        kem_ct_hex: bytesToHex(s.kem_ct),
        wrap_hex: bytesToHex(s.wrap),
      })),
      expected_slots_mac_hex: bytesToHex(out.envelope.slots_mac),
      expected_ciphertext_hex: bytesToHex(out.ciphertext),
      expected_plaintext_hex: bytesToHex(args.plaintext),
    },
  };
}

describe('build hybrid sealed-PoE KAT fixtures (BUILD_FIXTURES=1 only)', () => {
  it.runIf(RUN)('writes wrap-hybrid-n1.json + wrap-hybrid-n3.json', () => {
    const n1 = buildHybridFixture({
      name: 'hybrid-n1-empty',
      recipientSeeds: [fillBytes(0x11, 32)],
      eseeds: [fillBytes(0xe1, 64)],
      cek: fillBytes(0xab, 32),
      nonce: sequentialBytes(24),
      plaintext: new Uint8Array(0),
    });
    mirror('wrap-hybrid-n1.json', n1);

    const n3 = buildHybridFixture({
      name: 'hybrid-n3',
      recipientSeeds: [fillBytes(0x21, 32), fillBytes(0x22, 32), fillBytes(0x23, 32)],
      eseeds: [fillBytes(0xe1, 64), fillBytes(0xe2, 64), fillBytes(0xe3, 64)],
      cek: fillBytes(0xcd, 32),
      nonce: sequentialBytes(24),
      plaintext: sequentialBytes(32),
    });
    mirror('wrap-hybrid-n3.json', n3);
  });
});
