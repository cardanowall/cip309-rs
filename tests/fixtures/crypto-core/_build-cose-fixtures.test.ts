// Regenerator for Label 309-shaped fixtures consumed by canonical-cbor + COSE
// KAT tests. Runs only when BUILD_FIXTURES=1 is set in the environment:
//
//   BUILD_FIXTURES=1 pnpm --filter @cardanowall/crypto-core exec vitest run _build-cose-fixtures
//
// Computes byte-pinned payloads and Ed25519 signatures from the canonical
// minimal reference record, so the COSE_Sign1 KAT vectors remain in sync
// with the spec. The reference record body shape is
// `{ v, items: [{ uris, hashes }] }` (NOT the older `{ t, v, files }` shape);
// the byte-pinned expected sig-structure / signature / COSE_Sign1 in the JSON
// fixtures are reproduced verbatim from that reference record.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, it } from 'vitest';

import { encodeCanonicalCbor, type CanonicalCborValue } from '../../src/cbor/canonical';
import {
  CARDANO_POE_SIG_DOMAIN_PREFIX,
  buildLabel309SigStructure,
  coseSign1Label309Build,
} from '../../src/cose/sign1';
import { signEd25519 } from '../../src/sig/ed25519';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const HERE = path.dirname(fileURLToPath(import.meta.url));

// Reference-record pinned inputs.
const SHA2_DIGEST = hexToBytes('97a7881ce48f5bf457261797e06e3387a904f0ee70488d3c03090635800320ee');
const BLAKE2B_DIGEST = hexToBytes(
  '2d3b9520f17f6be4e26361b18afc8d7bbdbc2cd4209319a77f014f2fd0d409a4',
);

// Reference record body (sigs removed). Map key order is irrelevant for canonical
// CBOR encoding — `encodeCanonicalCbor` sorts by canonical bytewise key order.
const A2_RECORD_BODY: CanonicalCborValue = {
  v: 1,
  items: [
    {
      uris: [['ar://2cYNEzFs3PfGvKCEkx1pYBlAFc-FB6ZJpGvRwQEnGm0']],
      hashes: {
        'sha2-256': SHA2_DIGEST,
        'blake2b-256': BLAKE2B_DIGEST,
      },
    },
  ],
};

// RFC 8032 §7.1 Test 2 — signing key for the §A.2 in-signature-kid path.
const SIGNER_SECRET_KEY = hexToBytes(
  '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
);
const SIGNER_PUBLIC_KEY = hexToBytes(
  '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
);

function writeJson(filePath: string, value: unknown): void {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function buildCanonicalRoundtripFixture(): void {
  const target = path.resolve(HERE, 'cbor/canonical-encode-roundtrip.json');
  const corpus = JSON.parse(fs.readFileSync(target, 'utf8')) as {
    version: number;
    primitive: string;
    source: string;
    vectors: Array<Record<string, unknown>>;
  };
  const idx = corpus.vectors.findIndex((v) => v['name'] === 'cardano-poe-record-shaped');
  // Minimal v2 record `{v}` — small enough to hand-verify if needed.
  const recordMinimal: CanonicalCborValue = { v: 1 };
  const encoded = encodeCanonicalCbor(recordMinimal);
  const newVector = {
    name: 'cardano-poe-record-shaped',
    input_json: JSON.stringify(recordMinimal),
    expected_cbor_hex: bytesToHex(encoded),
  };
  if (idx >= 0) {
    corpus.vectors[idx] = newVector;
  } else {
    corpus.vectors.push(newVector);
  }
  writeJson(target, corpus);
}

function buildSigStructureFixture(): void {
  const target = path.resolve(HERE, 'cose/sig-structure.json');
  const corpus = JSON.parse(fs.readFileSync(target, 'utf8')) as {
    version: number;
    primitive: string;
    source: string;
    vectors: Array<Record<string, unknown>>;
  };
  const idx = corpus.vectors.findIndex((v) => v['name'] === 'cardano-poe-record-sig-v1-a2');
  const bodyCbor = encodeCanonicalCbor(A2_RECORD_BODY);
  const protectedBytes = encodeCanonicalCbor(
    new Map<number, number | Uint8Array>([
      [1, -8],
      [4, SIGNER_PUBLIC_KEY],
    ]) as unknown as CanonicalCborValue,
  );
  const sigStructure = buildLabel309SigStructure({
    bodyProtectedBytes: protectedBytes,
    recordBodyCbor: bodyCbor,
  });
  const prefixBytes = new TextEncoder().encode(CARDANO_POE_SIG_DOMAIN_PREFIX);
  const toSign = new Uint8Array(prefixBytes.length + bodyCbor.length);
  toSign.set(prefixBytes, 0);
  toSign.set(bodyCbor, prefixBytes.length);
  const newVector = {
    name: 'cardano-poe-record-sig-v1-a2',
    context: 'Signature1' as const,
    body_protected_bytes_hex: bytesToHex(protectedBytes),
    external_aad_hex: '',
    payload_hex: bytesToHex(toSign),
    expected_sig_structure_hex: bytesToHex(sigStructure),
  };
  if (idx >= 0) {
    corpus.vectors[idx] = newVector;
  } else {
    corpus.vectors.push(newVector);
  }
  writeJson(target, corpus);
}

function buildSign1BuildFixture(): void {
  const target = path.resolve(HERE, 'cose/sign1-build.json');
  const corpus = JSON.parse(fs.readFileSync(target, 'utf8')) as {
    version: number;
    primitive: string;
    source: string;
    vectors: Array<Record<string, unknown>>;
    cardano_poe_vectors: Array<Record<string, unknown>>;
  };
  const bodyCbor = encodeCanonicalCbor(A2_RECORD_BODY);
  const protectedBytes = encodeCanonicalCbor(
    new Map<number, number | Uint8Array>([
      [1, -8],
      [4, SIGNER_PUBLIC_KEY],
    ]) as unknown as CanonicalCborValue,
  );
  const sigStructure = buildLabel309SigStructure({
    bodyProtectedBytes: protectedBytes,
    recordBodyCbor: bodyCbor,
  });
  const signature = signEd25519({ seed: SIGNER_SECRET_KEY, message: sigStructure });
  const cose = coseSign1Label309Build({
    protectedHeader: new Map<number | string, unknown>([
      [1, -8],
      [4, SIGNER_PUBLIC_KEY],
    ]),
    unprotectedHeader: new Map<number | string, unknown>(),
    recordBodyCbor: bodyCbor,
    signerSecretKey: SIGNER_SECRET_KEY,
  });
  const newVector = {
    name: 'cardano-poe-record-sig-v1-a2-in-signature-kid',
    source: 'Label 309 reference COSE_Sign1 vector',
    signer_secret_key_hex: bytesToHex(SIGNER_SECRET_KEY),
    signer_public_key_hex: bytesToHex(SIGNER_PUBLIC_KEY),
    protected_header_int_int_pairs: [[1, -8]] as Array<[number, number]>,
    protected_header_int_bytes_pairs: [[4, bytesToHex(SIGNER_PUBLIC_KEY)]] as Array<
      [number, string]
    >,
    unprotected_header_int_bytes_pairs: [] as Array<[number, string]>,
    record_body_cbor_hex: bytesToHex(bodyCbor),
    expected_sig_structure_hex: bytesToHex(sigStructure),
    expected_signature_hex: bytesToHex(signature),
    expected_cose_sign1_hex: bytesToHex(cose),
  };
  const idx = corpus.cardano_poe_vectors.findIndex(
    (v) => v['name'] === 'cardano-poe-record-sig-v1-a2-in-signature-kid',
  );
  if (idx >= 0) {
    corpus.cardano_poe_vectors[idx] = newVector;
  } else {
    corpus.cardano_poe_vectors.push(newVector);
  }
  writeJson(target, corpus);
}

function buildSign1VerifyFixture(): void {
  const target = path.resolve(HERE, 'cose/sign1-verify.json');
  const corpus = JSON.parse(fs.readFileSync(target, 'utf8')) as {
    version: number;
    primitive: string;
    source: string;
    vectors: Array<Record<string, unknown>>;
    cardano_poe_vectors: Array<Record<string, unknown>>;
  };
  const bodyCbor = encodeCanonicalCbor(A2_RECORD_BODY);
  const cose = coseSign1Label309Build({
    protectedHeader: new Map<number | string, unknown>([
      [1, -8],
      [4, SIGNER_PUBLIC_KEY],
    ]),
    unprotectedHeader: new Map<number | string, unknown>(),
    recordBodyCbor: bodyCbor,
    signerSecretKey: SIGNER_SECRET_KEY,
  });
  const bodyHex = bytesToHex(bodyCbor);
  const messageHex = bytesToHex(cose);
  for (const v of corpus.cardano_poe_vectors) {
    if (v['name'] === 'happy-cardano-poe-a2-record-detached') {
      v['message_hex'] = messageHex;
      v['detached_record_body_cbor_hex'] = bodyHex;
    }
  }
  writeJson(target, corpus);
}

const SHOULD_BUILD = process.env['BUILD_FIXTURES'] === '1';

describe('crypto-core Label 309 fixture builder (BUILD_FIXTURES=1 to enable)', () => {
  it.runIf(SHOULD_BUILD)('regenerates canonical + COSE fixtures', () => {
    buildCanonicalRoundtripFixture();
    buildSigStructureFixture();
    buildSign1BuildFixture();
    buildSign1VerifyFixture();
  });

  it.skipIf(SHOULD_BUILD)('is gated; set BUILD_FIXTURES=1 to regenerate', () => {});
});
