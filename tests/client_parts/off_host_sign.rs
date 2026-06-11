// Off-host signing helper KAT + round-trip + hashed-mode + negative tests,
// byte-pinned against the shared `cose/sign1-build.json` corpus.
//
// Two layers are exercised:
//
// - The COSE construction itself (`build_label309_sig_structure`,
//   `encode_cose_sign1`) replays EVERY corpus vector from the raw
//   `record_body_cbor_hex` bytes — the fixture pins the Sig_structure, the
//   signature, and the COSE_Sign1 byte-for-byte, and the body enters that
//   construction as an opaque byte string.
// - The record-taking off-host helpers (`prepare_sig_structure`,
//   `assemble_cose_sign1`, hashed mode) run over the vectors whose bodies are
//   representable in the v1 record model (single-text-string `uris`); a body
//   predating that shape still byte-replays through the COSE layer above.

use cardanowall::cbor::{decode_canonical_cbor, CborValue};
use cardanowall::client::{
    assemble_cose_sign1, assemble_cose_sign1_hashed, build_to_sign, prepare_sig_structure,
    prepare_sig_structure_hashed, OffHostSignError,
};
use cardanowall::cose::{build_label309_sig_structure, encode_cose_sign1, CoseHeader};
use cardanowall::poe_standard::{
    encode_record_body_for_signing, EncScheme1, EncryptionEnvelope, ItemEntry, MerkleCommit,
    PoeRecord, Slot,
};
use cardanowall::verifier::{verify_record_signatures, CardanoNetwork};

const DOMAIN_PREFIX_HEX: &str = "63617264616e6f2d706f652d7265636f72642d7369672d7631";

/// Load the cardano-PoE build vectors from the canonical fixture tree.
fn cardano_poe_vectors() -> Vec<serde_json::Value> {
    let path = common::crypto_core_fixtures()
        .join("cose")
        .join("sign1-build.json");
    let corpus = common::read_fixture_json(&path);
    corpus["cardano_poe_vectors"]
        .as_array()
        .expect("cardano_poe_vectors is an array")
        .clone()
}

fn map_get<'a>(pairs: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    pairs
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(t) if t == key))
        .map(|(_, v)| v)
}

fn as_u64(value: &CborValue) -> u64 {
    match value {
        CborValue::Unsigned(n) => *n,
        other => panic!("expected unsigned, got {other:?}"),
    }
}

fn as_bytes(value: &CborValue) -> Vec<u8> {
    match value {
        CborValue::Bytes(b) => b.clone(),
        other => panic!("expected bytes, got {other:?}"),
    }
}

fn as_text(value: &CborValue) -> String {
    match value {
        CborValue::Text(t) => t.clone(),
        other => panic!("expected text, got {other:?}"),
    }
}

/// Decode a `uris` array of single text strings; `None` when an entry is any
/// other shape (a body predating the single-tstr URI form).
fn uris_from_cbor(value: &CborValue) -> Option<Vec<String>> {
    match value {
        CborValue::Array(items) => items
            .iter()
            .map(|u| match u {
                CborValue::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

fn slot_from_cbor(value: &CborValue) -> Slot {
    let pairs = match value {
        CborValue::Map(pairs) => pairs,
        other => panic!("expected slot map, got {other:?}"),
    };
    Slot {
        epk: map_get(pairs, "epk").map(as_bytes),
        kem_ct: map_get(pairs, "kem_ct").map(as_bytes),
        wrap: map_get(pairs, "wrap").map(as_bytes),
    }
}

/// Lower a decoded `enc` value to the model's envelope union: the typed
/// scheme-1 arm when its fields carry the typed shapes, the verbatim opaque
/// arm otherwise (either reading re-encodes to the original bytes).
fn envelope_from_cbor(value: &CborValue) -> EncryptionEnvelope {
    let pairs = match value {
        CborValue::Map(pairs) => pairs,
        other => panic!("expected enc map, got {other:?}"),
    };
    let typed_slots = map_get(pairs, "slots").map(|s| match s {
        CborValue::Array(items) => items
            .iter()
            .all(|slot| matches!(slot, CborValue::Map(slot_pairs)
                if slot_pairs.iter().all(|(_, v)| matches!(v, CborValue::Bytes(_))))),
        _ => false,
    });
    if typed_slots == Some(false) {
        return EncryptionEnvelope::Opaque(value.clone());
    }
    EncryptionEnvelope::Scheme1(EncScheme1 {
        scheme: as_u64(map_get(pairs, "scheme").unwrap()),
        aead: as_text(map_get(pairs, "aead").unwrap()),
        nonce: as_bytes(map_get(pairs, "nonce").unwrap()),
        kem: map_get(pairs, "kem").map(as_text),
        slots: map_get(pairs, "slots").map(|s| match s {
            CborValue::Array(items) => items.iter().map(slot_from_cbor).collect(),
            other => panic!("expected slots array, got {other:?}"),
        }),
        slots_mac: map_get(pairs, "slots_mac").map(as_bytes),
        passphrase: None,
    })
}

fn item_from_cbor(value: &CborValue) -> Option<ItemEntry> {
    let pairs = match value {
        CborValue::Map(pairs) => pairs,
        other => panic!("expected item map, got {other:?}"),
    };
    let hashes = match map_get(pairs, "hashes").unwrap() {
        CborValue::Map(hash_pairs) => hash_pairs
            .iter()
            .map(|(k, v)| (as_text(k), as_bytes(v)))
            .collect(),
        other => panic!("expected hashes map, got {other:?}"),
    };
    let uris = match map_get(pairs, "uris") {
        Some(raw) => Some(uris_from_cbor(raw)?),
        None => None,
    };
    Some(ItemEntry {
        hashes,
        uris,
        enc: map_get(pairs, "enc").map(envelope_from_cbor),
    })
}

fn merkle_from_cbor(value: &CborValue) -> Option<MerkleCommit> {
    let pairs = match value {
        CborValue::Map(pairs) => pairs,
        other => panic!("expected merkle map, got {other:?}"),
    };
    let uris = match map_get(pairs, "uris") {
        Some(raw) => Some(uris_from_cbor(raw)?),
        None => None,
    };
    Some(MerkleCommit {
        alg: as_text(map_get(pairs, "alg").unwrap()),
        root: as_bytes(map_get(pairs, "root").unwrap()),
        leaf_count: as_u64(map_get(pairs, "leaf_count").unwrap()),
        uris,
    })
}

/// Reconstruct the `PoeRecord` from a vector's `record_body_cbor_hex`, then
/// assert the reconstruction re-encodes to the exact same body bytes. Returns
/// `None` for a body the v1 record model cannot represent (its byte path is
/// still covered by the raw-body COSE replay).
fn record_from_vector(vector: &serde_json::Value) -> Option<PoeRecord> {
    let body = hex::decode(vector["record_body_cbor_hex"].as_str().unwrap()).unwrap();
    let decoded = decode_canonical_cbor(&body).expect("record body decodes");
    let pairs = match &decoded {
        CborValue::Map(pairs) => pairs,
        other => panic!("record body is not a map: {other:?}"),
    };
    let items = match map_get(pairs, "items") {
        Some(CborValue::Array(items)) => Some(
            items
                .iter()
                .map(item_from_cbor)
                .collect::<Option<Vec<_>>>()?,
        ),
        Some(other) => panic!("expected items array, got {other:?}"),
        None => None,
    };
    let merkle = match map_get(pairs, "merkle") {
        Some(CborValue::Array(entries)) => Some(
            entries
                .iter()
                .map(merkle_from_cbor)
                .collect::<Option<Vec<_>>>()?,
        ),
        Some(other) => panic!("expected merkle array, got {other:?}"),
        None => None,
    };
    let record = PoeRecord {
        v: as_u64(map_get(pairs, "v").unwrap()),
        items,
        merkle,
        supersedes: map_get(pairs, "supersedes").map(as_bytes),
        sigs: None,
        crit: map_get(pairs, "crit").map(|c| match c {
            CborValue::Array(items) => items.iter().map(as_text).collect(),
            other => panic!("expected crit array, got {other:?}"),
        }),
        extensions: Vec::new(),
    };
    // The reconstruction must be faithful: its signing body equals the fixture
    // body byte for byte.
    assert_eq!(
        encode_record_body_for_signing(&record).unwrap(),
        body,
        "reconstructed record re-encodes to the fixture body"
    );
    Some(record)
}

/// The vectors whose bodies the v1 record model represents, paired with their
/// reconstructed records.
fn representable_vectors() -> Vec<(serde_json::Value, PoeRecord)> {
    let out: Vec<(serde_json::Value, PoeRecord)> = cardano_poe_vectors()
        .into_iter()
        .filter_map(|v| record_from_vector(&v).map(|r| (v, r)))
        .collect();
    assert!(
        !out.is_empty(),
        "at least one corpus body must be representable"
    );
    out
}

fn hexs(value: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(value[key].as_str().unwrap()).unwrap()
}

/// The canonical path-1 protected header `{1: -8, 4: pubkey}`.
fn path1_protected(pubkey: &[u8]) -> CoseHeader {
    CoseHeader::new()
        .with_int(1, CborValue::int(-8))
        .with_int(4, CborValue::bytes(pubkey.to_vec()))
}

#[test]
fn off_host_sign_corpus_is_non_empty() {
    // Guards against a silently-empty corpus making every parametrised case a
    // no-op.
    assert_eq!(cardano_poe_vectors().len(), 4);
}

#[test]
fn cose_layer_replays_every_vector_from_raw_body_bytes() {
    use ed25519_dalek::Signer as _;
    for vector in cardano_poe_vectors() {
        let name = vector["name"].as_str().unwrap();
        let body = hexs(&vector, "record_body_cbor_hex");
        let pubkey = hexs(&vector, "signer_public_key_hex");
        let seed: [u8; 32] = hexs(&vector, "signer_secret_key_hex").try_into().unwrap();

        let protected = path1_protected(&pubkey);
        let protected_bytes = protected.encode_protected().unwrap();
        assert_eq!(protected_bytes.len(), 38, "{name}: 38-byte path-1 header");

        let sig_structure = build_label309_sig_structure(&protected_bytes, &body);
        assert_eq!(
            hex::encode(&sig_structure),
            vector["expected_sig_structure_hex"].as_str().unwrap(),
            "{name}: Sig_structure bytes"
        );

        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let signature = signing.sign(&sig_structure).to_bytes();
        assert_eq!(
            hex::encode(signature),
            vector["expected_signature_hex"].as_str().unwrap(),
            "{name}: signature bytes"
        );

        let cose_sign1 =
            encode_cose_sign1(&protected, &CoseHeader::new(), None, &signature).unwrap();
        assert_eq!(
            hex::encode(&cose_sign1),
            vector["expected_cose_sign1_hex"].as_str().unwrap(),
            "{name}: COSE_Sign1 bytes"
        );
    }
}

#[test]
fn build_to_sign_emits_prefix_then_record_body() {
    for (vector, record) in representable_vectors() {
        let to_sign = build_to_sign(&record).unwrap();
        let expected = format!(
            "{DOMAIN_PREFIX_HEX}{}",
            vector["record_body_cbor_hex"].as_str().unwrap()
        );
        assert_eq!(hex::encode(&to_sign), expected);
        assert_eq!(hex::encode(&to_sign[..25]), DOMAIN_PREFIX_HEX);
    }
}

#[test]
fn prepare_sig_structure_is_byte_pinned() {
    for (vector, record) in representable_vectors() {
        let pubkey = hexs(&vector, "signer_public_key_hex");
        let prepared = prepare_sig_structure(&record, &pubkey).unwrap();
        assert_eq!(
            hex::encode(&prepared.sig_structure_bytes),
            vector["expected_sig_structure_hex"].as_str().unwrap()
        );
        // The canonical path-1 protected header is always 38 bytes.
        let expected_protected = format!(
            "a201270458 20{}",
            vector["signer_public_key_hex"].as_str().unwrap()
        )
        .replace(' ', "");
        assert_eq!(
            hex::encode(&prepared.protected_header_bytes),
            expected_protected
        );
        assert_eq!(prepared.protected_header_bytes.len(), 38);
    }
}

#[test]
fn assemble_cose_sign1_is_byte_pinned() {
    use ed25519_dalek::Signer as _;
    for (vector, record) in representable_vectors() {
        let pubkey = hexs(&vector, "signer_public_key_hex");
        let seed: [u8; 32] = hexs(&vector, "signer_secret_key_hex").try_into().unwrap();
        let prepared = prepare_sig_structure(&record, &pubkey).unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let sig = signing.sign(&prepared.sig_structure_bytes).to_bytes();
        let assembled = assemble_cose_sign1(&record, &pubkey, &sig).unwrap();
        assert_eq!(
            hex::encode(&assembled.cose_sign1_bytes),
            vector["expected_cose_sign1_hex"].as_str().unwrap()
        );
        // The sigs[] entry carries the COSE_Sign1 as the same single string.
        assert_eq!(assembled.sig_entry.cose_sign1, assembled.cose_sign1_bytes);
    }
}

#[test]
fn assembled_signature_round_trips_through_the_verifier() {
    use ed25519_dalek::Signer as _;
    for (vector, record) in representable_vectors() {
        let pubkey = hexs(&vector, "signer_public_key_hex");
        let seed: [u8; 32] = hexs(&vector, "signer_secret_key_hex").try_into().unwrap();
        let prepared = prepare_sig_structure(&record, &pubkey).unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let sig = signing.sign(&prepared.sig_structure_bytes).to_bytes();
        let assembled = assemble_cose_sign1(&record, &pubkey, &sig).unwrap();

        let mut completed = record.clone();
        completed.sigs = Some(vec![assembled.sig_entry]);
        let checks = verify_record_signatures(&completed, CardanoNetwork::Mainnet);
        assert_eq!(checks.len(), 1);
        assert!(
            checks[0].valid,
            "signature should verify for {}",
            vector["name"]
        );
        assert_eq!(
            checks[0].signer_pub.as_deref(),
            Some(vector["signer_public_key_hex"].as_str().unwrap())
        );
    }
}

#[test]
fn hashed_mode_substitutes_blake2b224_and_round_trips() {
    use blake2::digest::consts::U28;
    use blake2::digest::Digest;
    use blake2::Blake2b;
    use ed25519_dalek::Signer as _;

    for (vector, record) in representable_vectors() {
        let pubkey = hexs(&vector, "signer_public_key_hex");
        let seed: [u8; 32] = hexs(&vector, "signer_secret_key_hex").try_into().unwrap();

        let to_sign = build_to_sign(&record).unwrap();
        let expected_hash: [u8; 28] = Blake2b::<U28>::digest(&to_sign).into();
        let prepared = prepare_sig_structure_hashed(&record, &pubkey).unwrap();
        assert_eq!(prepared.to_sign_hash_bytes, expected_hash.to_vec());
        assert_eq!(prepared.to_sign_hash_bytes.len(), 28);

        // The non-hashed and hashed protected headers are byte-identical.
        let non_hashed = prepare_sig_structure(&record, &pubkey).unwrap();
        assert_eq!(
            prepared.protected_header_bytes,
            non_hashed.protected_header_bytes
        );

        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let sig_hashed = signing.sign(&prepared.sig_structure_bytes).to_bytes();
        let sig_non_hashed = signing.sign(&non_hashed.sig_structure_bytes).to_bytes();
        // Hashed signature differs from the non-hashed one; the non-hashed one
        // matches the KAT.
        assert_ne!(sig_hashed, sig_non_hashed);
        assert_eq!(
            hex::encode(sig_non_hashed),
            vector["expected_signature_hex"].as_str().unwrap()
        );

        let assembled = assemble_cose_sign1_hashed(&record, &pubkey, &sig_hashed).unwrap();
        let mut completed = record.clone();
        completed.sigs = Some(vec![assembled.sig_entry]);
        let checks = verify_record_signatures(&completed, CardanoNetwork::Mainnet);
        assert!(checks[0].valid, "hashed-mode signature should verify");
        assert_eq!(
            checks[0].signer_pub.as_deref(),
            Some(vector["signer_public_key_hex"].as_str().unwrap())
        );
    }
}

#[test]
fn invalid_pubkey_and_signature_lengths_are_rejected() {
    let (_, record) = representable_vectors().remove(0);
    let pubkey = vec![0x11u8; 32];

    assert_eq!(
        prepare_sig_structure(&record, &[0u8; 31]).unwrap_err(),
        OffHostSignError::InvalidPubkeyLength
    );
    assert_eq!(
        assemble_cose_sign1(&record, &[0u8; 31], &[0u8; 64]).unwrap_err(),
        OffHostSignError::InvalidPubkeyLength
    );
    assert_eq!(
        assemble_cose_sign1(&record, &pubkey, &[0u8; 63]).unwrap_err(),
        OffHostSignError::InvalidSignatureLength
    );
    assert_eq!(
        prepare_sig_structure_hashed(&record, &[0u8; 31]).unwrap_err(),
        OffHostSignError::InvalidPubkeyLength
    );
    assert_eq!(
        assemble_cose_sign1_hashed(&record, &pubkey, &[0u8; 63]).unwrap_err(),
        OffHostSignError::InvalidSignatureLength
    );
    // The discriminator code surface.
    assert_eq!(
        OffHostSignError::InvalidPubkeyLength.code(),
        "INVALID_PUBKEY_LENGTH"
    );
    assert_eq!(
        OffHostSignError::InvalidSignatureLength.code(),
        "INVALID_SIGNATURE_LENGTH"
    );
}
