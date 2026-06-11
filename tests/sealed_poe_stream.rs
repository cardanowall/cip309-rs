//! Behavioural tests for the `chacha20-poly1305-stream64k` content format:
//! chunk-boundary layouts, the empty-plaintext form, and the full rejection
//! matrix (truncation, trailing data, non-final short chunk, flipped bytes),
//! exercised through both the whole-buffer helpers and the incremental chunk
//! machines — plus the pinned cross-SDK chunk-layout conformance vectors
//! (stream-layout.json).

mod common;

use cardanowall::sealed_poe::{
    chacha20_poly1305_encrypt, stream_open, stream_seal, StreamError, StreamOpener, StreamSealer,
    CHUNK_SIZE, TAG_SIZE,
};

const KEY: [u8; 32] = [0x07; 32];
const SEALED_CHUNK: usize = CHUNK_SIZE + TAG_SIZE;

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// The 12-byte chunk nonce: 11-byte big-endian counter, then the final flag.
fn nonce(counter: u64, last: bool) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[3..11].copy_from_slice(&counter.to_be_bytes());
    out[11] = u8::from(last);
    out
}

// ---------------------------------------------------------------------------
// Layout positives: empty / one byte / exact boundaries / multi-chunk
// ---------------------------------------------------------------------------

#[test]
fn pinned_constants() {
    assert_eq!(CHUNK_SIZE, 65536);
    assert_eq!(TAG_SIZE, 16);
}

#[test]
fn empty_plaintext_roundtrips_as_a_lone_tag() {
    let sealed = stream_seal(&KEY, b"");
    assert_eq!(sealed.len(), TAG_SIZE);
    assert_eq!(stream_open(&KEY, &sealed).unwrap(), Vec::<u8>::new());
}

#[test]
fn boundary_lengths_roundtrip_with_the_expected_chunk_count() {
    // (plaintext length, expected sealed length) across the chunk boundaries:
    // 1 byte; one byte below / exactly at / one byte above one full chunk;
    // exactly two chunks; a multi-chunk interior length.
    let cases: &[(usize, usize)] = &[
        (1, 1 + TAG_SIZE),
        (CHUNK_SIZE - 1, CHUNK_SIZE - 1 + TAG_SIZE),
        // Exactly one chunk: a single FINAL chunk, not a full chunk plus an
        // empty final.
        (CHUNK_SIZE, SEALED_CHUNK),
        (CHUNK_SIZE + 1, SEALED_CHUNK + 1 + TAG_SIZE),
        (2 * CHUNK_SIZE, 2 * SEALED_CHUNK),
        (2 * CHUNK_SIZE + 4242, 2 * SEALED_CHUNK + 4242 + TAG_SIZE),
    ];
    for &(len, expected_sealed) in cases {
        let plaintext = patterned(len);
        let sealed = stream_seal(&KEY, &plaintext);
        assert_eq!(sealed.len(), expected_sealed, "plaintext length {len}");
        assert_eq!(
            stream_open(&KEY, &sealed).unwrap(),
            plaintext,
            "plaintext length {len}"
        );
    }
}

#[test]
fn chunks_are_chacha20_poly1305_under_counter_flag_nonces_with_empty_aad() {
    // Pin the whole-buffer helper to the raw primitive across a 3-chunk stream:
    // chunk i is ChaCha20-Poly1305(key, uint88_be(i) ‖ flag, aad="", chunk_i).
    let plaintext = patterned(2 * CHUNK_SIZE + 5);
    let sealed = stream_seal(&KEY, &plaintext);
    let expected: Vec<u8> = [
        chacha20_poly1305_encrypt(&KEY, &nonce(0, false), b"", &plaintext[..CHUNK_SIZE]),
        chacha20_poly1305_encrypt(
            &KEY,
            &nonce(1, false),
            b"",
            &plaintext[CHUNK_SIZE..2 * CHUNK_SIZE],
        ),
        chacha20_poly1305_encrypt(&KEY, &nonce(2, true), b"", &plaintext[2 * CHUNK_SIZE..]),
    ]
    .concat();
    assert_eq!(sealed, expected);
}

// ---------------------------------------------------------------------------
// Rejection matrix
// ---------------------------------------------------------------------------

#[test]
fn open_rejects_a_blob_below_the_tag_floor() {
    assert_eq!(stream_open(&KEY, b""), Err(StreamError));
    assert_eq!(stream_open(&KEY, &[0u8; TAG_SIZE - 1]), Err(StreamError));
}

#[test]
fn open_rejects_truncation() {
    let plaintext = patterned(CHUNK_SIZE + 100);
    let sealed = stream_seal(&KEY, &plaintext);
    // Drop the whole final chunk: the remaining full chunk was sealed with
    // final_flag = 0, so reading it as final fails its tag.
    assert_eq!(stream_open(&KEY, &sealed[..SEALED_CHUNK]), Err(StreamError));
    // Drop part of the final chunk.
    assert_eq!(
        stream_open(&KEY, &sealed[..sealed.len() - 1]),
        Err(StreamError)
    );
    // Drop down into the first chunk.
    assert_eq!(
        stream_open(&KEY, &sealed[..SEALED_CHUNK - 1]),
        Err(StreamError)
    );
}

#[test]
fn open_rejects_trailing_data_after_the_final_chunk() {
    let sealed = stream_seal(&KEY, b"body");
    // Appended garbage re-parses as a longer final chunk (or an extra chunk);
    // either way no tag verifies at the new layout.
    let mut trailing = sealed.clone();
    trailing.extend_from_slice(&[0u8; 16]);
    assert_eq!(stream_open(&KEY, &trailing), Err(StreamError));

    // A zero-length final chunk appended after real chunks is a layout
    // violation (an empty final chunk is only valid for an empty plaintext):
    // sealed-one-full-chunk || lone-tag parses as full + 16-byte final → reject.
    let full = stream_seal(&KEY, &patterned(CHUNK_SIZE));
    let empty = stream_seal(&KEY, b"");
    let spliced: Vec<u8> = [full, empty].concat();
    assert_eq!(stream_open(&KEY, &spliced), Err(StreamError));
}

#[test]
fn open_rejects_any_flipped_byte() {
    let plaintext = patterned(CHUNK_SIZE + 33);
    let sealed = stream_seal(&KEY, &plaintext);
    // First chunk body, first chunk tag, final chunk body, final chunk tag.
    for idx in [0, SEALED_CHUNK - 1, SEALED_CHUNK, sealed.len() - 1] {
        let mut tampered = sealed.clone();
        tampered[idx] ^= 0x01;
        assert_eq!(
            stream_open(&KEY, &tampered),
            Err(StreamError),
            "flipped byte {idx}"
        );
    }
}

#[test]
fn open_rejects_a_wrong_key() {
    let sealed = stream_seal(&KEY, b"keyed");
    let other = [0x08u8; 32];
    assert_eq!(stream_open(&other, &sealed), Err(StreamError));
}

// ---------------------------------------------------------------------------
// Incremental machine semantics
// ---------------------------------------------------------------------------

#[test]
fn incremental_seal_and_open_match_the_whole_buffer_helpers() {
    let plaintext = patterned(CHUNK_SIZE + 9000);
    let mut sealer = StreamSealer::new(&KEY);
    let sealed: Vec<u8> = [
        sealer.seal_chunk(&plaintext[..CHUNK_SIZE], false),
        sealer.seal_chunk(&plaintext[CHUNK_SIZE..], true),
    ]
    .concat();
    assert_eq!(sealed, stream_seal(&KEY, &plaintext));

    let mut opener = StreamOpener::new(&KEY);
    let mut recovered = opener
        .open_chunk(&sealed[..SEALED_CHUNK], false)
        .expect("first chunk");
    recovered.extend_from_slice(
        &opener
            .open_chunk(&sealed[SEALED_CHUNK..], true)
            .expect("final chunk"),
    );
    assert!(opener.finished());
    assert_eq!(recovered, plaintext);
}

#[test]
fn opener_rejects_a_short_non_final_chunk() {
    // A non-final chunk must be exactly CHUNK_SIZE + TAG_SIZE sealed bytes.
    let sealed = stream_seal(&KEY, &patterned(CHUNK_SIZE + 5));
    let mut opener = StreamOpener::new(&KEY);
    assert_eq!(
        opener.open_chunk(&sealed[..SEALED_CHUNK - 1], false),
        Err(StreamError)
    );
}

#[test]
fn opener_rejects_a_final_flag_mismatch() {
    // A chunk sealed as non-final does not open as final, and vice versa: the
    // flag byte is part of the nonce.
    let plaintext = patterned(CHUNK_SIZE + 5);
    let sealed = stream_seal(&KEY, &plaintext);
    let mut opener = StreamOpener::new(&KEY);
    assert_eq!(
        opener.open_chunk(&sealed[..SEALED_CHUNK], true),
        Err(StreamError),
        "non-final chunk read as final"
    );

    let short = stream_seal(&KEY, b"only");
    let mut opener = StreamOpener::new(&KEY);
    assert_eq!(
        opener.open_chunk(&short, false),
        Err(StreamError),
        "final chunk read as non-final (and short)"
    );
}

#[test]
fn opener_rejects_an_empty_final_chunk_in_a_non_empty_stream() {
    let plaintext = patterned(CHUNK_SIZE);
    // Seal chunk 0 as non-final so the machine is mid-stream, then try to
    // close with a zero-length final chunk.
    let mut sealer_key = StreamSealer::new(&KEY);
    let chunk0 = sealer_key.seal_chunk(&plaintext, false);
    let lone_tag = stream_seal(&KEY, b""); // a syntactically valid empty final chunk
    let mut opener = StreamOpener::new(&KEY);
    opener
        .open_chunk(&chunk0, false)
        .expect("non-final chunk opens");
    assert_eq!(opener.open_chunk(&lone_tag, true), Err(StreamError));
}

#[test]
fn opener_releases_each_chunk_only_after_its_tag_verifies() {
    // Chunk 0 is intact, chunk 1 (final) is tampered: the incremental opener
    // releases chunk 0's plaintext, then fails on chunk 1 — the tentative
    // release model.
    let plaintext = patterned(CHUNK_SIZE + 77);
    let mut sealed = stream_seal(&KEY, &plaintext);
    let last = sealed.len() - 1;
    sealed[last] ^= 0xff;

    let mut opener = StreamOpener::new(&KEY);
    let chunk0 = opener
        .open_chunk(&sealed[..SEALED_CHUNK], false)
        .expect("intact chunk 0 opens");
    assert_eq!(chunk0, &plaintext[..CHUNK_SIZE]);
    assert_eq!(
        opener.open_chunk(&sealed[SEALED_CHUNK..], true),
        Err(StreamError)
    );

    // The whole-buffer helper rejects the same blob outright.
    assert_eq!(stream_open(&KEY, &sealed), Err(StreamError));
}

// --------------------------------------------------------------------------
// Pinned cross-SDK chunk-layout conformance vectors (stream-layout.json)
// --------------------------------------------------------------------------

fn stream_layout_corpus() -> serde_json::Value {
    common::read_fixture_json(
        &common::crypto_core_fixtures()
            .join("sealed-poe")
            .join("stream-layout.json"),
    )
}

fn hex_field(v: &serde_json::Value, key: &str) -> Vec<u8> {
    cardanowall::hex::decode(v[key].as_str().unwrap_or_else(|| panic!("field `{key}`")))
        .unwrap_or_else(|e| panic!("bad hex in `{key}`: {e}"))
}

/// Apply the fixture's ordered transform list to a sealed blob.
fn apply_stream_transforms(base: &[u8], transforms: &serde_json::Value) -> Vec<u8> {
    let mut out = base.to_vec();
    for transform in transforms.as_array().expect("transforms array") {
        out = match transform["kind"].as_str().expect("transform.kind") {
            "flip_byte" => {
                let offset = transform["offset"].as_u64().expect("offset") as usize;
                let mut mutated = out;
                mutated[offset] ^= 0x01;
                mutated
            }
            "truncate_to" => {
                let length = transform["length"].as_u64().expect("length") as usize;
                out[..length].to_vec()
            }
            "append_hex" => {
                let mut appended = out;
                appended.extend_from_slice(&hex_field(transform, "bytes_hex"));
                appended
            }
            "remove" => {
                let offset = transform["offset"].as_u64().expect("offset") as usize;
                let length = transform["length"].as_u64().expect("length") as usize;
                let mut removed = out[..offset].to_vec();
                removed.extend_from_slice(&out[offset + length..]);
                removed
            }
            other => panic!("unknown stream transform kind {other:?}"),
        };
    }
    out
}

#[test]
fn stream_layout_positive_vectors_seal_and_open_byte_identically() {
    let corpus = stream_layout_corpus();
    let payload_key = hex_field(&corpus, "payload_key_hex");
    for v in corpus["positive_vectors"].as_array().expect("positives") {
        let name = v["name"].as_str().expect("name");
        let plaintext = hex_field(v, "plaintext_hex");
        let sealed = stream_seal(&payload_key, &plaintext);
        assert_eq!(
            cardanowall::hex::encode(&sealed),
            v["expected_ciphertext_hex"].as_str().expect("ciphertext"),
            "{name}: sealed bytes"
        );
        assert_eq!(
            stream_open(&payload_key, &sealed).expect("open"),
            plaintext,
            "{name}: roundtrip"
        );
    }
}

#[test]
fn stream_layout_negative_vectors_fail_as_tampered() {
    let corpus = stream_layout_corpus();
    let payload_key = hex_field(&corpus, "payload_key_hex");
    let sealed_by_name: std::collections::BTreeMap<&str, Vec<u8>> = corpus["positive_vectors"]
        .as_array()
        .expect("positives")
        .iter()
        .map(|v| {
            (
                v["name"].as_str().expect("name"),
                stream_seal(&payload_key, &hex_field(v, "plaintext_hex")),
            )
        })
        .collect();
    for v in corpus["negative_vectors"].as_array().expect("negatives") {
        let name = v["name"].as_str().expect("name");
        assert_eq!(
            v["expected_error_code"].as_str(),
            Some("TAMPERED_CIPHERTEXT"),
            "{name}"
        );
        let base = &sealed_by_name[v["base"].as_str().expect("base")];
        let mutated = apply_stream_transforms(base, &v["transforms"]);
        assert!(
            stream_open(&payload_key, &mutated).is_err(),
            "{name}: the transformed blob must fail decryption"
        );
    }
}
