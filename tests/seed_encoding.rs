//! Byte-parity tests for the identity-seed codec.
//!
//! Replays the shared conformance fixture `seed-derive/seed-encoding-kat.json`
//! — the same JSON the TypeScript and Python SDKs consume. Passing it proves
//! this crate emits the exact pinned UPPERCASE display string for every seed,
//! accepts both single-case bech32 forms and every tolerated hex shape, and
//! rejects every malformed input with the same cross-implementation error
//! code.

mod common;

use cardanowall::hex;
use cardanowall::seed_encoding::{encode_identity_seed, parse_identity_seed};
use common::{crypto_core_fixtures, read_fixture_json};
use serde_json::Value;

fn array<'a>(fixture: &'a Value, key: &str) -> &'a Vec<Value> {
    fixture[key]
        .as_array()
        .unwrap_or_else(|| panic!("fixture must carry a `{key}` array"))
}

fn field<'a>(vector: &'a Value, key: &str) -> &'a str {
    vector[key]
        .as_str()
        .unwrap_or_else(|| panic!("vector field `{key}` must be a string: {vector}"))
}

fn fixture() -> Value {
    read_fixture_json(&crypto_core_fixtures().join("seed-derive/seed-encoding-kat.json"))
}

#[test]
fn encodes_every_pinned_seed_to_the_exact_uppercase_string() {
    let fixture = fixture();
    let vectors = array(&fixture, "vectors");
    assert!(!vectors.is_empty(), "encode vectors must not be empty");

    for vector in vectors {
        let name = field(vector, "name");
        let seed = hex::decode(field(vector, "seed_hex"))
            .unwrap_or_else(|e| panic!("vector {name}: bad seed_hex: {e}"));
        let encoded = encode_identity_seed(&seed)
            .unwrap_or_else(|e| panic!("vector {name}: encode failed: {e}"));
        assert_eq!(encoded, field(vector, "encoded"), "vector {name}: encoded");
    }
}

#[test]
fn parses_both_single_case_forms_and_raw_hex_back_to_the_seed() {
    let fixture = fixture();
    for vector in array(&fixture, "vectors") {
        let name = field(vector, "name");
        let seed_hex = field(vector, "seed_hex");
        let encoded = field(vector, "encoded");
        let lowercase = field(vector, "encoded_lowercase");

        // The two pinned forms are the same string in the two valid cases.
        assert_eq!(
            lowercase,
            encoded.to_ascii_lowercase(),
            "vector {name}: case pair"
        );
        for input in [encoded, lowercase, seed_hex] {
            let parsed = parse_identity_seed(input)
                .unwrap_or_else(|e| panic!("vector {name}: parse of {input:?} failed: {e}"));
            assert_eq!(hex::encode(&parsed), seed_hex, "vector {name}: {input:?}");
        }
    }
}

#[test]
fn accepts_every_tolerated_hex_input() {
    let fixture = fixture();
    let vectors = array(&fixture, "parse_vectors");
    assert!(!vectors.is_empty(), "parse vectors must not be empty");

    for vector in vectors {
        let name = field(vector, "name");
        let parsed = parse_identity_seed(field(vector, "input"))
            .unwrap_or_else(|e| panic!("vector {name}: parse failed: {e}"));
        assert_eq!(
            hex::encode(&parsed),
            field(vector, "expected_seed_hex"),
            "vector {name}"
        );
    }
}

#[test]
fn rejects_every_negative_input_with_the_pinned_error_code() {
    let fixture = fixture();
    let vectors = array(&fixture, "negative_vectors");
    assert!(!vectors.is_empty(), "negative vectors must not be empty");

    for vector in vectors {
        let name = field(vector, "name");
        let error = parse_identity_seed(field(vector, "input"))
            .expect_err(&format!("vector {name}: input must be rejected"));
        assert_eq!(
            error.code(),
            field(vector, "expected_error_code"),
            "vector {name}: error code ({error})"
        );
    }
}
