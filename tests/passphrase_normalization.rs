//! Conformance replay of the `cardano-poe-pw-norm-v1` byte-pin corpus.
//!
//! Every positive case must normalize to the pinned UTF-8 bytes AND derive
//! the pinned 32-byte CEK through Argon2id v19 under the corpus's fixed
//! salt/params — the same Argon2id construction the passphrase sealed-PoE
//! path runs — proving the embedded Unicode 16.0 tables and the Argon2id
//! engine byte-exact end-to-end against the TypeScript and Python SDKs.
//! Error cases must surface the pinned typed rejections.

mod common;

use argon2::{Algorithm, Argon2, Params, Version};
use cardanowall::hex;
use cardanowall::sealed_poe::{normalize_passphrase, MAX_PASSPHRASE_INPUT_BYTES};
use common::{crypto_core_fixtures, read_fixture_json};
use serde_json::Value;

fn load_corpus() -> Value {
    let path = crypto_core_fixtures().join("kdf/passphrase-normalization.json");
    read_fixture_json(&path)
}

fn field<'a>(vector: &'a Value, key: &str) -> &'a str {
    vector[key]
        .as_str()
        .unwrap_or_else(|| panic!("vector field `{key}` must be a string: {vector}"))
}

fn uint(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("field `{key}` must be an unsigned integer"))
}

/// The corpus's fixed Argon2id derivation, version pinned at 0x13 (19) with a
/// 32-byte output — the construction the passphrase path uses for its CEK.
fn derive_cek(corpus: &Value, password: &[u8]) -> Vec<u8> {
    let kdf = &corpus["kdf"];
    let salt = hex::decode(field(kdf, "salt_hex")).expect("corpus salt_hex must decode");
    let params = &kdf["params"];
    let m = u32::try_from(uint(params, "m")).expect("m fits u32");
    let t = u32::try_from(uint(params, "t")).expect("t fits u32");
    let p = u32::try_from(uint(params, "p")).expect("p fits u32");
    let out_bytes = usize::try_from(uint(kdf, "out_bytes")).expect("out_bytes fits usize");
    let params = Params::new(m, t, p, Some(out_bytes)).expect("corpus params are valid");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut cek = vec![0u8; out_bytes];
    argon
        .hash_password_into(password, &salt, &mut cek)
        .expect("corpus-pinned derivation succeeds");
    cek
}

#[test]
fn corpus_header_and_case_set() {
    let corpus = load_corpus();
    assert_eq!(field(&corpus, "primitive"), "cardano-poe-pw-norm-v1");
    assert_eq!(field(&corpus, "unicode_version"), "16.0.0");
    assert_eq!(
        uint(&corpus, "max_passphrase_input_bytes") as usize,
        MAX_PASSPHRASE_INPUT_BYTES
    );
    assert_eq!(field(&corpus["kdf"], "alg"), "argon2id");
    assert_eq!(uint(&corpus["kdf"], "argon2_version"), 19);
    assert_eq!(uint(&corpus["kdf"], "out_bytes"), 32);
    assert_eq!(
        corpus["vectors"].as_array().expect("vectors array").len(),
        17
    );
    assert_eq!(
        corpus["error_vectors"]
            .as_array()
            .expect("error_vectors array")
            .len(),
        8
    );
}

#[test]
fn every_positive_case_normalizes_and_derives_the_pinned_cek() {
    let corpus = load_corpus();
    let vectors = corpus["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "corpus carries no positive vectors");

    for vector in vectors {
        let name = field(vector, "name");
        let normalized = normalize_passphrase(field(vector, "passphrase"))
            .unwrap_or_else(|e| panic!("vector {name}: normalization failed: {e}"));
        assert_eq!(
            hex::encode(normalized.as_bytes()),
            field(vector, "expected_normalized_utf8_hex"),
            "vector {name}: normalized bytes"
        );
        // The corpus's readable string form and its hex form pin the same bytes.
        assert_eq!(
            normalized,
            field(vector, "expected_normalized"),
            "vector {name}: expected_normalized string form"
        );

        let cek = derive_cek(&corpus, normalized.as_bytes());
        assert_eq!(
            hex::encode(&cek),
            field(vector, "expected_cek_hex"),
            "vector {name}: CEK"
        );
    }
}

#[test]
fn every_error_case_surfaces_the_pinned_code() {
    let corpus = load_corpus();
    let vectors = corpus["error_vectors"]
        .as_array()
        .expect("error_vectors array");
    assert!(!vectors.is_empty(), "corpus carries no error vectors");

    for vector in vectors {
        let name = field(vector, "name");
        let err = normalize_passphrase(field(vector, "passphrase"))
            .expect_err(&format!("vector {name}: expected a typed rejection"));
        assert_eq!(
            err.code(),
            field(vector, "expected_error_code"),
            "vector {name}"
        );
    }
}
