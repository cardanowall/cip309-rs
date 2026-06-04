//! Byte-parity tests for the Crockford base32 codec + prefixed-id grammar.
//!
//! Pins the shared cross-language id fixture (`ids/cases.json`): the canonical
//! `<prefix>_<crockford>` encodings over fixed UUID payloads (driven through the
//! generic prefix-string codec), plus the `reject_is_prefixed_id` negative cases
//! (trailing-newline rejection). The same vectors back the Python suite, so
//! passing them proves this crate encodes and decodes ids byte-for-byte.

mod common;

use cardanowall::ids::{
    decode_bytes, decode_prefixed_id, encode_bytes, encode_prefixed_id, is_prefixed_id, IdError,
    IdPrefix,
};
use common::{read_fixture_json, sdk_py_fixtures};

#[test]
fn poe_is_the_standard_defined_prefix() {
    // `poe` is the single prefix the Label 309 standard defines; service-entity
    // prefixes (account / invoice / api-key) are gateway-specific and live
    // behind the generic prefix-string codec, not this enum.
    assert_eq!(IdPrefix::Poe.as_str(), "poe");
}

#[test]
fn cases_fixture_pins_encode_decode_and_guard() {
    let path = sdk_py_fixtures().join("ids/cases.json");
    let fixture = read_fixture_json(&path);
    let cases = fixture
        .as_array()
        .expect("ids cases fixture must be a JSON array");
    assert_eq!(cases.len(), 6, "expected 6 id cases (4 encode + 2 reject)");

    let mut encode_cases = 0;
    let mut reject_cases = 0;

    for case in cases {
        let id = case["id"].as_str().expect("case `id` must be a string");
        let prefix = case["prefix"]
            .as_str()
            .unwrap_or_else(|| panic!("case {id}: `prefix` must be a string"));

        match case["kind"].as_str() {
            Some("reject_is_prefixed_id") => {
                reject_cases += 1;
                let candidate = case["candidate"]
                    .as_str()
                    .unwrap_or_else(|| panic!("case {id}: `candidate` must be a string"));
                assert!(
                    !is_prefixed_id(prefix, candidate),
                    "case {id}: is_prefixed_id must reject {candidate:?}"
                );
            }
            None => {
                encode_cases += 1;
                let uuid = case["uuid"]
                    .as_str()
                    .unwrap_or_else(|| panic!("case {id}: `uuid` must be a string"));
                let expected = case["encoded"]
                    .as_str()
                    .unwrap_or_else(|| panic!("case {id}: `encoded` must be a string"));

                let encoded = encode_prefixed_id(prefix, uuid)
                    .unwrap_or_else(|e| panic!("case {id}: encode failed: {e}"));
                assert_eq!(encoded, expected, "case {id}: encoded form");

                let decoded = decode_prefixed_id(prefix, expected)
                    .unwrap_or_else(|e| panic!("case {id}: decode failed: {e}"));
                assert_eq!(decoded, uuid, "case {id}: round-trips back to the UUID");

                // The canonical lowercase wire form passes the cheap guard.
                assert!(is_prefixed_id(prefix, expected), "case {id}: guard accepts");
            }
            Some(other) => panic!("case {id}: unexpected kind {other:?}"),
        }
    }

    assert_eq!(encode_cases, 4, "expected 4 encode/decode cases");
    assert_eq!(reject_cases, 2, "expected 2 reject_is_prefixed_id cases");
}

#[test]
fn crockford_encode_decode_edges() {
    // 16 zero bytes → 26 zero symbols.
    assert_eq!(encode_bytes(&[0u8; 16]).unwrap(), "0".repeat(26));
    // 16 0xff bytes → 25 "z"s then a trailing "w" (top 3 bits set, 2 zero-pad).
    let ff = encode_bytes(&[0xffu8; 16]).unwrap();
    assert_eq!(&ff[..25], "z".repeat(25));
    assert_eq!(&ff[25..], "w");

    // Round-trip + uppercase/alias acceptance.
    assert_eq!(decode_bytes(&ff).unwrap(), [0xffu8; 16]);
    assert_eq!(decode_bytes(&ff.to_uppercase()).unwrap(), [0xffu8; 16]);

    // I/L → 1, O → 0 aliases on a zero encoding still decode to zero bytes.
    let zero = encode_bytes(&[0u8; 16]).unwrap();
    let massaged = format!("O{}o{}", &zero[1..13], &zero[14..]);
    assert_eq!(decode_bytes(&massaged).unwrap(), [0u8; 16]);
}

#[test]
fn crockford_decode_rejects_malformed_input() {
    let zero = encode_bytes(&[0u8; 16]).unwrap();

    // U is reserved → invalid character.
    assert!(matches!(
        decode_bytes(&format!("u{}", &zero[1..])),
        Err(IdError::InvalidCharacter('u', 0))
    ));
    // Non-base32 character.
    assert!(matches!(
        decode_bytes(&format!("!{}", &zero[1..])),
        Err(IdError::InvalidCharacter('!', 0))
    ));
    // Wrong length.
    assert_eq!(
        decode_bytes("0".repeat(25).as_str()).err(),
        Some(IdError::DecodeWrongLength(25))
    );
    assert_eq!(decode_bytes("").err(), Some(IdError::DecodeWrongLength(0)));
    // Non-zero pad bits.
    let tampered = format!("{}z", &zero[..25]);
    assert_eq!(decode_bytes(&tampered).err(), Some(IdError::NonZeroPadBits));

    // Encode rejects non-16-byte input.
    assert_eq!(
        encode_bytes(&[0u8; 15]).err(),
        Some(IdError::EncodeWrongByteLength(15))
    );
    assert_eq!(
        encode_bytes(&[0u8; 17]).err(),
        Some(IdError::EncodeWrongByteLength(17))
    );
}

#[test]
fn prefixed_id_decode_rejects_malformed_input() {
    let encoded = encode_prefixed_id("poe", "01977c4a-0066-7777-aaaa-bbbbbbbbbbbb").unwrap();

    // Mismatched prefix.
    assert_eq!(
        decode_prefixed_id("acct", &encoded).err(),
        Some(IdError::PrefixMismatch(
            "acct".to_string(),
            "poe".to_string()
        ))
    );
    // Missing separator.
    assert!(matches!(
        decode_prefixed_id("poe", "poenoseparatorhere00000000000000"),
        Err(IdError::MissingSeparator(_))
    ));
    // Body of wrong length.
    assert!(matches!(
        decode_prefixed_id("poe", "poe_tooshort"),
        Err(IdError::DecodeWrongLength(8))
    ));
    // Invalid base32 characters in the body.
    assert!(matches!(
        decode_prefixed_id("poe", &format!("poe_{}", "!".repeat(26))),
        Err(IdError::InvalidCharacter('!', 0))
    ));

    // Malformed UUIDs on encode.
    assert!(matches!(
        encode_prefixed_id("poe", "not-a-uuid"),
        Err(IdError::NotCanonicalUuid(_))
    ));
    assert!(matches!(
        encode_prefixed_id("poe", "01977c4a00667777aaaabbbbbbbbbbbb"),
        Err(IdError::NotCanonicalUuid(_))
    ));
    assert!(matches!(
        encode_prefixed_id("poe", "01977c4a-0066-7777-aaaa-bbbbbbbbbbb"),
        Err(IdError::NotCanonicalUuid(_))
    ));
}

#[test]
fn is_prefixed_id_guard_rejects_aliases_uppercase_and_bare_uuids() {
    let encoded = encode_prefixed_id("poe", "01977c4a-0066-7777-aaaa-bbbbbbbbbbbb").unwrap();
    assert!(is_prefixed_id("poe", &encoded));
    assert!(!is_prefixed_id("acct", &encoded));
    assert!(!is_prefixed_id(
        "poe",
        "01977c4a-0066-7777-aaaa-bbbbbbbbbbbb"
    ));
    assert!(!is_prefixed_id("poe", &encoded.to_uppercase()));

    let body = "0".repeat(26);
    assert!(!is_prefixed_id(
        "poe",
        &format!("poe_{}I{}", &body[..5], &body[6..])
    ));
    assert!(!is_prefixed_id(
        "poe",
        &format!("poe_{}o{}", &body[..5], &body[6..])
    ));
    assert!(!is_prefixed_id(
        "poe",
        &format!("poe_{}u{}", &body[..5], &body[6..])
    ));
}
