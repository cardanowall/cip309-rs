//! Conformance tests for the pinned Unicode 16.0.0 NFKC implementation,
//! replaying the shared NormalizationTest-derived oracle byte-exactly.

mod common;

use cardanowall::unicode_nfkc16::{is_assigned16, is_white_space16, nfkc16, Nfkc16Error};

struct OraclePair {
    source_hex: String,
    source: String,
    expected: String,
    parts: Vec<String>,
    source_code_points: Vec<u32>,
}

struct Oracle {
    pairs: Vec<OraclePair>,
    sample_assigned: Vec<u32>,
    sample_unassigned: Vec<u32>,
}

fn code_points_from_hex(seq: &str) -> Vec<u32> {
    seq.split(' ')
        .map(|token| u32::from_str_radix(token, 16).expect("oracle code points are hex"))
        .collect()
}

fn string_from_hex(seq: &str) -> String {
    code_points_from_hex(seq)
        .into_iter()
        .map(|cp| char::from_u32(cp).expect("oracle code points are scalar values"))
        .collect()
}

fn load_oracle() -> Oracle {
    let value =
        common::read_fixture_json(&common::crypto_core_fixtures().join("unicode/nfkc-16.0.json"));
    assert_eq!(
        value["ucd_version"].as_str(),
        Some("16.0.0"),
        "oracle must be pinned to UCD 16.0.0"
    );
    let pairs = value["pairs"]
        .as_array()
        .expect("oracle has a pairs array")
        .iter()
        .map(|entry| {
            let line = entry.as_str().expect("oracle pairs are strings");
            let (mapping, parts) = line.split_once('|').expect("pair has a parts tag");
            let (source_hex, expected_hex) =
                mapping.split_once(';').expect("pair has a ';' separator");
            OraclePair {
                source_hex: source_hex.to_owned(),
                source: string_from_hex(source_hex),
                expected: string_from_hex(expected_hex),
                parts: parts.split(' ').map(str::to_owned).collect(),
                source_code_points: code_points_from_hex(source_hex),
            }
        })
        .collect();
    let samples = |key: &str| -> Vec<u32> {
        value[key]
            .as_array()
            .expect("oracle has the sample array")
            .iter()
            .map(|entry| {
                let token = entry.as_str().expect("samples are hex strings");
                u32::from_str_radix(token, 16).expect("samples are hex")
            })
            .collect()
    };
    Oracle {
        pairs,
        sample_assigned: samples("sample_assigned"),
        sample_unassigned: samples("sample_unassigned"),
    }
}

#[test]
fn oracle_carries_the_full_corpus() {
    let oracle = load_oracle();
    assert!(oracle.pairs.len() > 30000);
    assert!(oracle.sample_assigned.len() >= 40);
    assert!(oracle.sample_unassigned.len() >= 40);
}

#[test]
fn replays_every_oracle_pair_byte_exactly() {
    let oracle = load_oracle();
    let mut failures: Vec<String> = Vec::new();
    for pair in &oracle.pairs {
        let actual = nfkc16(&pair.source).expect("oracle sources are assigned at 16.0");
        if actual != pair.expected {
            failures.push(format!(
                "{} -> {:?} (expected {:?})",
                pair.source_hex, actual, pair.expected
            ));
            if failures.len() >= 20 {
                break;
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn unlisted_assigned_code_points_are_nfkc_stable() {
    // NormalizationTest guarantees X == NFKC(X) for every code point that
    // never appears as column 1 of Part 1; replay that invariant over every
    // 17th assigned code point.
    let oracle = load_oracle();
    let part1_singles: std::collections::HashSet<u32> = oracle
        .pairs
        .iter()
        .filter(|pair| pair.source_code_points.len() == 1 && pair.parts.iter().any(|p| p == "1"))
        .map(|pair| pair.source_code_points[0])
        .collect();
    assert!(part1_singles.len() > 5000);

    let mut failures: Vec<String> = Vec::new();
    let mut assigned_seen = 0u32;
    let mut checked = 0u32;
    for cp in 0..=0x10FFFFu32 {
        if !is_assigned16(cp) {
            continue;
        }
        assigned_seen += 1;
        if !assigned_seen.is_multiple_of(17) {
            continue;
        }
        let Some(ch) = char::from_u32(cp) else {
            continue; // surrogate range
        };
        if part1_singles.contains(&cp) {
            continue;
        }
        let source = ch.to_string();
        checked += 1;
        if nfkc16(&source).expect("assigned code points normalize") != source {
            failures.push(format!("{cp:04X}"));
            if failures.len() >= 20 {
                break;
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    assert!(checked > 10000);
}

#[test]
fn rejects_every_sampled_unassigned_code_point() {
    let oracle = load_oracle();
    for &cp in &oracle.sample_unassigned {
        assert!(!is_assigned16(cp), "U+{cp:04X} must be unassigned");
        let ch = char::from_u32(cp).expect("sampled unassigned code points are scalar values");
        for text in [ch.to_string(), format!("a{ch}b")] {
            assert_eq!(
                nfkc16(&text),
                Err(Nfkc16Error::UnassignedCodePoint { code_point: cp })
            );
        }
    }
}

#[test]
fn accepts_every_sampled_assigned_code_point() {
    let oracle = load_oracle();
    for &cp in &oracle.sample_assigned {
        assert!(is_assigned16(cp), "U+{cp:04X} must be assigned");
        let ch = char::from_u32(cp).expect("sampled assigned code points are scalar values");
        nfkc16(&ch.to_string()).expect("assigned code points normalize");
    }
}

#[test]
fn is_assigned16_is_total_and_false_outside_code_point_space() {
    assert!(!is_assigned16(0x110000));
    assert!(!is_assigned16(u32::MAX));
}

#[test]
fn error_carries_the_stable_code_string() {
    let err = Nfkc16Error::UnassignedCodePoint { code_point: 0x0378 };
    assert_eq!(err.code(), "UNASSIGNED_CODEPOINT");
}

#[test]
fn accepts_assigned_astral_code_points() {
    assert_eq!(nfkc16("😀").as_deref(), Ok("\u{1F600}"));
}

#[test]
fn empty_string_is_identity() {
    assert_eq!(nfkc16("").as_deref(), Ok(""));
}

#[test]
fn white_space_property_is_pinned() {
    for cp in [
        0x09, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2000, 0x200A, 0x2028, 0x3000,
    ] {
        assert!(is_white_space16(cp), "U+{cp:04X} must be White_Space");
    }
    // U+200B ZERO WIDTH SPACE and U+FEFF are not White_Space; char::is_whitespace
    // already matches the property today, but it floats with the compiler's
    // Unicode version, which is exactly why the property is pinned.
    for cp in [0x08, 0x0E, 0x21, 0x200B, 0xFEFF, 0x3001] {
        assert!(!is_white_space16(cp), "U+{cp:04X} must not be White_Space");
    }
}
