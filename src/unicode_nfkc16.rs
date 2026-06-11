//! Pinned Unicode 16.0.0 NFKC normalization.
//!
//! Keys derived from passphrases must come out identical in every conformant
//! implementation, today and years from now, so this module never delegates to
//! a Unicode crate whose tables float with its own release cadence — two
//! runtimes on different Unicode versions can derive different keys from the
//! same passphrase. The tables here are generated from the Unicode 16.0.0 UCD
//! and pinned. Code points that Unicode 16.0 leaves unassigned are rejected
//! outright: the Unicode stability policy only guarantees normalization
//! stability for code points that are assigned in the pinned version, so
//! passing unassigned input through would re-open the drift.
//!
//! Algorithm (UAX #15, no quick-check fast path): validate the
//! assigned-at-16.0 guard (`&str` already guarantees Unicode scalar values, so
//! the lone-surrogate rejection the TypeScript and Python implementations
//! perform is structurally impossible here), fully decompose through the flat
//! NFKD table (recursion was resolved at table-generation time; Hangul is
//! algorithmic), canonically reorder by combining class, then canonically
//! compose (pair table with composition exclusions applied, plus algorithmic
//! Hangul).

use std::collections::HashMap;
use std::sync::OnceLock;

use thiserror::Error;

use crate::unicode_nfkc16_data as data;

/// Input that the pinned Unicode 16.0.0 profile rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Nfkc16Error {
    /// The input contains a code point that Unicode 16.0.0 leaves unassigned.
    /// Normalization of such input would not be stable across Unicode
    /// versions, so it is refused instead of passed through.
    #[error(
        "UNASSIGNED_CODEPOINT: code point U+{code_point:04X} is not assigned in Unicode 16.0.0"
    )]
    UnassignedCodePoint {
        /// The offending code point.
        code_point: u32,
    },
}

impl Nfkc16Error {
    /// The stable error-code string shared with the TypeScript and Python
    /// implementations.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Nfkc16Error::UnassignedCodePoint { .. } => "UNASSIGNED_CODEPOINT",
        }
    }
}

// Hangul decomposition/composition is algorithmic (UAX #15 section 3.12).
const HANGUL_S_BASE: u32 = 0xAC00;
const HANGUL_L_BASE: u32 = 0x1100;
const HANGUL_V_BASE: u32 = 0x1161;
const HANGUL_T_BASE: u32 = 0x11A7;
const HANGUL_L_COUNT: u32 = 19;
const HANGUL_V_COUNT: u32 = 21;
const HANGUL_T_COUNT: u32 = 28;
const HANGUL_N_COUNT: u32 = HANGUL_V_COUNT * HANGUL_T_COUNT; // 588
const HANGUL_S_COUNT: u32 = HANGUL_L_COUNT * HANGUL_N_COUNT; // 11172

const MAX_CODE_POINT: u32 = 0x10FFFF;

struct Tables {
    decomposition: HashMap<u32, Vec<u32>>,
    ccc: HashMap<u32, u8>,
    composition: HashMap<(u32, u32), u32>,
    /// Sorted, non-overlapping inclusive (start, end) pairs for binary search.
    assigned: Vec<(u32, u32)>,
    white_space: Vec<(u32, u32)>,
}

fn parse_hex(token: &str) -> u32 {
    u32::from_str_radix(token, 16).expect("pinned NFKC table data is well-formed hex")
}

fn parse_decomposition(packed: &str) -> HashMap<u32, Vec<u32>> {
    packed
        .split(';')
        .map(|entry| {
            let (key, targets) = entry
                .split_once('=')
                .expect("pinned NFKC decomposition entry has a '=' separator");
            (parse_hex(key), targets.split(' ').map(parse_hex).collect())
        })
        .collect()
}

fn parse_ccc(packed: &str) -> HashMap<u32, u8> {
    let mut out = HashMap::new();
    for entry in packed.split(';') {
        let (span, value) = entry
            .split_once(':')
            .expect("pinned NFKC ccc entry has a ':' separator");
        let combining =
            u8::try_from(parse_hex(value)).expect("canonical combining classes fit in u8");
        let (first, last) = match span.split_once('-') {
            Some((start, end)) => (parse_hex(start), parse_hex(end)),
            None => (parse_hex(span), parse_hex(span)),
        };
        for cp in first..=last {
            out.insert(cp, combining);
        }
    }
    out
}

fn parse_composition(packed: &str) -> HashMap<(u32, u32), u32> {
    packed
        .split(';')
        .map(|entry| {
            let (key, composed) = entry
                .split_once('=')
                .expect("pinned NFKC composition entry has a '=' separator");
            let (starter, combining) = key
                .split_once(' ')
                .expect("pinned NFKC composition key has a ' ' separator");
            (
                (parse_hex(starter), parse_hex(combining)),
                parse_hex(composed),
            )
        })
        .collect()
}

fn parse_ranges(packed: &str) -> Vec<(u32, u32)> {
    packed
        .split(';')
        .map(|entry| match entry.split_once('-') {
            Some((start, end)) => (parse_hex(start), parse_hex(end)),
            None => (parse_hex(entry), parse_hex(entry)),
        })
        .collect()
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| Tables {
        decomposition: parse_decomposition(&data::DECOMPOSITION_PACKED.concat()),
        ccc: parse_ccc(&data::CCC_PACKED.concat()),
        composition: parse_composition(&data::COMPOSITION_PACKED.concat()),
        assigned: parse_ranges(&data::ASSIGNED_RANGES_PACKED.concat()),
        white_space: parse_ranges(&data::WHITE_SPACE_RANGES_PACKED.concat()),
    })
}

fn in_ranges(ranges: &[(u32, u32)], code_point: u32) -> bool {
    ranges
        .binary_search_by(|&(start, end)| {
            if end < code_point {
                std::cmp::Ordering::Less
            } else if start > code_point {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Whether the code point is assigned (General_Category != Cn) in Unicode
/// 16.0.0. Values above U+10FFFF are never assigned.
#[must_use]
pub fn is_assigned16(code_point: u32) -> bool {
    code_point <= MAX_CODE_POINT && in_ranges(&tables().assigned, code_point)
}

/// Whether the code point has White_Space=Yes in Unicode 16.0.0.
#[must_use]
pub fn is_white_space16(code_point: u32) -> bool {
    code_point <= MAX_CODE_POINT && in_ranges(&tables().white_space, code_point)
}

fn ccc_of(t: &Tables, code_point: u32) -> u8 {
    t.ccc.get(&code_point).copied().unwrap_or(0)
}

fn decompose(t: &Tables, code_points: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(code_points.len());
    for &cp in code_points {
        if (HANGUL_S_BASE..HANGUL_S_BASE + HANGUL_S_COUNT).contains(&cp) {
            let s_index = cp - HANGUL_S_BASE;
            out.push(HANGUL_L_BASE + s_index / HANGUL_N_COUNT);
            out.push(HANGUL_V_BASE + (s_index % HANGUL_N_COUNT) / HANGUL_T_COUNT);
            let trailing = s_index % HANGUL_T_COUNT;
            if trailing != 0 {
                out.push(HANGUL_T_BASE + trailing);
            }
            continue;
        }
        match t.decomposition.get(&cp) {
            Some(mapped) => out.extend_from_slice(mapped),
            None => out.push(cp),
        }
    }
    out
}

/// Canonical Ordering Algorithm: stable insertion sort of nonzero-ccc runs.
fn canonical_reorder(t: &Tables, code_points: &mut [u32]) {
    for i in 1..code_points.len() {
        let cp = code_points[i];
        let combining = ccc_of(t, cp);
        if combining == 0 {
            continue;
        }
        let mut j = i;
        while j > 0 && ccc_of(t, code_points[j - 1]) > combining {
            code_points[j] = code_points[j - 1];
            j -= 1;
        }
        code_points[j] = cp;
    }
}

fn compose_pair(t: &Tables, a: u32, b: u32) -> Option<u32> {
    if (HANGUL_L_BASE..HANGUL_L_BASE + HANGUL_L_COUNT).contains(&a)
        && (HANGUL_V_BASE..HANGUL_V_BASE + HANGUL_V_COUNT).contains(&b)
    {
        return Some(
            HANGUL_S_BASE
                + ((a - HANGUL_L_BASE) * HANGUL_V_COUNT + (b - HANGUL_V_BASE)) * HANGUL_T_COUNT,
        );
    }
    if (HANGUL_S_BASE..HANGUL_S_BASE + HANGUL_S_COUNT).contains(&a)
        && (a - HANGUL_S_BASE).is_multiple_of(HANGUL_T_COUNT)
        && (HANGUL_T_BASE + 1..HANGUL_T_BASE + HANGUL_T_COUNT).contains(&b)
    {
        return Some(a + (b - HANGUL_T_BASE));
    }
    t.composition.get(&(a, b)).copied()
}

/// Canonical Composition Algorithm. A combining character composes with the
/// last starter when it is not blocked: either it directly follows the
/// starter, or every character in between has a strictly lower combining
/// class (the sequence is canonically ordered, so checking the immediately
/// preceding class suffices). Primary composites are always starters, so a
/// successful composition never changes the trailing combining class.
fn compose(t: &Tables, code_points: &[u32]) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::with_capacity(code_points.len());
    let mut starter_idx: Option<usize> = None;
    let mut last_ccc = 0u8;
    for &cp in code_points {
        let combining = ccc_of(t, cp);
        if let Some(idx) = starter_idx {
            if idx == out.len() - 1 || last_ccc < combining {
                if let Some(composed) = compose_pair(t, out[idx], cp) {
                    out[idx] = composed;
                    continue;
                }
            }
        }
        out.push(cp);
        last_ccc = combining;
        if combining == 0 {
            starter_idx = Some(out.len() - 1);
        }
    }
    out
}

/// Normalize to NFKC exactly as Unicode 16.0.0 defines it.
///
/// # Errors
///
/// Returns [`Nfkc16Error::UnassignedCodePoint`] when the input contains a
/// code point that Unicode 16.0.0 leaves unassigned (normalization of such
/// input would not be stable across Unicode versions).
pub fn nfkc16(input: &str) -> Result<String, Nfkc16Error> {
    let t = tables();
    let mut code_points: Vec<u32> = Vec::with_capacity(input.len());
    for ch in input.chars() {
        let cp = u32::from(ch);
        if !in_ranges(&t.assigned, cp) {
            return Err(Nfkc16Error::UnassignedCodePoint { code_point: cp });
        }
        code_points.push(cp);
    }
    let mut decomposed = decompose(t, &code_points);
    canonical_reorder(t, &mut decomposed);
    Ok(compose(t, &decomposed)
        .into_iter()
        .map(|cp| {
            char::from_u32(cp).expect("pinned NFKC tables only produce Unicode scalar values")
        })
        .collect())
}
