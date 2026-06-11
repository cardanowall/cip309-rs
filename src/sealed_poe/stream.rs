//! The `chacha20-poly1305-stream64k` content format: ChaCha20-Poly1305
//! (RFC 8439) in the 64 KiB segmented STREAM layout of the age v1
//! specification.
//!
//! The plaintext is split into chunks of exactly [`CHUNK_SIZE`] bytes; the
//! final chunk carries the remainder (`0..=CHUNK_SIZE`, zero only when the
//! whole plaintext is empty). Each chunk is sealed under the single-use content
//! `payload_key` with a 12-byte nonce of `uint88_be(counter) ‖ final_flag` and
//! an **empty** per-chunk AAD, producing a [`TAG_SIZE`]-byte Poly1305 tag per
//! chunk. The counter starts at 0 and increments per chunk; the final flag is
//! `0x01` on the last chunk and `0x00` otherwise, which domain-separates the
//! end of the stream so truncation, trailing data, and a short non-final chunk
//! are all detectable.
//!
//! The per-chunk AAD is empty by design: all context is bound transitively —
//! `payload_key` derives from the CEK, and the CEK is committed by the
//! on-chain `slots_mac` (slots path) or the in-ciphertext commitment header
//! (passphrase path).
//!
//! Two surfaces are exposed:
//!
//! - [`StreamSealer`] / [`StreamOpener`] — the incremental chunk machines, for
//!   callers that produce or consume a multi-GiB payload with bounded memory.
//!   A consumer MUST treat per-chunk plaintext as **tentative** (no side
//!   effects) until the whole-file plaintext-hash recheck passes.
//! - [`stream_seal`] / [`stream_open`] — whole-buffer conveniences over the
//!   machines, used by the wrap/unwrap and passphrase seal/open paths.

use thiserror::Error;
use zeroize::Zeroize;

use super::aead::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};

/// Plaintext bytes per non-final chunk. Pinned by the content format.
pub const CHUNK_SIZE: usize = 65536;

/// Poly1305 tag bytes appended to every sealed chunk. Pinned by the content
/// format.
pub const TAG_SIZE: usize = 16;

/// A full sealed chunk: [`CHUNK_SIZE`] plaintext bytes plus the tag.
const SEALED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

/// The chunk counter is an 11-byte (88-bit) big-endian integer, so a stream
/// admits at most `2^88` chunks — far above any realisable payload.
const MAX_CHUNK_COUNT: u128 = 1 << 88;

/// The content key is always 32 bytes (ChaCha20-Poly1305).
const PAYLOAD_KEY_LENGTH: usize = 32;

/// A STREAM open failure: a per-chunk authentication-tag failure or any
/// chunk-layout violation (truncation, trailing data after the final chunk, a
/// final flag on a non-last chunk, a non-final chunk of the wrong size, an
/// empty final chunk in a non-empty stream, or a tail too short to form a
/// chunk).
///
/// Deliberately a single opaque failure: which layout rule or tag failed is
/// not distinguished, matching the single-generic-failure rule for sealed-PoE
/// decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("stream decrypt failed")]
pub struct StreamError;

/// Assemble the 12-byte per-chunk nonce: `uint88_be(counter) ‖ final_flag`.
fn chunk_nonce(counter: u128, last: bool) -> [u8; 12] {
    debug_assert!(counter < MAX_CHUNK_COUNT);
    let mut nonce = [0u8; 12];
    // The low-order 11 bytes of the big-endian u128 are the 88-bit counter.
    nonce[..11].copy_from_slice(&counter.to_be_bytes()[5..]);
    nonce[11] = u8::from(last);
    nonce
}

/// Validate and copy a 32-byte payload key. Wrong-length key material is
/// caller misuse, mirroring how the AEAD primitives reject malformed keys.
fn payload_key_array(payload_key: &[u8]) -> [u8; PAYLOAD_KEY_LENGTH] {
    payload_key
        .try_into()
        .expect("the content payload_key MUST be exactly 32 bytes")
}

/// Incremental STREAM encryption: seal chunks one at a time.
///
/// Every chunk before the last MUST carry exactly [`CHUNK_SIZE`] plaintext
/// bytes; the last chunk (`last = true`) carries `0..=CHUNK_SIZE` bytes, zero
/// only when it is also the first (an empty plaintext is exactly one
/// zero-length final chunk). Violating these rules — or sealing past the final
/// chunk — is producer misuse and panics.
pub struct StreamSealer {
    key: [u8; PAYLOAD_KEY_LENGTH],
    counter: u128,
    finished: bool,
}

impl StreamSealer {
    /// Create a sealer over the 32-byte content `payload_key`.
    ///
    /// # Panics
    ///
    /// Panics if `payload_key` is not exactly 32 bytes (caller misuse).
    #[must_use]
    pub fn new(payload_key: &[u8]) -> Self {
        Self {
            key: payload_key_array(payload_key),
            counter: 0,
            finished: false,
        }
    }

    /// Seal the next chunk, returning `plaintext ‖ tag` (`plaintext.len() + 16`
    /// bytes). `last` marks the final chunk.
    ///
    /// # Panics
    ///
    /// Panics on producer misuse: a non-final chunk that is not exactly
    /// [`CHUNK_SIZE`] bytes, a final chunk over [`CHUNK_SIZE`] bytes, an empty
    /// final chunk in a non-empty stream, sealing after the final chunk, or a
    /// counter past `2^88` chunks.
    pub fn seal_chunk(&mut self, plaintext: &[u8], last: bool) -> Vec<u8> {
        assert!(!self.finished, "stream already sealed its final chunk");
        assert!(self.counter < MAX_CHUNK_COUNT, "chunk counter exhausted");
        if last {
            assert!(
                plaintext.len() <= CHUNK_SIZE,
                "final chunk MUST carry at most {CHUNK_SIZE} plaintext bytes"
            );
            assert!(
                !plaintext.is_empty() || self.counter == 0,
                "an empty final chunk is only valid when the whole plaintext is empty"
            );
        } else {
            assert!(
                plaintext.len() == CHUNK_SIZE,
                "every non-final chunk MUST carry exactly {CHUNK_SIZE} plaintext bytes"
            );
        }
        let nonce = chunk_nonce(self.counter, last);
        self.counter += 1;
        self.finished = last;
        chacha20_poly1305_encrypt(&self.key, &nonce, b"", plaintext)
    }

    /// Whether the final chunk has been sealed.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.finished
    }
}

impl Drop for StreamSealer {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Incremental STREAM decryption: open chunks one at a time.
///
/// Each chunk's plaintext is returned only after its tag verifies; the caller
/// MUST treat released bytes as tentative until the whole-file plaintext-hash
/// recheck passes. The opener enforces the chunk-layout rules on its inputs:
/// feeding it a malformed chunk sequence yields [`StreamError`], never a
/// panic — the sealed bytes are untrusted.
pub struct StreamOpener {
    key: [u8; PAYLOAD_KEY_LENGTH],
    counter: u128,
    finished: bool,
}

impl StreamOpener {
    /// Create an opener over the 32-byte content `payload_key`.
    ///
    /// # Panics
    ///
    /// Panics if `payload_key` is not exactly 32 bytes (caller misuse).
    #[must_use]
    pub fn new(payload_key: &[u8]) -> Self {
        Self {
            key: payload_key_array(payload_key),
            counter: 0,
            finished: false,
        }
    }

    /// Open the next sealed chunk (`plaintext ‖ tag`), returning its plaintext.
    /// `last` marks the final chunk.
    ///
    /// # Errors
    ///
    /// Returns [`StreamError`] when the chunk layout is violated (data after
    /// the final chunk, a non-final chunk that is not exactly full, a final
    /// chunk outside `TAG_SIZE..=CHUNK_SIZE+TAG_SIZE` bytes, an empty final
    /// chunk in a non-empty stream, a counter past `2^88`) or when the
    /// Poly1305 tag does not verify.
    pub fn open_chunk(&mut self, sealed: &[u8], last: bool) -> Result<Vec<u8>, StreamError> {
        if self.finished || self.counter >= MAX_CHUNK_COUNT {
            return Err(StreamError);
        }
        if last {
            if sealed.len() < TAG_SIZE || sealed.len() > SEALED_CHUNK_SIZE {
                return Err(StreamError);
            }
            // A zero-length final chunk is well-formed only as the sole chunk
            // of an empty plaintext.
            if sealed.len() == TAG_SIZE && self.counter != 0 {
                return Err(StreamError);
            }
        } else if sealed.len() != SEALED_CHUNK_SIZE {
            return Err(StreamError);
        }
        let nonce = chunk_nonce(self.counter, last);
        let plaintext =
            chacha20_poly1305_decrypt(&self.key, &nonce, b"", sealed).map_err(|_| StreamError)?;
        self.counter += 1;
        self.finished = last;
        Ok(plaintext)
    }

    /// Whether the final chunk has been opened.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.finished
    }
}

impl Drop for StreamOpener {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Seal a whole plaintext into the STREAM chunk sequence.
///
/// An empty plaintext seals as exactly one zero-length final chunk — a lone
/// 16-byte tag.
///
/// # Panics
///
/// Panics if `payload_key` is not exactly 32 bytes (caller misuse).
#[must_use]
pub fn stream_seal(payload_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut sealer = StreamSealer::new(payload_key);
    let chunk_count = plaintext.len().div_ceil(CHUNK_SIZE).max(1);
    let mut out = Vec::with_capacity(plaintext.len() + chunk_count * TAG_SIZE);
    if plaintext.is_empty() {
        out.extend_from_slice(&sealer.seal_chunk(b"", true));
        return out;
    }
    let mut chunks = plaintext.chunks(CHUNK_SIZE).peekable();
    while let Some(chunk) = chunks.next() {
        let last = chunks.peek().is_none();
        out.extend_from_slice(&sealer.seal_chunk(chunk, last));
    }
    out
}

/// Open a whole STREAM ciphertext, returning the plaintext.
///
/// The chunk layout is derived from the total length: every chunk before the
/// last is exactly `CHUNK_SIZE + TAG_SIZE` bytes and the tail is the final
/// chunk. A blob shorter than one tag, a tail too short to form a final chunk,
/// a zero-length final chunk in a non-empty stream, or any per-chunk tag
/// failure is malformed ciphertext.
///
/// # Errors
///
/// Returns [`StreamError`] on any chunk-layout violation or tag failure.
///
/// # Panics
///
/// Panics if `payload_key` is not exactly 32 bytes (caller misuse).
pub fn stream_open(payload_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, StreamError> {
    let total = ciphertext.len();
    if total < TAG_SIZE {
        return Err(StreamError);
    }
    let remainder = total % SEALED_CHUNK_SIZE;
    let (full_chunks, final_len) = if remainder == 0 {
        // The tail is a full final chunk (exactly CHUNK_SIZE plaintext bytes).
        (total / SEALED_CHUNK_SIZE - 1, SEALED_CHUNK_SIZE)
    } else if remainder >= TAG_SIZE {
        (total / SEALED_CHUNK_SIZE, remainder)
    } else {
        // The tail cannot form a well-formed final chunk.
        return Err(StreamError);
    };

    let mut opener = StreamOpener::new(payload_key);
    let mut out = Vec::with_capacity(total - (full_chunks + 1) * TAG_SIZE);
    for i in 0..full_chunks {
        let start = i * SEALED_CHUNK_SIZE;
        let mut plaintext =
            opener.open_chunk(&ciphertext[start..start + SEALED_CHUNK_SIZE], false)?;
        out.extend_from_slice(&plaintext);
        plaintext.zeroize();
    }
    let final_start = full_chunks * SEALED_CHUNK_SIZE;
    debug_assert_eq!(final_start + final_len, total);
    let mut plaintext = opener.open_chunk(&ciphertext[final_start..], true)?;
    out.extend_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic, self-contained invariants of the chunk machine. The
    // cross-implementation byte vectors are replayed by the integration suite.

    const KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn nonce_layout_is_uint88_be_counter_then_flag() {
        assert_eq!(chunk_nonce(0, false), [0u8; 12]);
        assert_eq!(
            chunk_nonce(0, true),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        );
        assert_eq!(
            chunk_nonce(1, false),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0]
        );
        assert_eq!(
            chunk_nonce(0x0102, true),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x01]
        );
        // The full 88-bit width is carried big-endian.
        assert_eq!(
            chunk_nonce(MAX_CHUNK_COUNT - 1, false),
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]
        );
    }

    #[test]
    fn each_chunk_is_a_chacha20_poly1305_seal_under_the_counter_nonce() {
        // Pin the machine to the raw primitive: chunk i is exactly
        // ChaCha20-Poly1305(key, uint88_be(i) ‖ flag, aad = "", chunk_i).
        let mut plaintext = vec![0xa5u8; CHUNK_SIZE];
        plaintext.extend_from_slice(b"tail");
        let sealed = stream_seal(&KEY, &plaintext);
        let expect_chunk0 =
            chacha20_poly1305_encrypt(&KEY, &chunk_nonce(0, false), b"", &plaintext[..CHUNK_SIZE]);
        let expect_chunk1 =
            chacha20_poly1305_encrypt(&KEY, &chunk_nonce(1, true), b"", &plaintext[CHUNK_SIZE..]);
        assert_eq!(&sealed[..SEALED_CHUNK_SIZE], expect_chunk0.as_slice());
        assert_eq!(&sealed[SEALED_CHUNK_SIZE..], expect_chunk1.as_slice());
    }

    #[test]
    fn empty_plaintext_is_one_zero_length_final_chunk() {
        let sealed = stream_seal(&KEY, b"");
        assert_eq!(sealed.len(), TAG_SIZE, "a lone 16-byte tag");
        assert_eq!(stream_open(&KEY, &sealed).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn sealer_rejects_misuse() {
        // Sealing past the final chunk.
        let mut sealer = StreamSealer::new(&KEY);
        let _ = sealer.seal_chunk(b"x", true);
        assert!(sealer.finished());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sealer.seal_chunk(b"y", true)
        }))
        .is_err());

        // A short non-final chunk.
        let mut sealer = StreamSealer::new(&KEY);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sealer.seal_chunk(b"short", false)
        }))
        .is_err());

        // An empty final chunk after a non-empty stream.
        let mut sealer = StreamSealer::new(&KEY);
        let _ = sealer.seal_chunk(&[0u8; CHUNK_SIZE], false);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sealer.seal_chunk(b"", true)
        }))
        .is_err());
    }

    #[test]
    fn opener_refuses_data_after_the_final_chunk() {
        let sealed = stream_seal(&KEY, b"body");
        let mut opener = StreamOpener::new(&KEY);
        assert_eq!(opener.open_chunk(&sealed, true).unwrap(), b"body");
        assert!(opener.finished());
        assert_eq!(opener.open_chunk(&sealed, true), Err(StreamError));
    }
}
