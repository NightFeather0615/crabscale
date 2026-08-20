//! Noise record framing for the TS2021 data phase.
//!
//! A record is `[0x04][u16 BE ciphertext length][ChaCha20-Poly1305 ciphertext]`.
//! The total frame size, including the 3-byte header, must not exceed 4096
//! bytes. Each direction uses an independent cipher and nonce counter.

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};

use crate::error::TransportError;
use crate::messages::{
    AEAD_TAG_LEN, MAX_RECORD_FRAME_SIZE, MAX_RECORD_PLAINTEXT, MSG_TYPE_ERROR, MSG_TYPE_RECORD,
    RECORD_HEADER_LEN,
};

/// A single-direction record cipher.
#[derive(Clone)]
pub struct RecordCipher {
    cipher: ChaCha20Poly1305,
    nonce: u64,
}

impl RecordCipher {
    /// Create a cipher for one direction of a Noise session.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&Key::from(key)),
            nonce: 0,
        }
    }

    fn next_nonce(&mut self) -> Nonce {
        assert_ne!(self.nonce, u64::MAX, "record nonce exhausted");
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.nonce.to_be_bytes());
        self.nonce += 1;
        Nonce::from(nonce)
    }

    /// Encrypt `plaintext` into one or more record frames.
    ///
    /// Plaintext larger than [`MAX_RECORD_PLAINTEXT`] is split across frames.
    pub fn encode(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut out = Vec::with_capacity(
            plaintext.len()
                + plaintext.len() / MAX_RECORD_PLAINTEXT * (RECORD_HEADER_LEN + AEAD_TAG_LEN)
                + RECORD_HEADER_LEN
                + AEAD_TAG_LEN,
        );
        for chunk in plaintext.chunks(MAX_RECORD_PLAINTEXT) {
            let mut body = chunk.to_vec();
            let nonce = self.next_nonce();
            let tag = self
                .cipher
                .encrypt_in_place_detached(&nonce, &[], &mut body)
                .expect("ChaCha20-Poly1305 encryption cannot fail");
            out.push(MSG_TYPE_RECORD);
            out.extend_from_slice(&((body.len() + AEAD_TAG_LEN) as u16).to_be_bytes());
            out.extend_from_slice(&body);
            out.extend_from_slice(tag.as_ref());
        }
        Ok(out)
    }

    /// Decrypt exactly one record frame from the front of `buf`.
    ///
    /// Returns the plaintext and the number of bytes consumed. Trailing bytes
    /// are left for the next call.
    pub fn decode_one(&mut self, buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, TransportError> {
        if buf.len() < RECORD_HEADER_LEN {
            return Ok(None);
        }
        let msg_type = buf[0];
        let len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        let total = RECORD_HEADER_LEN + len;
        if total > MAX_RECORD_FRAME_SIZE {
            return Err(TransportError::Oversized);
        }
        if buf.len() < total {
            return Ok(None);
        }
        match msg_type {
            MSG_TYPE_RECORD => {
                if len < AEAD_TAG_LEN {
                    return Err(TransportError::InvalidRecord);
                }
                let mut body = buf[RECORD_HEADER_LEN..total].to_vec();
                let tag = body.split_off(body.len() - AEAD_TAG_LEN);
                let nonce = self.next_nonce();
                self.cipher
                    .decrypt_in_place_detached(&nonce, &[], &mut body, tag.as_slice().into())
                    .map_err(|_| TransportError::HandshakeFailed)?;
                Ok(Some((body, total)))
            }
            MSG_TYPE_ERROR => {
                // Error records are cleartext; surface them as a handshake failure.
                Err(TransportError::HandshakeFailed)
            }
            other => Err(TransportError::UnexpectedMessageType(other)),
        }
    }
}

/// Decode a stream of record frames, buffering partial input.
#[derive(Clone)]
pub struct RecordDecoder {
    cipher: RecordCipher,
    buf: Vec<u8>,
}

impl RecordDecoder {
    /// Create a decoder for one direction of a Noise session.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: RecordCipher::new(key),
            buf: Vec::new(),
        }
    }

    /// Append incoming bytes and decode as many complete records as possible.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        while let Some((plaintext, consumed)) = self.cipher.decode_one(&self.buf)? {
            out.extend_from_slice(&plaintext);
            self.buf.drain(..consumed);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trip() {
        let mut enc = RecordCipher::new([7u8; 32]);
        let mut dec = RecordCipher::new([7u8; 32]);
        let plaintext = b"hello over noise";
        let framed = enc.encode(plaintext).unwrap();
        let (decoded, consumed) = dec.decode_one(&framed).unwrap().unwrap();
        assert_eq!(decoded, plaintext);
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn splits_large_plaintext() {
        let mut enc = RecordCipher::new([1u8; 32]);
        let mut dec = RecordCipher::new([1u8; 32]);
        let plaintext = vec![0xabu8; MAX_RECORD_PLAINTEXT * 2 + 10];
        let framed = enc.encode(&plaintext).unwrap();
        let mut decoded = Vec::new();
        let mut offset = 0;
        while let Some((chunk, consumed)) = dec.decode_one(&framed[offset..]).unwrap() {
            decoded.extend_from_slice(&chunk);
            offset += consumed;
        }
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut dec = RecordCipher::new([2u8; 32]);
        let mut buf = vec![MSG_TYPE_RECORD, 0xff, 0xff];
        buf.extend_from_slice(&[0u8; MAX_RECORD_FRAME_SIZE]);
        assert_eq!(dec.decode_one(&buf), Err(TransportError::Oversized));
    }

    #[test]
    fn rejects_unexpected_type() {
        let mut dec = RecordCipher::new([3u8; 32]);
        let mut buf = vec![0x09, 0x00, 0x00];
        buf.extend_from_slice(&[0u8; 4]);
        assert_eq!(
            dec.decode_one(&buf),
            Err(TransportError::UnexpectedMessageType(0x09))
        );
    }

    #[test]
    fn decoder_buffers_partial_frames() {
        let mut enc = RecordCipher::new([4u8; 32]);
        let mut dec = RecordDecoder::new([4u8; 32]);
        let framed = enc.encode(b"streamed").unwrap();
        let first = dec.feed(&framed[..3]).unwrap();
        assert!(first.is_empty());
        let rest = dec.feed(&framed[3..]).unwrap();
        assert_eq!(rest, b"streamed");
    }
}
