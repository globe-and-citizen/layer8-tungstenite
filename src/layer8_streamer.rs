//! This module provides a stream that can be used to read and write data to a stream. The stream is encrypted and decrypted
//! using the shared secret provided.
//!
//! This streamer is expected to be used by server middleware implementations when intercepting the stream.
use std::io::{self, Error, Read, Seek, SeekFrom, Write};

use layer8_primitives::crypto::Jwk;
use layer8_primitives::types::RoundtripEnvelope;

// use crate::protocol::frame::Frame;

/// This stream provides an indirection over the actual provided stream implementation. With the indirection we are able
/// to plug in custom logic for our layer8 needs.
///
/// Note: The writes and reads count reported are the unencrypted and decrypted message payloads.
#[derive(Debug)]
pub struct Layer8Stream<Stream> {
    stream: Stream,
    shared_secret: Jwk,
    // TODO: cleanup/gardening work for better debug code @Osoro
    // The websockets spec keeps track of the number of bytes written to the stream and is well formed at the header level.
    // In our case we have this naive marker for debug purposes.
    //
    // The tests assume no other writes are made, starts at pos 0.
    #[cfg(debug_assertions)]
    written_len: usize,
    #[cfg(debug_assertions)]
    read_len: usize,
}

impl<Stream> Layer8Stream<Stream> {
    /// Create a new Layer8Stream with the provided stream and shared secret.
    pub fn new(stream: Stream, shared_secret: Jwk) -> Self {
        #[cfg(not(debug_assertions))]
        {
            Layer8Stream { stream, shared_secret }
        }

        #[cfg(debug_assertions)]
        {
            Layer8Stream { stream, shared_secret, written_len: 0, read_len: 0 }
        }
    }
}

// TODO: Bug: update to respect Frames @Osoro
impl<Stream: Read> Read for Layer8Stream<Stream> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let encrypted_read_len = self.stream.read(buf)?;
        if encrypted_read_len == 0 {
            return Ok(0);
        }

        #[cfg(debug_assertions)]
        {
            self.read_len = encrypted_read_len;
        }

        // fixme, wtf is this :) @osoro
        // Base64 only contains A–Z , a–z , 0–9 , + , / and =
        // Format {"data":"base64str"}
        let mut well_formed_payload = vec![];
        for (i, c) in buf.iter().enumerate() {
            if b'}' == *c {
                well_formed_payload = buf[..=i].to_vec();
            }
        }

        if well_formed_payload.is_empty() || well_formed_payload.last().unwrap() != &b'}' {
            return Err(Error::new(
                std::io::ErrorKind::Other,
                "The payload is not well formed for json parsing",
            ));
        }

        let data_decrypted = {
            let envelope_data = RoundtripEnvelope::from_json_bytes(&well_formed_payload)
                .map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "Failed to parse json response: {}\n Body is: {}",
                            e,
                            String::from_utf8_lossy(buf)
                        ),
                    )
                })?
                .decode()
                .map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to decode response: {}", e),
                    )
                })?;

            self.shared_secret.symmetric_decrypt(&envelope_data).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("Failed to decrypt response: {}", e))
            })?
        };

        println!("data decrypted: {:?}", String::from_utf8_lossy(&data_decrypted));

        // Frame::

        let mut reader = std::io::Cursor::new(data_decrypted);
        let read_len = reader.read(buf)?;

        Ok(read_len)
    }
}

// TODO: Bug: update to respect Frames @Osoro
impl<Stream: Write> Write for Layer8Stream<Stream> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let data_encrypted =
            RoundtripEnvelope::encode(&self.shared_secret.symmetric_encrypt(buf).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("Failed to encrypt data: {}", e))
            })?)
            .to_json_bytes();

        let encrypted_written = self.stream.write(&data_encrypted)?;
        if encrypted_written.ne(&data_encrypted.len()) {
            return Err(Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Failed to write all encrypted data. Expected: {}, Written: {}",
                    data_encrypted.len(),
                    encrypted_written
                ),
            ));
        }

        #[cfg(debug_assertions)]
        {
            self.written_len = encrypted_written;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(debug_assertions)]
impl<Stream: Seek> Seek for Layer8Stream<Stream> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.stream.seek(pos)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};

    use layer8_primitives::crypto::{generate_key_pair, KeyUse};

    use crate::layer8_streamer::Layer8Stream;

    #[test]
    fn test_stream() {
        let (private_key, public_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
        let symmetric_key = private_key.get_ecdh_shared_secret(&public_key).unwrap();

        let cursor = std::io::Cursor::new(Vec::new());
        let mut stream = Layer8Stream::new(cursor, symmetric_key);

        let payload = b"Hello, World!";

        // write test
        let reported_written = stream.write(payload).unwrap();
        assert!(stream.written_len > payload.len());
        assert_eq!(reported_written, payload.len());

        // read test
        stream.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = vec![0u8; stream.written_len]; // This information is provided by the websocket header in actual implementation.
        let reported_read = stream.read(&mut buf).unwrap();

        // we expect the stream to have data to read from and it should be the same as the payload
        assert!(
            reported_read == payload.len(),
            "Expected: {}, Got: {}",
            payload.len(),
            reported_read
        );

        // assert the payload is the same as the read data
        assert_eq!(payload, &buf[..reported_read]);
    }
}
