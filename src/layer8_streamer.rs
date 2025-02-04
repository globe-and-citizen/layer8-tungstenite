//! This module provides a stream that can be used to read and write data to a stream. The stream is encrypted and decrypted
//! using the shared secret provided.
//!
//! This streamer is expected to be used by server middleware implementations when intercepting the stream.

use std::io::{Error, Read, Seek, Write};

use layer8_primitives::crypto::Jwk;
use layer8_primitives::types::RoundtripEnvelope;

const MAX_READ_LIMIT: u64 = 1024 * 1024 * 1024; // 1GB Default

/// This streamer provides an indirection over the actual provided stream implementation. With the indirection we are able
/// to plug in custom logic for our layer8 needs.
///
/// Note: Expect read and write operations to be blocking, no guarantees are provided as development is still in flux.
#[derive(Debug)]
pub struct Layer8Streamer<Stream> {
    /// The actual stream that we are wrapping.
    stream: Stream,
    /// The shared secret used to encrypt and decrypt the data, if provided.
    shared_secret: Option<Jwk>,
}

impl<Stream> Layer8Streamer<Stream> {
    /// Create a new Layer8Stream with the provided stream and shared secret.
    pub fn new(stream: Stream, shared_secret: Option<Jwk>) -> Self {
        Layer8Streamer { stream, shared_secret }
    }

    /// Get a reference to the underlying stream.
    pub fn get_ref(&self) -> &Stream {
        &self.stream
    }

    /// Get a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut Stream {
        &mut self.stream
    }
}

impl<Stream: Read + Write> Layer8Streamer<Stream> {
    /// Read a message from the stream, if possible.
    pub fn read(&mut self, read_limit: Option<u64>) -> std::io::Result<Option<Vec<u8>>> {
        self.read_message(read_limit)
    }

    /// Write a message to the stream, if possible.
    pub fn write(&mut self, message: &[u8]) -> std::io::Result<()> {
        self.write_message(message)
    }

    fn write_message(&mut self, message: &[u8]) -> std::io::Result<()> {
        let mut message = message.to_vec();
        if let Some(secret_key) = &self.shared_secret {
            message =
                RoundtripEnvelope::encode(&secret_key.symmetric_encrypt(&message).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("Failed to encrypt frame: {}", e))
                })?)
                .to_json_bytes()
        }

        self.stream
            .write(&message)
            .map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("Failed to write message: {}", e))
            })
            .map(|_| ())
    }

    fn read_message(&mut self, read_limit: Option<u64>) -> std::io::Result<Option<Vec<u8>>> {
        let mut data = Vec::new();
        {
            let stream_ref = std::io::Read::by_ref(&mut self.stream);
            stream_ref.take(read_limit.unwrap_or(MAX_READ_LIMIT)).read_to_end(&mut data)?;
            // drop our &mut stream_ref so we can use f again
        }

        // we expect the data to be encrypted, unless secret is not provided
        if let Some(secret_key) = &self.shared_secret {
            let data_ = RoundtripEnvelope::from_json_bytes(&data)
                .map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to parse json response: {}", e),
                    )
                })?
                .decode()
                .map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to decode response: {}", e),
                    )
                })?;

            data = secret_key.symmetric_decrypt(&data_).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("Failed to decrypt response: {}", e))
            })?;
        }

        Ok(Some(data))
    }
}

impl<Stream: Seek> Seek for Layer8Streamer<Stream> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.stream.seek(pos)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom};

    use layer8_primitives::crypto::{generate_key_pair, KeyUse};

    use crate::layer8_streamer::Layer8Streamer;

    #[test]
    fn test_stream() {
        let (private_key, public_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
        let symmetric_key = private_key.get_ecdh_shared_secret(&public_key).unwrap();

        let cursor = std::io::Cursor::new(Vec::new());
        let mut stream = Layer8Streamer::new(cursor, Some(symmetric_key));

        let payload = b"Hello, World!";

        stream.write(payload).unwrap();
        stream.seek(SeekFrom::Start(0)).unwrap(); // necessary for the cursor to read from the beginning

        // read test
        let msg = stream.read_message(None).unwrap().unwrap();
        matches!(msg, data if data.eq(&payload));
    }
}
