use std::io::Error;
use std::{io::Read, io::Write};

use layer8_primitives::crypto::Jwk;
use layer8_primitives::types::RoundtripEnvelope;

/// This stream provides an indirection over the actual provided stream implementation. With the indirection we are able
/// to plug in custom logic for our layer8 needs.
#[derive(Debug)]
pub struct Layer8Stream<Stream: Read + Write> {
    stream: Stream,
    shared_secret: Jwk,
}

impl<Stream: Read + Write> Layer8Stream<Stream> {
    /// Create a new Layer8Stream object.
    pub fn new(stream: Stream, shared_secret: Jwk) -> Self {
        Layer8Stream { stream, shared_secret }
    }
}

impl<Stream: Read + Write> Read for Layer8Stream<Stream> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let data_read = Vec::new();
        if data_read.is_empty() {
            return Ok(0);
        }

        let data_decrypted =
            RoundtripEnvelope::encode(&self.shared_secret.symmetric_decrypt(&data_read).map_err(
                |e| Error::new(std::io::ErrorKind::Other, format!("Failed to decrypt data: {}", e)),
            )?)
            .to_json_bytes();

        // unsafe copy
        buf.copy_from_slice(&data_decrypted);
        return Ok(data_decrypted.len());
    }
}

impl<Stream: Read + Write> Write for Layer8Stream<Stream> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let data_encrypted = self.shared_secret.symmetric_encrypt(&buf).map_err(|e| {
            Error::new(std::io::ErrorKind::Other, format!("Failed to encrypt data: {}", e))
        })?;

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

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use layer8_primitives::crypto::{generate_key_pair, KeyUse};

    use crate::layer8_streamer::Layer8Stream;

    #[test]
    fn test_stream() {
        let payload = b"Hello, World!";
        let (private_key, public_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
        let symmetric_key = private_key.get_ecdh_shared_secret(&public_key).unwrap();

        let mut stream = Layer8Stream::new(std::io::Cursor::new(Vec::new()), symmetric_key);
        let reported_write = stream.write(payload).unwrap();

        // we expect though the data to be encrypted the reported write was what was provided
        assert!(reported_write == payload.len());

        // we expect the stream to have data to read from and it should be the same as the payload
        let mut read_data = Vec::new();
        // let reported_read = stream.read(&mut read_data).unwrap();
        // assert!(reported_read == payload.len());

        // assert the payload is the same as the read data
        // assert_eq!(payload, read_data.as_slice());
    }
}
