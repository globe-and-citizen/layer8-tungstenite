use std::io::{self, Error, Read, Seek, SeekFrom, Write};

use layer8_primitives::crypto::Jwk;
use layer8_primitives::types::RoundtripEnvelope;

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

#[cfg(not(debug_assertions))]
impl<Stream: Read + Write> Layer8Stream<Stream> {
    pub fn new(stream: Stream, shared_secret: Jwk) -> Self {
        Layer8Stream { stream, shared_secret }
    }
}

#[cfg(debug_assertions)]
impl<Stream: Read + Write + Seek> Layer8Stream<Stream> {
    fn new_with_seekable(stream: Stream, shared_secret: Jwk) -> Self {
        Layer8Stream { stream, shared_secret, written_len: 0, read_len: 0 }
    }
}

impl<Stream: Read + Write> Layer8Stream<Stream> {
    // This method is an indirection that implements the Read trait for the Layer8Stream.
    // the output is the number of bytes we should report to the caller and the number of actual bytes written
    // that were encrypted and written to the stream.
    #[inline]
    fn common_write(&mut self, buf: &[u8]) -> io::Result<(usize, usize)> {
        if buf.is_empty() {
            return Ok((0, 0));
        }

        let data_encrypted =
            RoundtripEnvelope::encode(&self.shared_secret.symmetric_encrypt(&buf).map_err(
                |e| Error::new(std::io::ErrorKind::Other, format!("Failed to encrypt data: {}", e)),
            )?)
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

        Ok((encrypted_written, buf.len()))
    }

    // This method is an indirection that implements the Read trait for the Layer8Stream.
    // the output is the number of bytes we should report to the caller and the number of actual bytes read
    // that were read from the stream and decrypted.
    #[inline]
    fn common_read(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        let encrypted_read_len = self.stream.read(buf)?;
        if encrypted_read_len == 0 {
            return Ok((0, 0));
        }

        let data_decrypted = {
            let envelope_data = RoundtripEnvelope::from_json_bytes(&buf)
                .map_err(|e| {
                    Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "Failed to parse json response: {}\n Body is: {}",
                            e,
                            String::from_utf8_lossy(&buf)
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

        println!("data decrypted: \n{:?}", String::from_utf8_lossy(&data_decrypted));

        let mut reader = std::io::Cursor::new(data_decrypted);
        let read_len = reader.read(buf)?;
        if read_len == 0 {
            return Ok((0, 0));
        }

        Ok((encrypted_read_len, read_len))
    }
}

#[cfg(not(debug_assertions))]
impl<Stream: Read + Write> Read for Layer8Stream<Stream> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let (_, read_len) = self.common_read(buf)?;
        Ok(read_len)
    }
}

#[cfg(debug_assertions)]
impl<Stream: Read + Write + Seek> Read for Layer8Stream<Stream> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let (encrypted_read, read_len) = self.common_read(buf)?;
        self.read_len = encrypted_read;
        Ok(read_len)
    }
}

#[cfg(not(debug_assertions))]
impl<Stream: Read + Write> Write for Layer8Stream<Stream> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let (_, reported) = self.common_write(buf)?;
        Ok(reported)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(debug_assertions)]
impl<Stream: Read + Write + Seek> Write for Layer8Stream<Stream> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (encrypted_written, reported) = self.common_write(buf)?;
        self.written_len = encrypted_written;
        Ok(reported)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(debug_assertions)]
impl<Stream: Read + Write + Seek> Seek for Layer8Stream<Stream> {
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
        let mut stream = Layer8Stream::new_with_seekable(cursor, symmetric_key);

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

        println!("buf: {:?}", String::from_utf8_lossy(&buf[..reported_read]));

        // assert the payload is the same as the read data
        assert_eq!(payload, &buf[..reported_read]);
    }
}
