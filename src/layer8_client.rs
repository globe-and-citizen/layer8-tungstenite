//! This module provides a stream that can be used to read and write data to a stream. The stream is encrypted and decrypted
//! using the shared secret provided.
//!
//! This streamer is expected to be used by server middleware implementations when intercepting the stream.

use std::io::{self, Cursor, Error, Read, Seek, SeekFrom, Write};

use layer8_primitives::crypto::Jwk;
use layer8_primitives::types::RoundtripEnvelope;

use crate::protocol::frame::coding::{Data as OpData, OpCode};
use crate::protocol::frame::{Frame, FrameSocket};
use crate::Message;

/// This streamer provides an indirection over the actual provided stream implementation. With the indirection we are able
/// to plug in custom logic for our layer8 needs.
///
/// Note: Expect read and write operations to be blocking, no guarantees are provided as development is still in flux.
#[derive(Debug)]
pub struct Layer8Streamer<Stream> {
    /// The actual stream that we are wrapping.
    frame_socket: FrameSocket<Stream>,
    /// The shared secret used to encrypt and decrypt the data, if provided.
    shared_secret: Option<Jwk>,
}

impl<Stream> Layer8Streamer<Stream> {
    /// Create a new Layer8Stream with the provided stream and shared secret.
    pub fn new(stream: Stream, shared_secret: Option<Jwk>) -> Self {
        let frame_socket = FrameSocket::new(stream);
        Layer8Streamer { frame_socket, shared_secret }
    }
}

impl<Stream: Read + Write> Layer8Streamer<Stream> {
    /// TODO
    pub fn read(&mut self) -> std::io::Result<Option<Message>> {
        self.read_message()
    }

    /// TODO
    pub fn send(&mut self, message: Message) -> std::io::Result<()> {
        self.write_message(message)?;
        Ok(_ = self.frame_socket.flush())
    }

    /// TODO
    pub fn write(&mut self, message: Message) -> std::io::Result<()> {
        self.write_message(message)
    }

    /// TODO
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.frame_socket.flush().map_err(|e| {
            Error::new(std::io::ErrorKind::Other, format!("Failed to flush frame socket: {}", e))
        })
    }

    fn write_message(&mut self, message: Message) -> std::io::Result<()> {
        let frame = match message {
            Message::Text(data) => Frame::message(data, OpCode::Data(OpData::Text), true),
            Message::Binary(data) => Frame::message(data, OpCode::Data(OpData::Binary), true),
            Message::Ping(data) => Frame::ping(data),
            Message::Pong(data) => Frame::pong(data),
            Message::Close(code) => Frame::close(code),
            Message::Frame(f) => f,
        };

        // if frame requires encryption, we encrypt it
        let frame = if let Some(secret_key) = &self.shared_secret {
            let mut frame_buf = Vec::new();
            frame.format_into_buf(&mut frame_buf).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("Failed to format frame: {}", e))
            })?;

            let encrypted_payload = RoundtripEnvelope::encode(
                &secret_key.symmetric_encrypt(&frame_buf).map_err(|e| {
                    Error::new(std::io::ErrorKind::Other, format!("Failed to encrypt frame: {}", e))
                })?,
            )
            .to_json_bytes();

            Frame::message(encrypted_payload, OpCode::Data(OpData::Binary), true)
        } else {
            frame
        };

        self.frame_socket.write(frame).map_err(|e| {
            Error::new(std::io::ErrorKind::Other, format!("Failed to write frame: {}", e))
        })
    }

    fn read_message(&mut self) -> std::io::Result<Option<Message>> {
        // we try to read a frame from the stream, if unable but with no errors, we return 0
        let mut frame = match self.frame_socket.read(None).map_err(|e| {
            Error::new(std::io::ErrorKind::Other, format!("Failed to read frame: {}", e))
        })? {
            Some(frame) => frame,
            None => return Ok(None),
        };

        // we expect the frame to be encrypted, unless secret is not provided
        if let Some(secret_key) = &self.shared_secret {
            let data = RoundtripEnvelope::from_json_bytes(frame.payload())
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

            let data_decrypted = secret_key.symmetric_decrypt(&data).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("Failed to decrypt response: {}", e))
            })?;

            // reading the nested frame
            let mut frame_socket = FrameSocket::new(Cursor::new(data_decrypted));
            frame = match frame_socket.read(None).map_err(|e| {
                Error::new(std::io::ErrorKind::Other, format!("Failed to read frame: {}", e))
            })? {
                Some(frame) => frame,
                None => {
                    return Err(Error::new(
                        std::io::ErrorKind::Other,
                        "Failed to read nested frame".to_string(),
                    ))
                }
            };
        }

        Ok(Some(Message::Frame(frame)))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};

    use layer8_primitives::crypto::{generate_key_pair, KeyUse};

    use crate::layer8_client::Layer8Streamer;

    #[test]
    fn test_stream() {
        let (private_key, public_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
        let symmetric_key = private_key.get_ecdh_shared_secret(&public_key).unwrap();

        let cursor = std::io::Cursor::new(Vec::new());
        let mut stream = Layer8Streamer::new(cursor, Some(symmetric_key));

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
