//! This module provides a stream that can be used to read and write data to a stream. The stream is encrypted and decrypted
//! using the shared secret provided.
//!
//! This streamer is expected to be used by server middleware implementations when intercepting the stream.

use std::io::{Cursor, Error, Read, Seek, Write};

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
    /// Read a message from the stream, if possible.
    pub fn read(&mut self) -> std::io::Result<Option<Message>> {
        self.read_message()
    }

    /// Send a message to the stream, if possible.
    pub fn send(&mut self, message: Message) -> std::io::Result<()> {
        self.write_message(message)?;
        Ok(_ = self.frame_socket.flush())
    }

    /// Write a message to the stream, if possible.
    pub fn write(&mut self, message: Message) -> std::io::Result<()> {
        self.write_message(message)
    }

    /// Flush the stream, if possible.
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
            // todo: rm
            println!("encrypting frame: {}", String::from_utf8_lossy(frame.payload()));

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

            // todo: rm
            println!("encrypted frame!");
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
            // todo: rm
            println!("decrypting frame!");

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

            // todo: rm
            println!("decrypted frame: {:?}", String::from_utf8_lossy(frame.payload()));
        }

        Ok(Some(Message::Frame(frame)))
    }
}

impl<Stream: Seek> Seek for Layer8Streamer<Stream> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.frame_socket.get_mut().seek(pos)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom};

    use bytes::Bytes;

    use layer8_primitives::crypto::{generate_key_pair, KeyUse};

    use crate::layer8_streamer::Layer8Streamer;

    #[test]
    fn test_stream() {
        let (private_key, public_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
        let symmetric_key = private_key.get_ecdh_shared_secret(&public_key).unwrap();

        let cursor = std::io::Cursor::new(Vec::new());
        let mut stream = Layer8Streamer::new(cursor, Some(symmetric_key));

        let payload = Bytes::from(b"Hello, World!".to_vec());

        stream.write(crate::Message::Ping(payload.clone())).unwrap();
        stream.seek(SeekFrom::Start(0)).unwrap(); // necessary for the cursor to read from the beginning

        // read test
        let msg = stream.read_message().unwrap().unwrap();
        matches!(msg, crate::Message::Ping(data) if data.eq(&payload));
    }
}
