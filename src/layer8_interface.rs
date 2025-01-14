// // //! This module defines the Layer 8 interface for the Layer 8 protocol.

// // use std::io::Error;
// // use std::{io::Read, io::Write};

// // use http::Uri;
// // use layer8_primitives::crypto::Jwk;
// // use layer8_primitives::types::RoundtripEnvelope;

// // use crate::handshake::client::Response;
// // use crate::protocol::WebSocket;
// // use crate::{ClientHandshake, HandshakeError};

// // /// This trait is used to define the interactions we expect from a WebSocket client. It serves as an indirection
// // /// to the actual WebSocket client implementation.
// // pub trait WebsocketClient {
// //     /// Connect to a WebSocket server and return a WebSocket client object.
// //     fn connect<Stream>(
// //         &self,
// //         shared_secret: layer8_primitives::crypto::Jwk,
// //     ) -> Result<(WebSocket<Stream>, Response), HandshakeError<ClientHandshake<Stream>>>
// //     where
// //         Stream: Read + Write;
// // }

// // /// This struct represents a WebSocket client that uses the Layer 8 protocol.
// // #[derive(Debug, Clone)]
// // pub struct Layer8WebsocketClient {
// //     uri: Uri,
// // }

// // impl Layer8WebsocketClient {
// //     /// Create a new WebSocket client object.
// //     pub fn new(url: &str) -> Result<Self, String> {
// //         Ok(Layer8WebsocketClient {
// //             uri: url.parse::<http::Uri>().map_err(|e| format!("Invalid URL: {}", e))?,
// //         })
// //     }
// // }

// // fn ws_before_write(
// //     data: &[u8],
// //     shared_secret: &layer8_primitives::crypto::Jwk,
// // ) -> Result<Vec<u8>, String> {
// //     Ok(shared_secret
// //         .symmetric_encrypt(&data)
// //         .map_err(|e| format!("Failed to encrypt request: {}", e))?)
// // }

// // fn ws_after_read(
// //     data: &[u8],
// //     shared_secret: &layer8_primitives::crypto::Jwk,
// // ) -> Result<Vec<u8>, String> {
// //     Ok(data = RoundtripEnvelope::encode(
// //         &shared_secret
// //             .symmetric_decrypt(&data)
// //             .map_err(|e| format!("Failed to encrypt request: {}", e))?,
// //     )
// //     .to_json_bytes())
// // }

// // impl WebsocketClient for Layer8WebsocketClient {
// //     fn connect<Stream>(
// //         &self,
// //         shared_secret: layer8_primitives::crypto::Jwk,
// //     ) -> Result<(WebSocket<Stream>, Response), HandshakeError<ClientHandshake<Stream>>>
// //     where
// //         Stream: Read + Write,
// //     {
// //         unimplemented!()
// //     }
// // }

// // /// This trait is used to define the interactions we expect from a WebSocket server. It serves as an indirection
// // /// to the actual WebSocket server implementation.
// // pub trait WebsocketServer {}

// // #[cfg(test)]
// // mod tests {
// //     use super::Layer8WebsocketClient;

// //     #[test]
// //     fn normal_ws_example() {

// //         // let ws_client = Layer8WebsocketClient
// //     }
// // }

// use std::io::Error;
// use std::{io::Read, io::Write};

// use layer8_primitives::crypto::Jwk;
// use layer8_primitives::types::RoundtripEnvelope;

// /// This stream provides an indirection over the actual provided stream implementation. With the indirection we are able
// /// to plug in custom logic for our layer8 needs.
// #[derive(Debug)]
// pub struct Layer8Stream<Stream: Read + Write> {
//     stream: Stream,
//     shared_secret: Jwk,
// }

// impl<Stream: Read + Write> Layer8Stream<Stream> {
//     /// Create a new Layer8Stream object.
//     pub fn new(stream: Stream, shared_secret: Jwk) -> Self {
//         Layer8Stream { stream, shared_secret }
//     }
// }

// impl<Stream: Read + Write> Read for Layer8Stream<Stream> {
//     fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
//         let mut data_read = Vec::new();
//         self.stream.read_to_end(&mut data_read)?;
//         let data_decrypted =
//             RoundtripEnvelope::encode(&self.shared_secret.symmetric_decrypt(&data_read).map_err(
//                 |e| Error::new(std::io::ErrorKind::Other, format!("Failed to decrypt data: {}", e)),
//             )?)
//             .to_json_bytes()
//             .as_slice();

//         buf.copy_from_slice(&data_decrypted);
//         return Ok(data_decrypted.len());
//     }
// }

// impl<Stream: Read + Write> Write for Layer8Stream<Stream> {
//     fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
//         let data_encrypted = self.shared_secret.symmetric_encrypt(&buf).map_err(|e| {
//             Error::new(std::io::ErrorKind::Other, format!("Failed to encrypt data: {}", e))
//         })?;

//         self.stream.write(&data_encrypted);
//         Ok(buf.len())
//     }

//     fn flush(&mut self) -> std::io::Result<()> {
//         self.stream.flush()
//     }
// }
