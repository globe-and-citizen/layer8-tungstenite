use js_sys::{ArrayBuffer, Function, Object, Uint8Array};
use wasm_bindgen::prelude::*;
use web_sys::{BinaryType, Blob, WebSocket as BrowserWebSocket};

use layer8_primitives::crypto::Jwk;

/// WebSocket input-output stream using the browser's WebSocket API. This is necessary for
/// WebAssembly interop.
///
/// We are skipping Typescript since we need to leverage function overloading in our implementation, the overloads implementation
/// is finalized in a script since we can't do it in Rust.
#[wasm_bindgen(js_name = WebSocket, skip_typescript)]
#[derive(Debug)]
pub struct WasmWebSocket {
    socket: BrowserWebSocket,
    symmetric_key: Jwk,
}

enum SendVariants {
    Str(String),
    Blob(Blob),
    ArrayBuffer(ArrayBuffer),
    ArrayBufferView(Object),
    U8Array(Vec<u8>),
    JsU8Array(Uint8Array),
}

impl WasmWebSocket {
    /// Create this websocket wrapper.
    ///
    /// Also all plumbing for initialized connection is expected to have been done by the time we are calling this function.
    pub fn init(socket: BrowserWebSocket, secret_key: Jwk) -> Result<Self, JsValue> {
        Ok(WasmWebSocket { socket, symmetric_key: secret_key })
    }

    fn on_send(&self, data: SendVariants) -> Result<(), JsValue> {
        let data = self.encrypt(data);
        self.socket.send_with_u8_array(&data)
    }

    fn on_receive(&self, pipeline: Option<Function>) {
        todo!()

        //     self.0.set_onmessage(value.as_ref());
    }

    #[inline]
    fn encrypt(&self, data: SendVariants) -> Vec<u8> {
        let data: Vec<u8> = match data {
            SendVariants::Str(data) => data.as_bytes().into(),
            SendVariants::Blob(data) => Uint8Array::new(&data.array_buffer()).to_vec(),
            SendVariants::ArrayBuffer(data) => Uint8Array::new(&data).to_vec(),
            SendVariants::ArrayBufferView(data) => {
                todo!()
            }
            SendVariants::U8Array(data) => data,
            SendVariants::JsU8Array(data) => data.to_vec(),
        };

        self.symmetric_key
            .symmetric_encrypt(&data)
            .expect("this operation should be infalliable; report bug to the Layer8 team.")
    }
}

// This block implements the browser APIs for the WebAssembly interop.
#[wasm_bindgen(js_class = WebSocket)]
impl WasmWebSocket {
    /// Getter for the `url` field of this object.
    pub fn url(&self) -> String {
        self.socket.url()
    }

    /// Getter for the `readyState` field of this object.
    pub fn ready_state(&self) -> u16 {
        self.socket.ready_state()
    }

    /// Getter for the `bufferedAmount` field of this object.
    pub fn buffered_amount(&self) -> u32 {
        self.socket.buffered_amount()
    }

    /// Getter for the `onopen` field of this object.
    pub fn onopen(&self) -> Option<Function> {
        self.socket.onopen()
    }

    /// Setter for the `onopen` field of this object.
    pub fn set_onopen(&self, value: Option<Function>) {
        self.socket.set_onopen(value.as_ref());
    }

    /// Getter for the `onerror` field of this object.
    pub fn onerror(&self) -> Option<Function> {
        self.socket.onerror()
    }

    /// Setter for the `onerror` field of this object.
    pub fn set_onerror(&self, value: Option<Function>) {
        self.socket.set_onerror(value.as_ref());
    }

    /// Getter for the `onclose` field of this object.
    pub fn onclose(&self) -> Option<Function> {
        self.socket.onclose()
    }

    /// Setter for the `onclose` field of this object.
    pub fn set_onclose(&self, value: Option<Function>) {
        self.socket.set_onclose(value.as_ref());
    }

    /// Getter for the `extensions` field of this object.
    pub fn extensions(&self) -> String {
        self.socket.extensions()
    }

    /// Getter for the `protocol` field of this object.
    pub fn protocol(&self) -> String {
        self.socket.protocol()
    }

    /// Getter for the `binaryType` field of this object.
    pub fn onmessage(&self) -> Option<Function> {
        self.socket.onmessage()
    }

    /// Setter for the `binaryType` field of this object.
    pub fn set_onmessage(&self, value: Option<Function>) {
        self.on_receive(value);
    }

    /// Getter for the `binaryType` field of this object.
    pub fn binary_type(&self) -> BinaryType {
        self.socket.binary_type()
    }

    /// Setter for the `binaryType` field of this object.
    pub fn set_binary_type(&self, value: BinaryType) {
        self.socket.set_binary_type(value);
    }

    // /// Constructor for the `WebSocket` object.
    // #[wasm_bindgen(constructor)]
    // pub fn new(url: &str) -> Result<Self, JsValue> {
    //     WasmWebSocket::init(BrowserWebSocket::new(url)?)
    // }

    // /// Constructor for the `WebSocket` object.
    // // we need a script to include this override: todo
    // pub fn new_with_str(url: &str, protocols: &str) -> Result<Self, JsValue> {
    //     WasmWebSocket::init(BrowserWebSocket::new_with_str(url, protocols)?)
    // }

    // /// Constructor for the `WebSocket` object.
    // // we need a script to include this override: todo
    // pub fn new_with_str_sequence(url: &str, protocols: &JsValue) -> Result<WasmWebSocket, JsValue> {
    //     WasmWebSocket::init(BrowserWebSocket::new_with_str_sequence(url, protocols)?)
    // }

    /// close the connection
    pub fn close(&self) -> Result<(), JsValue> {
        self.socket.close()
    }

    /// close the connection
    // we need a script to include this override: todo
    pub fn close_with_code(&self, code: u16) -> Result<(), JsValue> {
        self.socket.close_with_code(code)
    }

    /// close the connection
    // we need a script to include this override: todo
    pub fn close_with_code_and_reason(&self, code: u16, reason: &str) -> Result<(), JsValue> {
        self.socket.close_with_code_and_reason(code, reason)
    }

    /// close the connection
    // we need a script to include this override: todo
    pub fn send_with_str(&self, data: &str) -> Result<(), JsValue> {
        self.socket.send_with_str(data)
    }

    /// close the connection
    // we need a script to include this override: todo
    pub fn send_with_blob(&self, data: &Blob) -> Result<(), JsValue> {
        self.socket.send_with_blob(data)
    }

    /// send the data to the connection
    // we need a script to include this override: todo
    pub fn send_with_array_buffer(&self, data: &ArrayBuffer) -> Result<(), JsValue> {
        self.socket.send_with_array_buffer(data)
    }

    /// send the data to the connection
    // we need a script to include this override: todo
    pub fn send_with_array_buffer_view(&self, data: &Object) -> Result<(), JsValue> {
        self.socket.send_with_array_buffer_view(data)
    }

    /// send the data to the connection
    // we need a script to include this override: todo
    pub fn send_with_u8_array(&self, data: &[u8]) -> Result<(), JsValue> {
        self.socket.send_with_u8_array(data)
    }

    /// send the data to the connection
    // we need a script to include this override: todo
    pub fn send_with_js_u8_array(&self, data: &Uint8Array) -> Result<(), JsValue> {
        self.socket.send_with_js_u8_array(data)
    }
}
