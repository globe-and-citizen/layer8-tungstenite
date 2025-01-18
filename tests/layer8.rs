use std::{
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    thread::spawn,
};

use layer8_primitives::crypto::{generate_key_pair, Jwk, KeyUse};
use layer8_tungstenite::{accept, connect, Message};

#[test]
fn ping() {
    env_logger::init();
    let (private_key, public_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
    let symmetric_key = private_key.get_ecdh_shared_secret(&public_key).unwrap();

    // run server in background
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("Can't listen, is port already in use?"); // assigns a port from any available port

    println!("Using addr: {}", listener.local_addr().unwrap());

    let port = listener.local_addr().unwrap().port();
    let secret_key = symmetric_key.clone();
    {
        spawn(move || {
            layer8_server_conn(&listener, secret_key);
        });
    }

    let (mut socket, _) =
        connect(format!("ws://localhost:{}", port)).expect("Can't connect to port");
    socket.set_shared_secret(symmetric_key);

    socket.send(Message::Ping(b"ping from layer8".to_vec().into())).expect("Failed to send ping");

    let out_msg = socket.read().expect("Failed to read");

    println!("msg: {:?}", out_msg);

    socket.close(None).expect("close failed");
}

fn layer8_server_conn(listener: &TcpListener, symmetric_key: Jwk) {
    for stream in listener.incoming() {
        let symmetric_key = symmetric_key.clone();
        spawn(move || {
            let mut websocket = accept(stream.unwrap()).unwrap();
            websocket.set_shared_secret(symmetric_key.clone());
            websocket.set_config(|cfg| {
                cfg.accept_unmasked_frames = true; // we should be able to relax this requirement; todo @osoro
            });

            loop {
                let msg = websocket
                    .read()
                    .map_err(|e| {
                        println!("Error reading message: {:?}", e);
                    })
                    .unwrap();
                if msg.is_ping() {
                    if let Message::Ping(val) = msg {
                        println!("Received ping: {:?}", val);
                    }
                    websocket.send(Message::Pong(b"pong from layer8".to_vec().into())).unwrap();
                } else if msg.is_binary() || msg.is_text() {
                    websocket.send(msg).unwrap();
                }
            }
        });
    }
}
