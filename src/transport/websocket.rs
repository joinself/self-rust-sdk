use crossbeam::channel;
use crossbeam::channel::{Receiver, Sender};
//use futures_util::{SinkExt, StreamExt};
use tokio::runtime::Runtime;
//use tokio::sync::Mutex;
//use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;

//use std::collections::HashMap;
use std::sync::Arc;
//use std::time::{Duration, Instant};

use crate::error::SelfError;
use crate::identifier::Identifier;
use crate::keypair::signing::KeyPair;
use crate::protocol;
use crate::token::Token;
//use crate::session::Session;

enum Event {
    Message(
        String,
        Message,
        Option<Arc<dyn Fn(Result<(), SelfError>) + Sync + Send>>,
    ),
    Done,
}

pub struct Websocket {
    endpoint: Url,
    read_tx: Sender<(Vec<u8>, Vec<u8>)>,
    read_rx: Receiver<(Vec<u8>, Vec<u8>)>,
    write_tx: Sender<Event>,
    write_rx: Receiver<Event>,
    runtime: Runtime,
    inboxes: Vec<KeyPair>,
}

impl Websocket {
    pub fn new(
        url: &str,
        self_id: &str,
        device_id: &str,
        signing_key: KeyPair,
    ) -> std::result::Result<Websocket, SelfError> {
        let endpoint = match Url::parse(url) {
            Ok(endpoint) => endpoint,
            Err(_) => return Err(SelfError::RestRequestURLInvalid),
        };

        let (read_tx, read_rx) = channel::bounded(256);
        let (write_tx, write_rx) = channel::bounded(256);

        let runtime = Runtime::new().unwrap();

        let ws = Websocket {
            endpoint: endpoint,
            read_tx: read_tx,
            read_rx: read_rx,
            write_tx: write_tx,
            write_rx: write_rx,
            runtime: runtime,
            inboxes: Vec::new(),
        };

        return Ok(ws);
    }

    /*
    pub fn connect(&mut self, offset: i64) -> std::result::Result<(), SelfError> {
        let handle = self.runtime.handle();
        let endpoint = self.endpoint.clone();
        let write_tx = self.write_tx.clone();
        let write_rx = self.write_rx.clone();
        let read_tx = self.read_tx.clone();

        // TODO cleanup old sockets!

        let (tx, rx) = channel::bounded(1);
        let requests: Arc<
            Mutex<HashMap<String, Arc<dyn Fn(Result<(), SelfError>) + Send + Sync>>>,
        > = Arc::new(Mutex::new(HashMap::new()));
        let requests_rx = requests.clone();
        let requests_tx = requests.clone();

        handle.spawn(async move {
            let result = match connect_async(&endpoint).await {
                Ok((socket, _)) => Ok(socket),
                Err(err) => {
                    println!("{}", err);
                    Err(SelfError::RestRequestConnectionFailed)
                }
            };

            tx.send(result).unwrap();
        });

        let (mut socket_tx, mut socket_rx) = rx
            .recv()
            .map_err(|_| SelfError::RestRequestConnectionFailed)??
            .split();

        handle.spawn(async move {
            while let Some(event) = socket_rx.next().await {
                let event = match event {
                    Ok(event) => event,
                    Err(_) => return,
                };

                if event.is_close() {
                    write_tx.send(Event::Done).unwrap();
                    return;
                }

                if event.is_ping() {
                    continue;
                }

                if event.is_pong() {
                    continue;
                }

                if event.is_binary() {
                    let data = event.into_data();

                    let event = crate::protocol::root_as_event(&data)
                        .expect("Failed to process websocket event");

                    /*
                    match event.type_() {
                        crate::protocol::MsgType::ACK => {
                            let notification = crate::protocol::root_as_notification(&data)
                                .expect("Failed to process notification event");

                            if let Some(id) = notification.id() {
                                let lock = requests_rx.lock().await;

                                if let Some(callback) = lock.get(id) {
                                    callback(Ok(()));
                                }

                                drop(lock);
                            }
                        }
                        crate::protocol::MsgType::ERR => {
                            let notification = crate::protocol::root_as_notification(&data)
                                .expect("Failed to process notification event");

                            if let Some(id) = notification.id() {
                                let lock = requests_rx.lock().await;

                                if let Some(callback) = lock.get(id) {
                                    // TODO implement correct error handling here
                                    callback(Err(SelfError::RestRequestConnectionFailed));
                                }

                                drop(lock);
                            }
                        }
                        crate::protocol::MsgType::MSG => {
                            let message = crate::protocol::root_as_message(&data)
                                .expect("Failed to process message event");

                            read_tx
                                .send((
                                    message.sender().unwrap().as_bytes().to_vec(),
                                    message.ciphertext().unwrap().to_vec(),
                                ))
                                .unwrap_or_else(|_| return);
                        }
                        _ => {}
                    }
                     */
                }
            }
        });

        // TODO replace RestRequestConnectionFailed with better errors
        handle.spawn(async move {
            for m in write_rx.iter() {
                match m {
                    Event::Message(id, msg, callback) => match {
                        if let Some(cb) = callback {
                            let mut lock = requests_tx.lock().await;
                            lock.insert(id, cb);
                            drop(lock);
                        }
                        socket_tx.send(msg).await
                    } {
                        Ok(_) => continue,
                        Err(_) => break,
                    },
                    Event::Done => break,
                }
            }
            socket_tx.close().await.expect("Failed to close socket");
        });

        let (tx, rx) = channel::bounded(1);
        //let (event_id, auth_message) = self.authenticate_message(offset)?;
        let deadline = Instant::now() + Duration::from_secs(5);

        let callback = Arc::new(move |result: Result<(), SelfError>| {
            tx.send(result)
                .expect("Failed to send authentication response");
        });

        self.write_tx
            .send(Event::Message(
                event_id,
                Message::Binary(auth_message),
                Some(callback),
            ))
            .map_err(|_| SelfError::RestRequestConnectionTimeout)?;

        return rx
            .recv_deadline(deadline)
            .map_err(|_| SelfError::RestRequestConnectionTimeout)?;
    }

    pub fn disconnect(&mut self) -> Result<(), SelfError> {
        return self
            .write_tx
            .send(Event::Done)
            .map_err(|_| SelfError::RestRequestConnectionFailed);
    }

    pub fn send(
        &self,
        recipients: Vec<&str>,
        message_type: &str,
        priority: u32,
        ciphertext: &[u8],
        callback: Arc<dyn Fn(Result<(), SelfError>) + Sync + Send>,
    ) {
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        for recipient in &recipients {
            builder.reset();

            let event_id = crate::transport::uuid();

            let id = builder.create_string(&event_id);
            let sender = builder.create_string(&self.sender_id);
            let recipient = builder.create_string(&recipient);
            let message_type = builder.create_vector(message_type.as_bytes());
            let ciphertext = builder.create_vector(ciphertext);

            let message = protocol::Message::create(
                &mut builder,
                &protocol::MessageArgs {
                    id: Some(id),
                    msgtype: protocol::MsgType::MSG,
                    subtype: protocol::MsgSubType::Unknown,
                    sender: Some(sender),
                    recipient: Some(recipient),
                    message_type: Some(message_type),
                    ciphertext: Some(ciphertext),
                    priority: priority,
                    collapse_key: None,
                    notification_payload: None,
                    metadata: Some(&protocol::Metadata::new(0, 0)),
                },
            );

            builder.finish(message, None);

            let msg = Vec::from(builder.finished_data());

            let event = Event::Message(event_id, Message::Binary(msg), Some(Arc::clone(&callback)));

            if let Err(_) = self.write_tx.send(event) {
                // TODO handle this error properly
                callback(Err(SelfError::RestRequestConnectionTimeout));
            }
        }
    }
    */

    pub fn assemble_payload(
        &self,
        from: &Identifier,
        to: &Identifier,
        sequence: u64,
        content: &[u8],
    ) -> Result<Vec<u8>, SelfError> {
        match from {
            Identifier::Owned(_) => {}
            _ => return Err(SelfError::WebsocketSenderIdentifierNotOwned),
        }

        // TODO pool/reuse these builders
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        let sender = builder.create_vector(&from.id());
        let recipient = builder.create_vector(&to.id());
        let content = builder.create_vector(content);

        let payload = protocol::Payload::create(
            &mut builder,
            &protocol::PayloadArgs {
                sender: Some(sender),
                recipient: Some(recipient),
                content: Some(content),
                sequence: sequence,
                timestamp: crate::time::unix(),
            },
        );

        builder.finish(payload, None);

        return Ok(builder.finished_data().to_vec());
    }

    pub fn assemble_message(
        &self,
        from: &Identifier,
        payload: &[u8],
        tokens: Option<Vec<Token>>,
    ) -> Result<(Vec<u8>, Vec<u8>), SelfError> {
        let owned_identifier = match from {
            Identifier::Owned(owned) => owned,
            _ => return Err(SelfError::WebsocketSenderIdentifierNotOwned),
        };

        // TODO pool/reuse these builders
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        let mut payload_sig_buf = vec![0; payload.len() + 1];
        payload_sig_buf[0] = protocol::SignatureType::PAYLOAD.0 as u8;
        payload_sig_buf[1..payload.len() + 1].copy_from_slice(&payload);
        let payload_sig = owned_identifier.sign(&payload_sig_buf);

        let mut signatures = Vec::new();

        let sig = builder.create_vector(&payload_sig);

        signatures.push(protocol::Signature::create(
            &mut builder,
            &protocol::SignatureArgs {
                type_: protocol::SignatureType::PAYLOAD,
                signer: None,
                signature: Some(sig),
            },
        ));

        if let Some(tokens) = tokens {
            for token in &tokens {
                match token {
                    Token::Authorization(auth) => {
                        let sig = builder.create_vector(&auth.token);

                        signatures.push(protocol::Signature::create(
                            &mut builder,
                            &protocol::SignatureArgs {
                                type_: protocol::SignatureType::AUTH,
                                signer: None,
                                signature: Some(sig),
                            },
                        ));
                    }
                    Token::Delegation(delegation) => {
                        let sig = builder.create_vector(&delegation.token);
                        let iss = builder.create_vector(&delegation.issuer.id());

                        signatures.push(protocol::Signature::create(
                            &mut builder,
                            &protocol::SignatureArgs {
                                type_: protocol::SignatureType::AUTH,
                                signer: Some(iss),
                                signature: Some(sig),
                            },
                        ));
                    }
                    _ => {
                        return Err(SelfError::WebsocketTokenUnsupported);
                    }
                }
            }
        } else {
            // TODO generate proof of work ...
        }

        let pld = builder.create_vector(payload);
        let sigs = builder.create_vector(&signatures);

        let msg = protocol::Message::create(
            &mut builder,
            &protocol::MessageArgs {
                payload: Some(pld),
                signatures: Some(sigs),
                pow: None,
            },
        );

        builder.finish(msg, None);

        let content = builder.finished_data().to_vec();

        builder.reset();

        let event_id = crate::crypto::random_id();

        let eid = builder.create_vector(&event_id);
        let cnt = builder.create_vector(&content);

        let event = protocol::Event::create(
            &mut builder,
            &protocol::EventArgs {
                id: Some(eid),
                type_: protocol::ContentType::MESSAGE,
                content: Some(cnt),
            },
        );

        builder.finish(event, None);

        return Ok((event_id, builder.finished_data().to_vec()));
    }

    pub fn receive(&mut self) -> Result<(Vec<u8>, Vec<u8>), SelfError> {
        return self
            .read_rx
            .recv()
            .map_err(|_| SelfError::RestRequestConnectionTimeout);
    }
}

/*
#[cfg(test)]
mod tests {
    use crate::protocol::MsgSubType;

    use super::*;
    use futures_util::stream::SplitSink;
    //use futures_util::{SinkExt, StreamExt};
    use tokio::{
        io::{AsyncRead, AsyncWrite},
        net::TcpListener,
    };
    use tokio_tungstenite::tungstenite::protocol::Message;
    use tokio_tungstenite::{accept_async, WebSocketStream};

    async fn ack<S>(socket_tx: &mut SplitSink<WebSocketStream<S>, Message>, id: &str)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let id = builder.create_string(id);

        let notification = protocol::Notification::create(
            &mut builder,
            &protocol::NotificationArgs {
                msgtype: protocol::MsgType::ACK,
                id: Some(id),
                error: None,
                errtype: crate::protocol::ErrType::ErrACL, // TODO define an ErrNone
            },
        );

        builder.finish(notification, None);

        (*socket_tx)
            .send(Message::binary(builder.finished_data()))
            .await
            .expect("Failed to send ACK");
    }

    async fn err<S>(socket_tx: &mut SplitSink<WebSocketStream<S>, Message>, id: &str, reason: &str)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let id = builder.create_string(id);
        let err = builder.create_string(reason);

        let notification = protocol::Notification::create(
            &mut builder,
            &protocol::NotificationArgs {
                msgtype: protocol::MsgType::ERR,
                id: Some(id),
                error: Some(err),
                errtype: crate::protocol::ErrType::ErrConnection, // TODO define an ErrNone
            },
        );

        builder.finish(notification, None);

        (*socket_tx)
            .send(Message::binary(builder.finished_data()))
            .await
            .expect("Failed to send ERR");
    }

    async fn msg<S>(
        socket_tx: &mut SplitSink<WebSocketStream<S>, Message>,
        sender: &str,
        recipient: &str,
        ciphertext: &str,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let id = builder.create_string(&crate::transport::uuid());
        let sender = builder.create_string(sender);
        let recipient = builder.create_string(recipient);
        let ciphertext = builder.create_vector(ciphertext.as_bytes());

        let message = protocol::Message::create(
            &mut builder,
            &protocol::MessageArgs {
                msgtype: protocol::MsgType::MSG,
                id: Some(id),
                sender: Some(sender),
                recipient: Some(recipient),
                ciphertext: Some(ciphertext),
                subtype: MsgSubType::Unknown,
                priority: 0,
                message_type: None,
                collapse_key: None,
                notification_payload: None,
                metadata: Some(&protocol::Metadata::new(0, 0)),
            },
        );

        builder.finish(message, None);

        (*socket_tx)
            .send(Message::binary(builder.finished_data()))
            .await
            .expect("Failed to send MSG");
    }

    async fn run_connection<S>(
        connection: WebSocketStream<S>,
        msg_tx: crossbeam::channel::Sender<Vec<Vec<u8>>>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut socket_tx, mut socket_rx) = connection.split();

        let auth_message = socket_rx
            .next()
            .await
            .unwrap()
            .expect("Failed to read message");

        if !auth_message.is_binary() {
            println!("Wrong message type received");
            socket_tx.close().await.expect("Closing socket failed");
            return;
        }

        let auth_message = auth_message.into_data();
        let auth_message =
            crate::protocol::root_as_auth(&auth_message).expect("Failed to read auth message");

        let auth_token = auth_message
            .token()
            .expect("Auth message was missing token");
        let auth_token = crate::message::Message::from_jwt(auth_token.as_bytes())
            .expect("Auth token was invalid");

        // we default to the public key as the signing key id for keys generated with this library, so no need to lookup
        let signing_key_id = auth_token.signing_key_ids().unwrap();
        let signing_key_id = signing_key_id.first().unwrap();
        let signing_key = crate::keypair::signing::PublicKey::import(
            signing_key_id,
            crate::keypair::Algorithm::Ed25519,
            signing_key_id,
        )
        .expect("Invalid auth token signing key");

        if auth_token.verify(&signing_key).is_err() {
            err(
                &mut socket_tx,
                auth_message.id().unwrap(),
                "invalid token signature",
            )
            .await;
            socket_tx.close().await.expect("Closing socket failed");
            return;
        };

        ack(&mut socket_tx, auth_message.id().unwrap()).await;

        let self_id = auth_token.get_field("iss").unwrap().as_str().unwrap();
        let device_id = auth_message.device().unwrap();
        let recipient = format!("{}:{}", self_id, device_id);

        for _ in 0..auth_message.offset() {
            msg(&mut socket_tx, "alice:device", &recipient, "test message").await;
        }

        let mut messages = vec![];

        while let Some(message) = socket_rx.next().await {
            let m = message.expect("Failed to read message");

            if m.is_binary() {
                let data = m.into_data().clone();

                let m = crate::protocol::root_as_message(&data).expect("Failed to parse message");

                if m.recipient().unwrap() == "alice:device" {
                    ack(&mut socket_tx, m.id().unwrap()).await;
                    messages.push(m.ciphertext().unwrap().to_vec());
                }
            }
        }

        msg_tx.send(messages).expect("Failed to send results");
    }

    fn test_server() -> (Runtime, Receiver<Vec<Vec<u8>>>) {
        let (con_tx, con_rx) = crossbeam::channel::bounded(1);
        let (msg_tx, msg_rx) = crossbeam::channel::bounded(10);

        let f = async move {
            let listener = TcpListener::bind("127.0.0.1:12345").await.unwrap();
            con_tx.send(()).unwrap();
            let (connection, _) = listener.accept().await.expect("No connections to accept");
            let stream = accept_async(connection).await;
            let stream = stream.expect("Failed to handshake with connection");
            run_connection(stream, msg_tx).await;
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.spawn(f);

        con_rx
            .recv_deadline(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .expect("Server not ready");

        return (rt, msg_rx);
    }

    #[test]
    fn send_and_receive() {
        let (rt, msg_rx) = test_server();

        let kp = KeyPair::new();

        // connect
        let mut ws = Websocket::new("ws://localhost:12345", "self_id", "device_id", kp).unwrap();
        ws.connect(1).unwrap();

        let (response_tx, response_rx) = crossbeam::channel::bounded(1);

        ws.send(
            vec!["alice:device"],
            "chat.message",
            0,
            "test-message".as_bytes(),
            Arc::new(move |result: Result<(), SelfError>| {
                response_tx.send(result).expect("Failed to send result");
            }),
        );

        let deadline = Instant::now() + Duration::from_secs(1);
        response_rx
            .recv_deadline(deadline)
            .expect("Timeout")
            .expect("Failed to send message");

        // disconnect so we can get the messages sent to the server
        ws.disconnect().unwrap();

        // get messages sent to server
        let msgs = msg_rx.recv().unwrap();
        assert_eq!(msgs.len(), 1);

        let msg = msgs.get(0).unwrap().clone();
        assert_eq!(msg, Vec::from("test-message"));

        let (sender, ciphertext) = ws.receive().expect("Failed to receive message");

        assert_eq!(sender, Vec::from("alice:device"));
        assert_eq!(ciphertext, Vec::from("test message"));

        rt.shutdown_background();
    }
}
*/
