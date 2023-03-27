use crossbeam::channel;
use crossbeam::channel::{Receiver, Sender};
use futures_util::{SinkExt, StreamExt};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::SelfError;
use crate::identifier::Identifier;
use crate::protocol::messaging;
use crate::token::Token;

enum Event {
    Message(
        Vec<u8>,
        Message,
        Option<Arc<dyn Fn(Result<(), SelfError>) + Sync + Send>>,
    ),
    Done,
}

pub struct Subscription {
    pub identifier: Identifier,
    pub from: i64,
    pub token: Option<Token>,
}

pub struct Websocket {
    endpoint: Url,
    read_tx: Sender<(Vec<u8>, Vec<u8>)>,
    read_rx: Receiver<(Vec<u8>, Vec<u8>)>,
    write_tx: Sender<Event>,
    write_rx: Receiver<Event>,
    runtime: Runtime,
    subscriptions: Vec<Subscription>,
}

impl Websocket {
    pub fn new(
        url: &str,
        subscriptions: Vec<Subscription>,
    ) -> std::result::Result<Websocket, SelfError> {
        let endpoint = match Url::parse(url) {
            Ok(endpoint) => endpoint,
            Err(_) => return Err(SelfError::RestRequestURLInvalid),
        };

        let (read_tx, read_rx) = channel::bounded(256);
        let (write_tx, write_rx) = channel::bounded(256);

        let runtime = Runtime::new().unwrap();

        let ws = Websocket {
            endpoint,
            read_tx,
            read_rx,
            write_tx,
            write_rx,
            runtime,
            subscriptions,
        };

        Ok(ws)
    }

    pub fn connect(&mut self) -> std::result::Result<(), SelfError> {
        let handle = self.runtime.handle();
        let endpoint = self.endpoint.clone();
        let write_tx = self.write_tx.clone();
        let write_rx = self.write_rx.clone();
        let read_tx = self.read_tx.clone();

        // TODO cleanup old sockets!

        let (tx, rx) = channel::bounded(1);
        let requests: Arc<
            Mutex<HashMap<Vec<u8>, Arc<dyn Fn(Result<(), SelfError>) + Send + Sync>>>,
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

                    let event =
                        messaging::root_as_event(&data).expect("Failed to process websocket event");

                    match event.type_() {
                        messaging::ContentType::ACKNOWLEDGEMENT => {
                            if let Some(id) = event.id() {
                                let lock = requests_rx.lock().await;

                                if let Some(callback) = lock.get(id) {
                                    callback(Ok(()));
                                }

                                drop(lock);
                            }
                        }
                        messaging::ContentType::ERROR => {
                            let error = match event.content() {
                                Some(content) => flatbuffers::root::<messaging::Error>(content)
                                    .expect("Failed to process websocket error content"),
                                None => continue,
                            };

                            println!("code: {} message: {:?}", error.code().0, error.error());

                            let event_id = match event.id() {
                                Some(id) => id,
                                None => continue,
                            };

                            let lock = requests_rx.lock().await;

                            if let Some(callback) = lock.get(event_id) {
                                // TODO replace this with a proper error
                                callback(Err(SelfError::WebsocketProtocolErrorUnknown));
                            }

                            drop(lock);
                        }
                        messaging::ContentType::MESSAGE => {
                            if let Some(content) = event.content() {
                                let message = flatbuffers::root::<messaging::Message>(content)
                                    .expect("Failed to process websocket message content");

                                let payload = match message.payload() {
                                    Some(payload) => {
                                        flatbuffers::root::<messaging::Payload>(payload)
                                            .expect("Failed to process websocket message content")
                                    }
                                    None => continue,
                                };

                                read_tx
                                    .send((
                                        payload.sender().unwrap().to_vec(),
                                        payload.content().unwrap().to_vec(),
                                    ))
                                    .unwrap_or(());
                            }
                        }
                        _ => {
                            println!("unknown event...");
                        }
                    }
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
                        Err(_) => {
                            break;
                        }
                    },
                    Event::Done => break,
                }
            }
            socket_tx.close().await.expect("Failed to close socket");
        });

        let (tx, rx) = channel::bounded(1);

        let (event_id, event_subscribe) = self.assemble_subscription(&self.subscriptions)?;

        let deadline = Instant::now() + Duration::from_secs(5);

        let callback = Arc::new(move |result: Result<(), SelfError>| {
            tx.send(result)
                .expect("Failed to send authentication response");
        });

        self.write_tx
            .send(Event::Message(
                event_id,
                Message::Binary(event_subscribe),
                Some(callback),
            ))
            .map_err(|_| SelfError::RestRequestConnectionTimeout)?;

        rx.recv_deadline(deadline)
            .map_err(|_| SelfError::RestRequestConnectionTimeout)?
    }

    pub fn disconnect(&mut self) -> Result<(), SelfError> {
        self.write_tx
            .send(Event::Done)
            .map_err(|_| SelfError::RestRequestConnectionFailed)
    }

    pub fn send(
        &self,
        from: &Identifier,
        to: &Identifier,
        sequence: u64,
        content: &[u8],
        tokens: Option<Vec<Token>>,
        callback: Arc<dyn Fn(Result<(), SelfError>) + Sync + Send>,
    ) {
        let payload = match self.assemble_payload(from, to, sequence, content) {
            Ok(payload) => payload,
            Err(err) => {
                callback(Err(err));
                return;
            }
        };

        let (event_id, event_message) = match self.assemble_message(from, &payload, tokens) {
            Ok(event) => event,
            Err(err) => {
                callback(Err(err));
                return;
            }
        };

        let event = Event::Message(
            event_id,
            Message::Binary(event_message),
            Some(Arc::clone(&callback)),
        );

        if let Err(_) = self.write_tx.send(event) {
            // TODO handle this error properly
            callback(Err(SelfError::RestRequestConnectionTimeout));
        }
    }

    pub fn receive(&mut self) -> Result<(Vec<u8>, Vec<u8>), SelfError> {
        self.read_rx
            .recv()
            .map_err(|_| SelfError::RestRequestConnectionTimeout)
    }

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

        let payload = messaging::Payload::create(
            &mut builder,
            &messaging::PayloadArgs {
                sender: Some(sender),
                recipient: Some(recipient),
                content: Some(content),
                sequence,
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
        payload_sig_buf[0] = messaging::SignatureType::PAYLOAD.0 as u8;
        payload_sig_buf[1..payload.len() + 1].copy_from_slice(payload);
        let sig = builder.create_vector(&owned_identifier.sign(&payload_sig_buf));

        let mut signatures = Vec::new();

        signatures.push(messaging::Signature::create(
            &mut builder,
            &messaging::SignatureArgs {
                type_: messaging::SignatureType::PAYLOAD,
                signer: None,
                signature: Some(sig),
            },
        ));

        if let Some(tokens) = tokens {
            for token in &tokens {
                match token {
                    Token::Authorization(auth) => {
                        let sig = builder.create_vector(&auth.token);

                        signatures.push(messaging::Signature::create(
                            &mut builder,
                            &messaging::SignatureArgs {
                                type_: messaging::SignatureType::AUTH,
                                signer: None,
                                signature: Some(sig),
                            },
                        ));
                    }
                    Token::Delegation(delegation) => {
                        let sig = builder.create_vector(&delegation.token);
                        let iss = builder.create_vector(&delegation.issuer.id());

                        signatures.push(messaging::Signature::create(
                            &mut builder,
                            &messaging::SignatureArgs {
                                type_: messaging::SignatureType::AUTH,
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

        let msg = messaging::Message::create(
            &mut builder,
            &messaging::MessageArgs {
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

        let event = messaging::Event::create(
            &mut builder,
            &messaging::EventArgs {
                id: Some(eid),
                type_: messaging::ContentType::MESSAGE,
                content: Some(cnt),
            },
        );

        builder.finish(event, None);

        return Ok((event_id, builder.finished_data().to_vec()));
    }

    fn assemble_subscription(
        &self,
        subscriptions: &[Subscription],
    ) -> Result<(Vec<u8>, Vec<u8>), SelfError> {
        let mut subs = Vec::new();
        let now = crate::time::unix();

        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        for subscription in subscriptions {
            let owned_identifier = match &subscription.identifier {
                Identifier::Owned(owned) => owned,
                _ => return Err(SelfError::WebsocketSenderIdentifierNotOwned),
            };

            let inbox = builder.create_vector(&subscription.identifier.id());

            let details = messaging::SubscriptionDetails::create(
                &mut builder,
                &messaging::SubscriptionDetailsArgs {
                    inbox: Some(inbox),
                    issued: now,
                    from: subscription.from,
                },
            );

            builder.finish(details, None);

            let mut details_sig_buf = vec![0; builder.finished_data().len() + 1];
            details_sig_buf[0] = messaging::SignatureType::PAYLOAD.0 as u8;
            details_sig_buf[1..builder.finished_data().len() + 1]
                .copy_from_slice(builder.finished_data());

            builder.reset();

            let sig = builder.create_vector(&owned_identifier.sign(&details_sig_buf));

            let mut sigs = Vec::new();

            sigs.push(messaging::Signature::create(
                &mut builder,
                &messaging::SignatureArgs {
                    type_: messaging::SignatureType::PAYLOAD,
                    signer: None,
                    signature: Some(sig),
                },
            ));

            if let Some(token) = &subscription.token {
                let subscription_token = match token {
                    Token::Subscription(subscription_token) => subscription_token,
                    _ => return Err(SelfError::WebsocketTokenUnsupported),
                };

                let sig = builder.create_vector(&subscription_token.token);

                sigs.push(messaging::Signature::create(
                    &mut builder,
                    &messaging::SignatureArgs {
                        type_: messaging::SignatureType::SUBSCRIPTION,
                        signer: None,
                        signature: Some(sig),
                    },
                ));
            }

            let signatures = builder.create_vector(&sigs);
            let details = builder.create_vector(&details_sig_buf[1..]);

            subs.push(messaging::Subscription::create(
                &mut builder,
                &messaging::SubscriptionArgs {
                    details: Some(details),
                    signatures: Some(signatures),
                },
            ))
        }

        let subs = builder.create_vector(&subs);

        let subscribe = messaging::Subscribe::create(
            &mut builder,
            &messaging::SubscribeArgs {
                subscriptions: Some(subs),
            },
        );

        builder.finish(subscribe, None);

        let content = builder.finished_data().to_vec();
        let event_id = crate::crypto::random_id();

        builder.reset();

        let eid = builder.create_vector(&event_id);
        let cnt = builder.create_vector(&content);

        let event = messaging::Event::create(
            &mut builder,
            &messaging::EventArgs {
                id: Some(eid),
                type_: messaging::ContentType::MESSAGE,
                content: Some(cnt),
            },
        );

        builder.finish(event, None);

        return Ok((event_id, builder.finished_data().to_vec()));
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        keypair::signing::{KeyPair, PublicKey},
        protocol::messaging,
    };

    use super::*;
    use futures_util::stream::SplitSink;
    use futures_util::{SinkExt, StreamExt};
    use tokio::{
        io::{AsyncRead, AsyncWrite},
        net::TcpListener,
    };
    use tokio_tungstenite::tungstenite::protocol::Message;
    use tokio_tungstenite::{accept_async, WebSocketStream};

    async fn ack<S>(socket_tx: &mut SplitSink<WebSocketStream<S>, Message>, id: &[u8])
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let id = builder.create_vector(id);

        let event = messaging::Event::create(
            &mut builder,
            &messaging::EventArgs {
                id: Some(id),
                type_: messaging::ContentType::ACKNOWLEDGEMENT,
                content: None,
            },
        );

        builder.finish(event, None);

        (*socket_tx)
            .send(Message::binary(builder.finished_data()))
            .await
            .expect("Failed to send ACK");
    }

    async fn err<S>(
        socket_tx: &mut SplitSink<WebSocketStream<S>, Message>,
        id: &[u8],
        reason: &[u8],
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        let reason = builder.create_vector(reason);

        let error = messaging::Error::create(
            &mut builder,
            &messaging::ErrorArgs {
                code: messaging::StatusCode::BADAUTH,
                error: Some(reason),
            },
        );

        builder.finish(error, None);
        let content = builder.finished_data().to_vec();
        builder.reset();

        let id = builder.create_vector(id);
        let content = builder.create_vector(&content);

        let event = messaging::Event::create(
            &mut builder,
            &messaging::EventArgs {
                id: Some(id),
                type_: messaging::ContentType::ACKNOWLEDGEMENT,
                content: Some(content),
            },
        );

        builder.finish(event, None);

        (*socket_tx)
            .send(Message::binary(builder.finished_data()))
            .await
            .expect("Failed to send ERR");
    }

    async fn msg<S>(
        socket_tx: &mut SplitSink<WebSocketStream<S>, Message>,
        from: &Identifier,
        to: &Identifier,
        sequence: u64,
        content: &[u8],
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let owned_identifier = match from {
            Identifier::Owned(owned) => owned,
            _ => return,
        };

        // TODO pool/reuse these builders
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        let sender = builder.create_vector(&from.id());
        let recipient = builder.create_vector(&to.id());
        let content = builder.create_vector(content);

        let payload = messaging::Payload::create(
            &mut builder,
            &messaging::PayloadArgs {
                sender: Some(sender),
                recipient: Some(recipient),
                content: Some(content),
                sequence,
                timestamp: crate::time::unix(),
            },
        );

        builder.finish(payload, None);
        let payload = builder.finished_data().to_vec();
        builder.reset();

        let mut payload_sig_buf = vec![0; payload.len() + 1];
        payload_sig_buf[0] = messaging::SignatureType::PAYLOAD.0 as u8;
        payload_sig_buf[1..payload.len() + 1].copy_from_slice(&payload);
        let sig = builder.create_vector(&owned_identifier.sign(&payload_sig_buf));

        let mut signatures = Vec::new();

        signatures.push(messaging::Signature::create(
            &mut builder,
            &messaging::SignatureArgs {
                type_: messaging::SignatureType::PAYLOAD,
                signer: None,
                signature: Some(sig),
            },
        ));

        let pld = builder.create_vector(&payload);
        let sigs = builder.create_vector(&signatures);

        let msg = messaging::Message::create(
            &mut builder,
            &messaging::MessageArgs {
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

        let event = messaging::Event::create(
            &mut builder,
            &messaging::EventArgs {
                id: Some(eid),
                type_: messaging::ContentType::MESSAGE,
                content: Some(cnt),
            },
        );

        builder.finish(event, None);

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

        let event = socket_rx
            .next()
            .await
            .unwrap()
            .expect("Failed to read message");

        if !event.is_binary() {
            println!("Wrong message type received");
            socket_tx.close().await.expect("Closing socket failed");
            return;
        }

        let event = event.into_data();
        let event = messaging::root_as_event(&event).expect("Failed to read auth message");
        let content = event.content().expect("Subscribe event missing content");
        let subscribe =
            flatbuffers::root::<messaging::Subscribe>(content).expect("Subscribe event invalid");

        let mut subscriptions = Vec::new();

        for subscription in subscribe
            .subscriptions()
            .expect("Subscribe subscriptions empty")
        {
            let details_buf = subscription.details().expect("Subscription details empty");
            let details_len = details_buf.len();
            let signatures = subscription
                .signatures()
                .expect("Subscription signatures empty");

            let details = flatbuffers::root::<messaging::SubscriptionDetails>(details_buf)
                .expect("Subscription details invalid");
            let inbox = details.inbox().expect("Subscription inbox missing");

            let (mut authenticated, mut authorized) = (false, false);
            let mut subscriber: Option<&[u8]> = None;

            // validate the subscriptions signatures
            for signature in signatures {
                let sig = signature.signature().expect("Subscription signature empty");

                match signature.type_() {
                    messaging::SignatureType::PAYLOAD => {
                        // authenticate the subscriber over the subscriptions details
                        let signer = signature.signer().unwrap_or(inbox);

                        let mut details_sig_buf = vec![0; details_len + 1];
                        details_sig_buf[0] = messaging::SignatureType::PAYLOAD.0 as u8;
                        details_sig_buf[1..details_len + 1].copy_from_slice(details_buf);

                        let pk = PublicKey::from_bytes(signer, crate::keypair::Algorithm::Ed25519)
                            .expect("Subscription signer invalid");

                        if !(pk.verify(&details_sig_buf, sig)) {
                            err(&mut socket_tx, event.id().unwrap(), b"bad auth").await;
                            return;
                        };

                        subscriptions.push(inbox.clone());

                        if inbox == signer {
                            (authenticated, authorized) = (true, true);
                            break;
                        }

                        subscriber = Some(signer);

                        authenticated = true;
                    }
                    messaging::SignatureType::SUBSCRIPTION => {
                        let mut subscription_sig_buf = vec![0; 65];
                        subscription_sig_buf[0] = messaging::SignatureType::SUBSCRIPTION.0 as u8;
                        subscription_sig_buf[1..33].copy_from_slice(inbox);
                        subscription_sig_buf[33..65]
                            .copy_from_slice(subscriber.expect("Subscriber empty"));

                        let pk = PublicKey::from_bytes(inbox, crate::keypair::Algorithm::Ed25519)
                            .expect("Subscription signer invalid");

                        if !pk.verify(&subscription_sig_buf, sig) {
                            err(&mut socket_tx, event.id().unwrap(), b"bad auth").await;
                            return;
                        };

                        authorized = true;
                    }
                    _ => continue, // skip other signature types for now
                }
            }

            assert!(authenticated && authorized);
        }

        ack(&mut socket_tx, event.id().unwrap()).await;

        let sender = Identifier::Owned(KeyPair::new());

        for subscription in subscriptions {
            let recipient = Identifier::Referenced(
                PublicKey::from_bytes(subscription, crate::keypair::Algorithm::Ed25519)
                    .expect("Invalid subscription public key"),
            );
            msg(&mut socket_tx, &sender, &recipient, 0, b"test message").await;
        }

        let mut messages = vec![];

        while let Some(message) = socket_rx.next().await {
            let m = message.expect("Failed to read message");

            if m.is_binary() {
                let data = m.into_data().clone();

                let event = messaging::root_as_event(&data).expect("Event invalid");
                let content = event.content().expect("Event content missing");
                let message = flatbuffers::root::<messaging::Message>(content)
                    .expect("Failed to process websocket message content");

                let payload = match message.payload() {
                    Some(payload) => flatbuffers::root::<messaging::Payload>(payload)
                        .expect("Failed to process websocket message content"),
                    None => continue,
                };

                // TODO validate message authentication and authorization
                if payload.recipient().is_some() {
                    ack(&mut socket_tx, event.id().unwrap()).await;
                    messages.push(payload.content().unwrap().to_vec());
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

        std::thread::sleep(std::time::Duration::from_millis(100));

        (rt, msg_rx)
    }

    #[test]
    fn send_and_receive() {
        let (rt, msg_rx) = test_server();

        let alice_kp = crate::keypair::signing::KeyPair::new();
        let alice_id = Identifier::Owned(alice_kp);
        let subs = vec![Subscription {
            identifier: alice_id.clone(),
            from: crate::time::unix(),
            token: None,
        }];

        let bob_kp = crate::keypair::signing::KeyPair::new();
        let bob_id = Identifier::Referenced(bob_kp.public());

        // connect
        let mut ws = Websocket::new("ws://localhost:12345", subs).unwrap();
        ws.connect().unwrap();

        let (response_tx, response_rx) = crossbeam::channel::bounded(1);

        ws.send(
            &alice_id,
            &bob_id,
            0,
            b"test message",
            None,
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
        assert_eq!(msg, Vec::from("test message"));

        let (_, ciphertext) = ws.receive().expect("Failed to receive message");
        assert_eq!(ciphertext, Vec::from("test message"));

        rt.shutdown_background();
    }
}
