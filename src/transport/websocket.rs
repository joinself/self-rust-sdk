use crossbeam::channel;
use crossbeam::channel::{Receiver, Sender};
use flatbuffers::{Vector, WIPOffset};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::sync::{broadcast, Mutex};
use tokio_tungstenite::tungstenite::{protocol, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use url::Url;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::crypto::pow;
use crate::error::SelfError;
use crate::keypair::signing::{KeyPair, PublicKey};
use crate::protocol::messaging::{self, ContentType, EventType};
use crate::time;
use crate::token::Token;

pub struct Event {
    pub content_type: ContentType,
    pub from_address: PublicKey,
    pub to_address: PublicKey,
    pub content: Vec<u8>,
    pub timestamp: i64,
    pub sequence: u64,
}

pub type OnConnectCB = Arc<dyn Fn() + Sync + Send>;
pub type OnDisconnectCB = Arc<dyn Fn(Result<(), SelfError>) + Sync + Send>;
pub type OnEventCB = Arc<dyn Fn(Event) + Sync + Send>;

#[derive(Clone)]
pub struct Callbacks {
    pub on_connect: OnConnectCB,
    pub on_disconnect: OnDisconnectCB,
    pub on_event: OnEventCB,
}

enum Signal {
    Send(Vec<u8>, protocol::Message, Option<ResponseCallback>),
    Done,
}

pub type SendCallback = Arc<dyn Fn(Result<(), SelfError>) + Sync + Send>;
pub type ResponseCallback = Arc<dyn Fn(Result<(), SelfError>) + Sync + Send>;

#[derive(Clone)]
pub struct Subscription {
    pub to_address: PublicKey,
    pub as_address: KeyPair,
    pub token: Option<Token>,
    pub last_active: i64,
    pub last_message: i64,
}

pub type RequestCache = Arc<Mutex<HashMap<Vec<u8>, ResponseCallback>>>;
pub type SubscriptionCache = Arc<Mutex<HashMap<Vec<u8>, Subscription>>>;

pub struct Websocket {
    endpoint: Url,
    callbacks: Callbacks,
    write_tx: Sender<Signal>,
    write_rx: Receiver<Signal>,
    event_tx: Sender<Event>,
    event_rx: Receiver<Event>,
    socket_tx_runtime: Arc<Runtime>,
    socket_rx_runtime: Arc<Runtime>,
    event_runtime: Arc<Runtime>,
    command_runtime: Arc<Runtime>,
    callback_runtime: Arc<Runtime>,
    subscriptions: SubscriptionCache,
}

// TODO fix subscriptions...
unsafe impl Send for Websocket {}
unsafe impl Sync for Websocket {}

impl Websocket {
    pub fn new(endpoint: &str, callbacks: Callbacks) -> Result<Websocket, SelfError> {
        let (write_tx, write_rx) = channel::bounded(256);
        let (event_tx, event_rx) = channel::unbounded();

        let event_runtime = Arc::new(Runtime::new().unwrap());
        let command_runtime = Arc::new(Runtime::new().unwrap());
        let callback_runtime = Arc::new(Runtime::new().unwrap());
        let socket_tx_runtime = Arc::new(Runtime::new().unwrap());
        let socket_rx_runtime = Arc::new(Runtime::new().unwrap());

        let endpoint = match Url::parse(endpoint) {
            Ok(endpoint) => endpoint,
            Err(_) => return Err(SelfError::HTTPRequestURLInvalid),
        };

        Ok(Websocket {
            endpoint,
            callbacks,
            write_tx,
            write_rx,
            event_tx,
            event_rx,
            event_runtime,
            command_runtime,
            callback_runtime,
            socket_tx_runtime,
            socket_rx_runtime,
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// connects to the websocket server
    pub fn connect(
        &mut self,
        shutdown: &broadcast::Receiver<()>,
    ) -> std::result::Result<(), SelfError> {
        let event_runtime = self.event_runtime.clone();
        let callback_runtime = self.callback_runtime.clone();
        let socket_tx_runtime = self.socket_tx_runtime.clone();
        let socket_rx_runtime = self.socket_rx_runtime.clone();
        let endpoint = self.endpoint.clone();
        let write_tx = self.write_tx.clone();
        let write_rx = self.write_rx.clone();
        let event_tx = self.event_tx.clone();
        let event_rx = self.event_rx.clone();
        let mut event_shutdown_rx = shutdown.resubscribe();
        let mut socket_tx_shutdown_rx = shutdown.resubscribe();
        let mut socket_rx_shutdown_rx = shutdown.resubscribe();
        let on_connect = self.callbacks.on_connect.clone();
        let on_event = self.callbacks.on_event.clone();
        let subscriptions = self.subscriptions.clone();

        // TODO cleanup old sockets!
        let (tx, rx) = channel::bounded(1);
        let requests: RequestCache = Arc::new(Mutex::new(HashMap::new()));
        let requests_rx = requests.clone();
        let requests_tx = requests.clone();

        socket_tx_runtime.spawn(async move {
            let result = match connect_async(&endpoint).await {
                Ok((socket, _)) => Ok(socket),
                Err(err) => {
                    println!("{}", err);
                    Err(SelfError::HTTPRequestConnectionFailed)
                }
            };

            tx.send(result).unwrap();
        });

        let (socket_tx, socket_rx) = rx
            .recv()
            .map_err(|_| SelfError::HTTPRequestConnectionFailed)??
            .split();

        // use a specific runtime for events so that
        // they can be processed sequentially
        event_runtime.spawn(async move {
            tokio::select! {
                _ = handle_event_callback(&event_rx, &on_event) => {}
                _ = event_shutdown_rx.recv() => {
                    //println!("shutting down event");
                }
            }
        });

        socket_rx_runtime.spawn(async move {
            tokio::select! {
                _ = handle_socket_rx(socket_rx, write_tx, event_tx, requests_rx, subscriptions, callback_runtime) => {}
                _ = socket_rx_shutdown_rx.recv() => {
                    //println!("shutting down socket rx");
                }
            }
        });

        // TODO replace HTTPRequestConnectionFailed with better errors
        socket_tx_runtime.spawn(async move {
            tokio::select! {
                _ = handle_socket_tx(socket_tx, write_rx, requests_tx) => {

                },
                _ = socket_tx_shutdown_rx.recv() => {
                    //println!("shutting down socket tx")
                }
            }
        });

        event_runtime.spawn(async move {
            on_connect();
        });

        Ok(())
    }

    /// subscribe to some inboxes
    pub fn subscribe(&self, subscriptions: &[Subscription]) -> Result<(), SelfError> {
        let (subs_tx, subs_rx) = channel::bounded(1);
        let (send_tx, send_rx) = channel::bounded(1);
        let deadline = Instant::now() + Duration::from_secs(5);
        let (event_id, event_subscribe) = assemble_subscription(subscriptions)?;

        let subscriptions = subscriptions.to_vec();
        let existing_subscriptions = self.subscriptions.clone();

        self.command_runtime.spawn(async move {
            let mut existing_subscriptions = existing_subscriptions.lock().await;

            for sub in subscriptions {
                existing_subscriptions.insert(sub.to_address.address().to_owned(), sub.clone());
            }

            subs_tx
                .send(())
                .expect("failed to send subscription update response");
        });

        subs_rx
            .recv_deadline(deadline)
            .map_err(|_| SelfError::HTTPRequestConnectionTimeout)?;

        let callback = Arc::new(move |result: Result<(), SelfError>| {
            send_tx
                .send(result)
                .expect("Failed to send subscription response");
        });

        self.write_tx
            .send(Signal::Send(
                event_id,
                protocol::Message::Binary(event_subscribe),
                Some(callback),
            ))
            .map_err(|_| SelfError::HTTPRequestConnectionTimeout)?;

        send_rx
            .recv_deadline(deadline)
            .map_err(|_| SelfError::HTTPRequestConnectionTimeout)??;

        Ok(())
    }

    /// get metrics for each subscription
    pub async fn metrics(&self) -> HashMap<(PublicKey, PublicKey), i64> {
        let mut metrics = HashMap::new();
        let timestamp = time::unix();

        for (_, subscription) in self.subscriptions.lock().await.iter() {
            let metric = if timestamp - subscription.last_active > 5 {
                timestamp
            } else {
                subscription.last_message
            };

            metrics.insert(
                (
                    subscription.to_address.to_owned(),
                    subscription.as_address.public().to_owned(),
                ),
                metric,
            );
        }

        metrics
    }

    /// send a message
    pub fn send(
        &self,
        from: &KeyPair,
        payload: &[u8],
        tokens: Option<Vec<Token>>,
        callback: SendCallback,
    ) {
        let (event_id, event_message) = match assemble_message(from, payload, tokens) {
            Ok(event) => event,
            Err(err) => {
                callback(Err(err));
                return;
            }
        };

        let event = Signal::Send(
            event_id,
            protocol::Message::Binary(event_message),
            Some(Arc::clone(&callback)),
        );

        if self.write_tx.send(event).is_err() {
            // TODO handle this error properly
            callback(Err(SelfError::HTTPRequestConnectionTimeout));
        }
    }

    /// open an inbox
    pub fn open(&self, address: &KeyPair) -> Result<(), SelfError> {
        let (tx, rx) = channel::bounded(1);
        let (event_id, event_open) = assemble_open(address)?;
        let deadline = Instant::now() + Duration::from_secs(5);

        let callback = Arc::new(move |result: Result<(), SelfError>| {
            tx.send(result)
                .expect("Failed to send subscription response");
        });

        self.write_tx
            .send(Signal::Send(
                event_id,
                protocol::Message::Binary(event_open),
                Some(callback),
            ))
            .map_err(|_| SelfError::HTTPRequestConnectionTimeout)?;

        rx.recv_deadline(deadline)
            .map_err(|_| SelfError::HTTPRequestConnectionTimeout)??;

        Ok(())
    }

    /// close an inbox
    pub fn close(&self, _address: &KeyPair) -> Result<(), SelfError> {
        // TODO assemble_close
        Ok(())
    }

    /// disconnect the websocket
    pub fn disconnect(&mut self) -> Result<(), SelfError> {
        self.write_tx
            .send(Signal::Done)
            .map_err(|_| SelfError::HTTPRequestConnectionFailed)
    }
}

async fn handle_socket_tx(
    mut socket_tx: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    write_rx: Receiver<Signal>,
    requests_tx: RequestCache,
) {
    for m in write_rx.iter() {
        match m {
            Signal::Send(id, msg, callback) => {
                if let Some(cb) = callback {
                    let mut lock = requests_tx.lock().await;
                    lock.insert(id, cb);
                    drop(lock);
                }

                // println!("sending message of size: {}", msg.len());

                match socket_tx.send(msg).await {
                    Ok(_) => continue,
                    Err(err) => {
                        println!("socket send failed: {:?}", err);
                        break;
                    }
                }
            }
            Signal::Done => break,
        }
    }
    socket_tx.close().await.expect("Failed to close socket");
}

async fn handle_socket_rx(
    mut socket_rx: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    write_tx: Sender<Signal>,
    event_tx: Sender<Event>,
    requests: RequestCache,
    mut subscriptions: SubscriptionCache,
    callback_runtime: Arc<Runtime>,
) {
    while let Some(event) = socket_rx.next().await {
        let event = match event {
            Ok(event) => event,
            Err(_) => {
                // println!("websocket failed with: {:?}", err);
                return;
            }
        };

        if event.is_close() {
            let _ = write_tx.send(Signal::Done);
            return;
        }

        if event.is_ping() {
            continue;
        }

        if event.is_pong() {
            continue;
        }

        if event.is_binary() {
            let result = handle_event_binary(
                &callback_runtime,
                &event_tx,
                &requests,
                &mut subscriptions,
                &event.into_data(),
            )
            .await;

            if result.is_err() {
                return;
            }
        };
    }
}

async fn handle_event_callback(event_rx: &Receiver<Event>, on_event: &OnEventCB) {
    while let Ok(event) = event_rx.recv() {
        on_event(event);
    }
}

async fn handle_event_binary(
    runtime: &Arc<Runtime>,
    event_tx: &Sender<Event>,
    requests: &RequestCache,
    subscriptions: &mut SubscriptionCache,
    data: &[u8],
) -> Result<(), SelfError> {
    let event = match messaging::root_as_event(data) {
        Ok(event) => event,
        Err(_) => return Err(SelfError::WebsocketProtocolEncodingInvalid),
    };

    match event.type_() {
        EventType::ACKNOWLEDGEMENT => {
            invoke_acknowledgement_callback(runtime, requests, event.id().map(|id| id.bytes()))
                .await
        }
        EventType::ERROR => {
            invoke_error_callback(
                runtime,
                requests,
                event.id().map(|id| id.bytes()),
                event.content().map(|content| content.bytes()),
            )
            .await
        }
        EventType::MESSAGE => {
            invoke_event_callback(
                event_tx,
                subscriptions,
                event.content().map(|content| content.bytes()),
            )
            .await
        }
        _ => Err(SelfError::WebsocketProtocolErrorUnknown),
    }
}

async fn invoke_acknowledgement_callback(
    runtime: &Arc<Runtime>,
    requests: &RequestCache,
    id: Option<&[u8]>,
) -> Result<(), SelfError> {
    if let Some(id) = id {
        let mut lock = requests.lock().await;

        if let Some(callback) = lock.remove(id) {
            runtime.spawn(async move {
                callback(Ok(()));
            });
        }
    }

    Ok(())
}

async fn invoke_error_callback(
    runtime: &Arc<Runtime>,
    requests: &RequestCache,
    id: Option<&[u8]>,
    content: Option<&[u8]>,
) -> Result<(), SelfError> {
    let error = match content {
        Some(content) => flatbuffers::root::<messaging::Error>(content),
        None => return Err(SelfError::WebsocketProtocolEncodingInvalid),
    }
    .map_err(|_| SelfError::WebsocketProtocolEncodingInvalid)?;

    println!("code: {} message: {:?}", error.code().0, error.error());

    if let Some(id) = id {
        let mut lock = requests.lock().await;

        if let Some(callback) = lock.remove(id) {
            runtime.spawn(async move {
                callback(Err(SelfError::WebsocketProtocolErrorUnknown));
            });
        }
    }

    Ok(())
}

async fn invoke_event_callback(
    event_tx: &Sender<Event>,
    subscriptions: &mut SubscriptionCache,
    content: Option<&[u8]>,
) -> Result<(), SelfError> {
    let content = match content {
        Some(content) => content,
        None => return Err(SelfError::WebsocketProtocolEmptyContent),
    };

    let message = match flatbuffers::root::<messaging::Message>(content) {
        Ok(message) => message,
        Err(_) => return Err(SelfError::WebsocketProtocolEncodingInvalid),
    };

    let payload = match message.payload() {
        Some(payload) => payload,
        None => return Err(SelfError::WebsocketProtocolEmptyContent),
    };

    let payload = match flatbuffers::root::<messaging::Payload>(payload.bytes()) {
        Ok(payload) => payload,
        Err(_) => return Err(SelfError::WebsocketProtocolEncodingInvalid),
    };

    // TODO authenticate message signatures!!!!

    let now = time::unix();
    let sequence = payload.sequence();
    let timestamp = payload.timestamp();

    // check this message is not from the future, allow for 5 seconds of drift
    if timestamp > now + 5 {
        return Err(SelfError::WebsocketEventTimestampInvalid);
    }

    let from_address = match payload.sender() {
        Some(from_address) => from_address,
        None => return Err(SelfError::WebsocketProtocolSenderInvalid),
    };

    let to_address = match payload.recipient() {
        Some(to_address) => to_address,
        None => return Err(SelfError::WebsocketProtocolRecipientInvalid),
    };

    // TODO decide whether this constitutes a fatal error, server cannot be trusted
    // if it sends bad data, we should maybe try to reconnect to another?
    let from_address = PublicKey::from_bytes(from_address.bytes())?;
    let to_address = PublicKey::from_bytes(to_address.bytes())?;

    // validate the message we have received is for a valid subscription we have
    let mut active_subs = subscriptions.clone().lock_owned().await;

    if let Some(subscription) = active_subs.get_mut(to_address.address()) {
        if timestamp > subscription.last_message {
            subscription.last_message = timestamp
        }
        subscription.last_active = now;
    } else {
        println!(
            "message received for an unknown recipient: {}",
            to_address.to_hex(),
        );
        return Ok(());
    }

    drop(active_subs);

    let content = match payload.content() {
        Some(content) => content.bytes().to_vec(),
        None => return Err(SelfError::WebsocketProtocolEmptyContent),
    };

    let content_type = payload.type_();

    // TODO pass through authentication status (token or proof of work)
    // to let the sdk decide whether to accept or reject new sessions
    // from unauthenticated users

    let event = Event {
        content_type,
        from_address,
        to_address,
        content,
        timestamp,
        sequence,
    };

    event_tx
        .send(event)
        .expect("failed to write to event channel");

    Ok(())
}

pub fn assemble_payload_message(
    from: &KeyPair,
    to: &PublicKey,
    sequence: u64,
    content: &[u8],
) -> Result<Vec<u8>, SelfError> {
    // TODO pool/reuse these builders
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

    let content = builder.create_vector(content);

    let mls_message = messaging::MlsMessage::create(
        &mut builder,
        &messaging::MlsMessageArgs {
            message: Some(content),
        },
    );

    builder.finish(mls_message, None);
    let mls_message = builder.finished_data().to_vec();
    builder.reset();

    let sender = builder.create_vector(from.address());
    let recipient = builder.create_vector(to.address());
    let content = builder.create_vector(&mls_message);

    let payload = messaging::Payload::create(
        &mut builder,
        &messaging::PayloadArgs {
            type_: ContentType::MLS_MESSAGE,
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

pub fn assemble_payload_key_package(
    from: &KeyPair,
    to: &PublicKey,
    sequence: u64,
    key_package: &[u8],
    send_token: Option<&[u8]>,
    push_token: Option<&[u8]>,
) -> Result<Vec<u8>, SelfError> {
    // TODO pool/reuse these builders
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

    let key_package = builder.create_vector(key_package);
    let send_token = send_token.map(|token| builder.create_vector(token));
    let push_token = push_token.map(|token| builder.create_vector(token));

    let mls_message = messaging::MlsKeyPackage::create(
        &mut builder,
        &messaging::MlsKeyPackageArgs {
            package: Some(key_package),
            send: send_token,
            push_: push_token,
        },
    );

    builder.finish(mls_message, None);
    let mls_message = builder.finished_data().to_vec();
    builder.reset();

    let sender = builder.create_vector(from.address());
    let recipient = builder.create_vector(to.address());
    let content = builder.create_vector(&mls_message);

    let payload = messaging::Payload::create(
        &mut builder,
        &messaging::PayloadArgs {
            type_: ContentType::MLS_KEY_PACKAGE,
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

pub fn assemble_payload_welcome(
    from: &KeyPair,
    to: &PublicKey,
    sequence: u64,
    welcome_message: &[u8],
    send_token: Option<&[u8]>,
    subscription_token: Option<&[u8]>,
) -> Result<Vec<u8>, SelfError> {
    // TODO pool/reuse these builders
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

    let welcome_message = builder.create_vector(welcome_message);
    let send_token = send_token.map(|token| builder.create_vector(token));
    let subscription_token = subscription_token.map(|token| builder.create_vector(token));

    let mls_message = messaging::MlsWelcome::create(
        &mut builder,
        &messaging::MlsWelcomeArgs {
            welcome: Some(welcome_message),
            send: send_token,
            subscription: subscription_token,
        },
    );

    builder.finish(mls_message, None);
    let mls_message = builder.finished_data().to_vec();
    builder.reset();

    let sender = builder.create_vector(from.address());
    let recipient = builder.create_vector(to.address());
    let content = builder.create_vector(&mls_message);

    let payload = messaging::Payload::create(
        &mut builder,
        &messaging::PayloadArgs {
            type_: ContentType::MLS_WELCOME,
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

pub fn assemble_payload_commit(
    from: &KeyPair,
    to: &PublicKey,
    sequence: u64,
    commit_message: &[u8],
) -> Result<Vec<u8>, SelfError> {
    // TODO pool/reuse these builders
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

    let commit_message = builder.create_vector(commit_message);

    let mls_message = messaging::MlsCommit::create(
        &mut builder,
        &messaging::MlsCommitArgs {
            commit: Some(commit_message),
        },
    );

    builder.finish(mls_message, None);
    let mls_message = builder.finished_data().to_vec();
    builder.reset();

    let sender = builder.create_vector(from.address());
    let recipient = builder.create_vector(to.address());
    let content = builder.create_vector(&mls_message);

    let payload = messaging::Payload::create(
        &mut builder,
        &messaging::PayloadArgs {
            type_: ContentType::MLS_COMMIT,
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
    from: &KeyPair,
    payload: &[u8],
    tokens: Option<Vec<Token>>,
) -> Result<(Vec<u8>, Vec<u8>), SelfError> {
    // TODO pool/reuse these builders
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

    let sig = builder.create_vector(&from.sign(payload));
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
                Token::Send(auth) => {
                    let sig = builder.create_vector(&auth.token);

                    signatures.push(messaging::Signature::create(
                        &mut builder,
                        &messaging::SignatureArgs {
                            type_: messaging::SignatureType::TOKEN,
                            signer: None,
                            signature: Some(sig),
                        },
                    ));
                }
                Token::Delegation(delegation) => {
                    let sig = builder.create_vector(&delegation.token);

                    signatures.push(messaging::Signature::create(
                        &mut builder,
                        &messaging::SignatureArgs {
                            type_: messaging::SignatureType::TOKEN,
                            signer: None,
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
            version: messaging::Version::V1,
            id: Some(eid),
            type_: messaging::EventType::MESSAGE,
            content: Some(cnt),
        },
    );

    builder.finish(event, None);

    return Ok((event_id, builder.finished_data().to_vec()));
}

fn assemble_subscription(subscriptions: &[Subscription]) -> Result<(Vec<u8>, Vec<u8>), SelfError> {
    let mut subs = Vec::new();
    let now = crate::time::unix();

    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
    let mut details_builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

    for subscription in subscriptions {
        let inbox = details_builder.create_vector(subscription.to_address.address());

        let details = messaging::SubscriptionDetails::create(
            &mut details_builder,
            &messaging::SubscriptionDetailsArgs {
                inbox: Some(inbox),
                issued: now,
                from: subscription.last_message,
            },
        );

        details_builder.finish(details, None);
        let details_buf = details_builder.finished_data().to_vec();
        details_builder.reset();

        let sig = builder.create_vector(&subscription.as_address.sign(&details_buf));

        let mut sigs = Vec::new();
        let mut signer: Option<WIPOffset<Vector<u8>>> = None;

        if subscription.token.is_some() {
            signer = Some(builder.create_vector(subscription.as_address.address()));
        }

        sigs.push(messaging::Signature::create(
            &mut builder,
            &messaging::SignatureArgs {
                type_: messaging::SignatureType::PAYLOAD,
                signer,
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
                    type_: messaging::SignatureType::TOKEN,
                    signer: None,
                    signature: Some(sig),
                },
            ));
        }

        let signatures = builder.create_vector(&sigs);
        let details = builder.create_vector(&details_buf);

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
            version: messaging::Version::V1,
            id: Some(eid),
            type_: messaging::EventType::SUBSCRIBE,
            content: Some(cnt),
        },
    );

    builder.finish(event, None);

    return Ok((event_id, builder.finished_data().to_vec()));
}

fn assemble_open(inbox: &KeyPair) -> Result<(Vec<u8>, Vec<u8>), SelfError> {
    let now = crate::time::unix();

    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

    let address = builder.create_vector(inbox.address());

    let details = messaging::OpenDetails::create(
        &mut builder,
        &messaging::OpenDetailsArgs {
            inbox: Some(address),
            issued: now,
        },
    );

    builder.finish(details, None);
    let details_buf = builder.finished_data().to_vec();
    builder.reset();

    let (pow_hash, pow_nonce) = pow::ProofOfWork::new(8).calculate(&details_buf);

    let details_sig = builder.create_vector(&inbox.sign(&details_buf));

    let signature = messaging::Signature::create(
        &mut builder,
        &messaging::SignatureArgs {
            type_: messaging::SignatureType::PAYLOAD,
            signer: None,
            signature: Some(details_sig),
        },
    );

    let details = builder.create_vector(&details_buf);
    let pow_hash = builder.create_vector(&pow_hash);

    let open = messaging::Open::create(
        &mut builder,
        &messaging::OpenArgs {
            details: Some(details),
            signature: Some(signature),
            pow: Some(pow_hash),
            nonce: pow_nonce,
        },
    );

    builder.finish(open, None);

    let content = builder.finished_data().to_vec();
    let event_id = crate::crypto::random_id();

    builder.reset();

    let eid = builder.create_vector(&event_id);
    let cnt = builder.create_vector(&content);

    let event = messaging::Event::create(
        &mut builder,
        &messaging::EventArgs {
            version: messaging::Version::V1,
            id: Some(eid),
            type_: messaging::EventType::OPEN,
            content: Some(cnt),
        },
    );

    builder.finish(event, None);

    return Ok((event_id, builder.finished_data().to_vec()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream::SplitSink;
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
                version: messaging::Version::V1,
                id: Some(id),
                type_: messaging::EventType::ACKNOWLEDGEMENT,
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
                version: messaging::Version::V1,
                id: Some(id),
                type_: messaging::EventType::ACKNOWLEDGEMENT,
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
        from: &KeyPair,
        to: &PublicKey,
        sequence: u64,
        content: &[u8],
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // TODO pool/reuse these builders
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        let content = builder.create_vector(content);

        let mls_message = messaging::MlsMessage::create(
            &mut builder,
            &messaging::MlsMessageArgs {
                message: Some(content),
            },
        );

        builder.finish(mls_message, None);
        let mls_message = builder.finished_data().to_vec();
        builder.reset();

        let sender = builder.create_vector(from.address());
        let recipient = builder.create_vector(to.address());
        let content = builder.create_vector(&mls_message);

        let payload = messaging::Payload::create(
            &mut builder,
            &messaging::PayloadArgs {
                type_: ContentType::MLS_MESSAGE,
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

        let signature = builder.create_vector(&from.sign(&payload));

        let signatures = vec![messaging::Signature::create(
            &mut builder,
            &messaging::SignatureArgs {
                type_: messaging::SignatureType::PAYLOAD,
                signer: None,
                signature: Some(signature),
            },
        )];

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
                version: messaging::Version::V1,
                id: Some(eid),
                type_: messaging::EventType::MESSAGE,
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
        let subscribe = flatbuffers::root::<messaging::Subscribe>(content.bytes())
            .expect("Subscribe event invalid");

        let mut subscriptions = Vec::new();

        for subscription in subscribe
            .subscriptions()
            .expect("Subscribe subscriptions empty")
        {
            let details_buf = subscription.details().expect("Subscription details empty");
            let signatures = subscription
                .signatures()
                .expect("Subscription signatures empty");

            let details = flatbuffers::root::<messaging::SubscriptionDetails>(details_buf.bytes())
                .expect("Subscription details invalid");
            let inbox = details.inbox().expect("Subscription inbox missing");

            let (mut authenticated_as, mut authorized_by, mut authorized_for) = (None, None, None);

            // validate the subscriptions signatures
            for signature in signatures {
                let sig = signature.signature().expect("Subscription signature empty");

                match signature.type_() {
                    messaging::SignatureType::PAYLOAD => {
                        // authenticate the subscriber over the subscriptions details
                        let signer = signature.signer().unwrap_or(inbox);

                        let pk = PublicKey::from_bytes(signer.bytes())
                            .expect("Subscription signer invalid");

                        if !(pk.verify(details_buf.bytes(), sig.bytes())) {
                            err(&mut socket_tx, event.id().unwrap().bytes(), b"bad auth").await;
                            return;
                        };

                        // if the signer is the inbox that a subscription is being requested for, then we can exit
                        if inbox.bytes() == signer.bytes() {
                            (authenticated_as, authorized_by) = (
                                Some(Vec::from(signer.bytes())),
                                Some(Vec::from(signer.bytes())),
                            );
                            break;
                        }

                        authenticated_as = Some(Vec::from(signer.bytes()));
                    }
                    messaging::SignatureType::TOKEN => {
                        let token = match Token::decode(sig.bytes()) {
                            Ok(token) => token,
                            Err(_) => {
                                err(
                                    &mut socket_tx,
                                    event.id().unwrap().bytes(),
                                    b"bad token encoding",
                                )
                                .await;
                                return;
                            }
                        };

                        match token {
                            Token::Subscription(token) => {
                                // TODO validate token if not handled by decoding step...
                                // token.validate();

                                (authorized_by, authorized_for) = (
                                    Some(token.issuer().to_owned()),
                                    Some(token.bearer().to_owned()),
                                );
                            }
                            _ => {
                                err(
                                    &mut socket_tx,
                                    event.id().unwrap().bytes(),
                                    b"invalid token",
                                )
                                .await;
                                return;
                            }
                        }
                    }
                    _ => continue, // skip other signature types for now
                }
            }

            let authenticated_as = match authenticated_as {
                Some(authenticated_as) => authenticated_as,
                None => {
                    err(
                        &mut socket_tx,
                        event.id().unwrap().bytes(),
                        b"unauthenticated subscription",
                    )
                    .await;
                    return;
                }
            };

            let authorized_by = match authorized_by {
                Some(authorized_by) => authorized_by,
                None => {
                    err(
                        &mut socket_tx,
                        event.id().unwrap().bytes(),
                        b"unauthorized subscription",
                    )
                    .await;
                    return;
                }
            };

            if inbox.bytes() != authorized_by {
                err(
                    &mut socket_tx,
                    event.id().unwrap().bytes(),
                    b"unauthorized subscription",
                )
                .await;
                return;
            }

            if authenticated_as != authorized_by {
                // if the authenticated user does not match the authorized user
                // check the authorizing user has authorized the authenticated user
                let authorized_for = match authorized_for {
                    Some(authorized_for) => authorized_for,
                    None => {
                        err(
                            &mut socket_tx,
                            event.id().unwrap().bytes(),
                            b"unauthorized subscription",
                        )
                        .await;
                        return;
                    }
                };

                if authenticated_as != authorized_for {
                    err(
                        &mut socket_tx,
                        event.id().unwrap().bytes(),
                        b"unauthorized subscription",
                    )
                    .await;
                    return;
                }
            }

            subscriptions.push(authorized_by);
        }

        ack(&mut socket_tx, event.id().unwrap().bytes()).await;

        let sender = KeyPair::new();

        for subscription in subscriptions {
            let recipient =
                PublicKey::from_bytes(&subscription).expect("Invalid subscription public key");
            msg(&mut socket_tx, &sender, &recipient, 0, b"test message").await;
        }

        let mut messages = vec![];

        while let Some(message) = socket_rx.next().await {
            let m = message.expect("Failed to read message");

            if m.is_binary() {
                let data = m.into_data().clone();

                let event = messaging::root_as_event(&data).expect("Event invalid");
                let content = event.content().expect("Event content missing");
                let message = flatbuffers::root::<messaging::Message>(content.bytes())
                    .expect("Failed to process websocket message content");

                let payload = match message.payload() {
                    Some(payload) => flatbuffers::root::<messaging::Payload>(payload.bytes())
                        .expect("Failed to process websocket message content"),
                    None => continue,
                };

                // TODO validate message authentication and authorization
                if payload.recipient().is_some() {
                    ack(&mut socket_tx, event.id().unwrap().bytes()).await;
                    messages.push(Vec::from(payload.content().unwrap().bytes()));
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
        let alice_id = alice_kp.public();

        let subs = vec![Subscription {
            to_address: alice_id.clone(),
            as_address: alice_kp.clone(),
            token: None,
            last_message: crate::time::unix(),
            last_active: crate::time::unix(),
        }];

        let bob_kp = crate::keypair::signing::KeyPair::new();
        let bob_id = bob_kp.public();

        let callbacks = Callbacks {
            on_connect: Arc::new(|| {}),
            on_disconnect: Arc::new(|_| {}),
            on_event: Arc::new(|_| {}),
        };

        let (shutdown_tx, shutdown_rx) = broadcast::channel(2);

        let mut ws =
            Websocket::new("ws://localhost:12345", callbacks).expect("failed to create websocket");

        ws.connect(&shutdown_rx).expect("failed to connect");
        ws.subscribe(&subs).expect("failed to subscribe");

        let (response_tx, response_rx) = crossbeam::channel::bounded(1);

        let payload = assemble_payload_message(&alice_kp, bob_id, 0, b"test message")
            .expect("failed to create payload");

        ws.send(
            &alice_kp,
            &payload,
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

        let msg = msgs.first().unwrap().clone();

        let content =
            flatbuffers::root::<messaging::MlsMessage>(&msg).expect("is not an mls message");
        let message = content.message().expect("message is empty");

        assert_eq!(message.bytes(), Vec::from("test message"));

        /*
            let (_, ciphertext) = ws.receive().expect("Failed to receive message");
            assert_eq!(ciphertext, Vec::from("test message"));
        */

        shutdown_tx
            .send(())
            .expect("failed to send shutdown signal");
        rt.shutdown_background();
    }
}
