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
use crate::keypair::KeyPair;
use crate::protocol;

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
    self_id: String,
    device_id: String,
    sender_id: String,
    signing_key: KeyPair,
    read_tx: Sender<Vec<u8>>,
    read_rx: Receiver<Vec<u8>>,
    write_tx: Sender<Event>,
    write_rx: Receiver<Event>,
    runtime: Runtime,
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
            self_id: String::from(self_id),
            device_id: String::from(device_id),
            sender_id: format!("{}:{}", self_id, device_id),
            signing_key: signing_key,
            read_tx: read_tx,
            read_rx: read_rx,
            write_tx: write_tx,
            write_rx: write_rx,
            runtime: runtime,
        };

        return Ok(ws);
    }

    pub fn connect(&mut self, offset: i64) -> std::result::Result<(), SelfError> {
        let handle = self.runtime.handle();
        let endpoint = self.endpoint.clone();
        let write_tx = self.write_tx.clone();
        let write_rx = self.write_rx.clone();
        let read_tx = self.read_tx.clone();

        // TODO cleanup old sockets!

        let (tx, rx) = channel::bounded(1);
        let requests: HashMap<String, Arc<dyn Fn(Result<(), SelfError>) + Send + Sync>> =
            HashMap::new();
        let requests: Arc<
            Mutex<HashMap<String, Arc<dyn Fn(Result<(), SelfError>) + Send + Sync>>>,
        > = Arc::new(Mutex::new(requests));
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
                    let header = crate::protocol::root_as_header(&data)
                        .expect("Failed to process websocket event");

                    match header.msgtype() {
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
                            read_tx.send(data).unwrap_or_else(|_| return);
                        }
                        _ => {}
                    }

                    continue;
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
        let (event_id, auth_message) = self.authenticate_message(offset)?;
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

    fn authenticate_message(&mut self, offset: i64) -> Result<(String, Vec<u8>), SelfError> {
        let mut token = crate::message::Message::new(
            "auth.token",
            &self.self_id,
            &self.self_id,
            Some(std::time::Duration::from_secs(5)),
            true,
        );

        token.sign(&self.signing_key)?;
        let token = token.to_jwt()?;

        let event_id = crate::transport::uuid();

        // TODO avoid allocating these each time
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        let id = builder.create_string(&event_id);
        let token = builder.create_string(&token);
        let device = builder.create_string(&self.device_id);

        let auth = protocol::Auth::create(
            &mut builder,
            &protocol::AuthArgs {
                msgtype: protocol::MsgType::AUTH,
                id: Some(id),
                device: Some(device),
                token: Some(token),
                offset: offset,
            },
        );

        builder.finish(auth, None);

        return Ok((event_id, Vec::from(builder.finished_data())));
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

    fn receive(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {}

    /*
    pub fn send_message(&self, message: Message, callback: Fn(Result<(), SelfError)>)) -> Result<(), SelfError> {
        return self
            .write_tx
            .send(Event::Message(message))
            .map_err(|_| SelfError::RestRequestConnectionFailed);
    }

    pub fn receive_message(&self) -> Result<Message, SelfError> {
        return self
            .read_rx
            .recv()
            .map_err(|_| SelfError::RestRequestConnectionFailed);
    }

    */
}

#[cfg(test)]
mod tests {

    use super::*;
    use tokio::{
        io::{AsyncRead, AsyncWrite},
        net::TcpListener,
    };
    use tokio_tungstenite::tungstenite::protocol::Message;
    use tokio_tungstenite::{accept_async, WebSocketStream};

    async fn run_connection<S>(
        connection: WebSocketStream<S>,
        msg_tx: crossbeam::channel::Sender<Vec<Message>>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut socket_tx, mut socket_rx) = connection.split();

        socket_tx
            .send(Message::Binary(Vec::from("olleh")))
            .await
            .expect("Failed to send message");

        let mut messages = vec![];

        while let Some(message) = socket_rx.next().await {
            let message = message.expect("Failed to get message");
            messages.push(message);
        }

        msg_tx.send(messages).expect("Failed to send results");
    }

    fn test_server() -> (Runtime, Receiver<Vec<Message>>) {
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

        let kp = KeyPair::new(crate::keypair::KeyPairType::Ed25519);

        // connect
        let mut ws = Websocket::new("ws://localhost:12345", "self_id", "device_id", kp).unwrap();
        ws.connect(0).unwrap();

        // receive a message
        let msg = ws.receive_message().unwrap();
        assert!(msg.is_binary());
        assert_eq!(msg.into_data(), Vec::from("olleh"));

        ws.send_message(Message::Binary(String::from("hello").as_bytes().to_vec()))
            .expect("Failed to send message");

        // disconnect so we can get the messages sent to the server
        ws.disconnect().unwrap();

        // get messages sent to server
        let msgs = msg_rx.recv().unwrap();
        assert_eq!(msgs.len(), 2);

        let msg = msgs.get(0).unwrap().clone();
        assert!(msg.is_binary());
        assert_eq!(msg.into_data(), Vec::from("hello"));

        let msg = msgs.get(1).unwrap().clone();
        assert!(msg.is_close());

        rt.shutdown_background();
    }
}
