use crossbeam::channel;
use crossbeam::channel::{Receiver, Sender};
use futures_util::{SinkExt, StreamExt};
use tokio::runtime::Runtime;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;

use crate::error::SelfError;

enum Event {
    Message(Message),
    Done,
}

pub struct Websocket {
    endpoint: Url,
    read_tx: Sender<Message>,
    read_rx: Receiver<Message>,
    write_tx: Sender<Event>,
    write_rx: Receiver<Event>,
    runtime: Runtime,
}

impl Websocket {
    pub fn new(url: &str) -> std::result::Result<Websocket, SelfError> {
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
        };

        return Ok(ws);
    }

    pub fn connect(&mut self) -> std::result::Result<(), SelfError> {
        let handle = self.runtime.handle();
        let endpoint = self.endpoint.clone();
        let write_tx = self.write_tx.clone();
        let write_rx = self.write_rx.clone();
        let read_tx = self.read_tx.clone();

        let (tx, rx) = channel::bounded(1);

        // TODO cleanup old sockets!

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

        let socket = rx
            .recv()
            .map_err(|_| SelfError::RestRequestConnectionFailed)??;
        let (mut socket_tx, mut socket_rx) = socket.split();

        handle.spawn(async move {
            while let Some(message) = socket_rx.next().await {
                let msg = match message {
                    Ok(msg) => msg,
                    Err(_) => return,
                };

                if msg.is_close() {
                    write_tx.send(Event::Done).unwrap();
                    return;
                }

                if msg.is_ping() {
                    continue;
                }

                if msg.is_pong() {
                    continue;
                }

                if msg.is_binary() {
                    read_tx.send(msg).unwrap_or_else(|_| return);
                    continue;
                }
            }
        });

        handle.spawn(async move {
            for m in write_rx.iter() {
                match m {
                    Event::Message(msg) => match socket_tx.send(msg).await {
                        Ok(_) => continue,
                        Err(_) => break,
                    },
                    Event::Done => break,
                }
            }
            socket_tx.close().await.expect("failed to close socket");
        });

        return Ok(());
    }

    pub fn disconnect(&mut self) -> Result<(), SelfError> {
        return self
            .write_tx
            .send(Event::Done)
            .map_err(|_| SelfError::RestRequestConnectionFailed);
    }

    /*
    fn authenticate(&self) {

    }

    fn reader(&mut self) {}
    */

    pub fn send(&self, message: Message) -> Result<(), SelfError> {
        return self
            .write_tx
            .send(Event::Message(message))
            .map_err(|_| SelfError::RestRequestConnectionFailed);
    }

    pub fn receive(&self) -> Result<Message, SelfError> {
        return self
            .read_rx
            .recv()
            .map_err(|_| SelfError::RestRequestConnectionFailed);
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Add;

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
            .recv_deadline(std::time::Instant::now().add(std::time::Duration::from_secs(1)))
            .expect("Server not ready");

        return (rt, msg_rx);
    }

    #[test]
    fn send_and_receive() {
        let (rt, msg_rx) = test_server();

        // connect
        let mut ws = Websocket::new("ws://localhost:12345").unwrap();
        ws.connect().unwrap();

        // receive a message
        let msg = ws.receive().unwrap();
        assert!(msg.is_binary());
        assert_eq!(msg.into_data(), Vec::from("olleh"));

        ws.send(Message::Binary(String::from("hello").as_bytes().to_vec()))
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
