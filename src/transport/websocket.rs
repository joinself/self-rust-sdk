use crossbeam::channel;
use crossbeam::channel::{Receiver, Sender};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use url::Url;

/*
use std::cell::RefCell;
use std::rc::Rc;
 */

use crate::error::SelfError;

pub struct Websocket {
    endpoint: Url,
    read_tx: Sender<Message>,
    read_rx: Receiver<Message>,
    write_tx: Sender<Message>,
    write_rx: Receiver<Message>,
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

        let (tx, rx) = channel::bounded(1);

        /*
        // TODO cleanup old sockets!
         */

        handle.spawn(async move {
            let result = match connect_async(&endpoint).await {
                Ok((socket, _)) => Ok(socket),
                Err(_) => Err(SelfError::RestRequestConnectionFailed),
            };

            tx.send(result).unwrap();
        });

        let result = rx.recv().unwrap();
        if result.is_err() {
            return Err(result.err().unwrap());
        }

        let socket = result.unwrap();
        let (mut socket_tx, socket_rx) = socket.split();

        let write_rx = self.write_rx.clone();
        let read_tx = self.read_tx.clone();

        handle.spawn(async move {
            for m in write_rx.iter() {
                socket_tx.send(m).await.unwrap_or_else(|_| return);
            }
            // TODO remove this
            println!("exiting writer loop");
        });

        handle.spawn(async move {
            socket_rx
                .for_each(|message| async {
                    if message.is_ok() {
                        let m = message.unwrap();

                        if m.is_close() {}

                        if m.is_ping() {}

                        if m.is_pong() {}

                        if m.is_binary() {
                            read_tx.send(m).unwrap_or_else(|_| return);
                            // TODO remove this
                        }
                    }
                })
                .await;

            println!("exiting writer loop");
        });

        //self.socket_tx.replace(socket_tx);

        return Ok(());
    }

    fn authenticate(&self) {}

    fn reader(&mut self) {}

    fn send(&self, message: Message) -> Result<(), SelfError> {
        return self
            .write_tx
            .send(message)
            .map_err(|_| SelfError::RestRequestConnectionFailed);
    }

    fn receive(&self) -> Result<Message, SelfError> {
        return self
            .read_rx
            .recv()
            .map_err(|_| SelfError::RestRequestConnectionFailed);
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn new() {
        let ws = Websocket::new("wss://messaging.joinself.com/v2/messaging").unwrap();
    }
}
