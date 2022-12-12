use crossbeam::channel;
use crossbeam::channel::{Sender, Receiver};
use futures_util::{SinkExt, StreamExt};
//use futures_util::stream::{SplitSink};
//use futures_util::{AsyncRead, AsyncWrite, AsyncWriteExt};
//use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio_tungstenite::{connect_async, WebSocketStream, MaybeTlsStream};
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;

use crate::error::SelfError;

pub struct Websocket {
    endpoint: Url,
    socket: Option<WebSocketStream<MaybeTlsStream<TcpStream>>>,
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
            socket: None,
            read_tx: read_tx,
            read_rx: read_rx,
            write_tx: write_tx,
            write_rx: write_rx,
            runtime: runtime,
        };

        return Ok(ws)
    }

    pub fn connect(&mut self) -> std::result::Result<(), SelfError> {
        let handle = self.runtime.handle();
        let endpoint = self.endpoint.clone();

        let (tx, rx) = channel::bounded(1);
        
        /*
        // TODO cleanup old sockets!
        if self.socket.is_some() {
            let result = self.socket.unwrap().close(None).await;
            if result.is_err() {
                // TODO implement error logging!
            }
        }
        */

        handle.spawn(async move {
            let result = match connect_async(&endpoint).await {
                Ok((socket, _)) => { Ok(socket) },
                Err(_) => Err(SelfError::RestRequestConnectionFailed),
            };

            tx.send(result).unwrap();
        });

        let result = rx.recv().unwrap();
        if result.is_err() {
            return Err(result.err().unwrap());
        }    
    
        let (mut socket_tx, _socket_rx) = result.unwrap().split();

        handle.spawn(async move {
            socket_tx.send(Message::binary(vec![0; 0])).await.expect("failed to send");
        });


        //self.socket.replace(result.unwrap());

        return Ok(());
    }

    fn authenticate(&self) {

    }

    fn reader(&mut self) {
        
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