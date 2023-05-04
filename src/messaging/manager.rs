//use crate::crypto::omemo::Group;
use crate::identifier::Identifier;
use crate::token::Token;
use crate::{error::SelfError, keypair::signing::PublicKey};

use mockall::predicate::*;
use mockall::*;

use std::sync::{Arc, Mutex};

pub type SendCallback = Arc<dyn Fn(Result<(), SelfError>) + Sync + Send>;

#[derive(Clone)]
pub struct Subscription {
    pub identifier: Identifier,
    pub from: i64,
    pub token: Option<Token>,
}

pub struct Messaging<'a> {
    url: String,
    storage: Arc<Mutex<dyn Storage + 'a>>,
    websocket: Arc<Mutex<dyn Transport + 'a>>,
}

#[automock]
pub trait Transport {
    fn connect(
        &mut self,
        url: &str,
        subscriptions: &[Subscription],
    ) -> std::result::Result<(), SelfError>;

    fn send(
        &self,
        from: &Identifier,
        to: &Identifier,
        sequence: u64,
        content: &[u8],
        tokens: Option<Vec<Token>>,
        callback: SendCallback,
    );

    fn receive(&mut self) -> Result<(Vec<u8>, Vec<u8>), SelfError>;
}

#[automock]
pub trait Storage {
    fn encrypt_and_queue(
        &mut self,
        recipient: &Identifier,
        plaintext: &[u8],
    ) -> Result<(Identifier, u64, Vec<u8>), SelfError>;

    fn decrypt_and_queue(
        &mut self,
        sender: &Identifier,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SelfError>;

    fn outbox_dequeue(&mut self, recipient: &Identifier, sequence: u64) -> Result<(), SelfError>;
}

impl<'a> Messaging<'a> {
    pub fn new(
        url: &str,
        storage: Arc<Mutex<dyn Storage + Send + 'a>>,
        websocket: Arc<Mutex<dyn Transport + Send + 'a>>,
    ) -> Messaging<'a> {
        Messaging {
            url: url.to_string(),
            storage,
            websocket,
        }
    }

    pub fn connect(&mut self) -> Result<(), SelfError> {
        let mut websocket = self.websocket.lock().expect("failed to lock websocket");
        websocket.connect(&self.url, &Vec::new())?;

        let Subscription: Vec<crate::messaging::Subscription> = Vec::new();

        let mut storage = self.storage.lock().expect("failed to lock storage");

        // for sub into storage.subscription_list()

        Ok(())
    }

    pub fn send(&mut self, to: &Identifier, plaintext: &[u8]) -> Result<(), SelfError> {
        let mut storage = self.storage.lock().unwrap();

        let (from, sequence, ciphertext) = storage.encrypt_and_queue(to, plaintext)?;
        storage.outbox_dequeue(to, sequence)?;
        drop(storage);

        // TODO get tokens

        let (resp_tx, resp_rx) = crossbeam::channel::bounded(1);

        self.websocket.lock().unwrap().send(
            &from,
            to,
            sequence,
            &ciphertext,
            None,
            Arc::new(move |resp| {
                resp_tx.send(resp).unwrap();
            }),
        );

        resp_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| SelfError::RestRequestConnectionTimeout)?
    }

    pub fn receive(&mut self) -> Result<(Identifier, Vec<u8>), SelfError> {
        let mut websocket = self.websocket.lock().unwrap();

        // TODO this will deadlock as we have to use a lock to protect
        // the websocket, even though it implements it's own synchronization
        // and implementing DerefMut doesn't work as we don't have anything
        // to deference, so it reccursively loops forever (╯°□°）╯︵ ┻━┻
        let (sender, ciphertext) = websocket.receive()?;
        drop(websocket);

        let sender_identifier = Identifier::Referenced(PublicKey::from_bytes(
            &sender,
            crate::keypair::Algorithm::Ed25519,
        )?);

        let mut storage = self.storage.lock().unwrap();

        let plaintext = storage.decrypt_and_queue(&sender_identifier, &ciphertext)?;

        // TODO handle dequeueing the processedciphertext message from the inbox queue

        Ok((sender_identifier, plaintext))
    }

    pub fn subscribe(&mut self, _to: &Identifier) -> Result<(), SelfError> {
        Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::keypair::signing::KeyPair;

    #[test]
    fn send() {
        let sender = Identifier::Referenced(KeyPair::new().public());
        let recipient = Identifier::Referenced(KeyPair::new().public());

        let mut ms = MockStorage::new();

        ms.expect_encrypt_and_queue()
            .times(1)
            .returning(move |_, _| Ok((sender.clone(), 0, b"encrypted-message".to_vec())));

        ms.expect_outbox_dequeue().times(1).returning(|_, _| Ok(()));

        let mut mw = MockTransport::new();

        mw.expect_connect().times(1).returning(|_, _| Ok(()));

        mw.expect_send()
            .times(1)
            .returning(|_, _, _, _, _, callback| {
                callback(Ok(()));
            });

        let mut m = Messaging::new(
            "https:://joinself.com",
            Arc::new(Mutex::new(ms)),
            Arc::new(Mutex::new(mw)),
        );
        m.connect().expect("failed to connect messaging");

        m.send(&recipient, b"plaintext-message")
            .expect("failed to send message");
    }

    #[test]
    fn receive() {
        let sender = Identifier::Referenced(KeyPair::new().public());
        let sender_clone = sender.clone();

        let mut ms = MockStorage::new();

        ms.expect_decrypt_and_queue()
            .times(1)
            .returning(|_, _| Ok(b"plaintext-message".to_vec()));

        let mut mw = MockTransport::new();

        mw.expect_connect().times(1).returning(|_, _| Ok(()));

        mw.expect_receive().times(1).returning(move || {
            Ok((
                sender_clone.public_key().id(),
                b"encrypted-message".to_vec(),
            ))
        });

        let mut m = Messaging::new(
            "https:://joinself.com",
            Arc::new(Mutex::new(ms)),
            Arc::new(Mutex::new(mw)),
        );

        m.connect().expect("failed to connect messaging");

        let (snd, plaintext) = m.receive().expect("failed to receive message");
        assert!(sender.eq(&snd));
        assert_eq!(plaintext, b"plaintext-message");
    }
}
