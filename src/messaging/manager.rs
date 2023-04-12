//use crate::crypto::omemo::Group;
use crate::identifier::Identifier;
use crate::token::Token;
use crate::{error::SelfError, keypair::signing::PublicKey};

use mockall::predicate::*;
use mockall::*;

use std::sync::Arc;

type SendCallback = Arc<dyn Fn(Result<(), SelfError>) + Sync + Send>;
// type MessageCallback = Arc<dyn Fn(&Identifier, &[u8]) + Sync + Send>;

pub struct Messaging<'a> {
    storage: Box<dyn Storage + 'a>,
    websocket: Box<dyn Websocket + 'a>,
}

#[automock]
pub trait Websocket {
    fn connect(&mut self) -> std::result::Result<(), SelfError>;

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

    fn outbox_dequeue(&mut self, recipient: &Identifier, sequence: u64) -> Result<(), SelfError>;

    fn decrypt_and_queue(
        &mut self,
        sender: &Identifier,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SelfError>;
}

impl<'a> Messaging<'a> {
    pub fn new(
        storage: Box<dyn Storage + Send + 'a>,
        mut websocket: Box<dyn Websocket + 'a>,
    ) -> Result<Messaging<'a>, SelfError> {
        websocket.connect()?;
        Ok(Messaging { storage, websocket })
    }

    pub fn send(&mut self, to: &Identifier, plaintext: &[u8]) -> Result<(), SelfError> {
        let (from, sequence, ciphertext) = self.storage.encrypt_and_queue(to, plaintext)?;

        self.storage.outbox_dequeue(to, sequence)?;

        // TODO get tokens

        let (resp_tx, resp_rx) = crossbeam::channel::bounded(1);

        self.websocket.send(
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
        let (sender, ciphertext) = self.websocket.receive()?;

        let sender_identifier = Identifier::Referenced(PublicKey::from_bytes(
            &sender,
            crate::keypair::Algorithm::Ed25519,
        )?);

        let plaintext = self
            .storage
            .decrypt_and_queue(&sender_identifier, &ciphertext)?;

        // TODO handle dequeueing the processed message from the inbox queue

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

        let mut mw = MockWebsocket::new();

        mw.expect_connect().times(1).returning(|| Ok(()));

        mw.expect_send()
            .times(1)
            .returning(|_, _, _, _, _, callback| {
                callback(Ok(()));
            });

        let mut m = Messaging::new(Box::new(ms), Box::new(mw)).expect("failed to create messaging");

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

        let mut mw = MockWebsocket::new();

        mw.expect_connect().times(1).returning(|| Ok(()));

        mw.expect_receive().times(1).returning(move || {
            Ok((
                sender_clone.public_key().id(),
                b"encrypted-message".to_vec(),
            ))
        });

        let mut m = Messaging::new(Box::new(ms), Box::new(mw)).expect("failed to create messaging");

        let (snd, plaintext) = m.receive().expect("failed to receive message");
        assert!(sender.eq(&snd));
        assert_eq!(plaintext, b"plaintext-message");
    }
}
