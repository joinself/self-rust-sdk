use crate::identifier::Identifier;
use crate::keypair::signing::{KeyPair, PublicKey};
use crate::keypair::Usage;
use crate::siggraph::SignatureGraph;
use crate::storage::Storage;
use crate::transport::rest::Rest;
use crate::transport::websocket::{Subscription, Websocket};
use crate::{
    error::SelfError,
    message::{Envelope, SignedContent},
    token::Token,
};

use std::{
    any::Any,
    sync::{Arc, Mutex},
};

pub type OnConnectCB = Box<dyn Fn(Box<dyn Any>)>;
pub type OnDisconnectCB = Box<dyn Fn(Box<dyn Any>, Result<(), SelfError>)>;
pub type OnRequestCB = Box<dyn Fn(Box<dyn Any>, &Envelope) -> i32>;
pub type OnResponseCB = Box<dyn Fn(Box<dyn Any>, &Envelope)>;
pub type OnMessageCB = Box<dyn Fn(Box<dyn Any>, &Envelope)>;

pub struct MessagingCallbacks {
    pub on_connect: Option<OnConnectCB>,
    pub on_disconnect: Option<OnDisconnectCB>,
    pub on_request: Option<OnRequestCB>,
    pub on_response: Option<OnResponseCB>,
    pub on_message: Option<OnMessageCB>,
}

pub struct Account {
    rest: Option<Rest>,
    storage: Option<Arc<Mutex<Storage>>>,
    websocket: Option<Websocket>,
}

impl Account {
    pub fn new() -> Account {
        Account {
            rest: None,
            storage: None,
            websocket: None,
        }
    }

    /// configures an account. if the account already exists, all existing state will
    /// be loaded and messaging subscriptions will be started
    pub fn configure(
        &mut self,
        api_endpoint: &str,
        messaging_endpoint: &str,
        storage_path: &str,
        encryption_key: &[u8],
        callbacks: MessagingCallbacks,
    ) -> Result<(), SelfError> {
        let rest = Rest::new(api_endpoint)?;
        let storage = Arc::new(Mutex::new(Storage::new(storage_path, encryption_key)?));
        let websocket = Websocket::new(messaging_endpoint)?;

        self.rest = Some(rest);
        self.storage = Some(storage);
        self.websocket = Some(websocket);

        Ok(())
    }

    pub fn register(&mut self, recovery_kp: &KeyPair) -> Result<Identifier, SelfError> {
        let rest = match &self.rest {
            Some(rest) => rest,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let storage = match &self.storage {
            Some(storage) => storage,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let websocket = match &mut self.websocket {
            Some(websocket) => websocket,
            None => return Err(SelfError::AccountNotConfigured),
        };

        // generate keypairs for account identifier and device
        let (identifier_kp, device_kp) = (KeyPair::new(), KeyPair::new());
        let identifier = Identifier::Owned(identifier_kp.clone());

        // convert device key to a curve25519 key
        let exchange_kp = device_kp.to_exchange_key()?;

        // construct a public key operation to serve as
        // the initial public state for the account
        let graph = SignatureGraph::new();

        let operation = graph
            .create()
            .id(&identifier_kp.id())
            .key_create_signing(&device_kp.public())
            .key_create_recovery(&recovery_kp.public())
            .sign(&identifier_kp)
            .sign(&device_kp)
            .sign(recovery_kp)
            .build()?;

        // create an olm account for the device identifier
        let mut olm_account = crate::crypto::account::Account::new(device_kp.clone(), exchange_kp);
        olm_account.generate_one_time_keys(100)?;

        let mut one_time_keys = Vec::new();
        ciborium::ser::into_writer(&olm_account.one_time_keys(), &mut one_time_keys)
            .expect("failed to encode one time keys");

        // submit public key operation to api
        rest.post("/v2/identities", operation, None, true)?;

        // upload prekeys for device key
        rest.post("/v2/prekeys", one_time_keys, Some(&device_kp), false)?;

        // persist account keys to keychain
        let mut storage = storage.lock().unwrap();

        storage.keypair_create(Usage::Identifier, &identifier_kp, None)?;
        storage.keypair_create(Usage::Messaging, &device_kp, Some(olm_account))?;

        // TODO determine whether it makes sense from a security perspective to store the recover key
        // storage.keypair_create(KeyRole::Identifier ,&recovery_kp, None)?;

        let subscriptions = storage.subscription_list()?;
        drop(storage);

        websocket.connect(&subscriptions)?;

        Ok(identifier)
    }

    pub fn register_anonymously(&mut self) -> Result<Identifier, SelfError> {
        Ok(Identifier::Referenced(
            crate::keypair::signing::PublicKey::from_bytes(
                vec![0; 32].as_slice(),
                crate::keypair::Algorithm::Ed25519,
            )?,
        ))
    }

    pub fn connect(&mut self, with: &Identifier) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn connect_as(&mut self, with: &Identifier, using: &Identifier) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn connect_anonymously(&mut self, with: &Identifier) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn send(&mut self, to: &Identifier, message: &SignedContent) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn accept(&mut self, message: &Envelope) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn reject(&mut self, message: &Envelope) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn link(&mut self, link_token: &Token) -> Result<(), SelfError> {
        Ok(())
    }

    fn socket_send(&mut self, to: &Identifier, plaintext: &[u8]) -> Result<(), SelfError> {
        let mut storage = match &mut self.storage {
            Some(storage) => storage.lock().unwrap(),
            None => return Err(SelfError::AccountNotConfigured),
        };

        let websocket = match &mut self.websocket {
            Some(websocket) => websocket,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let (from, sequence, ciphertext) = storage.encrypt_and_queue(to, plaintext)?;
        storage.outbox_dequeue(to, sequence)?;
        drop(storage);

        // TODO get tokens

        let (resp_tx, resp_rx) = crossbeam::channel::bounded(1);

        websocket.send(
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

    fn socket_receive(&mut self) -> Result<(Identifier, Vec<u8>), SelfError> {
        let websocket = match &mut self.websocket {
            Some(websocket) => websocket,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let mut storage = match &mut self.storage {
            Some(storage) => storage.lock().unwrap(),
            None => return Err(SelfError::AccountNotConfigured),
        };

        let (sender, ciphertext) = websocket.receive()?;

        let sender_identifier = Identifier::Referenced(PublicKey::from_bytes(
            &sender,
            crate::keypair::Algorithm::Ed25519,
        )?);

        let plaintext = storage.decrypt_and_queue(&sender_identifier, &ciphertext)?;

        // TODO handle dequeueing the processedciphertext message from the inbox queue

        Ok((sender_identifier, plaintext))
    }
}

impl Default for Account {
    fn default() -> Self {
        Account::new()
    }
}
