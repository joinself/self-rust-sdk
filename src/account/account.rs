use crate::identifier::Identifier;
use crate::keypair::signing::KeyPair;
use crate::keypair::Usage;
use crate::messaging::Messaging;
use crate::protocol::siggraph::KeyRole;
use crate::siggraph::SignatureGraph;
use crate::storage::Storage;
use crate::transport::rest::Rest;
use crate::transport::websocket::Websocket;
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

pub struct Account<'a> {
    messaging: Option<Messaging<'a>>,
    rest: Option<Rest>,
    storage: Option<Arc<Mutex<Storage>>>,
}

impl<'a> Account<'a> {
    pub fn new() -> Account<'a> {
        Account {
            rest: None,
            messaging: None,
            storage: None,
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
        let storage = Arc::new(Mutex::new(Storage::new(storage_path, encryption_key)?));
        let websocket = Arc::new(Mutex::new(Websocket::new()));
        let rest = Rest::new(api_endpoint)?;

        println!("api endpoint: {}", api_endpoint);
        println!("messaging endpoint: {}", messaging_endpoint);

        self.messaging = Some(Messaging::new(
            messaging_endpoint,
            storage.clone(),
            websocket,
        ));
        self.rest = Some(rest);
        self.storage = Some(storage);

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

        let messaging = match &mut self.messaging {
            Some(messaging) => messaging,
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
        drop(storage);

        messaging.connect()?;

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
}

impl<'a> Default for Account<'a> {
    fn default() -> Account<'a> {
        Account::new()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use httptest::{matchers::*, responders::*, Expectation, Server};

    #[test]
    fn register() {
        let server = Server::run();

        let m = all_of![
            request::method_path("POST", "/v2/identities"),
            request::headers(contains(key("x-self-pow-hash"))),
            request::headers(contains(key("x-self-pow-nonce"))),
        ];

        server.expect(
            Expectation::matching(m)
                .respond_with(status_code(201).body("{\"status\":\"success\"}")),
        );

        let recovery_key = KeyPair::new();
        let mut account = Account::new();

        let callbacks = MessagingCallbacks {
            on_connect: None,
            on_disconnect: None,
            on_request: None,
            on_response: None,
            on_message: None,
        };

        account
            .configure(
                &server.url_str("/"),
                &server.url_str("/"),
                "/tmp/",
                &[0; 32],
                callbacks,
            )
            .expect("failed to configure account");

        let identifier = account.register(&recovery_key).expect("failed to register");
        assert!(identifier.id().len() == 32);
    }
}
