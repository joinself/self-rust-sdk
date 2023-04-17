use crate::identifier::Identifier;
use crate::keypair::signing::KeyPair;
use crate::messaging::Messaging;
use crate::siggraph::SignatureGraph;
use crate::storage::Storage;
use crate::transport::rest::Rest;
use crate::transport::websocket::Websocket;
use crate::{
    error::SelfError,
    message::{Message, SignedMessage},
    token::Token,
};

use std::{
    any::Any,
    sync::{Arc, Mutex},
};

use reqwest::Url;

pub type OnConnectCB = Box<dyn Fn(Box<dyn Any>)>;
pub type OnDisconnectCB = Box<dyn Fn(Box<dyn Any>, Result<(), SelfError>)>;
pub type OnRequestCB = Box<dyn Fn(Box<dyn Any>, &Message) -> i32>;
pub type OnResponseCB = Box<dyn Fn(Box<dyn Any>, &Message)>;
pub type OnMessageCB = Box<dyn Fn(Box<dyn Any>, &Message)>;

pub struct MessagingCallbacks {
    pub on_connect: Option<OnConnectCB>,
    pub on_disconnect: Option<OnDisconnectCB>,
    pub on_request: Option<OnRequestCB>,
    pub on_response: Option<OnResponseCB>,
    pub on_message: Option<OnMessageCB>,
}

pub struct Account<'a> {
    rest: Rest,
    messaging: Option<Messaging<'a>>,
    storage: Option<Arc<Mutex<Storage>>>,
    server: Url,
}

impl<'a> Account<'a> {
    pub fn new() -> Account<'a> {
        Account {
            rest: Rest::new(),
            messaging: None,
            storage: None,
            server: Url::parse("https://api.joinself.com").expect("url parse shouldn't fail"),
        }
    }

    pub fn configure(
        &mut self,
        endpoint: &str,
        storage_path: &str,
        encryption_key: &[u8],
        callbacks: MessagingCallbacks,
    ) -> Result<(), SelfError> {
        // configures an account. if the account already exists, all existing state will
        // be loaded and messaging subscriptions will be started
        // self_status self_account_configure(self_account *account, char *storage_path, uint8_t *encryption_key_buf, uint32_t encryption_key_len, self_message_callbacks *msg_callbacks);

        let storage = Arc::new(Mutex::new(Storage::new()?));
        let websocket = Arc::new(Mutex::new(Websocket::new()));

        let messaging =
            Messaging::new("https://messaging.joinself.com", storage.clone(), websocket);

        Ok(())
    }

    pub fn register(&mut self, recovery_kp: &KeyPair) -> Result<Identifier, SelfError> {
        let storage = match &self.storage {
            Some(storage) => storage,
            None => return Err(SelfError::StorageConnectionFailed),
        };

        // generate keypairs for account identifier and device
        let (identifier_kp, device_kp) = (KeyPair::new(), KeyPair::new());
        let identifier = Identifier::Owned(identifier_kp.clone());

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

        // submit public key operation to api
        let url = self
            .server
            .join("/v2/identities")
            .map_err(|_| SelfError::RestRequestURLInvalid)?;
        self.rest.post(url.as_ref(), operation, None, true)?;

        // persist account keys to keychain
        storage
            .lock()
            .unwrap()
            .transaction(move |txn| {
                txn.execute(
                    "INSERT INTO account_keychain (id, role, key)
                    VALUES
                        (?1, ?2, ?3),
                        (?4, ?5, ?6),
                        (?7, ?8, ?9),
                    ",
                    (
                        &identifier_kp.id(),
                        0,
                        &identifier_kp.encode(),
                        &device_kp.id(),
                        1,
                        &device_kp.encode(),
                        &recovery_kp.id(),
                        2,
                        &recovery_kp.encode(),
                    ),
                )
                .is_ok()
            })
            .unwrap();

        //self.messaging.connect()?;

        Ok(identifier)
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

    pub fn send(&mut self, to: &Identifier, message: &SignedMessage) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn accept(&mut self, message: &Message) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn reject(&mut self, message: &Message) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn link(&mut self, link_token: &Token) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn server_set(&mut self, url: &str) -> Result<(), SelfError> {
        self.server = Url::parse(url).map_err(|_| SelfError::RestRequestURLInvalid)?;
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
            .configure(&server.url_str("/"), "/tmp/", &[0; 32], callbacks)
            .expect("failed to configure account");

        let identifier = account.register(&recovery_key).expect("failed to register");
        assert!(identifier.id().len() == 32);
    }
}
