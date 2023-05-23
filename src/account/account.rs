use crate::error::SelfError;
use crate::identifier::Identifier;
use crate::keypair::signing::KeyPair;
use crate::keypair::Usage;
use crate::message::{
    self, ConnectionRequest, ConnectionResponse, Content, Envelope, ResponseStatus,
};
use crate::protocol::api::PrekeyResponse;
use crate::siggraph::SignatureGraph;
use crate::storage::Storage;
use crate::token::Token;
use crate::transport::rest::Rest;
use crate::transport::websocket::{Callbacks, Websocket};

use std::{
    any::Any,
    sync::{Arc, Mutex, MutexGuard},
};

pub type OnConnectCB = Arc<dyn Fn(Arc<dyn Any + Send>) + Sync + Send>;
pub type OnDisconnectCB = Arc<dyn Fn(Arc<dyn Any + Send>, Result<(), SelfError>) + Sync + Send>;
pub type OnRequestCB = Arc<dyn Fn(Arc<dyn Any + Send>, &Envelope) -> ResponseStatus + Sync + Send>;
pub type OnResponseCB = Arc<dyn Fn(Arc<dyn Any + Send>, &Envelope) + Sync + Send>;
pub type OnMessageCB = Arc<dyn Fn(Arc<dyn Any + Send>, &Envelope) + Sync + Send>;

pub struct MessagingCallbacks {
    pub on_connect: Option<OnConnectCB>,
    pub on_disconnect: Option<OnDisconnectCB>,
    pub on_request: OnRequestCB,
    pub on_response: OnResponseCB,
    pub on_message: OnMessageCB,
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
        user_data: Arc<dyn Any + Send + Sync>,
        callbacks: MessagingCallbacks,
    ) -> Result<(), SelfError> {
        let rest = Rest::new(api_endpoint)?;
        let storage = Arc::new(Mutex::new(Storage::new(storage_path, encryption_key)?));
        let account_storage = storage.clone();

        let on_request_cb = callbacks.on_request;
        let on_response_cb = callbacks.on_response;
        let on_message_cb = callbacks.on_message;

        let ws_callbacks = Callbacks {
            on_connect: callbacks.on_connect.map(|on_connect| {
                let on_connect_ud = user_data.clone();

                Arc::new(move || {
                    on_connect(on_connect_ud.clone());
                }) as Arc<dyn Fn() + Send + Sync>
            }),
            on_disconnect: callbacks.on_disconnect.map(|on_disconnect| {
                let on_disconnect_ud = user_data.clone();

                Arc::new(move |result| {
                    on_disconnect(on_disconnect_ud.clone(), result);
                }) as Arc<dyn Fn(Result<(), SelfError>) + Send + Sync>
            }),
            on_message: Some(Arc::new(
                move |sender: &Identifier,
                      recipient: &Identifier,
                      subscriber: Option<Identifier>,
                      sequence: u64,
                      ciphertext: &[u8]| {
                    let on_message_ud = user_data.clone();
                    let on_message_st = storage.clone();
                    let mut storage = on_message_st.lock().unwrap();
                    match storage
                        .decrypt_and_queue(sender, recipient, subscriber, sequence, ciphertext)
                    {
                        Ok(plaintext) => {
                            match Content::decode(&plaintext) {
                                Ok(content) => {
                                    // TODO validate standard fields

                                    // route message to the correct callbacks
                                    if let Some(msg_type) = content.type_get() {
                                        if msg_type.ends_with(".req") {
                                            on_request_cb(
                                                on_message_ud.clone(),
                                                &Envelope {
                                                    to: recipient.clone(),
                                                    from: sender.clone(),
                                                    sequence,
                                                    content,
                                                },
                                            );
                                        } else if msg_type.ends_with(".res") {
                                            on_response_cb(
                                                on_message_ud.clone(),
                                                &Envelope {
                                                    to: recipient.clone(),
                                                    from: sender.clone(),
                                                    sequence,
                                                    content,
                                                },
                                            );
                                        } else {
                                            on_message_cb(
                                                on_message_ud.clone(),
                                                &Envelope {
                                                    to: recipient.clone(),
                                                    from: sender.clone(),
                                                    sequence,
                                                    content,
                                                },
                                            );
                                        }
                                    }
                                }
                                Err(err) => println!("failed to decode content: {}", err),
                            };
                        }
                        Err(err) => println!("failed to decrypt and queue message: {}", err),
                    }
                },
            )
                as Arc<
                    dyn Fn(&Identifier, &Identifier, Option<Identifier>, u64, &[u8]) + Send + Sync,
                >),
        };

        let websocket = Websocket::new(messaging_endpoint, ws_callbacks)?;

        self.rest = Some(rest);
        self.storage = Some(account_storage);
        self.websocket = Some(websocket);

        Ok(())
    }

    /// returns the primary messaging identifier of this account
    /// if the account has been registered as a persistent identifier
    /// then this will be the device that was created when the account
    /// was made. if the account is an ephemeral, then it will the
    /// ephemeral identifier
    pub fn messaging_identifer(&self) -> Option<Identifier> {
        if let Some(storage) = &self.storage {
            let mut storage = storage.lock().expect("failed to lock storage");

            if let Ok(keypairs) = storage.keypair_list(Some(Usage::Messaging), true) {
                // there should only be one persistent messaging keypair for this device
                if let Some(keypair) = keypairs.first() {
                    return Some(Identifier::Owned(keypair.to_owned()));
                }
            }
        }

        None
    }

    /// register a persistent identifier
    /// returns the persistent identifier created to group all other
    /// public key identifiers
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

        let device_identifier = Identifier::Owned(device_kp.clone());

        // submit public key operation to api
        rest.post("/v2/identities", &operation, None, None, true)?;

        // upload prekeys for device key
        rest.post(
            "/v2/prekeys",
            &one_time_keys,
            Some(&device_identifier),
            None,
            false,
        )?;

        // persist account keys to keychain
        let mut storage = storage.lock().unwrap();

        storage.keypair_create(Usage::Identifier, &identifier_kp, None, true)?;
        storage.keypair_create(Usage::Messaging, &device_kp, Some(olm_account), true)?;

        // TODO determine whether it makes sense from a security perspective to store the recover key
        // storage.keypair_create(KeyRole::Identifier ,&recovery_kp, None)?;

        let subscriptions = storage.subscription_list()?;
        drop(storage);

        websocket.connect(&subscriptions)?;

        Ok(identifier)
    }

    /// registers an epehemral identifier
    /// this type of account does not support key revocation or recovery
    /// and serves as only an identifier to send and receive messages from.
    /// this type of account can be linked to a persistent account as a
    /// device identifier later on
    pub fn register_anonymously(&mut self) -> Result<Identifier, SelfError> {
        Ok(Identifier::Referenced(
            crate::keypair::signing::PublicKey::from_bytes(
                vec![0; 32].as_slice(),
                crate::keypair::Algorithm::Ed25519,
            )?,
        ))
    }

    /// connect to another identifier
    pub fn connect(
        &mut self,
        with: &Identifier,
        authorization: Option<&Token>,
        _notification: Option<&Token>,
    ) -> Result<(), SelfError> {
        let using = match self.messaging_identifer() {
            Some(using) => using,
            None => return Err(SelfError::AccountNotConfigured),
        };

        // attempt to acquire a one time key for the identifier
        // and create a connection and session with the identifier
        self.connect_and_create_session(with, &using, authorization)?;

        // send a connection request to the identifier
        let request_id = crate::crypto::random_id();
        let now = crate::time::now();

        let mut msg = Content::new();
        msg.cti_set(&request_id);
        msg.type_set(message::MESSAGE_TYPE_CONNECTION_REQ);
        msg.issued_at_set(now.timestamp());
        msg.expires_at_set((now + chrono::Duration::days(7)).timestamp());

        let mut storage = match &mut self.storage {
            Some(storage) => storage.lock().unwrap(),
            None => return Err(SelfError::AccountNotConfigured),
        };

        let content = ConnectionRequest {
            ath: Some(token_create_authorization(&mut storage, with, &using)?),
            ntf: None,
        }
        .encode()?;

        msg.content_set(&content);

        drop(storage);

        self.encrypt_and_send(with, &msg.encode()?)?;

        // TODO if we have a notificaiton token, use it to notify the recipient

        Ok(())
    }

    /// connect to another identifier using an identifier that is already assoicated with this account
    pub fn connect_as(&mut self, _with: &Identifier, _using: &Identifier) -> Result<(), SelfError> {
        Ok(())
    }

    /// connect to another identifier with a new, anonymous and ephemeral identifier
    pub fn connect_anonymously(&mut self, _with: &Identifier) -> Result<(), SelfError> {
        Ok(())
    }

    /// sends a message to a given identifier
    pub fn send(&mut self, to: &Identifier, message: &Content) -> Result<(), SelfError> {
        self.encrypt_and_send(to, &message.encode()?)
    }

    pub fn accept(&mut self, message: &Envelope) -> Result<(), SelfError> {
        let mut storage = match &mut self.storage {
            Some(storage) => storage.lock().unwrap(),
            None => return Err(SelfError::AccountNotConfigured),
        };

        if let Some(msg_type) = message.content.type_get() {
            match msg_type.as_str() {
                message::MESSAGE_TYPE_CONNECTION_REQ => {
                    if let Some(payload) = message.content.content_get() {
                        let connection_req = message::ConnectionRequest::decode(&payload)?;

                        // save the tokens from the sender
                        if let Some(authorization_token) = connection_req.ath {
                            storage.token_create(
                                &message.from,
                                &message.to,
                                &authorization_token,
                            )?;
                        }

                        if let Some(notification_token) = connection_req.ntf {
                            storage.token_create(
                                &message.from,
                                &message.to,
                                &notification_token,
                            )?;
                        }

                        // generate tokens for the sender of the request
                        let token =
                            token_create_authorization(&mut storage, &message.from, &message.to)?;

                        // drop the storage lock
                        drop(storage);

                        // respond to sender
                        let content = ConnectionResponse {
                            ath: Some(token),
                            ntf: None, // TODO handle notification tokens,
                            sts: ResponseStatus::Accepted,
                        }
                        .encode()?;

                        // send a response accepting the request to the sender
                        let mut msg = Content::new();

                        if let Some(cti) = message.content.cti_get() {
                            msg.cti_set(&cti);
                        }
                        msg.type_set(message::MESSAGE_TYPE_CONNECTION_RES);
                        msg.issued_at_set(crate::time::now().timestamp());
                        msg.content_set(&content);

                        self.encrypt_and_send(&message.from, &msg.encode()?)?;
                    }
                }
                message::MESSAGE_TYPE_CREDENTIALS_REQ => {}

                _ => {}
            }
        };

        Ok(())
    }

    pub fn reject(&mut self, message: &Envelope) -> Result<(), SelfError> {
        let mut storage = match &mut self.storage {
            Some(storage) => storage.lock().unwrap(),
            None => return Err(SelfError::AccountNotConfigured),
        };

        if let Some(msg_type) = message.content.type_get() {
            match msg_type.as_str() {
                message::MESSAGE_TYPE_CONNECTION_REQ => {
                    if let Some(payload) = message.content.content_get() {
                        let connection_req = message::ConnectionRequest::decode(&payload)?;

                        // save the tokens from the sender, even though we are rejecting the request
                        // so we can avoid doing POW over the message to send the response
                        if let Some(authorization_token) = connection_req.ath {
                            storage.token_create(
                                &message.from,
                                &message.to,
                                &authorization_token,
                            )?;
                        }

                        if let Some(notification_token) = connection_req.ntf {
                            storage.token_create(
                                &message.from,
                                &message.to,
                                &notification_token,
                            )?;
                        }

                        // drop the storage lock
                        drop(storage);

                        // respond to sender
                        let content = ConnectionResponse {
                            ath: None,
                            ntf: None,
                            sts: ResponseStatus::Rejected,
                        }
                        .encode()?;

                        // send a response accepting the request to the sender
                        let mut msg = Content::new();

                        if let Some(cti) = message.content.cti_get() {
                            msg.cti_set(&cti);
                        }
                        msg.type_set(message::MESSAGE_TYPE_CONNECTION_RES);
                        msg.issued_at_set(crate::time::now().timestamp());
                        msg.content_set(&content);

                        self.encrypt_and_send(&message.from, &msg.encode()?)?;
                    }
                }
                message::MESSAGE_TYPE_CREDENTIALS_REQ => {}

                _ => {}
            }
        };

        Ok(())
    }

    pub fn link(&mut self, _link_token: &Token) -> Result<(), SelfError> {
        Ok(())
    }

    fn connect_and_create_session(
        &mut self,
        with: &Identifier,
        using: &Identifier,
        authorization: Option<&Token>,
    ) -> Result<(), SelfError> {
        let rest = match &mut self.rest {
            Some(rest) => rest,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let mut storage = match &mut self.storage {
            Some(storage) => storage.lock().unwrap(),
            None => return Err(SelfError::AccountNotConfigured),
        };

        let response = rest.get(
            &format!("/v2/prekeys/{}", &hex::encode(with.id())),
            Some(using),
            authorization,
            authorization.is_none(),
        )?;

        let prekey = PrekeyResponse::new(&response.data)?;

        storage.connection_add(using, with, None, Some(&prekey.key))
    }

    fn encrypt_and_send(&mut self, to: &Identifier, plaintext: &[u8]) -> Result<(), SelfError> {
        let mut storage = match &mut self.storage {
            Some(storage) => storage.lock().unwrap(),
            None => return Err(SelfError::AccountNotConfigured),
        };

        let websocket = match &mut self.websocket {
            Some(websocket) => websocket,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let (from, sequence, ciphertext) = storage.encrypt_and_queue(to, plaintext)?;
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
            .map_err(|_| SelfError::RestRequestConnectionTimeout)??;

        let mut storage = self
            .storage
            .as_ref()
            .expect("storage is set")
            .lock()
            .unwrap();

        storage.outbox_dequeue(&from, to, sequence)
    }
}

impl Default for Account {
    fn default() -> Self {
        Account::new()
    }
}

fn token_create_authorization(
    storage: &mut MutexGuard<Storage>,
    to: &Identifier,
    from: &Identifier,
) -> Result<Token, SelfError> {
    // get keypair for signing...
    let signing_key = storage.keypair_get(from)?;
    let signing_identifier = Identifier::Owned(signing_key.as_ref().clone());

    // create a token that never expires
    // TODO make configurable
    let token = Token::Authorization(crate::token::Authorization::new(
        &signing_identifier,
        Some(to),
        i64::MAX,
    ));

    // add the token to our own storage so we can track who has been given access
    // this allows us to know which tokens will need to be rotated/revoked, etc
    storage.token_create(&signing_identifier, to, &token)?;

    Ok(token)
}
