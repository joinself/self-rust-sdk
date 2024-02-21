use crate::account::responder::*;
use crate::account::token::token_create_authorization;

use crate::error::SelfError;
use crate::hashgraph::Hashgraph;
use crate::identifier::Identifier;
use crate::keypair::signing::KeyPair;
use crate::keypair::Usage;
use crate::message::{
    self, ConnectionRequest, Content, Envelope, GroupInviteRequest, ResponseStatus,
    MESSAGE_TYPE_CHAT_MSG,
};
use crate::protocol::api::{KeyCreateRequest, PrekeyResponse};
use crate::protocol::hashgraph;
use crate::storage::Storage;
use crate::time;
use crate::token::Token;
use crate::transport::rest::Rest;
use crate::transport::websocket::{Callbacks, Subscription, Websocket};

use std::sync::MutexGuard;
use std::{
    any::Any,
    sync::{Arc, Mutex},
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
            // TODO refactor out this handler
            on_message: Some(Arc::new(
                move |sender: &Identifier,
                      recipient: &Identifier,
                      subscriber: Option<Identifier>,
                      sequence: u64,
                      ciphertext: &[u8]|
                      -> Option<crate::transport::websocket::Response> {
                    let on_message_ud = user_data.clone();
                    let on_message_st = storage.clone();
                    let mut storage = on_message_st.lock().unwrap();

                    let plaintext = storage
                        .decrypt_and_queue(sender, recipient, subscriber, sequence, ciphertext);
                    drop(storage);

                    let mut response: Option<crate::transport::websocket::Response> = None;

                    match plaintext {
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
                                            let message = Envelope {
                                                to: recipient.clone(),
                                                from: sender.clone(),
                                                sequence,
                                                content,
                                            };

                                            // TODO log error rather than panic
                                            let resp = match msg_type.as_str() {
                                                MESSAGE_TYPE_CHAT_MSG => Some(chat_message_delivered(&message).expect("failed to build chat message delivered response")),
                                                _ => None,
                                            };

                                            // send message and setup callback
                                            if let Some((recipient, plaintext)) = resp {
                                                let mut storage = on_message_st.lock().unwrap();

                                                let (from, sequence, content) = storage
                                                    .encrypt_and_queue(&recipient, &plaintext)
                                                    .expect("failed to encrypt and queue response");

                                                drop(storage);

                                                let on_response_st = on_message_st.clone();

                                                let from_clone = from.clone();
                                                let sender_clone = sender.clone();

                                                response =
                                                    Some(crate::transport::websocket::Response {
                                                        from,
                                                        to: sender.clone(),
                                                        sequence,
                                                        content,
                                                        tokens: None,
                                                        callback: Arc::new(move |resp| {
                                                            if resp.is_err() {
                                                                // TODO log this
                                                                return;
                                                            }

                                                            let mut storage =
                                                                on_response_st.lock().unwrap();
                                                            storage
                                                                .outbox_dequeue(
                                                                    &from_clone,
                                                                    &sender_clone.clone(),
                                                                    sequence,
                                                                )
                                                                .expect(
                                                                    "failed to dequeue response",
                                                                );
                                                            drop(storage);
                                                        }),
                                                    });
                                            }

                                            on_message_cb(on_message_ud.clone(), &message);
                                        }
                                    }
                                }
                                Err(err) => println!("failed to decode content: {}", err),
                            };
                        }
                        Err(err) => println!("failed to decrypt and queue message: {}", err),
                    }

                    response
                },
            )
                as Arc<
                    dyn Fn(
                            &Identifier,
                            &Identifier,
                            Option<Identifier>,
                            u64,
                            &[u8],
                        ) -> Option<crate::transport::websocket::Response>
                        + Send
                        + Sync,
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
    pub fn register(&mut self) -> Result<Identifier, SelfError> {
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
        let (identifier_kp, invocation_kp, authentication_kp, assertion_kp) = (
            KeyPair::new(),
            KeyPair::new(),
            KeyPair::new(),
            KeyPair::new(),
        );
        let exchange_kp = KeyPair::new().to_exchange_key()?;
        let identifier = Identifier::Owned(identifier_kp.clone());

        // construct a public key operation to serve as
        // the initial public state for the account
        let graph = Hashgraph::new();

        let operation = graph
            .create()
            .id(&identifier_kp.id())
            .key_grant_embedded(&assertion_kp.public(), hashgraph::Role::Assertion)
            .key_grant_embedded(&authentication_kp.public(), hashgraph::Role::Authentication)
            .key_grant_embedded(&invocation_kp.public(), hashgraph::Role::Invocation)
            .key_grant_embedded(&exchange_kp.public(), hashgraph::Role::KeyAgreement)
            .sign(&identifier_kp)
            .sign(&assertion_kp)
            .sign(&authentication_kp)
            .sign(&invocation_kp)
            .build()?;

        // create an olm account for the device identifier
        let mut olm_account =
            crate::crypto::account::Account::new(authentication_kp.clone(), exchange_kp.clone());
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
        // storage.keypair_create(KeyRole::Recovery ,&recovery_kp, None)?;

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
            ath: Some(
                token_create_authorization(&mut storage, Some(with), &using, None)?.encode()?,
            ),
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

    /// creates an authorization and notification token (if a notification secret has been set) for the primary messaging identifier that can be shared with other identifier(s)
    pub fn token_generate(
        &mut self,
        with: Option<&Identifier>,
        expires: Option<i64>,
    ) -> Result<(Token, Option<Token>), SelfError> {
        let as_identifier = match self.messaging_identifer() {
            Some(as_identifier) => as_identifier,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let mut storage = match &mut self.storage {
            Some(storage) => storage.lock().unwrap(),
            None => return Err(SelfError::AccountNotConfigured),
        };

        let authentication_token =
            token_create_authorization(&mut storage, with, &as_identifier, expires)?;

        Ok((authentication_token, None))
    }

    /*
        /// creates an authorization and notification token for a new anonymous identifier that can be shared with other identifier(s)
        pub fn token_generate_anonymously(&mut self, with: Option<&Identifier>, expires: Option<i64>) -> Result<(Token, Token), SelfError> {

        }
    */

    /// sends a message to a given identifier
    pub fn send(&mut self, to: &Identifier, message: &Content) -> Result<(), SelfError> {
        message.validate()?;
        self.encrypt_and_send(to, &message.encode()?)
    }

    /// accepts and actions an incoming request or message
    pub fn accept(&mut self, message: &Envelope) -> Result<(), SelfError> {
        let mut storage = match &mut self.storage {
            Some(storage) => storage.lock().unwrap(),
            None => return Err(SelfError::AccountNotConfigured),
        };

        let websocket = match &mut self.websocket {
            Some(websocket) => websocket,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let _rest = match &self.rest {
            Some(rest) => rest,
            None => return Err(SelfError::AccountNotConfigured),
        };

        if let Some(msg_type) = message.content.type_get() {
            let response = match msg_type.as_str() {
                message::MESSAGE_TYPE_CONNECTION_REQ => {
                    Some(connection_request_accept(message, &mut storage)?)
                }
                message::MESSAGE_TYPE_CHAT_MSG => Some(chat_message_read(message)?),
                // message::MESSAGE_TYPE_GROUP_INVITE_REQ => Some(group_invite_accept(message, &mut storage, rest)?),
                _ => None,
            };

            if let Some((recipient, plaintext)) = response {
                encrypt_and_send(websocket, &mut storage, &recipient, &plaintext)?;
            }

            return Ok(());
        };

        Err(SelfError::MessageContentMissing)
    }

    /// rejects an incoming request
    pub fn reject(&mut self, message: &Envelope) -> Result<(), SelfError> {
        let mut storage = match &mut self.storage {
            Some(storage) => storage.lock().unwrap(),
            None => return Err(SelfError::AccountNotConfigured),
        };

        let websocket = match &mut self.websocket {
            Some(websocket) => websocket,
            None => return Err(SelfError::AccountNotConfigured),
        };

        if let Some(msg_type) = message.content.type_get() {
            let response = match msg_type.as_str() {
                message::MESSAGE_TYPE_CONNECTION_REQ => {
                    Some(connection_request_reject(message, &mut storage)?)
                }
                //message::MESSAGE_TYPE_CREDENTIALS_REQ => {}
                _ => None,
            };

            if let Some((recipient, plaintext)) = response {
                encrypt_and_send(websocket, &mut storage, &recipient, &plaintext)?;
            }

            return Ok(());
        };

        Ok(())
    }

    /// links an ephemeral identtiy with an existing persistent one
    pub fn link(&mut self, _link_token: &Token) -> Result<(), SelfError> {
        Ok(())
    }

    /// lists all groups
    pub fn group_list(&mut self) -> Result<Vec<Identifier>, SelfError> {
        Ok(Vec::new())
    }

    pub fn group_create(&mut self, using: &Identifier) -> Result<Identifier, SelfError> {
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

        // generate keypair for the group identifier
        let group_kp = KeyPair::new();
        let group_identifier = Identifier::Owned(group_kp.clone());

        let request = KeyCreateRequest::encode(&group_identifier)?;

        // submit public key to the to api
        rest.post("/v2/keys", &request, None, None, true)?;

        // persist account keys to keychain
        let mut storage = storage.lock().unwrap();

        storage.keypair_create(Usage::Group, &group_kp, None, false)?;

        // create tokens for the identifier that will join the group
        websocket.subscribe(vec![Subscription {
            to_identifier: group_identifier.clone(),
            as_identifier: Some(using.clone()),
            from: time::unix(),
            token: None, // TODO add token
        }])?;

        Ok(group_identifier)
    }

    pub fn group_invite(
        &mut self,
        group: &Identifier,
        members: &[&Identifier],
    ) -> Result<(), SelfError> {
        // TODO track group invites?

        // send a group invite request to each of the members

        for member in members {
            let request_id = crate::crypto::random_id();
            let now = crate::time::now();

            let mut msg = Content::new();
            msg.cti_set(&request_id);
            msg.type_set(message::MESSAGE_TYPE_CONNECTION_REQ);
            msg.issued_at_set(now.timestamp());
            msg.expires_at_set((now + chrono::Duration::days(7)).timestamp());

            let content = GroupInviteRequest { gid: group.id() }.encode()?;

            msg.content_set(&content);
            let plaintext = msg.encode()?;

            self.encrypt_and_send(member, &plaintext)?
        }

        Ok(())
    }

    /*

    pub fn group_kick(&mut self, group: &Identifier, members: &[&Identifier]) -> Result<(), SelfError> {

    }

    pub fn group_members(&mut self, group: &Identifier) -> Result<Vec<Identifier>, SelfError> {

    }

    pub fn group_leave(&mut self, group: &Identifier) -> Result<(), SelfError> {

    }

    pub fn group_close(&mut self, group: &Identifier) -> Result<(), SelfError> {

    }
    */

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

        encrypt_and_send(websocket, &mut storage, to, plaintext)
    }
}

impl Default for Account {
    fn default() -> Self {
        Account::new()
    }
}

fn encrypt_and_send(
    websocket: &mut Websocket,
    storage: &mut MutexGuard<Storage>,
    to: &Identifier,
    plaintext: &[u8],
) -> Result<(), SelfError> {
    let (from, sequence, ciphertext) = storage.encrypt_and_queue(to, plaintext)?;

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

    storage.outbox_dequeue(&from, to, sequence)
}
