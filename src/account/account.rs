use libc::group;

use crate::account::responder::*;
use crate::account::token::token_create_authorization;

use crate::error::SelfError;
use crate::hashgraph::Hashgraph;
use crate::keypair::signing::{self, KeyPair};
use crate::keypair::{exchange, Usage};
use crate::message::{
    self, ConnectionRequest, Content, Envelope, GroupInviteRequest, ResponseStatus,
    MESSAGE_TYPE_CHAT_MSG,
};

use crate::protocol::hashgraph;
use crate::storage::Storage;
use crate::time;
use crate::token::Token;
use crate::transport::rpc::Rpc;
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
    rpc: Option<Rpc>,
    storage: Option<Arc<Mutex<Storage>>>,
    websocket: Option<Websocket>,
}

impl Account {
    pub fn new() -> Account {
        Account {
            rpc: None,
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
                move |sender: &signing::PublicKey,
                      recipient: &signing::PublicKey,
                      subscriber: &signing::PublicKey,
                      sequence: u64,
                      ciphertext: &[u8]|
                      -> Option<crate::transport::websocket::Response> {
                    let on_message_ud = user_data.clone();
                    let on_message_st = storage.clone();
                    let mut storage = on_message_st.lock().unwrap();

                    // TODO lookup exchange key as we can't convert them anymore
                    // due to NIST compliance related restrictions
                    let sender_exchange = exchange::KeyPair::new();

                    let plaintext = storage.decrypt_and_queue(
                        sender,
                        sender_exchange.public(),
                        recipient,
                        Some(subscriber.to_owned()),
                        sequence,
                        ciphertext,
                    );
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
                                                        from: from.public().to_owned(),
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
                                                                    from_clone.public(),
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
                            &signing::PublicKey,
                            &signing::PublicKey,
                            &signing::PublicKey,
                            u64,
                            &[u8],
                        ) -> Option<crate::transport::websocket::Response>
                        + Send
                        + Sync,
                >),
        };

        let rpc = Rpc::new(api_endpoint)?;
        let websocket = Websocket::new(messaging_endpoint, ws_callbacks)?;

        self.rpc = Some(rpc);
        self.storage = Some(account_storage);
        self.websocket = Some(websocket);

        Ok(())
    }

    /// register a persistent identifier
    /// returns the persistent identifier created to group all other
    /// public key identifiers
    pub fn register(&mut self) -> Result<signing::PublicKey, SelfError> {
        let rpc = match &mut self.rpc {
            Some(rpc) => rpc,
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
        let exchange_kp = exchange::KeyPair::new();

        // construct a public key operation to serve as
        // the initial public state for the account
        let graph = Hashgraph::new();

        let operation = graph
            .create()
            .id(identifier_kp.address())
            .grant_embedded(&assertion_kp.address(), hashgraph::Role::Assertion)
            .grant_embedded(
                &authentication_kp.address(),
                hashgraph::Role::Authentication,
            )
            .grant_embedded(&invocation_kp.address(), hashgraph::Role::Invocation)
            .grant_embedded(&exchange_kp.address(), hashgraph::Role::KeyAgreement)
            .sign(&identifier_kp)
            .sign(&assertion_kp)
            .sign(&authentication_kp)
            .sign(&invocation_kp)
            .build()?;

        // create an olm account for the device identifier
        let mut olm_account =
            crate::crypto::account::Account::new(authentication_kp.clone(), exchange_kp);
        olm_account.generate_one_time_keys(100)?;

        // submit public key operation to api
        rpc.execute(&identifier_kp.address(), &operation)?;

        // upload prekeys for device key
        rpc.publish(&identifier_kp.address(), &olm_account.one_time_keys())?;

        // persist account keys to keychain
        let mut storage = storage.lock().unwrap();

        storage.keypair_signing_create(Usage::Identifier, &identifier_kp, None, true)?;
        storage.keypair_signing_create(
            Usage::Messaging,
            &authentication_kp,
            Some(olm_account),
            true,
        )?;

        // TODO determine whether it makes sense from a security perspective to store the recover key
        // storage.keypair_create(KeyRole::Recovery ,&recovery_kp, None)?;

        let subscriptions = storage.subscription_list()?;
        drop(storage);

        websocket.connect(&subscriptions)?;

        Ok(identifier_kp.public().to_owned())
    }

    /// connect to another identifier
    pub fn connect(
        &mut self,
        as_address: &signing::PublicKey,
        with_address: &signing::PublicKey,
        authorization: Option<&Token>,
        _notification: Option<&Token>,
    ) -> Result<(), SelfError> {
        // attempt to acquire a one time key for the identifier
        // and create a connection and session with the identifier
        self.connect_and_create_session(with_address, as_address, authorization)?;

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
                token_create_authorization(&mut storage, Some(with_address), as_address, None)?
                    .encode()?,
            ),
            ntf: None,
        }
        .encode()?;

        msg.content_set(&content);

        drop(storage);

        self.encrypt_and_send(with_address, &msg.encode()?)?;

        // TODO if we have a notificaiton token, use it to notify the recipient

        Ok(())
    }

    /// connect to another identifier using an identifier that is already assoicated with this account
    pub fn connect_as(
        &mut self,
        _with: &signing::PublicKey,
        _using: &signing::PublicKey,
    ) -> Result<(), SelfError> {
        Ok(())
    }

    /// connect to another identifier with a new, anonymous and ephemeral identifier
    pub fn connect_anonymously(&mut self, _with: &signing::PublicKey) -> Result<(), SelfError> {
        Ok(())
    }

    /// creates an authorization and notification token (if a notification secret has been set) for the primary messaging identifier that can be shared with other identifier(s)
    pub fn token_generate(
        &mut self,
        as_address: &signing::PublicKey,
        with_address: Option<&signing::PublicKey>,
        expires: Option<i64>,
    ) -> Result<(Token, Option<Token>), SelfError> {
        let mut storage = match &mut self.storage {
            Some(storage) => storage.lock().unwrap(),
            None => return Err(SelfError::AccountNotConfigured),
        };

        let authentication_token =
            token_create_authorization(&mut storage, with_address, as_address, expires)?;

        Ok((authentication_token, None))
    }

    /*
        /// creates an authorization and notification token for a new anonymous identifier that can be shared with other identifier(s)
        pub fn token_generate_anonymously(&mut self, with: Option<&signing::PublicKey>, expires: Option<i64>) -> Result<(Token, Token), SelfError> {

        }
    */

    /// sends a message to a given identifier
    pub fn send(&mut self, to: &signing::PublicKey, message: &Content) -> Result<(), SelfError> {
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
    pub fn group_list(&mut self) -> Result<Vec<signing::PublicKey>, SelfError> {
        Ok(Vec::new())
    }

    pub fn group_create(
        &mut self,
        as_address: &signing::PublicKey,
    ) -> Result<signing::PublicKey, SelfError> {
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

        //let request = KeyCreateRequest::encode(&group_identifier)?;

        // submit public key to the to api
        //rest.post("/v2/keys", &request, None, None, true)?;

        // persist account keys to keychain
        let mut storage = storage.lock().unwrap();

        let as_address = storage.keypair_signing_get(as_address)?;
        storage.keypair_signing_create(Usage::Group, &group_kp, None, false)?;

        // create tokens for the identifier that will join the group
        websocket.subscribe(vec![Subscription {
            to_address: group_kp.public().to_owned(),
            as_address: as_address.as_ref().to_owned(),
            from: time::unix(),
            token: None, // TODO add token
        }])?;

        Ok(group_kp.public().to_owned())
    }

    pub fn group_invite(
        &mut self,
        group: &signing::PublicKey,
        members: &[&signing::PublicKey],
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

            let content = GroupInviteRequest {
                gid: group.address().to_vec(),
            }
            .encode()?;

            msg.content_set(&content);
            let plaintext = msg.encode()?;

            self.encrypt_and_send(member, &plaintext)?
        }

        Ok(())
    }

    /*

    pub fn group_kick(&mut self, group: &signing::PublicKey, members: &[&signing::PublicKey]) -> Result<(), SelfError> {

    }

    pub fn group_members(&mut self, group: &signing::PublicKey) -> Result<Vec<signing::PublicKey>, SelfError> {

    }

    pub fn group_leave(&mut self, group: &signing::PublicKey) -> Result<(), SelfError> {

    }

    pub fn group_close(&mut self, group: &signing::PublicKey) -> Result<(), SelfError> {

    }
    */

    fn connect_and_create_session(
        &mut self,
        with: &signing::PublicKey,
        using: &signing::PublicKey,
        authorization: Option<&Token>,
    ) -> Result<(), SelfError> {
        let rpc = match &mut self.rpc {
            Some(rpc) => rpc,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let mut storage = match &mut self.storage {
            Some(storage) => storage.lock().unwrap(),
            None => return Err(SelfError::AccountNotConfigured),
        };

        let using = storage.keypair_signing_get(using)?;

        let one_time_key = rpc.acquire(with.address(), using.address())?;

        //let prekey = PrekeyResponse::new(&response.data)?;

        // storage.connection_add(using, with, None, Some(&prekey.key))
        Ok(())
    }

    fn encrypt_and_send(
        &mut self,
        to: &signing::PublicKey,
        plaintext: &[u8],
    ) -> Result<(), SelfError> {
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
    to: &signing::PublicKey,
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

    storage.outbox_dequeue(from.public(), to, sequence)
}
