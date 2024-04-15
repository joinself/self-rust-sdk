use crate::account::{Commit, KeyPackage, Message, Welcome};
use crate::crypto::e2e;
use crate::error::SelfError;
use crate::keypair::signing::{KeyPair, PublicKey};
use crate::storage::{query, Connection};
use crate::time;
use crate::token;
use crate::transport::rpc::Rpc;
use crate::transport::websocket::{self, Callbacks, Subscription, Websocket};

use std::any::Any;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Arc;

pub type OnConnectCB = Arc<dyn Fn() + Sync + Send>;
pub type OnDisconnectCB = Arc<dyn Fn(Result<(), SelfError>) + Sync + Send>;
pub type OnMessageCB = Arc<dyn Fn(&Message) + Sync + Send>;
pub type OnCommitCB = Arc<dyn Fn(&Commit) + Sync + Send>;
pub type OnKeyPackageCB = Arc<dyn Fn(&KeyPackage) + Sync + Send>;
pub type OnWelcomeCB = Arc<dyn Fn(&Welcome) + Sync + Send>;

pub struct MessagingCallbacks {
    pub on_connect: OnConnectCB,
    pub on_disconnect: OnDisconnectCB,
    pub on_message: OnMessageCB,
    pub on_commit: OnCommitCB,
    pub on_key_package: OnKeyPackageCB,
    pub on_welcome: OnWelcomeCB,
}

#[derive(Default)]
pub struct Account {
    rpc: Arc<AtomicPtr<Rpc>>,
    storage: Arc<AtomicPtr<Connection>>,
    websocket: Arc<AtomicPtr<Websocket>>,
}

impl Account {
    pub fn new() -> Account {
        Account {
            rpc: Arc::new(AtomicPtr::new(ptr::null_mut())),
            storage: Arc::new(AtomicPtr::new(ptr::null_mut())),
            websocket: Arc::new(AtomicPtr::new(ptr::null_mut())),
        }
    }

    /// configures an account. if the account already exists, all existing state will
    /// be loaded and messaging subscriptions will be started
    pub fn configure(
        &mut self,
        rpc_endpoint: &str,
        messaging_endpoint: &str,
        storage_path: &str,
        _storage_key: &[u8],
        callbacks: MessagingCallbacks,
    ) -> Result<(), SelfError> {
        let rpc = Rpc::new(rpc_endpoint)?;
        let rpc = Box::into_raw(Box::new(rpc));
        let result =
            self.rpc
                .compare_exchange(ptr::null_mut(), rpc, Ordering::SeqCst, Ordering::SeqCst);
        if result.is_err() {
            return Err(SelfError::AccountAlreadyConfigured);
        };

        let storage = Connection::new(storage_path)?;
        let storage = Box::into_raw(Box::new(storage));
        self.storage.swap(storage, Ordering::SeqCst);

        let mut websocket = Websocket::new(
            messaging_endpoint,
            Callbacks {
                on_connect: on_connect_cb(callbacks.on_connect),
                on_disconnect: on_disconnect_cb(callbacks.on_disconnect),
                on_message: on_message_cb(&self.storage, callbacks.on_message),
                on_commit: on_commit_cb(&self.storage, callbacks.on_commit),
                on_key_package: on_key_package_cb(&self.storage, callbacks.on_key_package),
                on_welcome: on_welcome_cb(&self.storage, callbacks.on_welcome),
            },
        )?;

        websocket.connect()?;

        let websocket = Box::into_raw(Box::new(websocket));
        self.websocket.swap(websocket, Ordering::SeqCst);

        // TODO - resume subscriptions
        // TODO - (re-)send messages in outbox
        // TODO - (re-)handle messages in inbox

        Ok(())
    }

    /// generates and stores a new signing keypair
    pub fn keypair_create(&self) -> Result<PublicKey, SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let signing_kp = KeyPair::new();
        let signing_pk = signing_kp.public().to_owned();

        unsafe {
            (*storage).transaction(|txn| {
                // TODO think about how what roles actually means here...
                query::keypair_create(txn, signing_kp, 0, crate::time::unix())?;

                Ok(())
            })?;
        }

        Ok(signing_pk)
    }

    /// opens a new messaging inbox and subscribes to it
    pub fn inbox_open(&self, key: Option<&PublicKey>) -> Result<PublicKey, SelfError> {
        let rpc = self.rpc.load(Ordering::SeqCst);
        if rpc.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let websocket = self.websocket.load(Ordering::SeqCst);
        if websocket.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let mut signing_kp: Option<KeyPair> = None;
        let mut subscription_token: Option<token::Subscription> = None;
        let mut key_packages: Vec<Vec<u8>> = Vec::new();

        unsafe {
            (*storage).transaction(|txn| {
                match key {
                    Some(key) => {
                        signing_kp = query::keypair_lookup(txn, key.address())?;
                    }
                    None => {
                        signing_kp = Some(KeyPair::new());
                        query::keypair_create(txn, signing_kp.clone().unwrap(), 0, time::unix())?;
                    }
                }

                if let Some(signing_kp) = &signing_kp {
                    subscription_token = Some(token::Subscription::new(
                        signing_kp,
                        signing_kp.public(),
                        time::unix(),
                        i64::MAX,
                    ));

                    query::token_create(
                        txn,
                        query::Token::Subscription,
                        signing_kp.address(),
                        signing_kp.address(),
                        signing_kp.address(),
                        subscription_token.as_ref().unwrap().as_bytes(),
                    )?;

                    // setup the mls credentials and generate some key packages
                    key_packages = e2e::mls_inbox_setup(txn, signing_kp, 4)?;

                    // TODO mark this keypair as used as a messaging inbox
                    // TODO validate this keypair is not:
                    // 1. already used as an inbox
                    // 2. if attached to an did, it must have an authentication role

                    // TODO update metrics on inbox subscription time
                };

                Ok(())
            })?;
        }

        let signing_kp = match signing_kp {
            Some(signing_kp) => signing_kp,
            None => return Err(SelfError::KeyPairNotFound),
        };

        let subscription_token = match subscription_token {
            Some(subscription_token) => subscription_token,
            None => return Err(SelfError::KeyPairNotFound),
        };

        // publish the key packages
        unsafe {
            (*rpc).publish(signing_kp.address(), &key_packages)?;

            // open & subscribe...
            (*websocket).open(&signing_kp)?;
            (*websocket).subscribe(&[Subscription {
                to_address: signing_kp.public().to_owned(),
                as_address: signing_kp.to_owned(),
                from: time::unix(),
                token: Some(token::Token::Subscription(subscription_token)),
            }])?;
        }

        Ok(signing_kp.public().to_owned())
    }

    /// permanently close an inbox
    pub fn inbox_close(&self, _key: &PublicKey) -> Result<(), SelfError> {
        Ok(())
    }

    // connect with another address
    pub fn connection_connect(
        &self,
        as_address: &PublicKey,
        with_address: &PublicKey,
        key_package: Option<&[u8]>,
    ) -> Result<(), SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let websocket = self.websocket.load(Ordering::SeqCst);
        if websocket.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe {
            match key_package {
                Some(key_package) => connection_establish(
                    &(*storage),
                    &(*websocket),
                    as_address,
                    with_address,
                    key_package,
                ),
                None => connection_negotiate(&(*storage), &(*websocket), as_address, with_address),
            }
        }
    }

    // accept a group connection
    pub fn connection_accept(
        &self,
        as_address: &PublicKey,
        welcome: &[u8],
        subscription_token: &[u8],
    ) -> Result<(), SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let websocket = self.websocket.load(Ordering::SeqCst);
        if websocket.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe {
            connection_accept(
                &(*storage),
                &(*websocket),
                as_address,
                welcome,
                subscription_token,
            )
        }
    }

    /// send a message to an address
    pub fn message_send(&self, to_address: &PublicKey, content: &[u8]) -> Result<(), SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let websocket = self.websocket.load(Ordering::SeqCst);
        if websocket.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let mut as_address: Option<KeyPair> = None;
        let mut from_address: Option<PublicKey> = None;
        let mut group_address: Option<PublicKey> = None;
        let mut ciphertext = Vec::new();
        let sequence: u64 = 0;

        unsafe {
            (*storage).transaction(|txn| {
                // TODO determine is this is a group, did or inbox address
                group_address = query::group_with(txn, to_address.address(), 1)?
                    .map(|address| PublicKey::from_bytes(&address).expect("failed to load key"));

                let group_address = match &group_address {
                    Some(group_address) => group_address,
                    None => return Err(SelfError::KeyPairNotFound),
                };

                from_address = query::group_as(txn, group_address.address(), 1)?
                    .map(|address| PublicKey::from_bytes(&address).expect("failed to load key"));

                let from_address = match &from_address {
                    Some(from_address) => from_address,
                    None => return Err(SelfError::KeyPairNotFound),
                };

                as_address = query::keypair_lookup(txn, from_address.address())?;
                if let Some(as_address) = &as_address {
                    ciphertext =
                        e2e::mls_group_encrypt(txn, group_address.address(), as_address, content)?;

                    // TODO load sequence...

                    query::outbox_queue(
                        txn,
                        query::Event::Message,
                        as_address.address(),
                        group_address.address(),
                        &ciphertext,
                        sequence,
                    )?;
                }

                Ok(())
            })?;
        }

        let as_address = match &as_address {
            Some(as_address) => as_address,
            None => return Err(SelfError::KeyPairNotFound),
        };

        let group_address = match &group_address {
            Some(group_address) => group_address,
            None => return Err(SelfError::KeyPairNotFound),
        };

        let payload =
            websocket::assemble_payload_message(as_address, group_address, 0, &ciphertext)?;

        let (resp_tx, resp_rx) = crossbeam::channel::bounded(1);

        unsafe {
            (*websocket).send(
                as_address,
                &payload,
                None,
                Arc::new(move |resp| {
                    resp_tx.send(resp).unwrap();
                }),
            );
        }

        resp_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| SelfError::RestRequestConnectionTimeout)??;

        unsafe {
            (*storage).transaction(|txn| {
                query::outbox_dequeue(txn, as_address.address(), group_address.address(), sequence)
            })
        }
    }

    /// creates a new group
    pub fn group_create(&self, as_address: &PublicKey) -> Result<PublicKey, SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let websocket = self.websocket.load(Ordering::SeqCst);
        if websocket.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };
        let group_kp = KeyPair::new();
        let group_pk = group_kp.public().to_owned();
        let mut as_keypair: Option<KeyPair> = None;

        let subscription_token =
            token::Subscription::new(&group_kp, as_address, time::unix(), i64::MAX);

        unsafe {
            (*storage).transaction(|txn| {
                // TODO think about how what roles actually means here...
                as_keypair = match query::keypair_lookup(txn, as_address.address())? {
                    Some(as_keypair) => Some(as_keypair),
                    None => return Err(SelfError::KeyPairNotFound),
                };

                query::keypair_create(txn, group_kp.clone(), 0, crate::time::unix())?;
                query::group_create(txn, group_kp.address(), 2)?;
                query::group_member_add(txn, group_kp.address(), as_address.address())?;
                e2e::mls_group_create(txn, group_kp.address(), as_keypair.as_ref().unwrap())?;
                query::token_create(
                    txn,
                    query::Token::Subscription,
                    group_kp.address(),
                    as_address.address(),
                    group_kp.address(),
                    subscription_token.as_bytes(),
                )
            })?;

            let as_keypair = match as_keypair {
                Some(as_keypair) => as_keypair,
                None => return Err(SelfError::KeyPairNotFound),
            };

            (*websocket).open(&group_kp)?;
            (*websocket).subscribe(&[Subscription {
                to_address: group_kp.public().to_owned(),
                as_address: as_keypair,
                from: time::unix(),
                token: Some(token::Token::Subscription(subscription_token)),
            }])?;
        }

        Ok(group_pk)
    }

    /// list all groups
    pub fn group_list(&self) -> Result<Vec<PublicKey>, SelfError> {
        Ok(Vec::new())
    }
}

impl Clone for Account {
    fn clone(&self) -> Self {
        Account {
            rpc: self.rpc.clone(),
            storage: self.storage.clone(),
            websocket: self.websocket.clone(),
        }
    }
}

fn connection_negotiate(
    storage: &Connection,
    websocket: &Websocket,
    as_address: &PublicKey,
    with_address: &PublicKey,
) -> Result<(), SelfError> {
    let mut key_package_payload: Option<Vec<u8>> = None;
    let mut as_keypair: Option<KeyPair> = None;

    storage.transaction(|txn| {
        as_keypair = query::keypair_lookup(txn, as_address.address())?;

        let as_address = match &as_keypair {
            Some(as_address) => as_address,
            None => return Err(SelfError::KeyPairNotFound),
        };

        // generate a key package
        let key_package = e2e::mls_key_package_create(txn, as_address)?;

        // generate a temporary send token

        // generate a temporary push token

        // load metrics to get sequence...

        // assemble key package message
        let key_package_encoded = websocket::assemble_payload_key_package(
            as_address,
            with_address,
            0,
            &key_package,
            None,
            None,
        )?;

        // queue message in inbox
        query::address_create(txn, with_address.address())?;
        query::outbox_queue(
            txn,
            query::Event::KeyPackage,
            as_address.address(),
            with_address.address(),
            &key_package_encoded,
            0,
        )?;

        key_package_payload = Some(key_package_encoded);

        Ok(())
    })?;

    // TODO send with any tokens we may have...

    let (resp_tx, resp_rx) = crossbeam::channel::bounded(1);

    let as_keypair = match &as_keypair {
        Some(as_keypair) => as_keypair,
        None => return Err(SelfError::KeyPairNotFound),
    };

    let key_package_payload = match &key_package_payload {
        Some(key_package_payload) => key_package_payload,
        None => return Err(SelfError::MessagePayloadInvalid),
    };

    // websocket send
    websocket.send(
        as_keypair,
        key_package_payload,
        None,
        Arc::new(move |resp| {
            resp_tx.send(resp).unwrap();
        }),
    );

    resp_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| SelfError::RestRequestConnectionTimeout)??;

    // notify...

    // deqeue sent...

    Ok(())
}

fn connection_establish(
    storage: &Connection,
    websocket: &Websocket,
    as_address: &PublicKey,
    with_address: &PublicKey,
    key_package: &[u8],
) -> Result<(), SelfError> {
    let group_kp = KeyPair::new();

    let mut welcome_payload: Option<Vec<u8>> = None;
    let mut commit_payload: Option<Vec<u8>> = None;
    let mut as_keypair: Option<KeyPair> = None;

    // generate tokens for ourself and our counterparty
    let as_send_token = token::Send::new(&group_kp, Some(as_address), time::unix(), i64::MAX);
    let with_send_token = token::Send::new(&group_kp, Some(with_address), time::unix(), i64::MAX);

    let as_subscription_token =
        token::Subscription::new(&group_kp, as_address, time::unix(), i64::MAX);

    let with_subscription_token =
        token::Subscription::new(&group_kp, with_address, time::unix(), i64::MAX);

    // TODO generate push token

    storage.transaction(|txn| {
        as_keypair = query::keypair_lookup(txn, as_address.address())?;

        let as_address = match &as_keypair {
            Some(as_address) => as_address,
            None => return Err(SelfError::KeyPairNotFound),
        };

        // TODO think about how what roles actually means here...
        query::keypair_create(txn, group_kp.clone(), 0, crate::time::unix())?;
        query::group_create(txn, group_kp.address(), 1)?;
        query::group_member_add(txn, group_kp.address(), as_address.address())?;
        query::group_member_add(txn, group_kp.address(), with_address.address())?;

        let (commit_message, welcome_message) = e2e::mls_group_create_with_members(
            txn,
            group_kp.address(),
            as_address,
            &[key_package],
        )?;

        // store our send and subscription tokens that we will use to con
        query::token_create(
            txn,
            query::Token::Send,
            group_kp.address(),
            as_address.address(),
            group_kp.address(),
            as_send_token.as_bytes(),
        )?;
        query::token_create(
            txn,
            query::Token::Subscription,
            group_kp.address(),
            as_address.address(),
            group_kp.address(),
            as_subscription_token.as_bytes(),
        )?;

        welcome_payload = Some(websocket::assemble_payload_welcome(
            as_address,
            with_address,
            0,
            &welcome_message,
            Some(with_send_token.as_bytes()),
            Some(with_subscription_token.as_bytes()),
        )?);

        commit_payload = Some(websocket::assemble_payload_commit(
            as_address,
            group_kp.public(),
            0,
            &commit_message,
        )?);

        // TODO setup/load metrics

        // queue commit and welcome message
        query::outbox_queue(
            txn,
            query::Event::Commit,
            as_address.address(),
            group_kp.address(),
            commit_payload.as_ref().unwrap(),
            0,
        )?;

        query::outbox_queue(
            txn,
            query::Event::Welcome,
            as_address.address(),
            with_address.address(),
            welcome_payload.as_ref().unwrap(),
            0,
        )?;

        // queue notification message

        Ok(())
    })?;

    let as_keypair = match &as_keypair {
        Some(as_keypair) => as_keypair,
        None => return Err(SelfError::KeyPairNotFound),
    };

    let commit_payload = match &commit_payload {
        Some(commit_payload) => commit_payload,
        None => return Err(SelfError::MessagePayloadInvalid),
    };

    let welcome_payload = match &welcome_payload {
        Some(welcome_payload) => welcome_payload,
        None => return Err(SelfError::MessagePayloadInvalid),
    };

    // open the group inbox and subscribe
    websocket.open(&group_kp)?;
    websocket.subscribe(&[Subscription {
        to_address: group_kp.public().to_owned(),
        as_address: as_keypair.to_owned(),
        from: time::unix(),
        token: Some(token::Token::Subscription(as_subscription_token)),
    }])?;

    let (resp_tx, resp_rx) = crossbeam::channel::bounded(1);

    // send the commit message to the group inbox
    websocket.send(
        as_keypair,
        commit_payload,
        None,
        Arc::new(move |resp| {
            resp_tx.send(resp).unwrap();
        }),
    );

    resp_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| SelfError::RestRequestConnectionTimeout)??;

    // TODO deque send

    // TODO send with any tokens we may have...

    let (resp_tx, resp_rx) = crossbeam::channel::bounded(1);

    // websocket send
    websocket.send(
        as_keypair,
        welcome_payload,
        None,
        Arc::new(move |resp| {
            resp_tx.send(resp).unwrap();
        }),
    );

    resp_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| SelfError::RestRequestConnectionTimeout)??;

    // TODO notify...

    // TODO deqeue sent...

    Ok(())
}

fn connection_accept(
    storage: &Connection,
    websocket: &Websocket,
    as_address: &PublicKey,
    welcome: &[u8],
    subscription_token: &[u8],
) -> Result<(), SelfError> {
    let mut group_address: Option<PublicKey> = None;
    let mut as_keypair: Option<KeyPair> = None;

    let subscription_token = match token::Token::decode(subscription_token)? {
        token::Token::Subscription(subscription) => subscription,
        _ => return Err(SelfError::TokenTypeInvalid),
    };

    storage.transaction(|txn| {
        as_keypair = query::keypair_lookup(txn, as_address.address())?;
        if as_keypair.is_none() {
            return Err(SelfError::KeyPairNotFound);
        }

        let (group, members) = e2e::mls_group_create_from_welcome(txn, welcome)?;
        query::group_create(txn, group.address(), 1)?;

        for member in members {
            query::group_member_add(txn, group.address(), member.address())?;
        }

        group_address = Some(group);

        query::token_create(
            txn,
            query::Token::Subscription,
            group_address.as_ref().unwrap().address(),
            as_address.address(),
            group_address.as_ref().unwrap().address(),
            subscription_token.as_bytes(),
        )?;

        // generate send token

        // generate push token

        // queue notification message

        Ok(())
    })?;

    let as_keypair = match &as_keypair {
        Some(as_keypair) => as_keypair,
        None => return Err(SelfError::KeyPairNotFound),
    };

    let group_address = match &group_address {
        Some(group_address) => group_address,
        None => return Err(SelfError::KeyPairNotFound),
    };

    // subscribe
    websocket.subscribe(&[Subscription {
        to_address: group_address.to_owned(),
        as_address: as_keypair.to_owned(),
        from: time::unix(),
        token: Some(token::Token::Subscription(subscription_token)),
    }])?;

    // TODO notify...

    // TODO deqeue sent...

    Ok(())
}

fn on_connect_cb(callback: OnConnectCB) -> websocket::OnConnectCB {
    Arc::new(move || {
        callback();
    })
}

fn on_disconnect_cb(callback: OnDisconnectCB) -> websocket::OnDisconnectCB {
    Arc::new(move |result| {
        callback(result);
    })
}

fn on_message_cb(
    storage: &Arc<AtomicPtr<Connection>>,
    callback: OnMessageCB,
) -> websocket::OnMessageCB {
    let storage = storage.clone();

    Arc::new(move |message| {
        let storage = storage.load(Ordering::SeqCst);
        let mut plaintext: Option<Vec<u8>> = None;

        unsafe {
            let result = (*storage).transaction(|txn| {
                let decrypted_message =
                    e2e::mls_group_decrypt(txn, message.recipient.address(), &message.message)?;

                query::address_create(txn, message.sender.address())?;
                query::inbox_queue(
                    txn,
                    query::Event::Message,
                    message.sender.address(),
                    message.recipient.address(),
                    &decrypted_message,
                    message.sequence,
                )?;

                plaintext = Some(decrypted_message);

                Ok(())
            });

            if let Err(err) = result {
                println!("transaction failed: {}", err);
                return;
            }
        }

        let plaintext = match plaintext {
            Some(plaintext) => plaintext,
            None => return,
        };

        callback(&Message::new(
            &message.sender,
            &message.recipient,
            &plaintext,
            message.sequence,
        ));

        unsafe {
            let result = (*storage).transaction(|txn| {
                query::inbox_dequeue(
                    txn,
                    message.sender.address(),
                    message.recipient.address(),
                    message.sequence,
                )
            });

            if let Err(err) = result {
                println!("transaction failed: {}", err);
            }
        }
    })
}

fn on_commit_cb(
    storage: &Arc<AtomicPtr<Connection>>,
    callback: OnCommitCB,
) -> websocket::OnCommitCB {
    let storage = storage.clone();

    Arc::new(move |commit| {
        let storage = storage.load(Ordering::SeqCst);

        unsafe {
            let result = (*storage).transaction(|txn| {
                query::address_create(txn, commit.sender.address())?;
                query::inbox_queue(
                    txn,
                    query::Event::Commit,
                    commit.sender.address(),
                    commit.recipient.address(),
                    &commit.commit,
                    commit.sequence,
                )?;

                Ok(())
            });

            if let Err(err) = result {
                println!("transaction failed: {}", err);
                return;
            }
        }

        callback(&Commit::new(
            &commit.sender,
            &commit.recipient,
            &commit.commit,
            commit.sequence,
        ));

        unsafe {
            let result = (*storage).transaction(|txn| {
                query::inbox_dequeue(
                    txn,
                    commit.sender.address(),
                    commit.recipient.address(),
                    commit.sequence,
                )
            });

            if let Err(err) = result {
                println!("transaction failed: {}", err);
            }
        }
    })
}

fn on_key_package_cb(
    storage: &Arc<AtomicPtr<Connection>>,
    callback: OnKeyPackageCB,
) -> websocket::OnKeyPackageCB {
    let storage = storage.clone();

    Arc::new(move |package| {
        let storage = storage.load(Ordering::SeqCst);

        unsafe {
            let result = (*storage).transaction(|txn| {
                query::address_create(txn, package.sender.address())?;
                query::inbox_queue(
                    txn,
                    query::Event::KeyPackage,
                    package.sender.address(),
                    package.recipient.address(),
                    &package.package,
                    package.sequence,
                )?;

                Ok(())
            });

            if let Err(err) = result {
                println!("transaction failed: {}", err);
                return;
            }
        }

        callback(&KeyPackage::new(
            &package.sender,
            &package.recipient,
            &package.package,
            package.sequence,
            true,
        ));

        unsafe {
            let result = (*storage).transaction(|txn| {
                query::inbox_dequeue(
                    txn,
                    package.sender.address(),
                    package.recipient.address(),
                    package.sequence,
                )
            });

            if let Err(err) = result {
                println!("transaction failed: {}", err);
            }
        }
    })
}

fn on_welcome_cb(
    storage: &Arc<AtomicPtr<Connection>>,
    callback: OnWelcomeCB,
) -> websocket::OnWelcomeCB {
    let storage = storage.clone();

    Arc::new(move |welcome| {
        let storage = storage.load(Ordering::SeqCst);

        unsafe {
            let result = (*storage).transaction(|txn| {
                query::address_create(txn, welcome.sender.address())?;
                query::inbox_queue(
                    txn,
                    query::Event::KeyPackage,
                    welcome.sender.address(),
                    welcome.recipient.address(),
                    &welcome.welcome,
                    welcome.sequence,
                )?;

                Ok(())
            });

            if let Err(err) = result {
                println!("transaction failed: {}", err);
                return;
            }
        }

        callback(&Welcome::new(
            &welcome.sender,
            &welcome.recipient,
            &welcome.welcome,
            welcome.sequence,
            &welcome.subscription,
            true,
        ));

        unsafe {
            let result = (*storage).transaction(|txn| {
                query::inbox_dequeue(
                    txn,
                    welcome.sender.address(),
                    welcome.recipient.address(),
                    welcome.sequence,
                )
            });

            if let Err(err) = result {
                println!("transaction failed: {}", err);
            }
        }
    })
}
