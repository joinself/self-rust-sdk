use crate::account::Message;
use crate::crypto::e2e;
use crate::error::SelfError;
use crate::keypair::signing::{KeyPair, PublicKey};
use crate::storage::{query, Connection};
use crate::time;
use crate::transport::rpc::Rpc;
use crate::transport::websocket::{self, Callbacks, Subscription, Websocket};

use std::any::Any;
use std::sync::Arc;

pub type OnConnectCB = Arc<dyn Fn(Arc<dyn Any + Send>) + Sync + Send>;
pub type OnDisconnectCB = Arc<dyn Fn(Arc<dyn Any + Send>, Result<(), SelfError>) + Sync + Send>;
pub type OnMessageCB = Arc<dyn Fn(Arc<dyn Any + Send>, &Message) -> Option<Message> + Sync + Send>;

pub struct MessagingCallbacks {
    pub on_connect: OnConnectCB,
    pub on_disconnect: OnDisconnectCB,
    pub on_message: OnMessageCB,
}

#[derive(Default)]
pub struct Account {
    rpc: Option<Rpc>,
    storage: Option<Arc<Connection>>,
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
        rpc_endpoint: &str,
        messaging_endpoint: &str,
        storage_path: &str,
        storage_key: &[u8],
        callbacks: MessagingCallbacks,
        user_data: Arc<dyn Any + Send + Sync>,
    ) -> Result<(), SelfError> {
        let rpc = Arc::new(Rpc::new(rpc_endpoint)?);
        let storage = Arc::new(Connection::new(storage_path)?);
        let websocket = Arc::new(Websocket::new(
            messaging_endpoint,
            Callbacks {
                on_connect: on_connect_cb(user_data.clone(), callbacks.on_connect),
                on_disconnect: on_disconnect_cb(user_data.clone(), callbacks.on_disconnect),
                on_message: on_message_cb(user_data.clone(), callbacks.on_message),
            },
        ));

        Ok(())
    }

    pub fn keypair_create(&self) -> Result<PublicKey, SelfError> {
        let storage = match &self.storage {
            Some(storage) => storage,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let signing_kp = KeyPair::new();
        let signing_pk = signing_kp.public().to_owned();

        storage.transaction(|txn| {
            // TODO think about how what roles actually means here...
            query::keypair_create(txn, signing_kp, 0, crate::time::unix())?;

            txn.commit()
        })?;

        Ok(signing_pk)
    }

    pub fn keypair_sign(&self) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn inbox_open(&self, key: Option<&PublicKey>) -> Result<PublicKey, SelfError> {
        let rpc = match &self.rpc {
            Some(rpc) => rpc,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let storage = match &self.storage {
            Some(storage) => storage,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let websocket = match &self.websocket {
            Some(websocket) => websocket,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let mut signing_kp: Option<KeyPair> = None;
        let mut key_packages: Vec<Vec<u8>> = Vec::new();

        storage.transaction(|txn| {
            match key {
                Some(key) => {
                    signing_kp = query::keypair_lookup(txn, key.address())?;
                },
                None => {
                    signing_kp = Some(KeyPair::new());
                    query::keypair_create(txn, signing_kp.clone().unwrap(), 0, time::unix())?;
                }
            }

            if let Some(signing_kp) = &signing_kp {
                // setup the mls credentials and generate some key packages
                key_packages = e2e::mls_inbox_setup(txn, signing_kp, 4)?;

                // TODO mark this keypair as used as a messaging inbox
                // TODO validate this keypair is not:
                // 1. already used as an inbox
                // 2. if attached to an did, it must have an authentication role

                // TODO update metrics on inbox subscription time
            };

            txn.commit()
        })?;

        let signing_kp = match signing_kp {
            Some(signing_kp) => signing_kp,
            None => return Err(SelfError::KeyPairNotFound),
        };

        // publish the key packages
        rpc.publish(signing_kp.address(), &key_packages)?;

        // open & subscribe...
        websocket.open(&signing_kp)?;
        websocket.subscribe(&[Subscription{
            to_address: signing_kp.public().to_owned(),
            as_address: signing_kp.to_owned(),
            from: time::unix(),
            token: None,
        }])?;

        Ok(signing_kp.public().to_owned())
    }

    pub fn inbox_close(&self, key: &PublicKey) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn message_send(&self, message: &Message) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn group_create(&self, as_address: &PublicKey) -> Result<PublicKey, SelfError> {
        let storage = match &self.storage {
            Some(storage) => storage,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let websocket = match &self.websocket {
            Some(websocket) => websocket,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let signing_kp = KeyPair::new();
        let signing_pk = signing_kp.public().to_owned();

        storage.transaction(|txn| {
            // TODO think about how what roles actually means here...
            query::keypair_create(txn, signing_kp.clone(), 0, crate::time::unix())?;
            e2e::mls_group_create(txn, &signing_kp)?;
            e2e::mls_group_add_self(txn, &signing_kp)?;



            txn.commit()
        })?;

        websocket.open(&signing_kp)?;
        websocket.subscribe(&[Subscription{
            to_address: signing_kp.public().to_owned(),
            as_address: signing_kp,
            from: time::unix(),
            token: None,
        }])?;

        Ok(signing_pk)
    }

    pub fn group_invite(&self, group: &PublicKey, as_address: &PublicKey, members: &[&PublicKey]) -> Result<(), SelfError> {
        let rpc = match &self.rpc {
            Some(rpc) => rpc,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let storage = match &self.storage {
            Some(storage) => storage,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let websocket = match &self.websocket {
            Some(websocket) => websocket,
            None => return Err(SelfError::AccountNotConfigured),
        };

        let mut as_kp: Option<KeyPair> = None;
        let mut group_kp: Option<KeyPair> = None;
        let mut welcome_message: Option<Vec<u8>> = None;
        let mut key_packages = Vec::new();

        // load our keypairs in a separate txn so we don't block
        // other operations when making our network calls 
        storage.transaction(|txn| {
            as_kp = query::keypair_lookup(txn, as_address.address())?;
            group_kp = query::keypair_lookup(txn, group.address())?;
            txn.commit()
        })?;

        let as_kp = match as_kp {
            Some(as_kp) => as_kp,
            None => return Err(SelfError::KeyPairNotFound),
        };

        let group_kp = match group_kp {
            Some(group_kp) => group_kp,
            None => return Err(SelfError::KeyPairNotFound),
        };

        for member in members {
            key_packages.push(rpc.acquire(member.address(), as_kp.address())?); 
        }

        // TODO we assume the simple case here of members not needing to negotiate a
        // different address to use for joining the group
        storage.transaction(|txn| {
            (commit_message, welcome_message) = e2e::mls_group_add_members(txn, &group_kp, key_packages)?.into();
            txn.commit()
        })




    }
}

fn on_connect_cb(
    user_data: Arc<dyn Any + Send + Sync>,
    callback: OnConnectCB,
) -> websocket::OnConnectCB {
    Arc::new(move || {
        callback(user_data.clone());
    })
}

fn on_disconnect_cb(
    user_data: Arc<dyn Any + Send + Sync>,
    callback: OnDisconnectCB,
) -> websocket::OnDisconnectCB {
    Arc::new(move |result| {
        callback(user_data.clone(), result);
    })
}

fn on_message_cb(
    user_data: Arc<dyn Any + Send + Sync>,
    callback: OnMessageCB,
) -> websocket::OnMessageCB {
    Arc::new(move |message| {
        callback(user_data.clone(), &Message::Custom);
        None
    })
}
