use crate::account::{operation, Commit, KeyPackage, Message, Welcome};
use crate::crypto::e2e;
use crate::error::SelfError;
use crate::hashgraph::{Hashgraph, Operation, RoleSet};
use crate::keypair::exchange;
use crate::keypair::signing::{self, KeyPair, PublicKey};
use crate::storage::{query, Connection};
use crate::transport::rpc::Rpc;
use crate::transport::websocket::{self, Callbacks, Websocket};

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
    pub fn keypair_signing_create(&self) -> Result<signing::PublicKey, SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let signing_kp = KeyPair::new();
        let signing_pk = signing_kp.public().to_owned();

        unsafe {
            (*storage).transaction(|txn| {
                // create a key with no roles assigned
                query::keypair_create(txn, signing_kp, 0, crate::time::unix())?;
                Ok(())
            })?;
        }

        Ok(signing_pk)
    }

    /// generates and stores a new signing keypair
    pub fn keypair_exchange_create(&self) -> Result<exchange::PublicKey, SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let exchange_kp = exchange::KeyPair::new();
        let exchange_pk = exchange_kp.public().to_owned();

        unsafe {
            (*storage).transaction(|txn| {
                // create a key with no roles assigned
                query::keypair_create(txn, exchange_kp, 0, crate::time::unix())?;
                Ok(())
            })?;
        }

        Ok(exchange_pk)
    }

    /// looks up keys assigned to an identity with a given set of roles
    pub fn keypair_signing_associated_with<T>(
        &self,
        did_address: &PublicKey,
        roles: T,
    ) -> Result<Vec<signing::PublicKey>, SelfError>
    where
        T: RoleSet,
    {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let mut public_keys: Vec<signing::PublicKey> = Vec::new();

        unsafe {
            (*storage).transaction(|txn| {
                for kp in query::keypair_associated_with::<signing::KeyPair>(
                    txn,
                    did_address.address(),
                    roles.roles(),
                )? {
                    public_keys.push(kp.public().to_owned());
                }
                Ok(())
            })?;
        }

        Ok(public_keys)
    }

    /// resolves a did document for a given address
    pub fn identity_resolve(&self, did_address: &PublicKey) -> Result<Hashgraph, SelfError> {
        let rpc = self.rpc.load(Ordering::SeqCst);
        if rpc.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe { operation::identity_resolve(&(*storage), &(*rpc), did_address.address()) }
    }

    /// execute an operation to update an existing document
    pub fn identity_execute(&self, operation: &mut Operation) -> Result<(), SelfError> {
        let rpc = self.rpc.load(Ordering::SeqCst);
        if rpc.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe { operation::identity_execute(&(*storage), &(*rpc), operation) }
    }

    /// opens a new messaging inbox and subscribes to it with the provided key
    pub fn inbox_open(&self) -> Result<PublicKey, SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let websocket = self.websocket.load(Ordering::SeqCst);
        if websocket.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe { operation::inbox_open(&(*storage), &(*websocket)) }
    }

    /// permanently close an inbox
    pub fn inbox_close(&self, _key: &PublicKey) -> Result<(), SelfError> {
        Ok(())
    }

    /// negotiate an encrypted session with another address
    pub fn connection_negotiate(
        &self,
        as_address: &PublicKey,
        with_address: &PublicKey,
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
            operation::connection_negotiate(&(*storage), &(*websocket), as_address, with_address)
        }
    }

    /// establish an encrypted session with another address using a provided key package
    pub fn connection_establish(
        &self,
        as_address: &PublicKey,
        with_address: &PublicKey,
        key_package: &[u8],
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
            operation::connection_establish(
                &(*storage),
                &(*websocket),
                as_address,
                with_address,
                key_package,
            )
        }
    }

    /// accept a group connection
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
            operation::connection_accept(
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

        unsafe { operation::message_send(&(*storage), &(*websocket), to_address, content) }
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

        unsafe { operation::group_create(&(*storage), &(*websocket), as_address) }
    }

    /// list all groups
    pub fn group_list(&self) -> Result<Vec<PublicKey>, SelfError> {
        Ok(Vec::new())
    }

    pub fn shutdown(&self) -> Result<(), SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let websocket = self.websocket.load(Ordering::SeqCst);
        if websocket.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        self.storage.store(ptr::null_mut(), Ordering::SeqCst);
        self.websocket.store(ptr::null_mut(), Ordering::SeqCst);

        unsafe {
            drop(Box::from_raw(storage));
            (*websocket).disconnect()?;
            drop(Box::from_raw(websocket));
        }

        Ok(())
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
