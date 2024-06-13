use prost::Message as ProstMessage;

use crate::account::operation;
use crate::credential::{Credential, Presentation, VerifiableCredential, VerifiablePresentation};
use crate::error::SelfError;
use crate::hashgraph::{Hashgraph, Operation, RoleSet};
use crate::keypair::exchange;
use crate::keypair::signing::{self, KeyPair, PublicKey};
use crate::message::{self, Commit, Content, ContentType, KeyPackage, Message, Welcome};
use crate::object;
use crate::protocol::messaging;
use crate::protocol::p2p::p2p;
use crate::storage::query::QueuedMessage;
use crate::storage::{query, Connection};
use crate::transport::object::ObjectStore;
use crate::transport::rpc::Rpc;
use crate::transport::websocket::{self, Callbacks, Websocket};

use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Arc;

pub type OnConnectCB = Arc<dyn Fn() + Sync + Send>;
pub type OnDisconnectCB = Arc<dyn Fn(Result<(), SelfError>) + Sync + Send>;
pub type OnMessageCB = Arc<dyn Fn(Message) + Sync + Send>;
pub type OnCommitCB = Arc<dyn Fn(Commit) + Sync + Send>;
pub type OnKeyPackageCB = Arc<dyn Fn(KeyPackage) + Sync + Send>;
pub type OnWelcomeCB = Arc<dyn Fn(Welcome) + Sync + Send>;

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
    object: Arc<AtomicPtr<ObjectStore>>,
    storage: Arc<AtomicPtr<Connection>>,
    websocket: Arc<AtomicPtr<Websocket>>,
}

impl Account {
    pub fn new() -> Account {
        Account {
            rpc: Arc::new(AtomicPtr::new(ptr::null_mut())),
            object: Arc::new(AtomicPtr::new(ptr::null_mut())),
            storage: Arc::new(AtomicPtr::new(ptr::null_mut())),
            websocket: Arc::new(AtomicPtr::new(ptr::null_mut())),
        }
    }

    /// configures an account. if the account already exists, all existing state will
    /// be loaded and messaging subscriptions will be started
    pub fn configure(
        &mut self,
        rpc_endpoint: &str,
        object_endpoint: &str,
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

        let object = ObjectStore::new(object_endpoint)?;
        let object = Box::into_raw(Box::new(object));
        self.object.swap(object, Ordering::SeqCst);

        let storage = Connection::new(storage_path)?;
        let storage = Box::into_raw(Box::new(storage));
        self.storage.swap(storage, Ordering::SeqCst);

        let mut websocket = Websocket::new(
            messaging_endpoint,
            Callbacks {
                on_connect: on_connect_cb(callbacks.on_connect),
                on_disconnect: on_disconnect_cb(callbacks.on_disconnect),
                on_event: on_event_cb(
                    &self.storage,
                    callbacks.on_commit,
                    callbacks.on_key_package,
                    callbacks.on_message,
                    callbacks.on_welcome,
                ),
            },
        )?;

        websocket.connect()?;

        let websocket = Box::into_raw(Box::new(websocket));
        self.websocket.swap(websocket, Ordering::SeqCst);

        unsafe {
            operation::subscription_load(&(*storage), &(*websocket))?;
        }

        // TODO - resume subscriptions
        // TODO - (re-)send messages in outbox
        // TODO - (re-)handle messages in inbox

        Ok(())
    }

    /// generates and stores a new signing keypair
    pub fn keychain_signing_create(&self) -> Result<signing::PublicKey, SelfError> {
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
    pub fn keychain_exchange_create(&self) -> Result<exchange::PublicKey, SelfError> {
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
    pub fn keychain_signing_associated_with<T>(
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

    /// lists all identities that the account either owns or is associated with
    pub fn identity_list(&self) -> Result<Vec<signing::PublicKey>, SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe { operation::identity_list(&(*storage)) }
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

    /// signs and issues a new verifiable credential
    pub fn credential_issue(
        &self,
        credential: &Credential,
    ) -> Result<VerifiableCredential, SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe { operation::credential_issue(&(*storage), credential) }
    }

    /// validates and stores a verifiable credential
    pub fn credential_store(&self, credential: &VerifiableCredential) -> Result<(), SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe { operation::credential_store(&(*storage), credential) }
    }

    /// looks up credentials by a given issuer
    pub fn credential_lookup_by_issuer(
        &self,
        issuer: &PublicKey,
    ) -> Result<Vec<VerifiableCredential>, SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe { operation::credential_lookup_by_issuer(&(*storage), issuer) }
    }

    /// looks up credentials by a given bearer
    pub fn credential_lookup_by_bearer(
        &self,
        bearer: &PublicKey,
    ) -> Result<Vec<VerifiableCredential>, SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe { operation::credential_lookup_by_bearer(&(*storage), bearer) }
    }

    /// looks up credentials by credential type
    pub fn credential_lookup_by_credential_type(
        &self,
        credential_type: &[&str],
    ) -> Result<Vec<VerifiableCredential>, SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe { operation::credential_lookup_by_credential_type(&(*storage), credential_type) }
    }

    /// issues a verifiable presentation containing verifiable credentials
    pub fn presentation_issue(
        &self,
        presentation: &Presentation,
    ) -> Result<VerifiablePresentation, SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe { operation::presentation_issue(&(*storage), presentation) }
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

    /// uploads an object
    pub fn object_upload(
        &self,
        as_address: &PublicKey,
        object: &object::Object,
        persist_local: bool,
    ) -> Result<(), SelfError> {
        let object_store = self.object.load(Ordering::SeqCst);
        if object_store.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe {
            operation::object_upload(
                &(*storage),
                &(*object_store),
                as_address,
                object,
                persist_local,
            )
        }
    }

    /// downloads an object
    pub fn object_download(
        &self,
        as_address: &PublicKey,
        object: &mut object::Object,
    ) -> Result<(), SelfError> {
        let object_store = self.object.load(Ordering::SeqCst);
        if object_store.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe { operation::object_download(&(*storage), &(*object_store), as_address, object) }
    }

    /// send a message to an address
    pub fn message_send(
        &self,
        to_address: &PublicKey,
        content: &message::Content,
    ) -> Result<(), SelfError> {
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

    /// finds the membership address for a group
    pub fn group_member_as(
        &self,
        group_address: &PublicKey,
    ) -> Result<Option<PublicKey>, SelfError> {
        let storage = self.storage.load(Ordering::SeqCst);
        if storage.is_null() {
            return Err(SelfError::AccountNotConfigured);
        };

        unsafe { operation::group_member_as(&(*storage), group_address) }
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
            object: self.object.clone(),
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

fn on_event_cb(
    storage: &Arc<AtomicPtr<Connection>>,
    on_commit: OnCommitCB,
    on_key_package: OnKeyPackageCB,
    on_message: OnMessageCB,
    on_welcome: OnWelcomeCB,
) -> websocket::OnEventCB {
    let storage = storage.clone();

    Arc::new(move |event| {
        let storage = storage.load(Ordering::SeqCst);
        let mut next: Option<QueuedMessage> = None;
        let mut sequence_rx: Option<u64> = None;

        unsafe {
            let result = (*storage).transaction(|txn| {
                // load the metrics for this to_address and from_address
                // determine if this message is in order or a duplicate
                sequence_rx = query::metrics_load_sequence_rx(
                    txn,
                    event.from_address.address(),
                    event.to_address.address(),
                )?;

                if let Some(sequence_rx) = sequence_rx {
                    if event.sequence <= sequence_rx {
                        // we've seen this event before, skip it
                        return Ok(());
                    }
                } else {
                    query::metrics_create(
                        txn,
                        event.from_address.address(),
                        event.to_address.address(),
                        0,
                        0,
                    )?;
                }

                let event_type = match event.content_type {
                    messaging::ContentType::MLS_COMMIT => query::Event::Commit,
                    messaging::ContentType::MLS_KEY_PACKAGE => query::Event::KeyPackage,
                    messaging::ContentType::MLS_MESSAGE => query::Event::Message,
                    messaging::ContentType::MLS_PROPOSAL => query::Event::Proposal,
                    messaging::ContentType::MLS_WELCOME => query::Event::Welcome,
                    _ => return Ok(()),
                };

                // store the event to our inbox
                query::address_create(txn, event.from_address.address())?;
                query::inbox_queue(
                    txn,
                    event_type,
                    event.from_address.address(),
                    event.to_address.address(),
                    &event.content,
                    event.timestamp,
                    event.sequence,
                )?;

                // attempt to get the next valid message sequence
                next = query::inbox_next(txn)?;

                Ok(())
            });

            if let Err(err) = result {
                println!("transaction failed: {}", err);
                return;
            }
        }

        // iterate through all messages we have available
        while let Some(next) = &next {
            let from_address =
                PublicKey::from_bytes(&next.from_address).expect("invalid address loaded");
            let to_address =
                PublicKey::from_bytes(&next.to_address).expect("invalid address loaded");

            match next.event {
                query::Event::Commit => {}
                query::Event::KeyPackage => {}
                query::Event::Message => {
                    let decoded_message = match p2p::Message::decode(next.message.as_ref()) {
                        Ok(decoded_message) => decoded_message,
                        Err(err) => {
                            println!("received invalid protobuf message: {}", err);
                            return;
                        }
                    };

                    let content_type = ContentType::from(decoded_message.r#type());
                    let content = match Content::decode(content_type, &decoded_message.content) {
                        Ok(content) => content,
                        Err(err) => {
                            println!("received invalid protobuf content: {}", err);
                            return;
                        }
                    };

                    on_message(Message::new(
                        decoded_message.id,
                        from_address,
                        to_address,
                        content,
                        next.sequence,
                        next.timestamp,
                    ));
                }
                query::Event::Proposal => {}
                query::Event::Welcome => {}
                query::Event::Invalid => return,
            }

            unsafe {
                let result = (*storage).transaction(|txn| {
                    query::inbox_dequeue(txn, &next.from_address, &next.to_address, next.sequence)
                });

                if let Err(err) = result {
                    println!("transaction failed: {}", err);
                }
            }
        }
    })
}
