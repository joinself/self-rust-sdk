use crate::crypto::omemo::Group;
use crate::crypto::session::Session;
use crate::error::SelfError;
use crate::storage::Storage;
use crate::transport::rest::Rest;
use crate::transport::websocket::Websocket;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// TODO use LRU cache for sessions
pub struct Messaging {
    storage: Storage,
    websocket: Websocket,
    rest: Rest,
    lock: Mutex<()>,
    gcache: HashMap<Vec<u8>, Group>,
    scache: HashMap<Vec<u8>, Session>,
}

impl Messaging {
    // TODO accept interfaces for storage and socket
    pub fn new(storage: Storage, websocket: Websocket, rest: Rest) -> Messaging {
        return Messaging {
            storage,
            websocket,
            rest,
            lock: Mutex::new(()),
            gcache: HashMap::new(),
            scache: HashMap::new(),
        };
    }

    pub fn send(&mut self, group: &[u8], plaintext: &[u8]) -> Result<(), SelfError> {
        let lock = self.lock.lock().unwrap();

        let group = match self.gcache.get_mut(group) {
            Some(group) => group,
            None => match self.load_group(group) {
                Some(group) => group,
                None => return Err(SelfError::StorageConnectionFailed), // TODO replace with group not found error,
            },
        };

        let ciphertext = group.encrypt(plaintext)?;

        self.websocket.send(
            Vec::new(),
            "chat.message",
            0,
            &ciphertext,
            Arc::new(|response| {
                response.unwrap();
            }),
        );

        drop(lock);

        //

        return Ok(());
    }

    pub fn create_group(&mut self, group: &[u8], owner: &[u8]) -> Result<(), SelfError> {
        self.storage.transaction(|txn| {
            return txn
                .execute(
                    "INSERT INTO messaging_groups (identity, owner) VALUES (?1, ?2)",
                    (group, owner),
                )
                .is_ok();
        })
    }

    fn load_group(&mut self, group: &[u8]) -> Option<&mut Group> {
        let group: Option<&mut Group> = None;

        self.storage.transaction(|txn| {
            let mut statement = txn
                .prepare("SELECT * FROM messaging_member WHERE identity = ?1")
                .expect("failed to prepare statement");

            let mut rows = match statement.query([b"bob"]) {
                Ok(rows) => rows,
                Err(_) => return false,
            };

            let row = match rows.next() {
                Ok(row) => match row {
                    Some(row) => row,
                    None => return false,
                },
                Err(_) => return false,
            };

            let identity: Vec<u8> = row.get(0).unwrap();
            let session: Vec<u8> = row.get(1).unwrap();

            return true;
        });

        return group;
    }
}
