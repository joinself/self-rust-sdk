//use crate::crypto::omemo::Group;
use crate::error::SelfError;
use crate::identifier::Identifier;
use crate::storage::Storage;
use crate::transport::rest::Rest;
use crate::transport::websocket::Websocket;

use std::sync::Mutex;

// TODO use LRU cache for sessions
pub struct Messaging {
    storage: Storage,
    websocket: Websocket,
    lock: Mutex<()>,
}

impl Messaging {
    // TODO accept interfaces for storage and socket
    pub fn new(storage: Storage, websocket: Websocket, _rest: Rest) -> Messaging {
        Messaging {
            storage,
            websocket,
            lock: Mutex::new(()),
        }
    }

    pub fn send(
        &mut self,
        from: &Identifier,
        to: &Identifier,
        plaintext: &[u8],
    ) -> Result<(), SelfError> {
        //let ciphertext = self.storage.encrypt_and_queue(to, )?;

        // batch session updates
        // storage.session_update(recipient_id)

        /*
        let lock = self.lock.lock().unwrap();

        //let (group, next_sequence)

        let group = match self.group_get(to) {
            Some(group) => group,
            None => return Err(SelfError::MessagingDestinationUnknown),
        };

        let ciphertext = group.encrypt(plaintext)?;

        drop(lock);

        self.websocket.send(
            from,
            to,
            0, // TODO load sequence
            &ciphertext,
            None,
            Arc::new(|response| {
                response.unwrap();
            }),
        );
        */

        return Ok(());
    }
}
