use crate::crypto::session;
use crate::error::SelfError;
use crate::identifier::Identifier;
use crate::storage::Storage;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct Session {
    storage: Storage,
    scache: Mutex<HashMap<Identifier, Arc<Mutex<session::Session>>>>,
}

impl Session {
    pub fn new(storage: Storage) -> Session {
        Session {
            storage,
            scache: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&mut self, with: &Identifier) -> Result<Arc<Mutex<session::Session>>, SelfError> {
        let mut scache = self.scache.lock().expect("scache lock failed");

        // check if the session exists in the cache
        if let Some(session) = scache.get(with) {
            return Ok(session.clone());
        };

        self.storage.transaction(|txn| {
            let mut statement = txn
                .prepare("SELECT * FROM crypto_session WHERE with = ?1")
                .expect("failed to prepare statement");

            let mut rows = match statement.query([with.id()]) {
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

            let mut session_encoded: Vec<u8> = row.get(2).unwrap();

            // TODO handle encryption for values
            if let Ok(session) = session::Session::from_pickle(&mut session_encoded, None) {
                scache.insert(with.clone(), Arc::new(Mutex::new(session)));
                return true;
            };

            false
        })?;

        // check if the session exists in the cache
        if let Some(session) = scache.get_mut(with) {
            return Ok(session.clone());
        };

        Err(SelfError::KeychainKeyNotFound)
    }

    pub fn create(
        &mut self,
        with: &Identifier,
        session: session::Session,
    ) -> Result<(), SelfError> {
        let mut scache = self.scache.lock().expect("scache lock failed");

        // check if the session exists in the cache
        if scache.contains_key(with) {
            return Err(SelfError::KeychainKeyExists);
        };

        // TODO handle encryption for values
        let session_encoded = session.pickle(None)?;

        self.storage.transaction(|txn| {
            txn.execute(
                "INSERT INTO account_keychain (with, session, offset) VALUES (?1, ?2, ?3)",
                (with.id(), session_encoded, 0),
            )
            .is_ok()
        })?;

        scache.insert(with.clone(), Arc::new(Mutex::new(session)));

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::crypto::session;
    use crate::keypair::signing::KeyPair;
    use crate::protocol::siggraph::KeyRole;

    #[test]
    fn create_and_get() {
        let storage = Storage::new().expect("storage failed");
        let mut sessions = Session::new(storage);

        let alice_skp = crate::keypair::signing::KeyPair::new();
        let alice_ekp = crate::keypair::exchange::KeyPair::new();
        let alice_ed25519_pk = alice_skp.public();
        let alice_curve25519_pk = alice_ekp.public();
        let mut alice_acc = crate::crypto::account::Account::new(alice_skp, alice_ekp);

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ekp = crate::keypair::exchange::KeyPair::new();
        let bob_curve25519_pk = bob_ekp.public();
        let mut bob_acc = crate::crypto::account::Account::new(bob_skp, bob_ekp);

        let alice_identifier = Identifier::Referenced(alice_ed25519_pk);

        alice_acc
            .generate_one_time_keys(10)
            .expect("failed to generate one time keys");

        let alices_one_time_keys: HashMap<String, serde_json::Value> =
            serde_json::from_slice(&alice_acc.one_time_keys())
                .expect("failed to load alices one time keys");

        let alices_one_time_key = alices_one_time_keys
            .get("curve25519")
            .and_then(|keys| keys.as_object()?.get("AAAAAQ"))
            .unwrap()
            .as_str()
            .unwrap();

        // encrypt a message from bob with a new session to alice
        let mut bobs_session_with_alice = bob_acc
            .create_outbound_session(&alice_curve25519_pk, alices_one_time_key.as_bytes())
            .expect("failed to create outbound session");

        let (mtype, mut bobs_message_to_alice_1) = bobs_session_with_alice
            .encrypt("hello alice, pt1".as_bytes())
            .expect("failed to encrypt message to alice");

        assert_eq!(mtype, 0);

        // store bobs session with alice
        sessions
            .create(&alice_identifier, bobs_session_with_alice)
            .expect("failed to create session");

        // create alices session with bob from bobs first message
        let mut alices_session_with_bob = alice_acc
            .create_inbound_session(&bob_curve25519_pk, &bobs_message_to_alice_1)
            .expect("failed to create inbound session");

        // remove the one time key from alices account
        alice_acc
            .remove_one_time_keys(&alices_session_with_bob)
            .expect("failed to remove session");

        // decrypt the message from bob
        let plaintext = alices_session_with_bob
            .decrypt(mtype, &mut bobs_message_to_alice_1)
            .expect("failed to decrypt bobs message");

        assert_eq!(&plaintext, "hello alice, pt1".as_bytes());

        // send a response message to bob
        let (mtype, mut alices_message_to_bob_1) = alices_session_with_bob
            .encrypt("hey bob".as_bytes())
            .expect("failed to encrypt message to bob");

        assert_eq!(mtype, 1);

        // load bobs session with alice
        let bobs_session_with_alice_arc = sessions
            .get(&alice_identifier)
            .expect("failed to get session");

        let bobs_session_with_alice_lock = bobs_session_with_alice_arc.as_ref().lock();

        let mut bobs_session_with_alice =
            bobs_session_with_alice_lock.expect("failed to lock session");

        // decrypt alices response
        let plaintext = bobs_session_with_alice
            .decrypt(mtype, &mut alices_message_to_bob_1)
            .expect("failed to decrypt message from alice");

        assert_eq!(&plaintext, "hey bob".as_bytes());
    }
}
