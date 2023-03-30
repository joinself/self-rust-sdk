use crate::error::SelfError;
use crate::keypair::signing::{KeyPair, PublicKey};
use crate::protocol::siggraph::KeyRole;
use crate::storage::Storage;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct Keychain {
    storage: Storage,
    kcache: Mutex<HashMap<PublicKey, KeyPair>>,
}

impl Keychain {
    pub fn new(storage: Storage) -> Keychain {
        Keychain {
            storage,
            kcache: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&mut self, public_key: &PublicKey) -> Result<KeyPair, SelfError> {
        let mut kcache = self.kcache.lock().expect("kcache lock failed");

        // check if the key exists in the cache
        if let Some(kp) = kcache.get(public_key) {
            return Ok(kp.clone());
        };

        self.storage.transaction(|txn| {
            let mut statement = txn
                .prepare("SELECT * FROM account_keychain WHERE public_key = ?1")
                .expect("failed to prepare statement");

            let mut rows = match statement.query([public_key.id()]) {
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

            let kp_encoded: Vec<u8> = row.get(3).unwrap();

            if let Ok(kp) = KeyPair::decode(&kp_encoded) {
                kcache.insert(kp.public(), kp);
                return true;
            };

            false
        })?;

        // check if the key exists in the cache
        if let Some(kp) = kcache.get(public_key) {
            return Ok(kp.clone());
        };

        Err(SelfError::KeychainKeyNotFound)
    }

    pub fn create(&mut self, role: KeyRole, keypair: &KeyPair) -> Result<(), SelfError> {
        let mut kcache = self.kcache.lock().expect("kcache lock failed");

        // check if the key exists in the cache
        if kcache.contains_key(&keypair.public()) {
            return Err(SelfError::KeychainKeyExists);
        };

        self.storage.transaction(|txn| {
            txn.execute(
                "INSERT INTO account_keychain (role, public_key, secret_key) VALUES (?1, ?2, ?3)",
                (role.0, keypair.public().id(), &keypair.encode()),
            )
            .is_ok()
        })?;

        kcache.insert(keypair.public(), keypair.clone());

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::keypair::signing::KeyPair;
    use crate::protocol::siggraph::KeyRole;

    #[test]
    fn create_and_get() {
        let kp = KeyPair::new();
        let storage = Storage::new().expect("storage failed");
        let mut keychain = Keychain::new(storage);

        let msg = vec![8; 128];
        let sig = kp.sign(&msg);

        keychain
            .create(KeyRole::Signing, &kp)
            .expect("failed to create keypair");

        let kp = keychain.get(&kp.public()).expect("failed to get keypair");

        assert!(kp.public().verify(&msg, &sig));
    }
}
