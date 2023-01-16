use crate::keypair::signing::KeyPair;
use crate::storage::Storage;
//use crate::transport::rest::Rest;

use std::sync::Arc;

pub struct Account {
    storage: Storage,
}

impl Account {
    pub fn new() -> Account {
        return Account {
            storage: Storage::new().unwrap(),
        };
    }

    /*
    pub fn import_legacy_device(device_id: &str, ed25519_seed: &[u8])  {

    }
    */

    pub fn register(&mut self) -> (KeyPair, KeyPair) {
        let (id_key, device_key, recovery_key) = (KeyPair::new(), KeyPair::new(), KeyPair::new());

        let id_key_id = id_key.public().to_vec();
        let id_key_encoded = id_key.encode();

        let device_key_id = device_key.public().to_vec();
        let device_key_encoded = device_key.encode();

        let recovery_key_id = recovery_key.public().to_vec();
        let recovery_key_encoded = recovery_key.encode();

        self.storage
            .transaction(move |txn| {
                txn.execute(
                    "INSERT INTO account_keychain (id, role, key)
                VALUES
                    (?1, ?2, ?3),
                    (?4, ?5, ?6),
                    (?7, ?8, ?9),
                ",
                    (
                        &id_key_id,
                        1,
                        &id_key_encoded,
                        &device_key_id,
                        1,
                        &device_key_encoded,
                        &recovery_key_id,
                        2,
                        &recovery_key_encoded,
                    ),
                )
                .is_ok()
            })
            .unwrap();

        return (device_key, recovery_key);
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn register() {
        let mut a = Account::new();
        a.register();
    }
}
