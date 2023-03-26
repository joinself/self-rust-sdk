use crate::error::SelfError;
use crate::identifier::Identifier;
use crate::keypair::signing::KeyPair;
use crate::siggraph::SignatureGraph;
use crate::storage::Storage;
use crate::transport::rest::Rest;

pub struct Account {
    rest: Rest,
    storage: Storage,
}

impl Account {
    pub fn new() -> Account {
        return Account {
            rest: Rest::new(),
            storage: Storage::new().unwrap(),
        };
    }

    pub fn register(&mut self, recovery_kp: &KeyPair) -> Result<Identifier, SelfError> {
        // generate keypairs for account identifier and device
        let (identifier_kp, device_kp) = (KeyPair::new(), KeyPair::new());
        let identifier = Identifier::Owned(identifier_kp.clone());

        // construct a public key operation to serve as
        // the initial public state for the account
        let graph = SignatureGraph::new();

        let operation = graph
            .create()
            .id(&identifier_kp.id())
            .key_create_signing(&device_kp.public())
            .key_create_recovery(&recovery_kp.public())
            .sign(&identifier_kp)
            .sign(&device_kp)
            .sign(recovery_kp)
            .build()?;

        // submit public key operation to api
        self.rest.post("/v2/identities", operation, None, true)?;

        // persist account keys to keychain
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
                        &identifier_kp.id(),
                        0,
                        &identifier_kp.encode(),
                        &device_kp.id(),
                        1,
                        &device_kp.encode(),
                        &recovery_kp.id(),
                        2,
                        &recovery_kp.encode(),
                    ),
                )
                .is_ok()
            })
            .unwrap();

        return Ok(identifier);
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn register() {
        let recovery_key = KeyPair::new();
        let mut account = Account::new();
        let identifier = account.register(&recovery_key).expect("failed to register");
        assert!(identifier.id().len() == 32);
    }
}
