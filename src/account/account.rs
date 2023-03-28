use crate::error::SelfError;
use crate::identifier::Identifier;
use crate::keypair::signing::KeyPair;
use crate::siggraph::SignatureGraph;
use crate::storage::Storage;
use crate::transport::rest::Rest;

use reqwest::Url;

pub struct Account {
    rest: Rest,
    storage: Storage,
    server: Url,
}

impl Account {
    pub fn new() -> Account {
        Account {
            rest: Rest::new(),
            storage: Storage::new().unwrap(),
            server: Url::parse("https://api.joinself.com").expect("url parse shouldn't fail"),
        }
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
        let url = self
            .server
            .join("/v2/identities")
            .map_err(|_| SelfError::RestRequestURLInvalid)?;
        self.rest.post(url.as_ref(), operation, None, true)?;

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

        Ok(identifier)
    }

    pub fn server_set(&mut self, url: &str) -> Result<(), SelfError> {
        self.server = Url::parse(url).map_err(|_| SelfError::RestRequestURLInvalid)?;
        Ok(())
    }
}

impl Default for Account {
    fn default() -> Self {
        Account::new()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use httptest::{matchers::*, responders::*, Expectation, Server};

    #[test]
    fn register() {
        let server = Server::run();

        let m = all_of![
            request::method_path("POST", "/v2/identities"),
            request::headers(contains(key("x-self-pow-hash"))),
            request::headers(contains(key("x-self-pow-nonce"))),
        ];

        server.expect(
            Expectation::matching(m)
                .respond_with(status_code(201).body("{\"status\":\"success\"}")),
        );

        let recovery_key = KeyPair::new();
        let mut account = Account::new();

        account
            .server_set(&server.url_str("/"))
            .expect("failed to set server url");

        let identifier = account.register(&recovery_key).expect("failed to register");
        assert!(identifier.id().len() == 32);
    }
}
