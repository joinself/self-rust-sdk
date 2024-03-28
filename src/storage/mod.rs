// mod adapter;
mod connection;
mod schema;
mod statement;
mod transaction;

pub mod query;

pub use self::connection::Connection;
pub use self::query::KeyPair;
pub use self::transaction::Transaction;

#[cfg(test)]
mod tests {
    use crate::storage::connection::Connection;
    use crate::storage::transaction::Transaction;
    use openmls::prelude::*;
    use openmls::treesync::RatchetTree;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::RustCrypto;

    pub struct OpenMlsBackend<'t> {
        crypto: RustCrypto,
        key_store: &'t Transaction,
    }

    impl OpenMlsBackend<'_> {
        pub fn new(txn: &Transaction) -> OpenMlsBackend {
            OpenMlsBackend {
                crypto: RustCrypto::default(),
                key_store: txn,
            }
        }
    }

    impl OpenMlsCryptoProvider for OpenMlsBackend<'_> {
        type CryptoProvider = RustCrypto;
        type RandProvider = RustCrypto;
        type KeyStoreProvider = Transaction;

        fn crypto(&self) -> &Self::CryptoProvider {
            &self.crypto
        }

        fn rand(&self) -> &Self::RandProvider {
            &self.crypto
        }

        fn key_store(&self) -> &Self::KeyStoreProvider {
            self.key_store
        }
    }

    #[test]
    fn mls_storage() {
        // Define ciphersuite and the crypto backend to use.
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let conn = Connection::new(":memory:").expect("failed to open connection");

        let mut welcome: Option<Welcome> = None;
        let mut alice_ratchet_tree: Option<RatchetTree> = None;

        conn.transaction(|txn| {
            let backend = &OpenMlsBackend::new(txn);

            // Now let's create two participants.

            // First they need credentials to identify them
            let (alice_credential_with_key, alice_signer) = generate_credential_with_key(
                "alice".into(),
                CredentialType::Basic,
                ciphersuite.signature_algorithm(),
                backend,
            );

            let (bobby_credential_with_key, bobby_signer) = generate_credential_with_key(
                "bobby".into(),
                CredentialType::Basic,
                ciphersuite.signature_algorithm(),
                backend,
            );

            // Then they generate key packages to facilitate the asynchronous handshakes
            // in MLS

            // Generate KeyPackages
            let bobby_key_package = generate_key_package(
                ciphersuite,
                backend,
                &bobby_signer,
                bobby_credential_with_key,
            );

            // Now alice starts a new group ...
            let mut alice_group = MlsGroup::new(
                backend,
                &alice_signer,
                &MlsGroupConfig::default(),
                alice_credential_with_key,
            )
            .expect("An unexpected error occurred.");

            // ... and invites bobby.
            // The key package has to be retrieved from bobby in some way. Most likely
            // via a server storing key packages for users.
            let (_, welcome_out, _) = alice_group
                .add_members(backend, &alice_signer, &[bobby_key_package])
                .expect("Could not add members.");

            // alice merges the pending commit that adds bobby.
            alice_group
                .merge_pending_commit(backend)
                .expect("error merging pending commit");

            // Sascha serializes the [`MlsMessageOut`] containing the [`Welcome`].
            let serialized_welcome = welcome_out
                .tls_serialize_detached()
                .expect("Error serializing welcome");

            // bobby can now de-serialize the message as an [`MlsMessageIn`] ...
            let mls_message_in = MlsMessageIn::tls_deserialize(&mut serialized_welcome.as_slice())
                .expect("An unexpected error occurred.");

            // ... and inspect the message.
            welcome = match mls_message_in.extract() {
                MlsMessageInBody::Welcome(welcome) => Some(welcome),
                // We know it's a welcome message, so we ignore all other cases.
                _ => unreachable!("Unexpected message type."),
            };

            alice_ratchet_tree = Some(alice_group.export_ratchet_tree());

            Ok(())
        })
        .expect("failed to execute transaction");

        conn.transaction(|txn| {
            let backend = &OpenMlsBackend::new(txn);

            // Now bobby can join the group.
            MlsGroup::new_from_welcome(
                backend,
                &MlsGroupConfig::default(),
                welcome.unwrap(),
                // The public tree is need and transferred out of band.
                // It is also possible to use the [`RatchetTreeExtension`]
                Some(alice_ratchet_tree.unwrap().into()),
            )
            .expect("Error joining group from Welcome");

            Ok(())
        })
        .expect("failed to execute transaction");
    }

    // A helper to create and store credentials.
    fn generate_credential_with_key(
        identity: Vec<u8>,
        credential_type: CredentialType,
        signature_algorithm: SignatureScheme,
        backend: &impl OpenMlsCryptoProvider,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        let credential = Credential::new(identity, credential_type).unwrap();
        let signature_keys = SignatureKeyPair::new(signature_algorithm)
            .expect("Error generating a signature key pair.");

        // Store the signature key into the key store so OpenMLS has access
        // to it.
        signature_keys
            .store(backend.key_store())
            .expect("Error storing signature keys in key store.");

        (
            CredentialWithKey {
                credential,
                signature_key: signature_keys.public().into(),
            },
            signature_keys,
        )
    }

    // A helper to create key package bundles.
    fn generate_key_package(
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        signer: &SignatureKeyPair,
        credential_with_key: CredentialWithKey,
    ) -> KeyPackage {
        // Create the key package
        KeyPackage::builder()
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                backend,
                signer,
                credential_with_key,
            )
            .unwrap()
    }
}
