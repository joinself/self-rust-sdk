use openmls::prelude::{config::CryptoConfig, Ciphersuite, *};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsCryptoProvider;

use crate::error::SelfError;
use crate::{keypair::signing::KeyPair, storage::Transaction};

pub const DEFAULT_CIPHER_SUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub struct MlsProvider<'t> {
    crypto: RustCrypto,
    key_store: &'t Transaction,
}

impl MlsProvider<'_> {
    pub fn new(txn: &Transaction) -> MlsProvider {
        MlsProvider {
            crypto: RustCrypto::default(),
            key_store: txn,
        }
    }
}

impl OpenMlsCryptoProvider for MlsProvider<'_> {
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

pub fn mls_inbox_setup(
    txn: &Transaction,
    signature_key: &KeyPair,
    key_packages: usize,
) -> Result<Vec<Vec<u8>>, SelfError> {
    let backend = &MlsProvider::new(txn);
    let mut packages = Vec::new();

    let credential = mls_credential_create(backend, signature_key)?;

    for _ in 0..key_packages {
        // generate a key package for asynchronous handshake
        let key_package = mls_key_package_generate(backend, signature_key, credential.clone())?;

        let mut encoded_key_package = Vec::new();
        ciborium::ser::into_writer(&key_package, &mut encoded_key_package)
            .expect("failed to encode key package");

        packages.push(encoded_key_package);
    }

    Ok(packages)
}

pub fn mls_key_package_create(
    txn: &Transaction,
    signature_key: &KeyPair,
) -> Result<Vec<u8>, SelfError> {
    let backend = &MlsProvider::new(txn);
    let credential = mls_credential(signature_key)?;

    // generate a key package for asynchronous handshake
    let key_package = mls_key_package_generate(backend, signature_key, credential.clone())?;

    let mut encoded_key_package = Vec::new();
    ciborium::ser::into_writer(&key_package, &mut encoded_key_package)
        .expect("failed to encode key package");

    Ok(encoded_key_package)
}

pub fn mls_group_create(txn: &Transaction, signature_key: &KeyPair) -> Result<(), SelfError> {
    let backend = &MlsProvider::new(txn);

    let credential =
        Credential::new(signature_key.address().to_owned(), CredentialType::Basic).unwrap();

    let group_cfg = &MlsGroupConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    MlsGroup::new(
        backend,
        signature_key,
        group_cfg,
        CredentialWithKey {
            credential,
            signature_key: signature_key.public().public_key_bytes().into(),
        },
    )
    .map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })?;

    Ok(())
}

pub fn mls_group_add_self(
    txn: &Transaction,
    signature_key: &KeyPair,
) -> Result<Vec<u8>, SelfError> {
    let backend = &MlsProvider::new(txn);

    let mut group = match MlsGroup::load(&GroupId::from_slice(signature_key.address()), backend) {
        Some(group) => group,
        None => return Err(SelfError::KeyPairNotFound),
    };

    group.create_message(backend, signer, message)

    let credential = mls_credential(signature_key)?;
    let key_package = mls_key_package_generate(backend, signature_key, credential)?;

    let (commit_out, _, _) = group
        .add_members(backend, signature_key, &[key_package])
        .map_err(|err| {
            println!("mls error: {}", err);
            SelfError::StorageUnknown
        })?;

    group.merge_pending_commit(backend).map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })?;

    commit_out.tls_serialize_detached().map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })
}


pub fn mls_group_add_members(
    txn: &Transaction,
    signature_key: &KeyPair,
    key_packages: Vec<Vec<u8>>,
) -> Result<(Vec<u8>, Vec<u8>), SelfError> {
    let backend = &MlsProvider::new(txn);

    let mut group = match MlsGroup::load(&GroupId::from_slice(signature_key.address()), backend) {
        Some(group) => group,
        None => return Err(SelfError::KeyPairNotFound),
    };

    let key_packages: Vec<KeyPackage> = key_packages
        .iter()
        .map({
            |kp| {
                ciborium::de::from_reader(kp.as_slice()).expect("failed to deserialize key package")
            }
        })
        .collect();

    let (commit_out, welcome_out, _) = group
        .add_members(backend, signature_key, &key_packages)
        .map_err(|err| {
            println!("mls error: {}", err);
            SelfError::StorageUnknown
        })?;

    group.merge_pending_commit(backend).map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })?;

    let commit = commit_out.tls_serialize_detached().map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })?;

    let welcome = welcome_out.tls_serialize_detached().map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })?;

    Ok((commit, welcome))
}

fn mls_credential_create(
    backend: &impl OpenMlsCryptoProvider,
    signature_key: &KeyPair,
) -> Result<CredentialWithKey, SelfError> {
    let credential =
        Credential::new(signature_key.address().to_owned(), CredentialType::Basic).unwrap();

    // Store the signature key into the key store so OpenMLS has access
    // to it.
    backend
        .key_store()
        .store(&signature_key.id(), signature_key)
        .map_err(|err| {
            println!("mls error: {}", err);
            SelfError::StorageUnknown
        })?;

    Ok(CredentialWithKey {
        credential,
        signature_key: signature_key.public().public_key_bytes().into(),
    })
}

fn mls_credential(
    signature_key: &KeyPair,
) -> Result<CredentialWithKey, SelfError> {
    let credential =
        Credential::new(signature_key.address().to_owned(), CredentialType::Basic).unwrap();

    Ok(CredentialWithKey {
        credential,
        signature_key: signature_key.public().public_key_bytes().into(),
    })
}

// A helper to create key package bundles.
fn mls_key_package_generate(
    backend: &impl OpenMlsCryptoProvider,
    signer: &KeyPair,
    credential: CredentialWithKey,
) -> Result<KeyPackage, SelfError> {
    // Create the key package
    KeyPackage::builder()
        .build(
            CryptoConfig {
                ciphersuite: crate::crypto::e2e::DEFAULT_CIPHER_SUITE,
                version: ProtocolVersion::default(),
            },
            backend,
            signer,
            credential,
        )
        .map_err(|err| {
            println!("mls error: {}", err);
            SelfError::StorageUnknown
        })
}
