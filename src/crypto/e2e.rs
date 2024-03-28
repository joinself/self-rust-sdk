use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;

use crate::error::SelfError;
use crate::{
    keypair::signing::{KeyPair, PublicKey},
    storage::Transaction,
};

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
        let key_package_encoded = key_package
            .tls_serialize_detached()
            .expect("failed to encode key package");

        packages.push(key_package_encoded);
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
    let key_package_encoded = key_package
        .tls_serialize_detached()
        .expect("failed to encode key package");

    Ok(key_package_encoded)
}

pub fn mls_group_create(
    txn: &Transaction,
    group_address: &[u8],
    signature_key: &KeyPair,
) -> Result<(), SelfError> {
    let backend = &MlsProvider::new(txn);

    let credential =
        Credential::new(signature_key.address().to_owned(), CredentialType::Basic).unwrap();

    let group_cfg = &MlsGroupConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let mut group = MlsGroup::new_with_group_id(
        backend,
        signature_key,
        group_cfg,
        GroupId::from_slice(group_address),
        CredentialWithKey {
            credential,
            signature_key: signature_key.public().public_key_bytes().into(),
        },
    )
    .map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })?;

    group.save(backend).map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })?;

    Ok(())
}

pub fn mls_group_create_from_welcome(
    txn: &Transaction,
    welcome: &[u8],
) -> Result<(PublicKey, Vec<PublicKey>), SelfError> {
    let backend = &MlsProvider::new(txn);

    let group_cfg = &MlsGroupConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let message_in = MlsMessageIn::tls_deserialize_bytes(welcome).map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })?;

    let welcome = match message_in.extract() {
        MlsMessageInBody::Welcome(welcome) => welcome,
        _ => return Err(SelfError::StorageUnknown),
    };

    let mut group =
        MlsGroup::new_from_welcome(backend, group_cfg, welcome, None).map_err(|err| {
            println!("mls error: {}", err);
            SelfError::StorageUnknown
        })?;

    group.save(backend).map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })?;

    let mut members = Vec::new();
    let group_address = PublicKey::from_bytes(group.group_id().as_slice())?;

    for member in group.members() {
        members.push(PublicKey::from_bytes(member.credential.identity())?)
    }

    Ok((group_address, members))
}

pub fn mls_group_create_with_members(
    txn: &Transaction,
    group_address: &[u8],
    signature_key: &KeyPair,
    key_packages: &[&[u8]],
) -> Result<(Vec<u8>, Vec<u8>), SelfError> {
    let backend = &MlsProvider::new(txn);

    let credential =
        Credential::new(signature_key.address().to_owned(), CredentialType::Basic).unwrap();

    let group_cfg = &MlsGroupConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let mut group = MlsGroup::new_with_group_id(
        backend,
        signature_key,
        group_cfg,
        GroupId::from_slice(group_address),
        CredentialWithKey {
            credential,
            signature_key: signature_key.public().public_key_bytes().into(),
        },
    )
    .map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })?;

    let mut key_packages_decoded = Vec::new();

    for kp in key_packages {
        let key_package_in = KeyPackageIn::tls_deserialize_bytes(kp).map_err(|err| {
            println!("mls error: {}", err);
            SelfError::StorageUnknown
        })?;

        let key_package = key_package_in
            .validate(backend.crypto(), ProtocolVersion::default())
            .map_err(|err| {
                println!("mls error: {}", err);
                SelfError::StorageUnknown
            })?;

        key_packages_decoded.push(key_package);
    }

    let (commit_out, welcome_out, _) = group
        .add_members(backend, signature_key, &key_packages_decoded)
        .map_err(|err| {
            println!("mls error: {}", err);
            SelfError::StorageUnknown
        })?;

    group.merge_pending_commit(backend).map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })?;

    group.save(backend).map_err(|err| {
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

pub fn mls_group_add_members(
    txn: &Transaction,
    group_address: &[u8],
    signature_key: &KeyPair,
    key_packages: &[&[u8]],
) -> Result<(Vec<u8>, Vec<u8>), SelfError> {
    let backend = &MlsProvider::new(txn);

    let mut group = match MlsGroup::load(&GroupId::from_slice(group_address), backend) {
        Some(group) => group,
        None => {
            return {
                println!("group is none");
                Err(SelfError::KeyPairNotFound)
            }
        }
    };

    let mut key_packages_decoded = Vec::new();

    for kp in key_packages {
        let key_package_in = KeyPackageIn::tls_deserialize_bytes(*kp).map_err(|err| {
            println!("mls error: {}", err);
            SelfError::StorageUnknown
        })?;

        let key_package = key_package_in
            .validate(backend.crypto(), ProtocolVersion::default())
            .map_err(|err| {
                println!("mls error: {}", err);
                SelfError::StorageUnknown
            })?;

        key_packages_decoded.push(key_package);
    }

    let (commit_out, welcome_out, _) = group
        .add_members(backend, signature_key, &key_packages_decoded)
        .map_err(|err| {
            println!("mls error: {}", err);
            SelfError::StorageUnknown
        })?;

    group.merge_pending_commit(backend).map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })?;

    group.save(backend).map_err(|err| {
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

pub fn mls_group_encrypt(
    txn: &Transaction,
    group_address: &[u8],
    as_address: &KeyPair,
    plaintext: &[u8],
) -> Result<Vec<u8>, SelfError> {
    let backend = &MlsProvider::new(txn);

    let mut group = match MlsGroup::load(&GroupId::from_slice(group_address), backend) {
        Some(group) => group,
        None => return Err(SelfError::KeyPairNotFound),
    };

    let message = group
        .create_message(backend, as_address, plaintext)
        .map_err(|err| {
            println!("mls error: {}", err);
            SelfError::StorageUnknown
        })?;

    message.tls_serialize_detached().map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })
}

pub fn mls_group_decrypt(
    txn: &Transaction,
    group_address: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SelfError> {
    let backend = &MlsProvider::new(txn);

    let message_in = MlsMessageIn::tls_deserialize_exact(ciphertext).map_err(|err| {
        println!("mls error: {}", err);
        SelfError::StorageUnknown
    })?;

    let message = match message_in.extract() {
        MlsMessageInBody::PrivateMessage(message) => message,
        _ => return Err(SelfError::StorageUnknown),
    };

    let mut group = match MlsGroup::load(&GroupId::from_slice(group_address), backend) {
        Some(group) => group,
        None => return Err(SelfError::KeyPairNotFound),
    };

    let application_message = match group.process_message(backend, message) {
        Ok(application_message) => application_message,
        Err(err) => {
            println!("mls error: {}", err);
            return Err(SelfError::StorageUnknown);
        }
    };

    match application_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => Ok(message.into_bytes()),
        _ => Err(SelfError::StorageUnknown),
    }
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

fn mls_credential(signature_key: &KeyPair) -> Result<CredentialWithKey, SelfError> {
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
