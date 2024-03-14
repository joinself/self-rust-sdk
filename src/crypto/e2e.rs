use openmls::prelude::Ciphersuite;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsCryptoProvider;

use crate::storage::Transaction;

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
