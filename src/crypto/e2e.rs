use openmls::prelude::{config::CryptoConfig, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use openmls_traits::key_store::MlsEntity;

const DEFAULT_CIPHER_SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct Provider {
    crypto: RustCrypto,
    store: Store,
}

impl OpenMlsCryptoProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = Store;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &self.store
    }
}

pub struct Group {}

impl Group {
    pub fn new() -> Group {
        let implementation = OpenMlsRustCrypto::default();

        Group {}
    }
}
