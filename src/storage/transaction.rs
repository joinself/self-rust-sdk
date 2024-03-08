use libsqlite3_sys::sqlite3;
use openmls_traits::key_store::{MlsEntity, MlsEntityId, OpenMlsKeyStore};

use crate::error::MlsError;

pub struct Transaction {}

impl Transaction {
    pub fn new(db: *mut sqlite3) -> Transaction {
        Transaction {}
    }
}

impl OpenMlsKeyStore for Transaction {
    type Error = MlsError;

    fn store<V: MlsEntity>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        match V::ID {
            MlsEntityId::SignatureKeyPair => {}
            MlsEntityId::HpkePrivateKey => {}
            MlsEntityId::KeyPackage => {}
            MlsEntityId::PskBundle => {}
            MlsEntityId::EncryptionKeyPair => {}
            MlsEntityId::GroupState => {}
        }

        Ok(())
    }

    fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V> {
        match V::ID {
            MlsEntityId::SignatureKeyPair => {}
            MlsEntityId::HpkePrivateKey => {}
            MlsEntityId::KeyPackage => {}
            MlsEntityId::PskBundle => {}
            MlsEntityId::EncryptionKeyPair => {}
            MlsEntityId::GroupState => {}
        }

        None
    }

    fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        match V::ID {
            MlsEntityId::SignatureKeyPair => {}
            MlsEntityId::HpkePrivateKey => {}
            MlsEntityId::KeyPackage => {}
            MlsEntityId::PskBundle => {}
            MlsEntityId::EncryptionKeyPair => {}
            MlsEntityId::GroupState => {}
        }

        Ok(())
    }
}
