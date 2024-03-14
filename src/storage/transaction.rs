use libsqlite3_sys::sqlite3;
use openmls_traits::key_store::{MlsEntity, MlsEntityId, OpenMlsKeyStore};

use crate::error::SelfError;
use crate::storage::statement::Statement;

pub struct Transaction {
    conn: *mut sqlite3,
}

impl Transaction {
    pub fn new(conn: *mut sqlite3) -> Result<Transaction, SelfError> {
        Statement::new(conn, "BEGIN EXCLUSIVE;")?.execute()?;
        Ok(Transaction { conn })
    }

    pub fn prepare(&self, statement: &str) -> Result<Statement, SelfError> {
        Statement::new(self.conn, statement)
    }

    pub fn commit(&self) -> Result<(), SelfError> {
        Statement::new(self.conn, "COMMIT;")?.execute()
    }

    pub fn rollback(&self) -> Result<(), SelfError> {
        Statement::new(self.conn, "ROLLBACK;")?.execute()
    }
}

impl OpenMlsKeyStore for Transaction {
    type Error = SelfError;

    fn store<V: MlsEntity>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        // println!("mls store: {:?} ({:?})", hex::encode(k), V::ID as u8);

        let mut data = Vec::new();
        ciborium::into_writer(&v, &mut data).expect("failed to serialize data");

        let stmt =
            match V::ID {
                MlsEntityId::SignatureKeyPair => self
                    .prepare("INSERT INTO signature_key_pairs (address, value) VALUES (?1, ?2);"),
                MlsEntityId::HpkePrivateKey => {
                    self.prepare("INSERT INTO hpke_private_keys (address, value) VALUES (?1, ?2);")
                }
                MlsEntityId::KeyPackage => {
                    self.prepare("INSERT INTO key_packages (address, value) VALUES (?1, ?2);")
                }
                MlsEntityId::PskBundle => {
                    self.prepare("INSERT INTO psk_bundles (address, value) VALUES (?1, ?2);")
                }
                MlsEntityId::EncryptionKeyPair => self
                    .prepare("INSERT INTO encryption_key_pairs (address, value) VALUES (?1, ?2);"),
                MlsEntityId::GroupState => {
                    self.prepare("INSERT INTO group_states (address, value) VALUES (?1, ?2);")
                }
            }
            .expect("failed to build mls store statement");

        stmt.bind_blob(1, k).expect("failed to bind mls key");
        stmt.bind_blob(2, &data).expect("failed to bind mls value");
        stmt.execute()
            .expect("failed to execute mls store statement");

        Ok(())
    }

    fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V> {
        // println!("mls read: {:?} ({:?})", hex::encode(k), V::ID as u8);

        let stmt = match V::ID {
            MlsEntityId::SignatureKeyPair => {
                self.prepare("SELECT value FROM signature_key_pairs WHERE address = ?1;")
            }
            MlsEntityId::HpkePrivateKey => {
                self.prepare("SELECT value FROM hpke_private_keys WHERE address = ?1;")
            }
            MlsEntityId::KeyPackage => {
                self.prepare("SELECT value FROM key_packages WHERE address = ?1;")
            }
            MlsEntityId::PskBundle => {
                self.prepare("SELECT value FROM psk_bundles WHERE address = ?1;")
            }
            MlsEntityId::EncryptionKeyPair => {
                self.prepare("SELECT value FROM encryption_key_pairs WHERE address = ?1;")
            }
            MlsEntityId::GroupState => {
                self.prepare("SELECT value FROM group_states WHERE address = ?1;")
            }
        }
        .expect("failed to build mls read statement");

        stmt.bind_blob(1, k).expect("failed to bind mls key");
        if !stmt.step().expect("failed to step query") {
            return None;
        }

        let data = match stmt.column_blob(0).expect("failed to get column") {
            Some(data) => data,
            None => return None,
        };

        Some(
            ciborium::from_reader::<V, &[u8]>(data.as_ref())
                .expect("failed to deserialize group state"),
        )
    }

    fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        // println!("mls delete: {:?} ({:?})", hex::encode(k), V::ID as u8);

        let stmt = match V::ID {
            MlsEntityId::SignatureKeyPair => {
                self.prepare("DELETE FROM signature_key_pairs WHERE address = ?1;")
            }
            MlsEntityId::HpkePrivateKey => {
                self.prepare("DELETE FROM hpke_private_keys WHERE address = ?1;")
            }
            MlsEntityId::KeyPackage => self.prepare("DELETE FROM key_packages WHERE address = ?1;"),
            MlsEntityId::PskBundle => self.prepare("DELETE FROM psk_bundles WHERE address = ?1;"),
            MlsEntityId::EncryptionKeyPair => {
                self.prepare("DELETE FROM encryption_key_pairs WHERE address = ?1;")
            }
            MlsEntityId::GroupState => self.prepare("DELETE FROM group_states WHERE address = ?1;"),
        }
        .expect("failed to build mls delete statement");

        stmt.bind_blob(1, k)
            .expect("failed to bind mls key")
            .execute()
            .expect("failed to execute mls delete statement");

        Ok(())
    }
}

unsafe impl Sync for Transaction {}

unsafe impl Send for Transaction {}

impl Drop for Transaction {
    fn drop(&mut self) {}
}
