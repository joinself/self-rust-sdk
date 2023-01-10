use rusqlite::{Connection, Result, Transaction};

use std::sync::Arc;

use crate::error::SelfError;

pub struct Storage {
    conn: Connection,
}

impl Storage {
    pub fn new() -> Result<Storage, SelfError> {
        let conn = Connection::open_in_memory().map_err(|_| SelfError::StorageConnectionFailed)?;

        let mut storage = Storage { conn };

        storage.setup_crypto_session_table()?;

        Ok(storage)
    }

    fn setup_crypto_session_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE crypto_sessions (
                identity BLOB PRIMARY KEY,
                session BLOB NOT NULL
            )",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        return Ok(());
    }

    pub fn transaction(
        &mut self,
        execute: Arc<dyn Fn(&mut Transaction) -> bool + Sync + Send>,
    ) -> Result<(), SelfError> {
        let mut txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        if !execute(&mut txn) {
            txn.rollback()
                .map_err(|_| SelfError::StorageTransactionRollbackFailed)?;
        } else {
            txn.commit()
                .map_err(|_| SelfError::StorageTransactionCommitFailed)?;
        };

        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction() {
        let mut storage = Storage::new().expect("failed to create transaction");

        // create a session
        storage
            .transaction(Arc::new(|txn| {
                if txn
                    .execute(
                        "INSERT INTO crypto_sessions (identity, session) VALUES (?1, ?2)",
                        (b"bob", b"session-with-bob"),
                    )
                    .is_err()
                {
                    return false;
                };
                return true;
            }))
            .expect("failed to create transaction");

        // load a session
        storage
            .transaction(Arc::new(|txn| {
                let mut statement = txn
                    .prepare("SELECT * FROM crypto_sessions WHERE identity = ?1")
                    .expect("failed to prepare statement");

                let mut rows = statement.query([b"bob"]).expect("failed to execute query");
                let row = rows.next().expect("no rows found").unwrap();

                let identity: Vec<u8> = row.get(0).unwrap();
                let session: Vec<u8> = row.get(1).unwrap();

                assert_eq!(identity, b"bob");
                assert_eq!(session, b"session-with-bob");

                return true;
            }))
            .expect("failed to create transaction");
    }
}
