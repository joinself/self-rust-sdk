use rusqlite::{Connection, Result, Transaction};

use crate::error::SelfError;

pub struct Storage {
    conn: Connection,
}

impl Storage {
    pub fn new() -> Result<Storage, SelfError> {
        let conn = Connection::open_in_memory().map_err(|_| SelfError::StorageConnectionFailed)?;

        /*
        let conn = Connection::open("/tmp/test.db").map_err(|_| SelfError::StorageConnectionFailed)?;
        conn.pragma_update(None, "synchronous", &"NORMAL").unwrap();
        conn.pragma_update(None, "journal_mode", &"WAL").unwrap();
        conn.pragma_update(None, "temp_store", &"MEMORY").unwrap();
        */

        let mut storage = Storage { conn };

        storage.setup_crypto_accounts_table()?;
        storage.setup_crypto_sessions_table()?;
        storage.setup_account_keychain_table()?;
        storage.setup_messaging_tokens_table()?;
        storage.setup_messaging_groups_table()?;
        storage.setup_messaging_membership_table()?;

        Ok(storage)
    }

    fn setup_crypto_accounts_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE crypto_accounts (
                    id INTEGER PRIMARY KEY,
                    identity BLOB NOT NULL,
                    account BLOB NOT NULL,
                    offset INTEGER
                );
                CREATE UNIQUE INDEX idx_crypto_accounts_identity
                ON crypto_accounts (identity);",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    fn setup_crypto_sessions_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE crypto_sessions (
                    id INTEGER PRIMARY KEY,
                    with BLOB NOT NULL,
                    session BLOB NOT NULL,
                    offset INTEGER
                );
                CREATE UNIQUE INDEX idx_crypto_sessions_identity
                ON crypto_sessions (identity);",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    fn setup_account_keychain_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE account_keychain (
                    id INTEGER PRIMARY KEY,
                    role INTEGER NOT NULL,
                    public_key BLOB NOT NULL,
                    secret_key BLOB NOT NULL
                );
                CREATE UNIQUE INDEX idx_account_keychain_public_key
                ON account_keychain (public_key);",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    fn setup_messaging_tokens_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE messaging_tokens (
                    id INTEGER PRIMARY KEY,
                    recipient BLOB NOT NULL,
                    sender BLOB NOT NULL,
                    token BLOB NOT NULL
                );
                CREATE UNIQUE INDEX idx_messaging_tokens_recipient
                ON messaging_tokens (recipient);",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    fn setup_messaging_groups_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE messaging_groups (
                    id INTEGER PRIMARY KEY,
                    identity BLOB NOT NULL,
                    owner BLOB NOT NULL
                );
                CREATE UNIQUE INDEX idx_messaging_groups_identity
                ON messaging_groups (identity);",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    fn setup_messaging_membership_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE messaging_members (
                    id INTEGER PRIMARY KEY,
                    group_id INTEGER NOT NULL,
                    member INTEGER NOT NULL
                );
                CREATE UNIQUE INDEX idx_messaging_members_group_member
                ON messaging_members (group_id, member);",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    pub fn transaction<F>(&mut self, execute: F) -> Result<(), SelfError>
    where
        F: FnOnce(&Transaction) -> bool,
    {
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

        Ok(())
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
            .transaction(|txn| {
                txn.execute(
                    "INSERT INTO crypto_sessions (identity, session) VALUES (?1, ?2)",
                    (b"bob", b"session-with-bob"),
                )
                .is_ok()
            })
            .expect("failed to create transaction");

        // load a session
        storage
            .transaction(|txn| {
                let mut statement = txn
                    .prepare("SELECT * FROM crypto_sessions WHERE identity = ?1")
                    .expect("failed to prepare statement");

                let mut rows = statement.query([b"bob"]).expect("failed to execute query");
                let row = rows.next().expect("no rows found").unwrap();

                let identity: Vec<u8> = row.get(1).unwrap();
                let session: Vec<u8> = row.get(2).unwrap();

                assert_eq!(identity, b"bob");
                assert_eq!(session, b"session-with-bob");

                true
            })
            .expect("failed to create transaction");
    }
}
