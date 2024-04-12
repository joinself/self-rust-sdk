use libsqlite3_sys::{
    sqlite3, sqlite3_close_v2, sqlite3_db_mutex, sqlite3_mutex_enter, sqlite3_mutex_leave,
    sqlite3_open_v2, SQLITE_OK, SQLITE_OPEN_CREATE, SQLITE_OPEN_FULLMUTEX, SQLITE_OPEN_READWRITE,
};

use std::ffi::CString;
use std::ptr;

use crate::error::SelfError;
use crate::storage::schema::{
    schema_create_addresses, schema_create_groups, schema_create_keypairs, schema_create_members,
    schema_create_mls_encryption_key_pairs, schema_create_mls_group_states,
    schema_create_mls_hpke_private_keys, schema_create_mls_key_packages,
    schema_create_mls_psk_bundles, schema_create_mls_signature_key_pairs, schema_create_tokens,
};
use crate::storage::statement::Statement;
use crate::storage::transaction::Transaction;

use super::schema::{schema_create_inbox, schema_create_outbox};

pub struct Connection {
    conn: *mut sqlite3,
}

impl Connection {
    pub fn new(path: &str) -> Result<Connection, SelfError> {
        let flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX;
        let path = CString::new(path).expect("invalid db path");

        let mut conn: *mut sqlite3 = ptr::null_mut();

        unsafe {
            let result = sqlite3_open_v2(path.as_ptr(), &mut conn, flags, ptr::null());

            sqlite_check_result(result)?;
        }

        let connection = Connection { conn };

        // set sqlite pragmas
        connection.pragma("PRAGMA synchronous = normal;")?;
        connection.pragma("PRAGMA journal_mode = wal2;")?;
        connection.pragma("PRAGMA temp_store = memory;")?;

        // schema migrations
        connection.transaction(|txn| {
            schema_create_addresses(txn);
            schema_create_groups(txn);
            schema_create_keypairs(txn);
            schema_create_members(txn);
            schema_create_tokens(txn);
            schema_create_inbox(txn);
            schema_create_outbox(txn);
            schema_create_mls_signature_key_pairs(txn);
            schema_create_mls_hpke_private_keys(txn);
            schema_create_mls_key_packages(txn);
            schema_create_mls_psk_bundles(txn);
            schema_create_mls_encryption_key_pairs(txn);
            schema_create_mls_group_states(txn);

            Ok(())
        })?;

        Ok(connection)
    }

    pub fn transaction<F>(&self, execute: F) -> Result<(), SelfError>
    where
        F: FnOnce(&mut Transaction) -> Result<(), SelfError>,
    {
        unsafe {
            let mutex = sqlite3_db_mutex(self.conn);
            sqlite3_mutex_enter(mutex);

            let mut txn = Transaction::new(self.conn)?;

            let result = match execute(&mut txn) {
                Ok(()) => txn.commit(),
                Err(err) => match txn.rollback() {
                    Ok(_) => Err(err),
                    Err(txn_err) => Err(txn_err),
                },
            };

            sqlite3_mutex_leave(mutex);

            result
        }
    }

    fn pragma(&self, pragma: &str) -> Result<(), SelfError> {
        Statement::new(self.conn, pragma)?.execute()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe {
            sqlite3_mutex_enter(sqlite3_db_mutex(self.conn));
            sqlite3_close_v2(self.conn);
            sqlite3_mutex_leave(sqlite3_db_mutex(self.conn));
        }
    }
}

/// sychronization/locking happens inside of sqlite
unsafe impl Send for Connection {}
unsafe impl Sync for Connection {}

pub fn sqlite_check_result(result: i32) -> Result<(), SelfError> {
    match result {
        SQLITE_OK => Ok(()),
        _ => Err(SelfError::StorageUnknown),
    }
}

pub fn sqlite_check_result_debug(_conn: *mut sqlite3, result: i32) -> Result<(), SelfError> {
    match result {
        SQLITE_OK => Ok(()),
        _ => {
            /*
            println!("sqlite status: {}", result);

            unsafe {
                let msg = CStr::from_ptr(sqlite3_errmsg(conn));
                println!(
                    "sqlite error: {}",
                    msg.to_str().expect("failed to convert sqlite error")
                );
            }
            */

            Err(SelfError::StorageUnknown)
        }
    }
}

#[cfg(test)]
mod tests {
    // use rand::Rng;
    use super::Connection;

    #[test]
    fn connection() {
        let conn = Connection::new(":memory:").expect("failed to open connection");

        conn.transaction(|txn| {
            let stmt = txn
                .prepare(
                    "CREATE TABLE test_addresses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        address BLOB NOT NULL
                    );

                    CREATE UNIQUE INDEX idx_addresss_address
                    ON addresses (address);",
                )
                .expect("failed to prepare statement");

            stmt.execute()
        })
        .expect("failed to execute transaction");

        conn.transaction(|txn| {
            let address = vec![1; 33];

            let statement = txn
                .prepare("INSERT OR IGNORE INTO test_addresses (address) VALUES (?1)")
                .expect("failed to create statement");

            statement
                .bind_blob(1, &address)
                .expect("failed to bind blob");

            statement.execute().expect("failed to execute statement");

            let stmt = txn
                .prepare("SELECT id, address FROM test_addresses;")
                .expect("failed to prepare statement");

            while stmt.step().expect("failed to step statement") {
                // let id = stmt.column_integer(0);
                // let address = stmt.column_blob(1);
                // println!("row id: {:?} address: {:?}", id, address);
            }

            Ok(())
        })
        .expect("failed to execute transaction");

        /*
            let start = std::time::Instant::now();

            let mut address: Vec<u8> = vec![1; 33];

            conn.transaction(|txn| {
                for i in 0..100000 {
                    rand::thread_rng().fill(address.as_mut_slice());

                    let statement = txn
                        .prepare("INSERT OR IGNORE INTO addresses (address) VALUES (?1)")
                        .expect("failed to create statement");

                    statement
                        .bind_blob(1, &address)
                        .expect("failed to bind blob");
                }

                Ok(())
            })
            .expect("failed to run transaction");

            println!("took: {} ms", start.elapsed().as_millis());
        */
    }
}
