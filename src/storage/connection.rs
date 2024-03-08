use libsqlite3_sys::{
    sqlite3, sqlite3_bind_text, sqlite3_open_v2, sqlite3_prepare_v2, sqlite3_stmt, SQLITE_OK,
    SQLITE_OPEN_CREATE, SQLITE_OPEN_FULLMUTEX, SQLITE_OPEN_READWRITE,
};

use std::ffi::{c_char, c_int, CString};
use std::ptr;

use crate::error::DbError;
use crate::statement::Statement;

pub struct Connection {
    conn: *mut sqlite3,
}

impl Connection {
    pub fn new(path: &str) -> Result<Connection, DbError> {
        let flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX;
        let path = CString::new(path).expect("invalid db path");

        let mut conn: *mut sqlite3 = ptr::null_mut();

        unsafe {
            let result = sqlite3_open_v2(path.as_ptr(), &mut conn, flags, ptr::null());

            sqlite_check_result(result)?;
        }

        Ok(Connection { conn })
    }

    pub fn prepare(&self, statement: &str) -> Result<Statement, DbError> {
        unsafe {
            let mut stmt = ptr::null_mut();
            let mut tail = ptr::null();

            let result = sqlite3_prepare_v2(
                self.conn,
                statement.as_ptr().cast::<c_char>(),
                statement.len() as c_int,
                &mut stmt as *mut *mut sqlite3_stmt,
                &mut tail as *mut *const c_char,
            );

            sqlite_check_result(result)?;

            Ok(Statement::new(stmt))
        }
    }
}

pub fn sqlite_check_result(result: i32) -> Result<(), DbError> {
    match result {
        SQLITE_OK => Ok(()),
        _ => Err(DbError::Unknown),
    }
}

#[cfg(test)]
mod test {

    use super::Connection;

    #[test]
    fn connection() {
        let conn = Connection::new(":memory:").expect("failed to open connection");

        let stmt = conn
            .prepare(
                "
            CREATE TABLE addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL
            );

            CREATE UNIQUE INDEX idx_addresss_address
            ON addresses (address);
        ",
            )
            .expect("failed to prepare statement");

        stmt.execute().expect("failed to execute statement");

        let address = vec![1; 33];

        let statement = conn
            .prepare("INSERT OR IGNORE INTO addresses (address) VALUES (?1)")
            .expect("failed to create statement");

        statement
            .bind_blob(1, &address)
            .expect("failed to bind blob");

        statement.execute().expect("failed to execute statement");

        let stmt = conn
            .prepare("SELECT id, address FROM addresses;")
            .expect("failed to prepare statement");

        while stmt.step().expect("failed to step statement") {
            let id = stmt.column_integer(0);
            let address = stmt.column_blob(1);

            println!("row id: {:?} address: {:?}", id, address);
        }
    }
}
