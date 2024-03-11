use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use libsqlite3_sys::{
    sqlite3, sqlite3_bind_blob, sqlite3_bind_double, sqlite3_bind_int64, sqlite3_bind_null,
    sqlite3_bind_text, sqlite3_column_blob, sqlite3_column_bytes, sqlite3_column_double,
    sqlite3_column_int64, sqlite3_column_text, sqlite3_column_type, sqlite3_finalize,
    sqlite3_prepare_v2, sqlite3_reset, sqlite3_step, sqlite3_stmt, SQLITE_BLOB, SQLITE_DONE,
    SQLITE_FLOAT, SQLITE_INTEGER, SQLITE_NULL, SQLITE_ROW, SQLITE_TEXT, SQLITE_TRANSIENT,
};

use crate::error::SelfError;
use crate::storage::connection::sqlite_check_result_debug;

pub struct Statement {
    conn: *mut sqlite3,
    stmt: *mut sqlite3_stmt,
}

impl Statement {
    pub fn new(conn: *mut sqlite3, statement: &str) -> Result<Statement, SelfError> {
        let mut stmt = ptr::null_mut();
        let mut tail = ptr::null();

        unsafe {
            let result = sqlite3_prepare_v2(
                conn,
                statement.as_ptr().cast::<c_char>(),
                statement.len() as c_int,
                &mut stmt as *mut *mut sqlite3_stmt,
                &mut tail as *mut *const c_char,
            );

            sqlite_check_result_debug(conn, result)?;

            Ok(Statement { conn, stmt })
        }
    }

    pub fn execute(&self) -> Result<(), SelfError> {
        self.step().map(|_| ())
    }

    pub fn step(&self) -> Result<bool, SelfError> {
        unsafe {
            match sqlite3_step(self.stmt) {
                SQLITE_ROW => Ok(true),
                SQLITE_DONE => Ok(false),
                result => Err(sqlite_check_result_debug(self.conn, result).unwrap_err()),
            }
        }
    }

    pub fn reset(&self) -> Result<(), SelfError> {
        unsafe {
            let result = sqlite3_reset(self.stmt);
            sqlite_check_result_debug(self.conn, result)
        }
    }

    pub fn bind_text(&self, column: i32, text: &str) -> Result<&Statement, SelfError> {
        unsafe {
            let result = sqlite3_bind_text(
                self.stmt,
                column as c_int,
                text.as_ptr().cast::<c_char>(),
                text.len() as c_int,
                SQLITE_TRANSIENT(),
            );

            sqlite_check_result_debug(self.conn, result)?
        }

        Ok(self)
    }

    pub fn bind_blob(&self, column: i32, blob: &[u8]) -> Result<&Statement, SelfError> {
        unsafe {
            let result = sqlite3_bind_blob(
                self.stmt,
                column as c_int,
                blob.as_ptr().cast::<c_void>(),
                blob.len() as c_int,
                SQLITE_TRANSIENT(),
            );

            sqlite_check_result_debug(self.conn, result)?
        }

        Ok(self)
    }

    pub fn bind_float(&self, column: i32, float: f64) -> Result<&Statement, SelfError> {
        unsafe {
            let result = sqlite3_bind_double(self.stmt, column as c_int, float);
            sqlite_check_result_debug(self.conn, result)?
        }

        Ok(self)
    }

    pub fn bind_integer(&self, column: i32, integer: i64) -> Result<&Statement, SelfError> {
        unsafe {
            let result = sqlite3_bind_int64(self.stmt, column as c_int, integer);
            sqlite_check_result_debug(self.conn, result)?
        }

        Ok(self)
    }

    pub fn bind_null(&self, column: i32) -> Result<&Statement, SelfError> {
        unsafe {
            let result = sqlite3_bind_null(self.stmt, column as c_int);
            sqlite_check_result_debug(self.conn, result)?
        }

        Ok(self)
    }

    pub fn column_text(&self, column: i32) -> Result<Option<String>, SelfError> {
        if let Some(column_type_correct) = self.column_type_is(column, SQLITE_TEXT) {
            if !column_type_correct {
                return Err(SelfError::StorageColumnTypeMismatch);
            }
        } else {
            return Ok(None);
        }

        unsafe {
            let text_buf = sqlite3_column_text(self.stmt, column);
            let text_len = sqlite3_column_bytes(self.stmt, column);
            let text = std::slice::from_raw_parts(text_buf, text_len as usize);

            let text_ref = match std::str::from_utf8(text) {
                Ok(text_ref) => text_ref,
                Err(_) => return Err(SelfError::StorageTextUtf8Invalid),
            };

            Ok(Some(String::from(text_ref)))
        }
    }

    pub fn column_blob(&self, column: i32) -> Result<Option<Vec<u8>>, SelfError> {
        if let Some(column_type_correct) = self.column_type_is(column, SQLITE_BLOB) {
            if !column_type_correct {
                return Err(SelfError::StorageColumnTypeMismatch);
            }
        } else {
            return Ok(None);
        }

        unsafe {
            let blob_buf = sqlite3_column_blob(self.stmt, column);
            let blob_len = sqlite3_column_bytes(self.stmt, column);
            let blob = std::slice::from_raw_parts(blob_buf.cast::<u8>(), blob_len as usize);
            Ok(Some(blob.to_vec()))
        }
    }

    pub fn column_float(&self, column: i32) -> Result<Option<f64>, SelfError> {
        if let Some(column_type_correct) = self.column_type_is(column, SQLITE_FLOAT) {
            if !column_type_correct {
                return Err(SelfError::StorageColumnTypeMismatch);
            }
        } else {
            return Ok(None);
        }

        unsafe {
            let double = sqlite3_column_double(self.stmt, column);
            Ok(Some(double))
        }
    }

    pub fn column_integer(&self, column: i32) -> Result<Option<i64>, SelfError> {
        if let Some(column_type_correct) = self.column_type_is(column, SQLITE_INTEGER) {
            if !column_type_correct {
                return Err(SelfError::StorageColumnTypeMismatch);
            }
        } else {
            return Ok(None);
        }

        unsafe {
            let integer = sqlite3_column_int64(self.stmt, column);
            Ok(Some(integer))
        }
    }

    fn column_type_is(&self, column: i32, ctype: i32) -> Option<bool> {
        unsafe {
            match sqlite3_column_type(self.stmt, column) {
                SQLITE_NULL => None,
                column_type => Some(column_type == ctype),
            }
        }
    }
}

unsafe impl Send for Statement {}

impl Drop for Statement {
    fn drop(&mut self) {
        unsafe {
            sqlite3_finalize(self.stmt);
        }
    }
}
