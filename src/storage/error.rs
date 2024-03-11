use std::fmt;

#[derive(Debug, PartialEq)]
pub enum MlsError {
    Unknown,
}

impl std::error::Error for MlsError {}

impl fmt::Display for MlsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MlsError::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum DbError {
    Unknown,
    ColumnTypeMismatch,
    TextUtf8Invalid,
}

impl std::error::Error for DbError {}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DbError::Unknown => write!(f, "Unknown"),
            DbError::ColumnTypeMismatch => write!(f, "Column type mismatch"),
            DbError::TextUtf8Invalid => write!(f, "Text utf8 invalid"),
        }
    }
}
