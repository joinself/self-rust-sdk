use serde::{Deserialize, Serialize};

use crate::{error::SelfError, token::Token};

use super::ResponseStatus;

pub enum Response {
    Connection(ConnectionResponse),
}

#[derive(Serialize, Deserialize)]
pub struct ConnectionResponse {
    pub ath: Option<Token>, // authentication token
    pub ntf: Option<Token>, // notification token
    pub sts: ResponseStatus,
}

impl ConnectionResponse {
    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        let mut data = Vec::new();
        ciborium::ser::into_writer(self, &mut data).map_err(|_| SelfError::TokenEncodingInvalid)?;
        Ok(data)
    }

    pub fn decode(data: &[u8]) -> Result<ConnectionResponse, SelfError> {
        ciborium::de::from_reader(data).map_err(|_| SelfError::MessageDecodingInvalid)
    }
}
