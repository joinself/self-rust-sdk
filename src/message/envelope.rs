use serde::{Deserialize, Serialize};

use super::Content;
use crate::{error::SelfError, identifier::Identifier};

#[derive(Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub to: Identifier,
    pub from: Identifier,
    pub sequence: u64,
    pub content: Content,
}

impl Envelope {
    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        let mut data = Vec::new();
        ciborium::ser::into_writer(self, &mut data).map_err(|_| SelfError::TokenEncodingInvalid)?;
        Ok(data)
    }

    pub fn decode(data: &[u8]) -> Result<Envelope, SelfError> {
        ciborium::de::from_reader(data).map_err(|_| SelfError::MessageDecodingInvalid)
    }
}
