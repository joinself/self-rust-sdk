use serde::{Deserialize, Serialize};

use crate::{error::SelfError, identifier::Identifier};

#[derive(Serialize, Deserialize, Debug)]
pub struct PrekeyResponse {
    pub key: Vec<u8>,
}

impl PrekeyResponse {
    pub fn new(body: &[u8]) -> Result<Self, SelfError> {
        ciborium::de::from_reader(body).map_err(|_| SelfError::RestResposeBodyInvalid)
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyCreateRequest {
    pub identifier: Vec<u8>,
}

impl KeyCreateRequest {
    pub fn encode(identifier: &Identifier) -> Result<Vec<u8>, SelfError> {
        let mut buffer = Vec::new();

        // TODO update error
        ciborium::ser::into_writer(
            &KeyCreateRequest {
                identifier: identifier.id(),
            },
            &mut buffer,
        )
        .map_err(|_| SelfError::MessageEncodingInvalid)?;

        Ok(buffer)
    }
}
