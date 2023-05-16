use serde::{Deserialize, Serialize};

use crate::error::SelfError;

#[derive(Serialize, Deserialize, Debug)]
pub struct PrekeyResponse {
    pub key: Vec<u8>,
}

impl PrekeyResponse {
    pub fn new(body: &[u8]) -> Result<Self, SelfError> {
        ciborium::de::from_reader(body).map_err(|_| SelfError::RestResposeBodyInvalid)
    }
}
