use crate::error::SelfError;
use crate::identifier::Identifier;

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub enum Token {
    Authorization(Authorization),
    Notification(Notification),
    Subscription(Subscription),
    Delegation(Delegation),
}

impl Token {
    pub fn kind(&self) -> u8 {
        match (*self).clone() {
            Authorization => 1,
            Notification => 2,
            Subscription => 3,
            Delegation => 4,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        let mut encoded_token = Vec::new();
        ciborium::ser::into_writer(self, &mut encoded_token)
            .map_err(|_| SelfError::TokenEncodingInvalid)?;
        Ok(encoded_token)
    }

    pub fn decode(bytes: &[u8]) -> Result<Token, SelfError> {
        ciborium::de::from_reader(bytes).map_err(|_| SelfError::TokenEncodingInvalid)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub token: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Notification {
    pub token: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub token: Vec<u8>,
    pub issuer: Identifier,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub token: Vec<u8>,
}
