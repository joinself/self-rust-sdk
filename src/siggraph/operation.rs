use crate::siggraph::action::Action;
use crate::{error::SelfError, keypair::KeyPair};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Operation {
    pub sequence: i32,
    pub previous: String,
    pub version: String,
    pub timestamp: i64,
    pub actions: Vec<Action>,
}

impl Operation {
    pub fn parse(operation: &[u8]) -> Result<Operation, SelfError> {
        let op = match serde_json::from_slice(operation) {
            Ok(op) => op,
            Err(_) => return Err(SelfError::SiggraphOperationJSONInvalid),
        };

        return Ok(op);
    }

    pub fn verify(&self, signing_key: KeyPair) {}
}
