use crate::siggraph::action::Action;
use crate::{error::SelfError, keypair::KeyPair, message::message::Message};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Operation {
    pub sequence: i32,
    pub previous: String,
    pub version: String,
    pub timestamp: i64,
    pub actions: Vec<Action>,
    #[serde(skip)]
    message: Option<Message>,
}

impl Operation {
    pub fn from_bytes(data: &[u8]) -> Result<Operation, SelfError> {
        let msg = match Message::from_bytes(data) {
            Ok(msg) => msg,
            Err(err) => return Err(err),
        };

        let mut operation: Operation = match msg.to_custom_payload() {
            Ok(operation) => operation,
            Err(err) => return Err(err),
        };

        if operation.version != "1.0.0" {
            return Err(SelfError::SiggraphOperationVersionInvalid);
        }

        if operation.sequence < 0 {
            return Err(SelfError::SiggraphOperationSequenceOutOfOrder);
        }

        if operation.timestamp < 1 {
            return Err(SelfError::SiggraphOperationTimestampInvalid);
        }

        if operation.actions.len() < 1 {
            return Err(SelfError::SiggraphOperationNOOP);
        }

        operation.message = Some(msg);

        return Ok(operation);
    }

    pub fn verify(&self, signing_key: &KeyPair) -> Result<(), SelfError> {
        if self.message.is_none() {
            return Err(SelfError::SiggraphOperationNotSigned);
        }

        return self.message.as_ref().unwrap().verify(signing_key);
    }

    pub fn sign(&mut self, signing_key: &KeyPair) -> Result<(), SelfError> {
        if self.message.is_none() {
            let mut msg = Message::new_from_payload(self)?;

            msg.sign(signing_key)?;

            self.message = Some(msg);

            return Ok(());
        }

        self.message.as_mut().unwrap().sign(signing_key)?;

        return Ok(());
    }

    pub fn signing_key_ids(&self) -> Option<Vec<String>> {
        if self.message.is_none() {
            return None;
        }

        return self.message.as_ref().unwrap().signing_key_ids();
    }

    pub fn action_by_kid(&self, kid: &str) -> Option<Action> {
        for action in &self.actions {
            if action.kid == kid {
                return Some((*action).clone());
            }
        }

        return None;
    }

    /*
    fn timestamp(&self) -> chrono::DateTime<chrono::Utc> {

    }
     */

    pub fn to_jws(&mut self) -> Result<String, SelfError> {
        if self.message.is_none() {
            return Err(SelfError::SiggraphOperationNotSigned);
        }

        return self.message.as_mut().unwrap().to_jws();
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::keypair::{KeyPair, KeyPairType};
    use crate::siggraph::action::{ActionType, KeyRole};

    #[test]
    fn serialize_deserialize() {
        let kp = KeyPair::new(KeyPairType::Ed25519);

        let mut op = Operation {
            sequence: 0,
            previous: String::from("previous"),
            version: String::from("1.0.0"),
            timestamp: 1,
            actions: Vec::new(),
            message: None,
        };

        op.actions.push(Action {
            kid: String::from("kid"),
            did: Some(String::from("did")),
            role: Some(KeyRole::Device),
            action: ActionType::KeyAdd,
            effective_from: 1,
            key: Some(String::from("key")),
        });

        // try to encode or verify with a signature
        assert!(op.to_jws().is_err());
        assert!(op.verify(&kp).is_err());

        // sign and verify
        assert!(op.sign(&kp).is_ok());
        assert!(op.verify(&kp).is_ok());

        // encode, decode and re-verify
        let encoded_operation = op.to_jws().unwrap();
        let decoded_operation = Operation::from_bytes(encoded_operation.as_bytes()).unwrap();
        assert!(decoded_operation.verify(&kp).is_ok());
    }
}
