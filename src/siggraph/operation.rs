use crate::error::SelfError;
use crate::keypair::signing::{KeyPair, PublicKey};
use crate::message::{Message, Signature};
use crate::siggraph::action::Action;

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
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
    pub fn new(sequence: i32, previous: &str, timestamp: i64, actions: Vec<Action>) -> Operation {
        return Operation {
            sequence: sequence,
            previous: String::from(previous),
            version: String::from("1.0.0"),
            timestamp: timestamp,
            actions: actions,
            message: None,
        };
    }

    pub fn from_bytes(data: &[u8]) -> Result<Operation, SelfError> {
        let msg = match Message::from_jws(data) {
            Ok(msg) => msg,
            Err(err) => return Err(err),
        };

        let mut operation: Operation = match msg.to_custom_payload() {
            Ok(operation) => operation,
            Err(err) => return Err(err),
        };

        operation.message = Some(msg);
        operation.validate()?;

        return Ok(operation);
    }

    pub fn validate(&self) -> Result<(), SelfError> {
        if self.version != "1.0.0" {
            return Err(SelfError::SiggraphOperationVersionInvalid);
        }

        if self.sequence < 0 {
            return Err(SelfError::SiggraphOperationSequenceOutOfOrder);
        }

        if self.timestamp < 1 {
            return Err(SelfError::SiggraphOperationTimestampInvalid);
        }

        if self.actions.len() < 1 {
            return Err(SelfError::SiggraphOperationNOOP);
        }

        return Ok(());
    }

    pub fn verify(&self, signing_key: &PublicKey) -> Result<(), SelfError> {
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

    pub fn timestamp(&self) -> DateTime<Utc> {
        if self.timestamp > i32::MAX as i64 {
            return DateTime::from_utc(
                NaiveDateTime::from_timestamp(self.timestamp / 1000, 0),
                Utc,
            );
        }

        return DateTime::from_utc(NaiveDateTime::from_timestamp(self.timestamp, 0), Utc);
    }

    pub fn signatures(&self) -> Vec<Signature> {
        if self.message.is_none() {
            return vec![];
        }

        return self.message.as_ref().unwrap().signatures();
    }

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
    use crate::keypair::signing::KeyPair;
    use crate::siggraph::action::{ActionType, KeyRole};

    #[test]
    fn serialize_deserialize() {
        let kp = KeyPair::new();

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
        assert!(op.verify(&kp.public()).is_err());

        // sign and verify
        assert!(op.sign(&kp).is_ok());
        assert!(op.verify(&kp.public()).is_ok());

        // encode, decode and re-verify
        let encoded_operation = op.to_jws().unwrap();
        let decoded_operation = Operation::from_bytes(encoded_operation.as_bytes()).unwrap();
        assert!(decoded_operation.verify(&kp.public()).is_ok());
    }
}
