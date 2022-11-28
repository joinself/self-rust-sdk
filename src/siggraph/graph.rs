use crate::error::SelfError;
use crate::siggraph::action::{Action, ActionType, KeyRole};
use crate::siggraph::node::Node;
use crate::siggraph::operation::Operation;

use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub struct SignatureGraph {
    root: Option<Rc<RefCell<Node>>>,
    keys: HashMap<String, Rc<RefCell<Node>>>,
    devices: HashMap<String, Rc<RefCell<Node>>>,
    signatures: HashMap<String, usize>,
    operations: Vec<Operation>,
    recovery_key: Option<Rc<RefCell<Node>>>,
}

impl SignatureGraph {
    pub fn new(history: Vec<Operation>) -> Result<SignatureGraph, SelfError> {
        let mut sg = SignatureGraph {
            root: None,
            keys: HashMap::new(),
            devices: HashMap::new(),
            signatures: HashMap::new(),
            operations: Vec::new(),
            recovery_key: None,
        };

        for operation in &history {
            sg.execute(operation)?
        }

        return Ok(sg);
    }

    pub fn execute(&mut self, operation: &Operation) -> Result<(), SelfError> {
        // check the sequence is in order
        if operation.sequence != self.operations.len() as i32 {
            return Err(SelfError::SiggraphOperationSequenceOutOfOrder);
        }

        if operation.sequence > 0 {
            // check the previous signature matches, if not the first (root) operation
            let previous = match self.signatures.get(&operation.previous) {
                Some(previous) => *previous,
                None => return Err(SelfError::SiggraphOperationPreviousSignatureInvalid),
            };

            if previous != self.operations.len() - 1 {
                return Err(SelfError::SiggraphOperationPreviousSignatureInvalid);
            }

            // check the timestamp is greater than the previous operations
            if self.operations[self.operations.len() - 1].timestamp() == operation.timestamp()
                || self.operations[self.operations.len() - 1].timestamp() > operation.timestamp()
            {
                return Err(SelfError::SiggraphOperationTimestampInvalid);
            }

            // check the operation was signed by one or more keys
            let signing_key_ids = match operation.signing_key_ids() {
                Some(signing_key_ids) => signing_key_ids,
                None => return Err(SelfError::SiggraphOperationSigningKeyInvalid),
            };

            for signing_key_id in signing_key_ids {
                // check the key used to sign the operation exists
                let signing_key = match self.keys.get(&signing_key_id) {
                    Some(signing_key) => signing_key.clone(),
                    None => return Err(SelfError::SiggraphOperationSigningKeyInvalid),
                };

                // check the signign key hasn't been revoked before the operation
                if (*signing_key).borrow().revoked_at().is_some() {
                    let revoked_at = (*signing_key).borrow().revoked_at().unwrap();

                    if operation.timestamp() > revoked_at {
                        return Err(SelfError::SiggraphOperationSignatureKeyRevoked);
                    }
                }

                // if this operation is an account recovery, check that it revokes the active recovery key
                if (*signing_key).borrow().typ == KeyRole::Recovery {
                    let action = operation.action_by_kid(&signing_key_id);
                    if action.is_none() {
                        return Err(SelfError::SiggraphOperationAccountRecoveryActionInvalid);
                    }

                    if action.unwrap().action != ActionType::KeyRevoke {
                        return Err(SelfError::SiggraphOperationAccountRecoveryActionInvalid);
                    }
                }
            }

            // run actions
            for action in &operation.actions {
                action.validate()?;

                match action.action {
                    ActionType::KeyAdd => {
                        self.add(operation, action)?;
                    }
                    ActionType::KeyRevoke => {
                        self.revoke(operation, action)?;
                    }
                }
            }

            let signing_key_ids = match operation.signing_key_ids() {
                Some(signing_key_ids) => signing_key_ids,
                None => return Err(SelfError::SiggraphOperationSigningKeyInvalid),
            };

            for signing_key_id in signing_key_ids {
                // check the key used to sign the operation exists
                let signing_key = match self.keys.get(&signing_key_id) {
                    Some(signing_key) => signing_key.clone(),
                    None => return Err(SelfError::SiggraphOperationSigningKeyInvalid),
                };

                // check that the operation was signed before the signing key was revoked
                if operation.timestamp() < (*signing_key).borrow().created_at().unwrap()
                    || !(*signing_key).borrow().revoked_at().is_none()
                        && operation.timestamp() > (*signing_key).borrow().revoked_at().unwrap()
                {
                    return Err(SelfError::SiggraphOperationSignatureKeyRevoked);
                }

                operation.verify(&(*signing_key).borrow().pk)?;

                let mut valid: bool = false;

                // check all keys to ensure that at least one key is active
                for key in self.keys.values() {
                    let k = (**key).borrow();

                    if k.revoked_at().is_none() {
                        valid = true;
                        break;
                    }
                }

                if !valid {
                    return Err(SelfError::SiggraphOperationNoValidKeys);
                }

                // check there is an active recovery key
                if self.recovery_key.is_none() {
                    return Err(SelfError::SiggraphOperationNoValidRecoveryKey);
                }

                let recovery_key = self.recovery_key.as_ref().unwrap().clone();

                if (*recovery_key).borrow().revoked_at().is_some() {
                    return Err(SelfError::SiggraphOperationNoValidRecoveryKey);
                }

                // add the operation to the history
                self.operations.push(operation.clone());
            }
        }

        return Ok(());
    }

    pub fn add(&mut self, operation: &Operation, action: &Action) -> Result<(), SelfError> {
        return Ok(());
    }

    pub fn revoke(&mut self, operation: &Operation, action: &Action) -> Result<(), SelfError> {
        return Ok(());
    }
}
