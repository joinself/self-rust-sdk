use crate::error::SelfError;
use crate::keypair::{KeyPair, KeyPairType};
use crate::siggraph::action::{Action, ActionType, KeyRole};
use crate::siggraph::node::Node;
use crate::siggraph::operation::Operation;

use std::borrow::BorrowMut;
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

            if signing_key_ids.len() != 1 {
                return Err(SelfError::SiggraphOperationSigningKeyInvalid);
            }
 
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

            if signing_key_ids.len() != 1 {
                return Err(SelfError::SiggraphOperationSigningKeyInvalid);
            }

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
                self.signatures.insert(operation.signatures().first().unwrap().signature.clone(), operation.sequence as usize);
            }
        }

        return Ok(());
    }

    pub fn add(&mut self, operation: &Operation, action: &Action) -> Result<(), SelfError> {
        // lookup the key the action refers to
        if self.keys.contains_key(&action.kid) {
            return Err(SelfError::SiggraphActionKeyDuplicate);
        }

        if action.key.is_none() {
            return Err(SelfError::SiggraphActionPublicKeyLengthBad);
        }

        if action.role.is_none() {
            return Err(SelfError::SiggraphActionRoleMissing);
        }
        
        let public_key = action.key.as_ref().unwrap();
        let public_key_role = action.role.as_ref().unwrap();

        let kp = match public_key_role {
            KeyRole::Device => KeyPair::from_public_key(&action.kid, KeyPairType::Ed25519, &public_key),
            KeyRole::Recovery => KeyPair::from_public_key(&action.kid, KeyPairType::Ed25519, &public_key),
        }?;

        let node = Rc::new(RefCell::new(Node{
            kid: action.kid.clone(),
            did: action.did.clone(),
            typ: public_key_role.clone(),
            seq: operation.sequence,
            ca: operation.timestamp,
            ra: 0,
            pk: kp,
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }));

        match public_key_role {
            KeyRole::Device => {
                let did = node.borrow().did.as_ref().unwrap().clone();

                // check there are no devices with an active key
                let device = self.devices.get(&did);
                if device.is_some() && device.as_ref().unwrap().borrow().ra < 1 {
                    return Err(SelfError::SiggraphActionMultipleActiveDeviceKeys);
                }

                self.devices.insert(did, node.clone());
            },
            KeyRole::Recovery => {
                // check there are only one active recovery keys
                if self.recovery_key.is_some() {
                    if self.recovery_key.as_ref().unwrap().borrow().ra == 0 {
                        return Err(SelfError::SiggraphActionMultipleActiveRecoveryKeys);
                    }
                }

                self.recovery_key = Some(node.clone());
            },
        };

        let kid = node.borrow().kid.clone();
        self.keys.insert(kid.clone(), node.clone());        

        let signing_key_id = operation.signing_key_ids().unwrap()[0].clone();

        if operation.sequence == 0 && signing_key_id == kid {
            self.root = Some(node.clone());
        } else {
            let parent = self.keys.get(&signing_key_id).ok_or_else(|| SelfError::SiggraphActionSigningKeyInvalid)?;

            node.as_ref().borrow_mut().incoming.push(parent.clone());
            parent.as_ref().borrow_mut().outgoing.push(node.clone());
        }

        return Ok(());
    }

    pub fn revoke(&mut self, operation: &Operation, action: &Action) -> Result<(), SelfError> {
        // lookup the key the action refers to
        let node = self.keys.get(&action.kid);
        if node.is_none() {
            return Err(SelfError::SiggraphActionKeyMissing);
        }

        // if the key does not exist, then the revocation is invalid
        if operation.sequence == 0 {
            return Err(SelfError::SiggraphActionInvalidKeyRevocation);
        }

        let mut revoked_key = node.unwrap().as_ref().borrow_mut();

        if revoked_key.ra != 0 {
            return Err(SelfError::SiggraphActionKeyAlreadyRevoked);
        }

        revoked_key.ra = action.effective_from;

        let signing_key_id = operation.signing_key_ids().unwrap()[0].clone();
        let signing_key = self.keys.get(&signing_key_id).ok_or_else(|| SelfError::SiggraphActionSigningKeyInvalid)?;

        if signing_key.borrow().typ == KeyRole::Recovery {
            // if the signing key was a recovery key, then nuke all existing keys
            let mut root = self.root.as_ref().unwrap().as_ref().borrow_mut();
            root.ra = action.effective_from;

            for child_node in root.collect() {
                let mut child_key = child_node.as_ref().borrow_mut();
                if child_key.ra != 0 {
                    child_key.ra = action.effective_from;
                }
            }
        } else {
            // revoke all child keys created after the revocation takes effect
            for child_node in revoked_key.collect() {
                let mut child_key = child_node.as_ref().borrow_mut();

                if child_key.created_at().unwrap() < action.effective_from().unwrap() {
                    child_key.ra = action.effective_from;
                }
            }
        }

        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn new() {

    }

}