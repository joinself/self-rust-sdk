use crate::error::SelfError;
use crate::keypair::{KeyPair, KeyPairType};
use crate::siggraph::action::{Action, ActionType, KeyRole};
use crate::siggraph::node::Node;
use crate::siggraph::operation::Operation;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use chrono::{DateTime, Utc};

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
        operation.validate()?;

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

                drop(signing_key);
            }
        }

        // run actions
        for action in &operation.actions {
            action.validate()?;

            if operation.sequence > 0 && action.effective_from().is_some() {
                if action.effective_from().unwrap() < self.root.as_ref().unwrap().borrow().created_at().unwrap() {
                    return Err(SelfError::SiggraphActionEffectiveFromInvalid);
                }
            }

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
                println!("revoked at recovery key {}", (*recovery_key).borrow().revoked_at().unwrap());
                return Err(SelfError::SiggraphOperationNoValidRecoveryKey);
            }

            // add the operation to the history
            self.operations.push(operation.clone());
            self.signatures.insert(
                operation.signatures().first().unwrap().signature.clone(),
                operation.sequence as usize,
            );
        }

        return Ok(());
    }

    pub fn is_key_valid(&self, kid: &str, at: DateTime<Utc>) -> bool {
        println!(">>> get key");
        let k = match self.keys.get(kid) {
            Some(k) => k.clone(),
            None => return false,
        };

        let k = k.borrow();

        if k.created_at().is_none() {
            println!(">>> created at none");
            return false;
        }

        if k.created_at().unwrap() == at && k.revoked_at().is_none() || k.created_at().unwrap() < at && k.revoked_at().is_none() {
            return true;
        }

        if k.revoked_at().is_none() {
            println!(">>> revoked at none");
            return false;
        }

        if k.created_at().unwrap() == at && k.revoked_at().unwrap() > at || k.created_at().unwrap() < at && k.revoked_at().unwrap() > at {
            return true;
        }

        println!(">>> fallthrough");

        return false;
    }

    fn add(&mut self, operation: &Operation, action: &Action) -> Result<(), SelfError> {
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
            KeyRole::Device => {
                KeyPair::from_public_key(&action.kid, KeyPairType::Ed25519, &public_key)
            }
            KeyRole::Recovery => {
                KeyPair::from_public_key(&action.kid, KeyPairType::Ed25519, &public_key)
            }
        }?;

        let node = Rc::new(RefCell::new(Node {
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
            }
            KeyRole::Recovery => {
                // check there are only one active recovery keys
                if self.recovery_key.is_some() {
                    if self.recovery_key.as_ref().unwrap().borrow().ra == 0 {
                        return Err(SelfError::SiggraphActionMultipleActiveRecoveryKeys);
                    }
                }

                self.recovery_key = Some(node.clone());
            }
        };

        let kid = node.borrow().kid.clone();
        self.keys.insert(kid.clone(), node.clone());

        let signing_key_id = operation.signing_key_ids().unwrap()[0].clone();

        if operation.sequence == 0 && signing_key_id == kid {
            self.root = Some(node.clone());
        } else {
            let parent = self
                .keys
                .get(&signing_key_id)
                .ok_or_else(|| SelfError::SiggraphActionSigningKeyInvalid)?;

            node.as_ref().borrow_mut().incoming.push(parent.clone());
            parent.as_ref().borrow_mut().outgoing.push(node.clone());
        }

        return Ok(());
    }

    fn revoke(&mut self, operation: &Operation, action: &Action) -> Result<(), SelfError> {
        // if this is the first (root) operation, then key revocation is not permitted
        if operation.sequence == 0 {
            return Err(SelfError::SiggraphActionInvalidKeyRevocation);
        }

        // lookup the key the action refers to
        let node = self
            .keys
            .get(&action.kid)
            .ok_or_else(|| SelfError::SiggraphActionKeyMissing)?
            .clone();

        // if the key has been revoked, then fail
        let mut revoked_key = node.as_ref().borrow_mut();
        if revoked_key.ra != 0 {
            return Err(SelfError::SiggraphActionKeyAlreadyRevoked);
        }

        revoked_key.ra = action.effective_from;

        // drop mutable reference to make borrow checker happy for
        // when we iterate over child nodes later
        drop(revoked_key);

        let signing_key_id = operation.signing_key_ids().unwrap()[0].clone();

        let node = self
            .keys
            .get(&signing_key_id)
            .ok_or_else(|| SelfError::SiggraphActionSigningKeyInvalid)?
            .clone();

        if node.as_ref().borrow().typ == KeyRole::Recovery {
            // if the signing key was a recovery key, then nuke all existing keys
            let mut root = self.root.as_ref().unwrap().as_ref().borrow_mut();
            root.ra = action.effective_from;

            for child_node in root.collect() {
                let mut child_key = child_node.as_ref().borrow_mut();
                if child_key.ra != 0 {
                    child_key.ra = action.effective_from;
                }
            }

            return Ok(());
        }

        // get and re-borrow revoked key as immutable ref this time
        let node = self
            .keys
            .get(&action.kid)
            .ok_or_else(|| SelfError::SiggraphActionSigningKeyInvalid)?
            .clone();

        let revoked_key = node.as_ref().borrow();

        // revoke all child keys created after the revocation takes effect
        for child_node in revoked_key.collect() {
            let mut child_key = child_node.as_ref().borrow_mut();

            if child_key.created_at().unwrap() < action.effective_from().unwrap() {
                child_key.ra = action.effective_from;
            }
        }

        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use std::{collections::HashMap};

    use crate::{
        error::SelfError,
        keypair::KeyPair,
        siggraph::action::{Action, ActionType, KeyRole},
        siggraph::graph::SignatureGraph,
        siggraph::operation::Operation,
    };

    struct TestOperation {
        signer: String,
        operation: Operation,
        error: Result<(), SelfError>,
    }

    fn test_keys() -> HashMap<String, KeyPair> {
        let mut keys = HashMap::new();

        for id in 0..10 {
            let kp = KeyPair::new(crate::keypair::KeyPairType::Ed25519);
            keys.insert(id.to_string(), kp);
        }

        return keys;
    }

    fn test_operation(
        keys: &HashMap<String, KeyPair>,
        signer: &str,
        operation: &mut Operation,
    ) -> String {
        let sk = keys.get(signer).unwrap();
        operation.sign(&sk).unwrap();

        return operation
            .signatures()
            .first()
            .as_ref()
            .unwrap()
            .signature
            .clone();
    }

    fn test_execute(keys: &HashMap<String, KeyPair>, test_history: &mut Vec<TestOperation>) -> SignatureGraph {
        let mut sg = SignatureGraph::new(Vec::new()).unwrap();

        let mut previous = String::from("-");

        for test_op in test_history {
            if test_op.operation.previous == "previous" {
                test_op.operation.previous = previous;
            }

            previous = test_operation(keys, &test_op.signer, &mut test_op.operation);

            let result = sg.execute(&test_op.operation);
            if test_op.error.is_err() {
                assert_eq!(
                    result.err().unwrap(),
                    *test_op.error.as_ref().err().unwrap()
                );
            } else {
                if result.is_err() {
                    println!("{:?}", result);
                }
                assert_eq!(test_op.error.is_ok(), result.is_ok());
            }
        }

        return sg;
    }

    #[test]
    fn execute_valid_single_entry() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![TestOperation {
            signer: String::from("0"),
            operation: Operation::new(
                0,
                "-",
                now,
                vec![
                    Action {
                        kid: keys["0"].id(),
                        did: Some(String::from("device-1")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now,
                        key: Some(base64::encode_config(
                            keys["0"].public(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    },
                    Action {
                        kid: keys["1"].id(),
                        did: None,
                        role: Some(KeyRole::Recovery),
                        action: ActionType::KeyAdd,
                        effective_from: now,
                        key: Some(base64::encode_config(
                            keys["1"].public(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    },
                ],
            ),
            error: Ok(()),
        }];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_valid_multi_entry() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![Action {
                        kid: keys["2"].id(),
                        did: Some(String::from("device-2")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now + 1,
                        key: Some(base64::encode_config(
                            keys["2"].public(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    2,
                    "previous",
                    now + 2,
                    vec![Action {
                        kid: keys["3"].id(),
                        did: Some(String::from("device-3")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now + 2,
                        key: Some(base64::encode_config(
                            keys["3"].public(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("2"),
                operation: Operation::new(
                    3,
                    "previous",
                    now + 3,
                    vec![Action {
                        kid: keys["4"].id(),
                        did: Some(String::from("device-4")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now + 3,
                        key: Some(base64::encode_config(
                            keys["4"].public(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("3"),
                operation: Operation::new(
                    4,
                    "previous",
                    now + 4,
                    vec![
                        Action {
                            kid: keys["2"].id(),
                            did: None,
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyRevoke,
                            effective_from: now + 4,
                            key: None,
                        },
                        Action {
                            kid: keys["5"].id(),
                            did: Some(String::from("device-2")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now + 4,
                            key: Some(base64::encode_config(
                                keys["5"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_valid_multi_entry_with_recovery() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![Action {
                        kid: keys["2"].id(),
                        did: Some(String::from("device-2")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now + 1,
                        key: Some(base64::encode_config(
                            keys["2"].public(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    2,
                    "previous",
                    now + 2,
                    vec![Action {
                        kid: keys["3"].id(),
                        did: Some(String::from("device-3")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now + 2,
                        key: Some(base64::encode_config(
                            keys["3"].public(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("2"),
                operation: Operation::new(
                    3,
                    "previous",
                    now + 3,
                    vec![Action {
                        kid: keys["4"].id(),
                        did: Some(String::from("device-4")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now + 3,
                        key: Some(base64::encode_config(
                            keys["4"].public(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("3"),
                operation: Operation::new(
                    4,
                    "previous",
                    now + 4,
                    vec![
                        Action {
                            kid: keys["2"].id(),
                            did: None,
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyRevoke,
                            effective_from: now + 4,
                            key: None,
                        },
                        Action {
                            kid: keys["5"].id(),
                            did: Some(String::from("device-2")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now + 4,
                            key: Some(base64::encode_config(
                                keys["5"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("1"),
                operation: Operation::new(
                    5,
                    "previous",
                    now + 5,
                    vec![
                        Action {
                            did: None,
                            kid: keys["1"].id(),
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyRevoke,
                            effective_from: now + 5,
                            key: None,
                        },
                        Action {
                            kid: keys["6"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now + 5,
                            key: Some(base64::encode_config(
                                keys["6"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["7"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 5,
                            key: Some(base64::encode_config(
                                keys["7"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_sequence_ordering() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    3,
                    "previous",
                    now + 1,
                    vec![Action {
                        kid: keys["2"].id(),
                        did: Some(String::from("device-2")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now + 1,
                        key: Some(base64::encode_config(
                            keys["2"].public(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
                ),
                error: Err(SelfError::SiggraphOperationSequenceOutOfOrder),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_timestamp() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    now,
                    vec![Action {
                        kid: keys["2"].id(),
                        did: Some(String::from("device-2")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now,
                        key: Some(base64::encode_config(
                            keys["2"].public(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
                ),
                error: Err(SelfError::SiggraphOperationTimestampInvalid),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_previous_signature() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "invalid-previous",
                    now + 1,
                    vec![Action {
                        kid: keys["2"].id(),
                        did: Some(String::from("device-2")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now + 1,
                        key: Some(base64::encode_config(
                            keys["2"].public(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
                ),
                error: Err(SelfError::SiggraphOperationPreviousSignatureInvalid),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_duplicate_key_identifier() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![Action {
                        kid: keys["0"].id(),
                        did: Some(String::from("device-2")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now + 1,
                        key: Some(base64::encode_config(
                            keys["2"].public(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
                ),
                error: Err(SelfError::SiggraphActionKeyDuplicate),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_no_active_keys() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![
                        Action {
                        kid: keys["0"].id(),
                        did: None,
                        role: None,
                        action: ActionType::KeyRevoke,
                        effective_from: now +1,
                        key: None,
                    }
                    ],
                ),
                error: Err(SelfError::SiggraphOperationNoValidKeys),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_no_active_recovery_keys() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![
                        Action {
                        kid: keys["1"].id(),
                        did: None,
                        role: None,
                        action: ActionType::KeyRevoke,
                        effective_from: now +1,
                        key: None,
                    }
                    ],
                ),
                error: Err(SelfError::SiggraphOperationNoValidRecoveryKey),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_multiple_active_recovery_keys() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![
                        Action {
                            kid: keys["2"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["2"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Err(SelfError::SiggraphActionMultipleActiveRecoveryKeys),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_multiple_active_device_keys() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![
                        Action {
                            kid: keys["2"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["2"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Err(SelfError::SiggraphActionMultipleActiveDeviceKeys),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_revoked_key_creation() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: Some(String::from("device-2")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["2"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["2"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: None,
                            action: ActionType::KeyRevoke,
                            effective_from: now + 1,
                            key: None,
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("1"),
                operation: Operation::new(
                    2,
                    "previous",
                    now + 2,
                    vec![
                        Action {
                            kid: keys["3"].id(),
                            did: Some(String::from("device-3")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now + 2,
                            key: Some(base64::encode_config(
                                keys["3"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Err(SelfError::SiggraphOperationSignatureKeyRevoked),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_signing_key() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("3"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![
                        Action {
                            kid: keys["1"].id(),
                            did: Some(String::from("device-2")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Err(SelfError::SiggraphOperationSigningKeyInvalid),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_recovery_no_revoke() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("1"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![
                        Action {
                            kid: keys["2"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["2"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["3"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["3"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Err(SelfError::SiggraphOperationAccountRecoveryActionInvalid),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_empty_actions() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 2,
                    vec![
                    ],
                ),
                error: Err(SelfError::SiggraphOperationNOOP),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_already_revoked_key() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: Some(String::from("device-2")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["2"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["2"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: None,
                            action: ActionType::KeyRevoke,
                            effective_from: now + 1,
                            key: None,
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    2,
                    "previous",
                    now + 2,
                    vec![
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: None,
                            action: ActionType::KeyRevoke,
                            effective_from: now + 2,
                            key: None,
                        },
                    ],
                ),
                error: Err(SelfError::SiggraphActionKeyAlreadyRevoked),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_key_reference() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: Some(String::from("device-2")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["2"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["2"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![
                        Action {
                            kid: keys["9"].id(),
                            did: None,
                            role: None,
                            action: ActionType::KeyRevoke,
                            effective_from: now + 1,
                            key: None,
                        },
                    ],
                ),
                error: Err(SelfError::SiggraphActionKeyMissing),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_root_operation_key_revocation() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: Some(String::from("device-2")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["2"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["2"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["0"].id(),
                            did: None,
                            role: None,
                            action: ActionType::KeyRevoke,
                            effective_from: now,
                            key: None,
                        },
                    ],
                ),
                error: Err(SelfError::SiggraphActionInvalidKeyRevocation),
            }
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_operation_signature() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: Some(String::from("device-2")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["9"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["2"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["2"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("1"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![
                        Action {
                            kid: keys["3"].id(),
                            did: Some(String::from("device-3")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["3"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Err(SelfError::MessageSignatureInvalid),
            }
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_operation_signature_root() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["9"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Err(SelfError::MessageSignatureInvalid),
            }
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_revocation_before_root_operation_timestamp() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now,
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: Some(String::from("device-2")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now,
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["2"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now + 1,
                            key: Some(base64::encode_config(
                                keys["2"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    now + 1,
                    vec![
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: None,
                            action: ActionType::KeyRevoke,
                            effective_from: now - 100,
                            key: None,
                        },
                    ],
                ),
                error: Err(SelfError::SiggraphActionEffectiveFromInvalid),
            }
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn is_key_valid() {
        let now = Utc::now();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    0,
                    "-",
                    now.timestamp(),
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from: now.timestamp(),
                            key: Some(base64::encode_config(
                                keys["0"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                        Action {
                            kid: keys["1"].id(),
                            did: None,
                            role: Some(KeyRole::Recovery),
                            action: ActionType::KeyAdd,
                            effective_from: now.timestamp(),
                            key: Some(base64::encode_config(
                                keys["1"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(
                    1,
                    "previous",
                    (now + chrono::Duration::seconds(1)).timestamp(),
                    vec![
                        Action {
                            kid: keys["0"].id(),
                            did: None,
                            role: None,
                            action: ActionType::KeyRevoke,
                            effective_from: (now + chrono::Duration::seconds(1)).timestamp(),
                            key: None,
                        },
                        Action {
                            kid: keys["2"].id(),
                            did: Some(String::from("device-1")),
                            role: Some(KeyRole::Device),
                            action: ActionType::KeyAdd,
                            effective_from:  (now + chrono::Duration::seconds(1)).timestamp(),
                            key: Some(base64::encode_config(
                                keys["2"].public(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            }
        ];

        let sg = test_execute(&keys, &mut test_history);

        assert!(sg.is_key_valid(&keys["1"].id(), now));
        assert!(!sg.is_key_valid(&keys["1"].id(), now + chrono::Duration::seconds(1)));
        
    }
}


