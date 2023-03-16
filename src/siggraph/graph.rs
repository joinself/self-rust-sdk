use crate::error::SelfError;
use crate::keypair::signing::PublicKey;
use crate::keypair::Algorithm;
use crate::siggraph::node::Node;
use crate::siggraph::schema::schema::{
    Action, CreateKey, Operation, Recover, RevokeKey, Signature, SignatureHeader, SignedOperation,
};

use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use chrono::{DateTime, Utc};

use super::schema::schema::{root_as_signed_operation, Actionable};
use super::{KeyAlgorithm, KeyRole};

pub struct SignatureGraph<'a> {
    id: Option<Vec<u8>>,
    root: Option<Rc<RefCell<Node>>>,
    keys: HashMap<Vec<u8>, Rc<RefCell<Node>>>,
    hashes: HashMap<Vec<u8>, usize>,
    operations: Vec<Operation<'a>>,
    recovery_key: Option<Rc<RefCell<Node>>>,
    sig_buf: Vec<u8>,
}

impl<'a> SignatureGraph<'_> {
    pub fn new(history: Vec<Vec<u8>>) -> Result<SignatureGraph<'a>, SelfError> {
        let mut sg = SignatureGraph {
            id: None,
            root: None,
            keys: HashMap::new(),
            hashes: HashMap::new(),
            operations: Vec::new(),
            recovery_key: None,
            sig_buf: vec![0; 96],
        };

        for operation in &history {
            sg.execute_operation(operation, true)?
        }

        return Ok(sg);
    }

    pub fn load(history: Vec<Vec<u8>>) -> Result<SignatureGraph<'a>, SelfError> {
        let mut sg = SignatureGraph {
            id: None,
            root: None,
            keys: HashMap::new(),
            hashes: HashMap::new(),
            operations: Vec::new(),
            recovery_key: None,
            sig_buf: vec![0; 96],
        };

        for operation in &history {
            sg.execute_operation(operation, false)?
        }

        return Ok(sg);
    }

    pub fn execute(&mut self, operation: &[u8]) -> Result<(), SelfError> {
        self.execute_operation(operation, true)
    }

    fn execute_operation(&mut self, operation: &[u8], verify: bool) -> Result<(), SelfError> {
        let signed_op = root_as_signed_operation(operation)
            .map_err(|_| SelfError::SiggraphOperationDecodingInvalid)?;

        let op_bytes = signed_op
            .operation()
            .ok_or_else(|| SelfError::SiggraphOperationDecodingInvalid)?;

        let op = flatbuffers::root::<Operation<'_>>(op_bytes)
            .map_err(|_| SelfError::SiggraphOperationDecodingInvalid)?;

        let op_hash = crate::crypto::hash::blake2b(op_bytes);

        let mut signers = HashSet::new();

        if verify {
            // copy the operation hash to our temporary buffer we
            // will use to calculate signatures for each signer
            self.sig_buf[32..].copy_from_slice(&op_hash);

            self.validate_operation(&signed_op, &op, &mut signers)?;

            if op.sequence() > 0 {
                self.authorize_operation(&op, &signers)?;
            }
        }

        let actions = match op.actions() {
            Some(actions) => actions,
            None => return Err(SelfError::SiggraphOperationNOOP),
        };

        for action in actions {
            match action.actionable_type() {
                Actionable::CreateKey => {
                    let create_key = action.actionable_as_create_key().unwrap();
                    self.create_key(&op, &create_key, &signers)?;
                }
                Actionable::RevokeKey => {}
                Actionable::Recover => {}
                _ => return Err(SelfError::SiggraphActionUnknown),
            }
        }

        return Ok(());
    }

    fn validate_operation(
        &mut self,
        signed_op: &SignedOperation,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        // check the sequence is in order and version of the operation are correct
        if op.sequence() != self.operations.len() as u32 {
            return Err(SelfError::SiggraphOperationSequenceOutOfOrder);
        }

        if op.version() != 2 {
            return Err(SelfError::SiggraphOperationVersionInvalid);
        }

        if op.actions().is_none() || op.actions().is_some_and(|a| a.len() < 1) {
            return Err(SelfError::SiggraphOperationNOOP);
        }

        let signatures = match signed_op.signatures() {
            Some(signatures) => signatures,
            None => return Err(SelfError::SiggraphOperationNotSigned),
        };

        if op.sequence() == 0 {
            // check the root operation contains a signature using the secret key
            // used to generate the identifier for the account, as well as a signature
            // by the device and recovery key
            if signatures.len() < 3 {
                return Err(SelfError::SiggraphOperationNotEnoughSigners);
            }

            let previous = match op.previous() {
                Some(previous) => previous,
                None => return Err(SelfError::SiggraphOperationPreviousHashMissing),
            };

            let hash_index = match self.hashes.get(previous) {
                Some(hash_index) => *hash_index,
                None => return Err(SelfError::SiggraphOperationPreviousHashMissing),
            };

            // check the provided previous hash matches the hash of the last operation
            if hash_index != self.operations.len() - 1 {
                return Err(SelfError::SiggraphOperationPreviousHashInvalid);
            }

            // check the timestamp is greater than the previous operations
            if self.operations[self.operations.len() - 1].timestamp() == op.timestamp()
                || self.operations[self.operations.len() - 1].timestamp() > op.timestamp()
            {
                return Err(SelfError::SiggraphOperationTimestampInvalid);
            }
        }

        for (i, sig) in signatures.iter().enumerate() {
            let hdr_bytes = match sig.header() {
                Some(hdr_bytes) => hdr_bytes,
                None => return Err(SelfError::SiggraphOperationSignatureHeaderMissing),
            };

            let signature = match sig.signature() {
                Some(signature) => signature,
                None => return Err(SelfError::SiggraphOperationSignatureInvalid),
            };

            let hdr_hash = crate::crypto::hash::blake2b(hdr_bytes);
            self.sig_buf[64..].copy_from_slice(&hdr_hash);

            let hdr = flatbuffers::root::<SignatureHeader<'_>>(hdr_bytes)
                .map_err(|_| SelfError::SiggraphOperationSignatureHeaderInvalid)?;

            let signer = match hdr.signer() {
                Some(signer) => signer,
                None => return Err(SelfError::SiggraphOperationSignatureSignerMissing),
            };

            if op.sequence() == 0 && i == 0 {
                // if this is the first signature on the first operation
                // this is the key used as an identifier for the account.
                // copy it to the sig buffer for verifying signatures
                self.id = Some(signer.to_vec());
                self.sig_buf.copy_from_slice(signer);
            }

            // TODO store signature alg in header
            let signers_pk = PublicKey::from_bytes(signer, crate::keypair::Algorithm::Ed25519)?;
            if !signers_pk.verify(&self.sig_buf, signature) {
                return Err(SelfError::SiggraphOperationSignatureInvalid);
            };

            signers.insert(signer.to_vec());
        }

        return Ok(());
    }

    fn authorize_operation(
        &self,
        op: &Operation,
        signers: &HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        let mut authorized = false;

        for signer in signers {
            let signing_key = match self.keys.get(signer) {
                Some(signing_key) => signing_key,
                None => continue,
            };

            let created_at = (*signing_key).as_ref().borrow().ca;
            let revoked_at = (*signing_key).as_ref().borrow().ra;

            if op.timestamp() < created_at {
                return Err(SelfError::SiggraphOperationSignatureKeyRevoked);
            }

            // check the signign key hasn't been revoked before the operation
            if revoked_at > 0 && op.timestamp() > revoked_at {
                return Err(SelfError::SiggraphOperationSignatureKeyRevoked);
            }

            authorized = true;
            drop(signing_key);
        }

        if !authorized {
            return Err(SelfError::SiggraphOperationSigningKeyInvalid);
        }

        return Ok(());
    }

    fn create_key(
        &mut self,
        op: &Operation,
        ck: &CreateKey,
        signers: &HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        let key = match ck.key() {
            Some(key) => key,
            None => return Err(SelfError::SiggraphActionKeyMissing),
        };

        if self.id.as_ref().is_some_and(|id| id.eq(key)) {
            return Err(SelfError::SiggraphActionKeyDuplicate);
        }

        if signers.get(key).is_none() {
            return Err(SelfError::SiggraphOperationNotEnoughSigners);
        }

        if self.keys.get(key).is_some() {
            return Err(SelfError::SiggraphActionKeyDuplicate);
        }

        if op.sequence() > 0 && ck.effective_from() < self.operations[0].timestamp() {
            return Err(SelfError::SiggraphOperationTimestampInvalid);
        }

        let node = Rc::new(RefCell::new(Node {
            typ: ck.role(),
            seq: op.sequence(),
            ca: op.timestamp(),
            ra: 0,
            pk: PublicKey::from_bytes(key, Algorithm::Ed25519)?,
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }));

        if ck.role() == KeyRole::Recovery
            && self
                .recovery_key
                .as_ref()
                .is_some_and(|rk| rk.as_ref().borrow().ra == 0)
        {
            return Err(SelfError::SiggraphActionMultipleActiveRecoveryKeys);
        }

        self.keys.insert(key.to_vec(), node.clone());

        for signer in signers {
            if op.sequence() == 0 && self.root.is_none() {
                if key.eq(signer) && !self.id.as_ref().is_some_and(|id| key.eq(&*id)) {
                    self.root = Some(node.clone());
                }
                continue;
            }

            if key.eq(signer) {
                // this is a self signed signature, skip it
                continue;
            }

            let parent = self
                .keys
                .get(key)
                .ok_or_else(|| SelfError::SiggraphActionSigningKeyInvalid)?;

            node.as_ref().borrow_mut().incoming.push(parent.clone());
            parent.as_ref().borrow_mut().outgoing.push(node.clone());
        }

        return Ok(());
    }

    fn revoke_key(&mut self, op: &Operation, rk: &RevokeKey) -> Result<(), SelfError> {
        let key = match rk.key() {
            Some(key) => key,
            None => return Err(SelfError::SiggraphActionKeyMissing),
        };

        let node = match self.keys.get(key) {
            Some(node) => node,
            None => return Err(SelfError::SiggraphActionKeyMissing),
        };

        // if this is the first (root) operation, then key revocation is not permitted
        if op.sequence() == 0 {
            return Err(SelfError::SiggraphActionInvalidKeyRevocation);
        }

        // if the key has been revoked, then fail
        if node.as_ref().borrow().ra != 0 {
            return Err(SelfError::SiggraphActionKeyAlreadyRevoked);
        }

        // check if the effective from timestamp is after the first operation
        if rk.effective_from() < self.operations[0].timestamp() {
            return Err(SelfError::SiggraphOperationTimestampInvalid);
        }

        node.borrow_mut().ra = rk.effective_from();

        // get and re-borrow revoked key as immutable ref this time
        let node = self
            .keys
            .get(key)
            .ok_or_else(|| SelfError::SiggraphActionSigningKeyInvalid)?
            .clone();

        let revoked_key = node.as_ref().borrow();

        // revoke all child keys created after the revocation takes effect
        for child_node in revoked_key.collect() {
            let mut child_key = child_node.as_ref().borrow_mut();

            if child_key.ca >= rk.effective_from() {
                child_key.ra = rk.effective_from();
            }
        }

        return Ok(());
    }

    fn recover(
        &mut self,
        op: &Operation,
        rc: &Recover,
        signers: &HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        // if this is the first (root) operation, then recovery is not permitted
        if op.sequence() == 0 {
            return Err(SelfError::SiggraphActionInvalidKeyRevocation);
        }

        if rc.effective_from() < self.operations[0].timestamp() {
            return Err(SelfError::SiggraphOperationTimestampInvalid);
        }

        let mut signed_by_recovery_key = false;

        for signer in signers {
            if self
                .recovery_key
                .as_ref()
                .is_some_and(|rk| rk.as_ref().borrow().pk.eq(signer))
            {
                signed_by_recovery_key = true;
                break;
            }
        }

        if !signed_by_recovery_key {
            return Err(SelfError::SiggraphOperationAccountRecoveryActionInvalid);
        }

        self.root.as_ref().unwrap().borrow_mut().ra = rc.effective_from();

        // if the signing key was a recovery key, then nuke all existing keys
        let mut root = self.root.as_ref().unwrap().as_ref().borrow_mut();
        root.ra = rc.effective_from();

        for child_node in root.collect() {
            let mut child_key = child_node.as_ref().borrow_mut();
            if child_key.ra != 0 {
                child_key.ra = rc.effective_from();
            }
        }

        return Ok(());
    }

    pub fn is_key_valid(&self, id: &[u8], at: i64) -> bool {
        let k = match self.keys.get(id) {
            Some(k) => k.as_ref(),
            None => return false,
        }
        .borrow();

        if k.ca == 0 {
            return false;
        }

        if k.ca == at && k.ra == 0 || k.ca < at && k.ra == 0 {
            return true;
        }

        if k.ra == 0 {
            return false;
        }

        if k.ca == at && k.ra > at || k.ca < at && k.ra > at {
            return true;
        }

        return false;
    }

    fn action_by_key(&self, op: &Operation, key: &[u8]) -> Option<Action<'a>> {
        let actions = match op.actions() {
            Some(actions) => actions,
            None => return None,
        };

        for action in actions {
            match action.actionable_type() {
                Actionable::CreateKey => {}
                Actionable::RevokeKey => {}
                Actionable::Recover => {}
                _ => return None,
            }
        }

        return None;
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use std::collections::HashMap;

    use crate::{error::SelfError, keypair::signing::KeyPair, siggraph::graph::SignatureGraph};

    struct TestOperation {
        signers: Vec<Vec<u8>>,
        operation: Operation,
        error: Result<(), SelfError>,
    }

    fn test_keys() -> HashMap<String, KeyPair> {
        let mut keys = HashMap::new();

        for id in 0..10 {
            let kp = KeyPair::new();
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
        operation.sign(sk).unwrap();

        return operation
            .signatures()
            .first()
            .as_ref()
            .unwrap()
            .signature
            .clone();
    }

    fn test_execute(
        keys: &HashMap<String, KeyPair>,
        test_history: &mut Vec<TestOperation>,
    ) -> SignatureGraph {
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
                            keys["0"].public().to_vec(),
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
                            keys["1"].public().to_vec(),
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                            keys["2"].public().to_vec(),
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
                            keys["3"].public().to_vec(),
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
                            keys["4"].public().to_vec(),
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
                                keys["5"].public().to_vec(),
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                            keys["2"].public().to_vec(),
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
                            keys["3"].public().to_vec(),
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
                            keys["4"].public().to_vec(),
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
                                keys["5"].public().to_vec(),
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
                                keys["6"].public().to_vec(),
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
                                keys["7"].public().to_vec(),
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                            keys["2"].public().to_vec(),
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                            keys["2"].public().to_vec(),
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                            keys["2"].public().to_vec(),
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                            keys["2"].public().to_vec(),
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                        did: None,
                        role: None,
                        action: ActionType::KeyRevoke,
                        effective_from: now,
                        key: None,
                    }],
                ),
                error: Err(SelfError::SiggraphOperationSignatureKeyRevoked),
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                        kid: keys["1"].id(),
                        did: None,
                        role: None,
                        action: ActionType::KeyRevoke,
                        effective_from: now + 1,
                        key: None,
                    }],
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                        did: None,
                        role: Some(KeyRole::Recovery),
                        action: ActionType::KeyAdd,
                        effective_from: now + 1,
                        key: Some(base64::encode_config(
                            keys["2"].public().to_vec(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                        did: Some(String::from("device-1")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now,
                        key: Some(base64::encode_config(
                            keys["2"].public().to_vec(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                                keys["2"].public().to_vec(),
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
                        kid: keys["1"].id(),
                        did: None,
                        role: None,
                        action: ActionType::KeyRevoke,
                        effective_from: now + 1,
                        key: None,
                    }],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("1"),
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
                            keys["3"].public().to_vec(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                    vec![Action {
                        kid: keys["1"].id(),
                        did: Some(String::from("device-2")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now + 1,
                        key: Some(base64::encode_config(
                            keys["1"].public().to_vec(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                                keys["2"].public().to_vec(),
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
                                keys["3"].public().to_vec(),
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
            TestOperation {
                signer: String::from("0"),
                operation: Operation::new(1, "previous", now + 2, vec![]),
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                                keys["2"].public().to_vec(),
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
                        kid: keys["1"].id(),
                        did: None,
                        role: None,
                        action: ActionType::KeyRevoke,
                        effective_from: now + 1,
                        key: None,
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
                        kid: keys["1"].id(),
                        did: None,
                        role: None,
                        action: ActionType::KeyRevoke,
                        effective_from: now + 2,
                        key: None,
                    }],
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                                keys["2"].public().to_vec(),
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
                        kid: keys["9"].id(),
                        did: None,
                        role: None,
                        action: ActionType::KeyRevoke,
                        effective_from: now + 1,
                        key: None,
                    }],
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
                            keys["0"].public().to_vec(),
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
                            keys["1"].public().to_vec(),
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
                            keys["2"].public().to_vec(),
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
        }];

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
                                keys["0"].public().to_vec(),
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
                                keys["9"].public().to_vec(),
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
                                keys["2"].public().to_vec(),
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
                    vec![Action {
                        kid: keys["3"].id(),
                        did: Some(String::from("device-3")),
                        role: Some(KeyRole::Device),
                        action: ActionType::KeyAdd,
                        effective_from: now + 1,
                        key: Some(base64::encode_config(
                            keys["3"].public().to_vec(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    }],
                ),
                error: Err(SelfError::MessageSignatureInvalid),
            },
        ];

        test_execute(&keys, &mut test_history);
    }

    #[test]
    fn execute_invalid_operation_signature_root() {
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
                            keys["9"].public().to_vec(),
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
                            keys["1"].public().to_vec(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                    },
                ],
            ),
            error: Err(SelfError::MessageSignatureInvalid),
        }];

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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                                keys["2"].public().to_vec(),
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
                        kid: keys["1"].id(),
                        did: None,
                        role: None,
                        action: ActionType::KeyRevoke,
                        effective_from: now - 100,
                        key: None,
                    }],
                ),
                error: Err(SelfError::SiggraphActionEffectiveFromInvalid),
            },
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
                                keys["0"].public().to_vec(),
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
                                keys["1"].public().to_vec(),
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
                            effective_from: (now + chrono::Duration::seconds(1)).timestamp(),
                            key: Some(base64::encode_config(
                                keys["2"].public().to_vec(),
                                base64::URL_SAFE_NO_PAD,
                            )),
                        },
                    ],
                ),
                error: Ok(()),
            },
        ];

        let sg = test_execute(&keys, &mut test_history);

        assert!(sg.is_key_valid(&keys["0"].id(), now));
        assert!(!sg.is_key_valid(&keys["0"].id(), now + chrono::Duration::seconds(1)));
        assert!(!sg.is_key_valid(&keys["0"].id(), now + chrono::Duration::seconds(2)));
        assert!(!sg.is_key_valid(&keys["0"].id(), now - chrono::Duration::seconds(1)));
        assert!(sg.is_key_valid(&keys["2"].id(), now + chrono::Duration::seconds(1)));
        assert!(sg.is_key_valid(&keys["2"].id(), now + chrono::Duration::seconds(2)));
        assert!(!sg.is_key_valid(&keys["0"].id(), now - chrono::Duration::seconds(1)));
    }
}
