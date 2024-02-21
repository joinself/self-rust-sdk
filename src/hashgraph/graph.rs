use flatbuffers::{ForwardsUOffset, Vector};
use http::header;

use crate::error::SelfError;
use crate::hashgraph::{node::Node, node::RoleEntry, operation::OperationBuilder};
use crate::keypair::signing::PublicKey;
use crate::keypair::Algorithm;
use crate::protocol::hashgraph::{
    root_as_signed_operation, Action, Actionable, Description, Operation, Role, Signature,
    SignatureHeader, SignedOperation,
};

use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

pub struct Hashgraph {
    identifier: Option<Vec<u8>>,
    controller: Option<Vec<u8>>,
    root: Option<Rc<RefCell<Node>>>,
    operations: Vec<Vec<u8>>,
    keys: HashMap<Vec<u8>, Rc<RefCell<Node>>>,
    hashes: HashMap<Vec<u8>, usize>,
    sig_buf: Vec<u8>,
}

impl Hashgraph {
    /// creates a new empty hashgraph
    pub fn new() -> Hashgraph {
        Hashgraph {
            identifier: None,
            controller: None,
            root: None,
            keys: HashMap::new(),
            hashes: HashMap::new(),
            operations: Vec::new(),
            sig_buf: vec![0; 97],
        }
    }

    /// loads a hashgraph from a collection of operations. validation of signatures can optionally be skipped
    pub fn load(history: &[Vec<u8>], verify: bool) -> Result<Hashgraph, SelfError> {
        let mut sg = Hashgraph {
            identifier: None,
            controller: None,
            root: None,
            keys: HashMap::new(),
            hashes: HashMap::new(),
            operations: Vec::new(),
            sig_buf: vec![0; 97],
        };

        for operation in history {
            sg.execute_operation(operation.to_owned(), verify)?
        }

        Ok(sg)
    }

    pub fn identifier(&self) -> &[u8] {
        return self.identifier;
    }

    pub fn controller(&self) -> &[u8] {
        return self.controller;
    }

    pub fn create(&self) -> OperationBuilder {
        let mut ob = OperationBuilder::new();

        ob.sequence(self.operations.len() as u32)
            .timestamp(crate::time::unix());

        if let Some(id) = &self.id {
            ob.id(id);
        }

        if let Some(last_op) = self.operations.last() {
            // compute the hash of the last operation
            ob.previous(&crate::crypto::hash::sha3(last_op));
        }

        ob
    }

    pub fn execute(&mut self, operation: Vec<u8>) -> Result<(), SelfError> {
        self.execute_operation(operation, true)
    }

    fn collect_signers(
        &self,
        signed_op: &SignedOperation,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
        verify: bool,
    ) -> Result<(), SelfError> {
        let signatures = signed_op.signatures().unwrap();

        for (i, signature) in signatures.iter().enumerate() {
            let header_data = match signature.header() {
                Some(header_data) => header_data,
                None => return Err(SelfError::HashgraphInvalidSignatureHeader),
            };

            if verify {
                let header_hash = crate::crypto::hash::sha3(header_data);
                self.sig_buf[65..97].copy_from_slice(&header_hash);
            }

            let header = flatbuffers::root::<SignatureHeader>(header_data)
                .map_err(|_| Err(SelfError::HashgraphInvalidSignatureHeader))?;

            let signer = match header.signer() {
                Some(signer) => signer,
                None => return Err(SelfError::HashgraphInvalidSigner),
            };

            if signer.len() < 33 {
                return Err(SelfError::HashgraphInvalidSignerLength);
            }

            if verify {
                if op.sequence() == 0 && i == 0 {
                    // if this is the first signature on the first operation
                    // this is the key used as an identifier for the account.
                    // copy it to the sig buffer for verifying signatures
                    self.id = Some(signer.to_vec());
                    self.sig_buf[0..33].copy_from_slice(signer);
                }

                let signature_data = match signature.signature() {
                    Some(signature) => signature,
                    None => return Err(SelfError::HashgraphInvalidSignatureLength),
                };

                let signers_pk = PublicKey::from_bytes(signer, crate::keypair::Algorithm::Ed25519)?;
                if !signers_pk.verify(&self.sig_buf, signature_data) {
                    return Err(SelfError::HashgraphInvalidSignature);
                }

                if signers.contains(signer) {
                    return Err(SelfError::HashgraphDuplicateSigner);
                }
            }

            signers.insert(signer.to_vec());
        }

        Ok(())
    }

    fn validate_operation(
        &mut self,
        signed_op: &SignedOperation,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        if self.deactivated {
            return Err(SelfError::HashgraphDeactivated);
        }

        // check the sequence is in order and version of the operation are correct
        if op.sequence() != self.operations.len() as u32 {
            return Err(SelfError::SiggraphOperationSequenceOutOfOrder);
        }

        if op.version() != 1 {
            return Err(SelfError::SiggraphOperationVersionInvalid);
        }

        if op.actions().is_none() {
            return Err(SelfError::SiggraphOperationNOOP);
        }

        let signatures = match signed_op.signatures() {
            Some(signatures) => signatures,
            None => return Err(SelfError::HashgraphOperationsUnsigned),
        };

        if op.sequence() == 0 {
            if signatures.len() < 2 {
                return Err(SelfError::HashgraphNotEnoughSigners);
            }
        } else {
            let previous_hash = match op.previous() {
                Some(previous_hash) => previous_hash,
                None => return Err(SelfError::HashgraphInvalidPreviousHash),
            };

            let hash_index = match self.hashes.get(previous_hash) {
                Some(hash_index) => hash_index,
                None => return Err(SelfError::HashgraphInvalidPreviousHash),
            };

            if hash_index != self.operations.len() - 1 {
                return Err(SelfError::HashgraphInvalidPreviousHash);
            }

            let previous_op = self.operation(self.operations.len() - 1);

            if previous_op.timestamp() >= op.timestamp() {
                return Err(SelfError::HashgraphInvalidTimestamp);
            }
        }

        self.collect_signers(signed_op, op, signers, true)
    }

    fn authorize_operation(
        &self,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        if op.sequence() == 0 {
            return Ok(());
        }

        let mut authorized = false;

        for (_, signer) in signers.iter().enumerate() {
            let signing_key = match self.keys.get(signer) {
                Some(signing_key) => signing_key.as_ref(),
                None => continue,
            };

            // signing key must have capabilityInvocation role to update the document
            if !signing_key.has_roles(Role::CapabilityInvocation) {
                return Err(SelfError::HashgraphSignerRoleInvalid);
            }

            if op.timestamp() < signing_key.created_at {
                return Err(SelfError::HashgraphSigningKeyRevoked);
            }

            // check the signing key hasn't been revoked before the operation
            if !signing_key.revoked_at == 0 && op.timestamp() > signing_key.revoked_at {
                return Err(SelfError::HashgraphSigningKeyRevoked);
            }

            authorized = true
        }

        if !authorized {
            return Err(SelfError::HashgraphOperationUnauthorized);
        }

        Ok(())
    }

    fn execute_operation(&mut self, op: &[u8], verify: bool) -> Result<(), SelfError> {
        let mut signers = HashSet::new();

        let signed_operation = flatbuffers::root::<SignedOperation>(op)
            .map_err(|_| Err(SelfError::HashgraphOperationInvalid))?;
        let signed_operation_hash = crate::crypto::hash::sha3(op);

        let operation_data = match signed_operation.operation() {
            Some(operation_data) => operation_data,
            None => return Err(SelfError::HashgraphOperationInvalid),
        };

        let operation = flatbuffers::root::<Operation>(operation_data)
            .map_err(|_| Err(SelfError::HashgraphOperationInvalid))?;

        if operation.actions().is_none() {
            return Err(SelfError::HashgraphOperationNOOP);
        }

        if verify {
            let operation_hash = crate::crypto::hash::sha3(operation_data);

            // copy the operation hash to ourr temporary buffer we
            // will use to calcuate signatures for each signer
            self.sig_buf[33..65].copy_from_slice(&operation_hash);

            self.validate_operation(&signed_operation, &operation, &mut signers)?;
            self.authorize_operation(&operation, &mut signers)?;
            self.validate_actions(&operation, &mut signers)?;
        } else {
            self.collect_signers(&signed_operation, &operation, &mut signers, false)?;
        }

        self.execute_actions(&operation, &mut signers)?;

        self.hashes
            .insert(signed_operation_hash, self.operations.len());
        self.operations.push(op);

        Ok(())
    }

    fn validate_actions(
        &self,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        // references contains a list of any referenced or embedded key
        // and the action that was performed on it
        let mut references = HashMap::new();

        let actions = match op.actions() {
            Some(actions) => actions,
            None => return Err(SelfError::HashgraphOperationNOOP),
        };

        for (i, action) in actions.iter().enumerate() {
            match action.actionable() {
                Actionable::Grant => {
                    self.validate_action_grant(op, signers, &mut references, &action)?
                }
                Actionable::Modify => {
                    self.validate_action_modify(op, signers, &mut references, &action)?
                }
                Actionable::Revoke => {
                    self.validate_action_revoke(op, signers, &mut references, &action)?
                }
                Actionable::Recover => {
                    self.validate_action_recover(op, signers, &mut references, &action)?
                }
                Actionable::Deactivate => {
                    self.validate_action_deactivate(op, signers, &mut references, &action)?
                }
            }
        }

        // check this operation has been signed by keys that actually
        // exist or are created by this operation
        for (i, id) in signers.iter().enumerate() {
            // if this is the identity key, skip it
            if op.sequence() == 0 && self.sig_buf[0..33] == id {
                continue;
            }

            if let Some(action) = references.get(id) {
                if action == Actionable::Grant {
                    continue;
                }
            }

            if self.keys.contains_key(id) {
                continue;
            }

            return Err(SelfError::HashgraphSignerUnknown);
        }

        let mut active_keys = false;

        // check that there is still at least one active key with
        // the capability to update the document
        for (id, key) in self.keys.iter() {
            // check if the key is still active
            if key.as_ref().revoked_at == 0 {
                continue;
            }

            // is this key referenced by any action?
            // is this reference just modifying and not revoking?
            if let Some(reference) = references.get(id) {
                if reference == Actionable::Modify {
                    active_keys = true;
                }
            } else {
                active_keys = true;
            }
        }

        // if there are no active existing keys, check for
        // new keys added by the operation
        if !active_keys {
            for (_, action) in references.iter() {
                if action == Actionable::Grant
                    || action == Actionable::Modify
                    || action == Actionable::Deactivate
                {
                    active_keys = true;
                    break;
                }
            }
        }

        if !active_keys {
            return Err(SelfError::HashgraphNoActiveKeys);
        }

        Ok(())
    }

    fn execute_actions(
        &self,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
    ) -> Result<(), SelfError> {
        let actions = match op.actions() {
            Some(actions) => actions,
            None => return Err(SelfError::HashgraphOperationNOOP),
        };

        for (i, action) in actions.iter().enumerate() {
            match action.actionable() {
                Actionable::Grant => self.execute_action_grant(op, signers, &action)?,
                Actionable::Modify => self.execute_action_modify(op, &action)?,
                Actionable::Revoke => self.execute_action_revoke(&action)?,
                Actionable::Recover => self.execute_action_recover(&action)?,
                Actionable::Deactivate => self.execute_action_deactivate(&action)?,
            }
        }

        Ok(())
    }

    fn validate_action_grant(
        &self,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
        references: &mut HashMap<Vec<u8>, Actionable>,
        action: &Action,
    ) -> Result<(), SelfError> {
        match action.description_type() {
            Description::Embedded => {
                if let Some(embedded) = action.description_as_embedded() {
                    let id = match embedded.id() {
                        Some(id) => id,
                        None => return Err(SelfError::HashgraphInvalidKeyLength),
                    };

                    if id.len() != 33 {
                        return Err(SelfError::HashgraphInvalidKeyLength);
                    }

                    // check that the key has self signed the operation
                    if !signers.contains(id) {
                        return Err(SelfError::HashgraphSelfSignatureRequired);
                    }

                    // check this embedded key does not already exist
                    if self.keys.contains_key(id) {
                        return Err(SelfError::HashgraphDuplicateKey);
                    }

                    if action.roles() == 0 {
                        return Err(SelfError::HashgraphNoRolesAssigned);
                    }

                    let mut uses: u64 = 0;

                    for role in 1..6 {
                        if 1 << role == Role::Verification {
                            // we're not checking if this is a multi-role key here
                            continue;
                        }

                        if action.roles() & 1 << role == 1 {
                            uses += 1;
                        }
                    }

                    // if an embedded key has more than one role and it isn't a verification key
                    // that can have multiple uses, then error
                    if uses > 1 && action.roles() & Role::Verification == 0 {
                        return Err(SelfError::HashgraphMultiRoleKeyViolation);
                    }

                    if references.contains_key(id) {
                        return Err(SelfError::HashgraphDuplicateAction);
                    }

                    references.insert(id.to_vec(), Actionable::Grant)
                }
            }
            Description::Reference => {
                if let Some(reference) = action.description_as_reference() {
                    let id = match reference.id() {
                        Some(id) => id,
                        None => return Err(SelfError::HashgraphInvalidKeyLength),
                    };

                    if id.len() != 33 {
                        return Err(SelfError::HashgraphInvalidKeyLength);
                    }

                    let controller = match reference.controller() {
                        Some(controller) => controller,
                        None => return Err(SelfError::HashgraphInvalidControllerLength),
                    };

                    if controller.len() != 33 {
                        return Err(SelfError::HashgraphInvalidControllerLength);
                    }

                    // check that the key has self signed the operation
                    if !signers.contains(id) {
                        return Err(SelfError::HashgraphSelfSignatureRequired);
                    }

                    // check this embedded key does not already exist
                    if self.keys.contains_key(id) {
                        return Err(SelfError::HashgraphDuplicateKey);
                    }

                    if action.roles() == 0 {
                        return Err(SelfError::HashgraphNoRolesAssigned);
                    }

                    if references.contains_key(id) {
                        return Err(SelfError::HashgraphDuplicateAction);
                    }

                    references.insert(id.to_vec(), Actionable::Grant)
                }
            }
        }

        Ok(())
    }

    fn execute_action_grant(
        &mut self,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
        action: &Action,
    ) -> Result<(), SelfError> {
        match action.description_type() {
            Description::Embedded => {
                if let Some(embedded) = action.description_as_embedded() {
                    let id = match embedded.id() {
                        Some(id) => id,
                        None => return Err(SelfError::HashgraphInvalidKeyLength),
                    };

                    let controller = match embedded.controller() {
                        Some(controller) => Some(controller.to_vec()),
                        None => None,
                    };

                    let node = Rc::new(RefCell::new(Node {
                        controller,
                        sequence: op.sequence(),
                        roles: vec![RoleEntry {
                            role: action.roles(),
                            from: op.timestamp(),
                        }],
                        public_key: id.to_vec(),
                        created_at: op.timestamp(),
                        revoked_at: 0,
                        incoming: Vec::new(),
                        outgoing: Vec::new(),
                    }));

                    // link it to the signing keys that created it, unless it's
                    // a self signed signature
                    for signer in signers.iter() {
                        if op.sequence() == 0 && self.root.is_none() {
                            if signer == id
                                && self.identifier.is_some_and(|identifier| identifier != id)
                            {
                                self.root = Some(node.clone())
                            }
                            continue;
                        }

                        if id == signer {
                            // this is a self signed signature, skip it
                            continue;
                        }

                        let parent = match self.keys.get(signer) {
                            Some(parent) => parent,
                            None => {
                                if op.sequence() == 0 {
                                    // this is the signature by the identifier key, skip it
                                    continue;
                                }

                                return Err(SelfError::HashgraphUnknownSigner);
                            }
                        };

                        node.as_ref().borrow_mut().incoming.push((*parent).clone());
                        parent.as_ref().borrow_mut().outgoing.push(node.clone());
                    }

                    self.keys.insert(id.to_vec(), node);
                }
            }
            Description::Reference => {
                if let Some(reference) = action.description_as_reference() {
                    let id = match reference.id() {
                        Some(id) => id,
                        None => return Err(SelfError::HashgraphInvalidKeyLength),
                    };

                    let controller = match reference.controller() {
                        Some(controller) => controller.to_vec(),
                        None => return Err(SelfError::HashgraphInvalidControllerLength),
                    };

                    let node = Rc::new(RefCell::new(Node {
                        controller: Some(controller),
                        sequence: op.sequence(),
                        roles: vec![RoleEntry {
                            role: action.roles(),
                            from: op.timestamp(),
                        }],
                        public_key: id.to_vec(),
                        created_at: op.timestamp(),
                        revoked_at: 0,
                        incoming: Vec::new(),
                        outgoing: Vec::new(),
                    }));

                    // link it to the signing keys that created it, unless it's
                    // a self signed signature
                    for signer in signers.iter() {
                        if op.sequence() == 0 && self.root.is_none() {
                            if signer == id
                                && self.identifier.is_some_and(|identifier| identifier != id)
                            {
                                self.root = Some(node.clone())
                            }
                            continue;
                        }

                        if id == signer {
                            // this is a self signed signature, skip it
                            continue;
                        }

                        let parent = match self.keys.get(signer) {
                            Some(parent) => parent,
                            None => {
                                if op.sequence() == 0 {
                                    // this is the signature by the identifier key, skip it
                                    continue;
                                }

                                return Err(SelfError::HashgraphUnknownSigner);
                            }
                        };

                        node.as_ref().borrow_mut().incoming.push((*parent).clone());
                        parent.as_ref().borrow_mut().outgoing.push(node.clone());
                    }

                    self.keys.insert(id.to_vec(), node);
                }
            }
        }

        Ok(())
    }

    fn validate_action_revoke(
        &self,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
        references: &mut HashMap<Vec<u8>, Actionable>,
        action: &Action,
    ) -> Result<(), SelfError> {
        if op.sequence() == 0 {
            return Err(SelfError::HashgraphInvalidRevoke);
        }

        match action.description_type() {
            Description::Embedded => return Err(SelfError::HashgraphInvalidEmbeddedDescription),
            Description::Reference => {
                if let Some(reference) = action.description_as_reference() {
                    let id = match reference.id() {
                        Some(id) => id,
                        None => return Err(SelfError::HashgraphInvalidKeyLength),
                    };

                    if id.len() != 33 {
                        return Err(SelfError::HashgraphInvalidKeyLength);
                    }

                    if let Some(controller) = reference.controller() {
                        if controller.len() != 33 {
                            return Err(SelfError::HashgraphInvalidControllerLength);
                        }
                    }

                    // check this embedded key does not already exist
                    let key = match self.keys.get(id) {
                        Some(key) => key,
                        None => return Err(SelfError::HashgraphReferencedDescriptionNotFound),
                    };

                    if key.as_ref().revoked_at != 0 {
                        return Err(SelfError::HashgraphKeyAlreadyRevoked);
                    }

                    if key.created_at > action.from() {
                        return Err(SelfError::HashgraphInvalidRevocationTimestamp);
                    }

                    if references.contains_key(id) {
                        return Err(SelfError::HashgraphDuplicateAction);
                    }

                    references.insert(id.to_vec(), Actionable::Revoke);
                }
            }
        }

        Ok(())
    }

    fn execute_action_revoke(&mut self, action: &Action) -> Result<(), SelfError> {
        if let Some(reference) = action.description_as_reference() {
            let id = match reference.id() {
                Some(id) => id,
                None => return Err(SelfError::HashgraphInvalidKeyLength),
            };

            let key = match self.keys.get_mut(id) {
                Some(key) => key,
                None => return Err(SelfError::HashgraphReferencedDescriptionNotFound),
            };

            key.as_ref().borrow_mut().revoked_at = action.from();

            // revoke all child keys created after the
            // time the revocation takes effect
            for child in key.as_ref().borrow().collect() {
                let borrowed_child = child.as_ref.borrow_mut();
                if borrowed_child.created_at >= action.from() {
                    borrowed_child.revoked_at = action.from();
                }
            }
        }

        Ok(())
    }

    fn validate_action_modify(
        &self,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
        references: &mut HashMap<Vec<u8>, Actionable>,
        action: &Action,
    ) -> Result<(), SelfError> {
        if op.sequence() == 0 {
            return Err(SelfError::HashgraphInvalidModify);
        }

        match action.description_type() {
            Description::Embedded => return Err(SelfError::HashgraphInvalidEmbeddedDescription),
            Description::Reference => {
                if let Some(reference) = action.description_as_reference() {
                    let id = match reference.id() {
                        Some(id) => id,
                        None => return Err(SelfError::HashgraphInvalidKeyLength),
                    };

                    if id.len() != 33 {
                        return Err(SelfError::HashgraphInvalidKeyLength);
                    }

                    if let Some(controller) = reference.controller() {
                        if controller.len() != 33 {
                            return Err(SelfError::HashgraphInvalidControllerLength);
                        }
                    }

                    // check this embedded key does not already exist
                    let key = match self.keys.get(id) {
                        Some(key) => key.as_ref().borrow_mut(),
                        None => return Err(SelfError::HashgraphReferencedDescriptionNotFound),
                    };

                    if action.roles() == 0 {
                        return Err(SelfError::HashgraphNoRolesAssigned);
                    }

                    if let Some(roles) = key.roles.last() {
                        if roles == action.roles() {
                            return Err(SelfError::HashgraphModifyNOOP);
                        }

                        if !key.has_roles(Role::Verification) {
                            return Err(SelfError::HashgraphInvalidKeyReuse);
                        }
                    }

                    if key.revoked_at != 0 {
                        return Err(SelfError::HashgraphKeyAlreadyRevoked);
                    }

                    if references.contains_key(id) {
                        return Err(SelfError::HashgraphDuplicateAction);
                    }

                    references.insert(id.to_vec(), Actionable::Revoke);
                }
            }
        }

        Ok(())
    }

    fn operation(&self, index: usize) -> Operation {
        let signed_op = root_as_signed_operation(&self.operations[index]).unwrap();
        let op_bytes = signed_op.operation().unwrap();

        return flatbuffers::root::<Operation>(op_bytes).unwrap();
    }
}

impl Default for Hashgraph {
    fn default() -> Self {
        Hashgraph::new()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use flatbuffers::{Vector, WIPOffset};

    use crate::{
        error::SelfError,
        hashgraph::Hashgraph,
        keypair::signing::KeyPair,
        protocol::hashgraph::{
            Action, ActionArgs, Actionable, CreateKey, CreateKeyArgs, KeyAlgorithm, KeyRole,
            Operation, OperationArgs, Recover, RecoverArgs, RevokeKey, RevokeKeyArgs, Signature,
            SignatureArgs, SignatureHeader, SignatureHeaderArgs, SignedOperation,
            SignedOperationArgs,
        },
    };

    struct TestSigner {
        id: Vec<u8>,
        sk: KeyPair,
    }

    struct TestAction {
        key: Vec<u8>,
        alg: KeyAlgorithm,
        role: KeyRole,
        actionable: Actionable,
        effective_from: i64,
    }

    struct TestOperation {
        id: KeyPair,
        version: u8,
        sequence: u32,
        timestamp: i64,
        previous: Vec<u8>,
        actions: Vec<TestAction>,
        signers: Vec<TestSigner>,
        error: Result<(), SelfError>,
    }

    fn test_keys() -> Vec<KeyPair> {
        let mut keys = Vec::new();

        for _ in 0..10 {
            let kp = KeyPair::new();
            keys.push(kp);
        }

        keys
    }

    fn test_operation(test_op: &mut TestOperation) -> (Vec<u8>, Vec<u8>) {
        let mut op_builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let mut sg_builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let mut fn_builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        let mut actions = Vec::new();

        for action in &test_op.actions {
            match action.actionable {
                Actionable::CreateKey => {
                    let kb = op_builder.create_vector(&action.key);

                    let ck = CreateKey::create(
                        &mut op_builder,
                        &CreateKeyArgs {
                            key: Some(kb),
                            alg: action.alg,
                            role: action.role,
                            effective_from: action.effective_from,
                        },
                    );

                    let ac = Action::create(
                        &mut op_builder,
                        &ActionArgs {
                            actionable_type: Actionable::CreateKey,
                            actionable: Some(ck.as_union_value()),
                        },
                    );

                    actions.push(ac);
                }
                Actionable::RevokeKey => {
                    let kb = op_builder.create_vector(&action.key);

                    let rk = RevokeKey::create(
                        &mut op_builder,
                        &RevokeKeyArgs {
                            key: Some(kb),
                            effective_from: action.effective_from,
                        },
                    );

                    let ac = Action::create(
                        &mut op_builder,
                        &ActionArgs {
                            actionable_type: Actionable::RevokeKey,
                            actionable: Some(rk.as_union_value()),
                        },
                    );

                    actions.push(ac);
                }
                Actionable::Recover => {
                    let rk = Recover::create(
                        &mut op_builder,
                        &RecoverArgs {
                            effective_from: action.effective_from,
                        },
                    );

                    let ac = Action::create(
                        &mut op_builder,
                        &ActionArgs {
                            actionable_type: Actionable::Recover,
                            actionable: Some(rk.as_union_value()),
                        },
                    );

                    actions.push(ac);
                }
                _ => {}
            }
        }

        let actions_vec = op_builder.create_vector(&actions);
        let mut previous: Option<WIPOffset<Vector<u8>>> = None;

        if !test_op.previous.is_empty() {
            previous = Some(op_builder.create_vector(&test_op.previous));
        }

        let op = Operation::create(
            &mut op_builder,
            &OperationArgs {
                version: test_op.version,
                sequence: test_op.sequence,
                timestamp: test_op.timestamp,
                previous,
                actions: Some(actions_vec),
            },
        );

        op_builder.finish(op, None);

        let op_hash = crate::crypto::hash::sha3(op_builder.finished_data());

        let mut sig_buf: Vec<u8> = vec![0; 96];
        sig_buf[..32].copy_from_slice(&test_op.id.id());
        sig_buf[32..64].copy_from_slice(&op_hash);

        let mut signatures = Vec::new();

        for signer in &test_op.signers {
            sg_builder.reset();

            let sb = sg_builder.create_vector(&signer.id);

            let header =
                SignatureHeader::create(&mut sg_builder, &SignatureHeaderArgs { signer: Some(sb) });

            sg_builder.finish(header, None);

            let header_hash = crate::crypto::hash::sha3(sg_builder.finished_data());

            sig_buf[64..].copy_from_slice(&header_hash);
            let signature = signer.sk.sign(&sig_buf);

            let hb = fn_builder.create_vector(sg_builder.finished_data());
            let sb = fn_builder.create_vector(&signature);

            let sig = Signature::create(
                &mut fn_builder,
                &SignatureArgs {
                    header: Some(hb),
                    signature: Some(sb),
                },
            );

            signatures.push(sig);
        }

        let op_signatures = fn_builder.create_vector(&signatures);
        let op_data = fn_builder.create_vector(op_builder.finished_data());

        let signed_op = SignedOperation::create(
            &mut fn_builder,
            &SignedOperationArgs {
                operation: Some(op_data),
                signatures: Some(op_signatures),
            },
        );

        fn_builder.finish(signed_op, None);

        let signed_op_hash = crate::crypto::hash::sha3(fn_builder.finished_data());

        return (fn_builder.finished_data().to_vec(), signed_op_hash);
    }

    fn test_execute(test_history: &mut Vec<TestOperation>) -> Hashgraph {
        let mut sg = Hashgraph::new();
        let mut previous_hash: Option<Vec<u8>> = None;

        for test_op in test_history {
            if test_op.previous.is_empty() {
                if let Some(previous) = previous_hash {
                    test_op.previous = previous;
                }
            }

            let (signed_op, previous) = test_operation(test_op);

            previous_hash = Some(previous);

            let result = sg.execute(signed_op);
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

        sg
    }

    #[test]
    fn execute_valid_single_entry() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![TestOperation {
            id: keys[0].clone(),
            version: 2,
            sequence: 0,
            timestamp: now,
            previous: Vec::new(),
            signers: vec![
                TestSigner {
                    id: keys[0].id(),
                    sk: keys[0].clone(),
                },
                TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                },
                TestSigner {
                    id: keys[2].id(),
                    sk: keys[2].clone(),
                },
            ],
            actions: vec![
                TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: 0,
                },
                TestAction {
                    key: keys[2].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::CreateKey,
                    effective_from: 0,
                },
            ],
            error: Ok(()),
        }];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_valid_multi_entry() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 2,
                timestamp: now + 2,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[4].id(),
                        sk: keys[4].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[4].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 2,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 3,
                timestamp: now + 3,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                    TestSigner {
                        id: keys[5].id(),
                        sk: keys[5].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[5].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 3,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 4,
                timestamp: now + 4,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[4].id(),
                        sk: keys[4].clone(),
                    },
                    TestSigner {
                        id: keys[6].id(),
                        sk: keys[6].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[6].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 4,
                }],
                error: Ok(()),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_valid_multi_entry_with_recovery() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 2,
                timestamp: now + 2,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[4].id(),
                        sk: keys[4].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[4].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 2,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 3,
                timestamp: now + 3,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                    TestSigner {
                        id: keys[5].id(),
                        sk: keys[5].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[5].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 3,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 4,
                timestamp: now + 4,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[4].id(),
                        sk: keys[4].clone(),
                    },
                    TestSigner {
                        id: keys[6].id(),
                        sk: keys[6].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[6].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 4,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 5,
                timestamp: now + 5,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                    TestSigner {
                        id: keys[7].id(),
                        sk: keys[7].clone(),
                    },
                    TestSigner {
                        id: keys[8].id(),
                        sk: keys[8].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::Recover,
                        effective_from: now + 5,
                    },
                    TestAction {
                        key: keys[7].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now + 5,
                    },
                    TestAction {
                        key: keys[8].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now + 5,
                    },
                ],
                error: Ok(()),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_sequence_ordering() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 3,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphOperationSequenceOutOfOrder),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_timestamp() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                }],
                error: Err(SelfError::SiggraphOperationTimestampInvalid),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_previous_hash() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: vec![0; 32],
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphOperationPreviousHashInvalid),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_signature() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[4].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphOperationSignatureInvalid),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_signature_identity() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![TestOperation {
            id: keys[0].clone(),
            version: 2,
            sequence: 0,
            timestamp: now,
            previous: Vec::new(),
            signers: vec![
                TestSigner {
                    id: keys[0].id(),
                    sk: keys[4].clone(),
                },
                TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                },
                TestSigner {
                    id: keys[2].id(),
                    sk: keys[2].clone(),
                },
            ],
            actions: vec![
                TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
                TestAction {
                    key: keys[2].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
            ],
            error: Err(SelfError::SiggraphOperationSignatureInvalid),
        }];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_signature_key() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![TestOperation {
            id: keys[0].clone(),
            version: 2,
            sequence: 0,
            timestamp: now,
            previous: Vec::new(),
            signers: vec![
                TestSigner {
                    id: keys[0].id(),
                    sk: keys[0].clone(),
                },
                TestSigner {
                    id: keys[1].id(),
                    sk: keys[4].clone(),
                },
                TestSigner {
                    id: keys[2].id(),
                    sk: keys[2].clone(),
                },
            ],
            actions: vec![
                TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
                TestAction {
                    key: keys[2].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
            ],
            error: Err(SelfError::SiggraphOperationSignatureInvalid),
        }];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_signature_missing() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![TestOperation {
            id: keys[0].clone(),
            version: 2,
            sequence: 0,
            timestamp: now,
            previous: Vec::new(),
            signers: vec![
                TestSigner {
                    id: keys[0].id(),
                    sk: keys[0].clone(),
                },
                TestSigner {
                    id: keys[2].id(),
                    sk: keys[2].clone(),
                },
            ],
            actions: vec![
                TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
                TestAction {
                    key: keys[2].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
            ],
            error: Err(SelfError::SiggraphOperationNotEnoughSigners),
        }];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_key_signing_duplicate() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphActionKeyDuplicate),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_key_signing_revocation() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphOperationNoValidKeys),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_key_recovery_revocation() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[2].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphOperationNoValidRecoveryKey),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_key_recovery_duplicate() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[4].id(),
                        sk: keys[4].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[4].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphActionMultipleActiveRecoveryKeys),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_signature_signer_revoked() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[3].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 1,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 2,
                timestamp: now + 2,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                    TestSigner {
                        id: keys[4].id(),
                        sk: keys[4].clone(),
                    },
                ],
                actions: vec![TestAction {
                    key: keys[4].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 2,
                }],
                error: Err(SelfError::SiggraphOperationSignatureKeyRevoked),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_signature_signer_unauthorized() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[4].id(),
                    sk: keys[4].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphOperationSigningKeyInvalid),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_actions_empty() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![],
                error: Err(SelfError::SiggraphOperationNOOP),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_action_revoke_duplicate() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[3].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 1,
                }],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 2,
                timestamp: now + 2,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 2,
                }],
                error: Err(SelfError::SiggraphActionKeyAlreadyRevoked),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_action_revoke_reference() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 1,
                }],
                error: Err(SelfError::SiggraphActionKeyMissing),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_action_revoke_root() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![TestOperation {
            id: keys[0].clone(),
            version: 2,
            sequence: 0,
            timestamp: now,
            previous: Vec::new(),
            signers: vec![
                TestSigner {
                    id: keys[0].id(),
                    sk: keys[0].clone(),
                },
                TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                },
                TestSigner {
                    id: keys[2].id(),
                    sk: keys[2].clone(),
                },
                TestSigner {
                    id: keys[3].id(),
                    sk: keys[3].clone(),
                },
            ],
            actions: vec![
                TestAction {
                    key: keys[1].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
                TestAction {
                    key: keys[2].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
                TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Signing,
                    actionable: Actionable::CreateKey,
                    effective_from: now,
                },
                TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::RevokeKey,
                    effective_from: now + 1,
                },
            ],
            error: Err(SelfError::SiggraphActionKeyMissing),
        }];

        test_execute(&mut test_history);
    }

    #[test]
    fn execute_invalid_action_revoke_timestamp() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[3].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![TestSigner {
                    id: keys[1].id(),
                    sk: keys[1].clone(),
                }],
                actions: vec![TestAction {
                    key: keys[3].id(),
                    alg: KeyAlgorithm::Ed25519,
                    role: KeyRole::Recovery,
                    actionable: Actionable::RevokeKey,
                    effective_from: now - 100,
                }],
                error: Err(SelfError::SiggraphOperationTimestampInvalid),
            },
        ];

        test_execute(&mut test_history);
    }

    #[test]
    fn is_key_valid() {
        let now = Utc::now().timestamp();
        let keys = test_keys();

        // revoke the only signing key
        let mut test_history = vec![
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 0,
                timestamp: now,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[0].id(),
                        sk: keys[0].clone(),
                    },
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[2].id(),
                        sk: keys[2].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                    TestAction {
                        key: keys[2].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Recovery,
                        actionable: Actionable::CreateKey,
                        effective_from: now,
                    },
                ],
                error: Ok(()),
            },
            TestOperation {
                id: keys[0].clone(),
                version: 2,
                sequence: 1,
                timestamp: now + 1,
                previous: Vec::new(),
                signers: vec![
                    TestSigner {
                        id: keys[1].id(),
                        sk: keys[1].clone(),
                    },
                    TestSigner {
                        id: keys[3].id(),
                        sk: keys[3].clone(),
                    },
                ],
                actions: vec![
                    TestAction {
                        key: keys[1].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::RevokeKey,
                        effective_from: now + 1,
                    },
                    TestAction {
                        key: keys[3].id(),
                        alg: KeyAlgorithm::Ed25519,
                        role: KeyRole::Signing,
                        actionable: Actionable::CreateKey,
                        effective_from: now + 1,
                    },
                ],
                error: Ok(()),
            },
        ];

        let sg = test_execute(&mut test_history);

        assert!(sg.is_key_valid(&keys[1].id(), now));
        assert!(!sg.is_key_valid(&keys[1].id(), now + 1));
        assert!(!sg.is_key_valid(&keys[1].id(), now + 2));
        assert!(!sg.is_key_valid(&keys[1].id(), now - 1));
        assert!(sg.is_key_valid(&keys[3].id(), now + 1));
        assert!(sg.is_key_valid(&keys[3].id(), now + 2));
        assert!(!sg.is_key_valid(&keys[0].id(), now - 1));
    }
}
