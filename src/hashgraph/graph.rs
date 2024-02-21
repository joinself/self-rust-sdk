use flatbuffers::{ForwardsUOffset, Vector};
use http::header;

use crate::error::SelfError;
use crate::hashgraph::{node::Node, node::RoleEntry, operation::OperationBuilder};
use crate::keypair::signing::PublicKey;
use crate::keypair::Algorithm;
use crate::protocol::hashgraph::{
    root_as_signed_operation, Action, Actionable, Description, Operation, Role, Signature,
    SignatureHeader, SignedOperation, Version,
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
    deactivated: bool,
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
            deactivated: false,
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
            deactivated: false,
            sig_buf: vec![0; 97],
        };

        for operation in history {
            sg.execute_operation(operation, verify)?
        }

        Ok(sg)
    }

    pub fn identifier(&self) -> Option<&[u8]> {
        self.identifier
            .and_then(|identifier| Some(identifier.as_ref()))
    }

    pub fn controller(&self) -> Option<&[u8]> {
        self.controller
            .and_then(|controller| Some(controller.as_ref()))
    }

    pub fn create(&self) -> OperationBuilder {
        let mut ob = OperationBuilder::new();

        ob.sequence(self.operations.len() as u32)
            .timestamp(crate::time::unix());

        if let Some(id) = &self.identifier {
            ob.id(id);
        }

        if let Some(last_op) = self.operations.last() {
            // compute the hash of the last operation
            ob.previous(&crate::crypto::hash::sha3(last_op));
        }

        ob
    }

    pub fn execute(&mut self, operation: Vec<u8>) -> Result<(), SelfError> {
        self.execute_operation(&operation, true)
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
                .map_err(|_| SelfError::HashgraphInvalidSignatureHeader)?;

            let signer = match header.signer() {
                Some(signer) => signer,
                None => return Err(SelfError::HashgraphInvalidSignerLength),
            };

            if signer.len() < 33 {
                return Err(SelfError::HashgraphInvalidSignerLength);
            }

            if verify {
                if op.sequence() == 0 && i == 0 {
                    // if this is the first signature on the first operation
                    // this is the key used as an identifier for the account.
                    // copy it to the sig buffer for verifying signatures
                    self.identifier = Some(signer.to_vec());
                    self.sig_buf[0..33].copy_from_slice(signer);
                }

                let signature_data = match signature.signature() {
                    Some(signature) => signature,
                    None => return Err(SelfError::HashgraphInvalidSignatureLength),
                };

                if signature_data.len() != 64 {
                    return Err(SelfError::HashgraphInvalidSignatureLength);
                }

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
            return Err(SelfError::HashgraphOperationSequenceOutOfOrder);
        }

        if op.version() != Version::V0 {
            return Err(SelfError::HashgraphOperationVersionInvalid);
        }

        if op.actions().is_none() {
            return Err(SelfError::HashgraphOperationNOOP);
        }

        let signatures = match signed_op.signatures() {
            Some(signatures) => signatures,
            None => return Err(SelfError::HashgraphOperationUnsigned),
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

            if *hash_index != self.operations.len() - 1 {
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
                Some(signing_key) => signing_key.as_ref().borrow(),
                None => continue,
            };

            // signing key must have capabilityInvocation role to update the document
            if !signing_key.has_roles(Role::Invocation.bits()) {
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
            .map_err(|_| SelfError::HashgraphOperationInvalid)?;
        let signed_operation_hash = crate::crypto::hash::sha3(op);

        let operation_data = match signed_operation.operation() {
            Some(operation_data) => operation_data,
            None => return Err(SelfError::HashgraphOperationInvalid),
        };

        let operation = flatbuffers::root::<Operation>(operation_data)
            .map_err(|_| SelfError::HashgraphOperationInvalid)?;

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
        self.operations.push(op.to_vec());

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
            if op.sequence() == 0 && self.sig_buf[0..33] == *id {
                continue;
            }

            if let Some(action) = references.get(id) {
                if *action == Actionable::Grant {
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
            if key.as_ref().borrow().revoked_at == 0 {
                continue;
            }

            // is this key referenced by any action?
            // is this reference just modifying and not revoking?
            if let Some(reference) = references.get(id) {
                if *reference == Actionable::Modify {
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
                if *action == Actionable::Grant
                    || *action == Actionable::Modify
                    || *action == Actionable::Deactivate
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
                        if 1 << role == Role::Verification.bits() {
                            // we're not checking if this is a multi-role key here
                            continue;
                        }

                        if action.roles() & 1 << role == 1 {
                            uses += 1;
                        }
                    }

                    // if an embedded key has more than one role and it isn't a verification key
                    // that can have multiple uses, then error
                    if uses > 1 && action.roles() & Role::Verification.bits() == 0 {
                        return Err(SelfError::HashgraphMultiRoleKeyViolation);
                    }

                    if references.contains_key(id) {
                        return Err(SelfError::HashgraphDuplicateAction);
                    }

                    references.insert(id.to_vec(), Actionable::Grant);
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

                    references.insert(id.to_vec(), Actionable::Grant);
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
                        public_key: PublicKey::from_bytes(id, Algorithm::Ed25519)?,
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

                                return Err(SelfError::HashgraphSignerUnknown);
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
                        public_key: PublicKey::from_bytes(id, Algorithm::Ed25519)?,
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

                                return Err(SelfError::HashgraphSignerUnknown);
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
                        Some(key) => key.as_ref().borrow(),
                        None => return Err(SelfError::HashgraphReferencedDescriptionNotFound),
                    };

                    if key.revoked_at != 0 {
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
                let mut borrowed_child = child.as_ref().borrow_mut();

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
                        if roles.role == action.roles() {
                            return Err(SelfError::HashgraphModifyNOOP);
                        }

                        if !key.has_roles(Role::Verification.bits()) {
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

    fn execute_action_modify(&mut self, op: &Operation, action: &Action) -> Result<(), SelfError> {
        if let Some(reference) = action.description_as_reference() {
            let id = match reference.id() {
                Some(id) => id,
                None => return Err(SelfError::HashgraphInvalidKeyLength),
            };

            let mut key = match self.keys.get_mut(id) {
                Some(key) => key.as_ref().borrow_mut(),
                None => return Err(SelfError::HashgraphReferencedDescriptionNotFound),
            };

            key.roles.push(RoleEntry {
                from: op.timestamp(),
                role: action.roles(),
            })
        }

        Ok(())
    }

    fn validate_action_recover(
        &self,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
        references: &mut HashMap<Vec<u8>, Actionable>,
        action: &Action,
    ) -> Result<(), SelfError> {
        if op.sequence() == 0 {
            return Err(SelfError::HashgraphInvalidRecover);
        }

        let root = match self.root {
            Some(root) => root.as_ref().borrow(),
            None => return Err(SelfError::HashgraphInvalidState),
        };

        if root.revoked_at == 0 {
            if references.contains_key(&root.public_key.id()) {
                return Err(SelfError::HashgraphDuplicateAction);
            }

            references.insert(root.public_key.id(), Actionable::Recover);
        }

        for child in root.collect().iter() {
            let borrowed_child = child.as_ref().borrow();

            if borrowed_child.revoked_at == 0 {
                if references.contains_key(&borrowed_child.public_key.id()) {
                    return Err(SelfError::HashgraphDuplicateAction);
                }

                references.insert(root.public_key.id(), Actionable::Recover);
            }
        }

        Ok(())
    }

    fn execute_action_recover(&mut self, action: &Action) -> Result<(), SelfError> {
        let mut root = match self.root {
            Some(root) => root.as_ref().borrow_mut(),
            None => return Err(SelfError::HashgraphInvalidState),
        };

        if root.revoked_at == 0 {
            root.revoked_at = action.from();
        }

        for child in root.collect().iter() {
            let mut borrowed_child = child.as_ref().borrow_mut();

            if borrowed_child.revoked_at == 0 {
                borrowed_child.revoked_at = action.from();
            }
        }

        Ok(())
    }

    fn validate_action_deactivate(
        &self,
        op: &Operation,
        signers: &mut HashSet<Vec<u8>>,
        references: &mut HashMap<Vec<u8>, Actionable>,
        action: &Action,
    ) -> Result<(), SelfError> {
        if op.sequence() == 0 {
            return Err(SelfError::HashgraphInvalidRecover);
        }

        let root = match self.root {
            Some(root) => root.as_ref().borrow(),
            None => return Err(SelfError::HashgraphInvalidState),
        };

        if root.revoked_at == 0 {
            if references.contains_key(&root.public_key.id()) {
                return Err(SelfError::HashgraphDuplicateAction);
            }

            references.insert(root.public_key.id(), Actionable::Deactivate);
        }

        for child in root.collect().iter() {
            let borrowed_child = child.as_ref().borrow();

            if borrowed_child.revoked_at == 0 {
                if references.contains_key(&borrowed_child.public_key.id()) {
                    return Err(SelfError::HashgraphDuplicateAction);
                }

                references.insert(root.public_key.id(), Actionable::Deactivate);
            }
        }

        Ok(())
    }

    fn execute_action_deactivate(&mut self, action: &Action) -> Result<(), SelfError> {
        let mut root = match self.root {
            Some(root) => root.as_ref().borrow_mut(),
            None => return Err(SelfError::HashgraphInvalidState),
        };

        if root.revoked_at == 0 {
            root.revoked_at = action.from();
        }

        for child in root.collect().iter() {
            let mut borrowed_child = child.as_ref().borrow_mut();

            if borrowed_child.revoked_at == 0 {
                borrowed_child.revoked_at = action.from();
            }
        }

        self.deactivated = true;

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
mod tests {}
