use crate::{
    error::SelfError,
    hashgraph::role::{Method, Role, RoleSet},
    keypair::signing::{KeyPair, PublicKey},
    protocol::hashgraph,
};

pub struct Operation<'a> {
    sequence: u32,
    operation: Vec<u8>,
    sig_buf: Vec<u8>,
    created: Vec<(u64, Vec<u8>)>,
    updated: Vec<(u64, Vec<u8>)>,
    signers: Vec<PublicKey>,
    signatures: Vec<(Vec<u8>, Vec<u8>)>,
    builder: flatbuffers::FlatBufferBuilder<'a>,
}

impl<'a> Operation<'a> {
    pub fn new(
        sequence: u32,
        operation: Vec<u8>,
        sig_buf: Vec<u8>,
        created: Vec<(u64, Vec<u8>)>,
        updated: Vec<(u64, Vec<u8>)>,
        signers: Vec<PublicKey>,
    ) -> Operation<'a> {
        return Operation {
            sequence,
            operation,
            sig_buf,
            created,
            updated,
            signers,
            signatures: Vec::new(),
            builder: flatbuffers::FlatBufferBuilder::with_capacity(1024),
        };
    }

    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    pub fn identifier(&self) -> &[u8] {
        &self.sig_buf[0..33]
    }

    pub fn created(&self) -> &[(u64, Vec<u8>)] {
        &self.created
    }

    pub fn updated(&self) -> &[(u64, Vec<u8>)] {
        &self.updated
    }

    pub fn signers(&self) -> &[PublicKey] {
        &self.signers
    }

    pub fn sign(&mut self, with: &KeyPair) -> &mut Self {
        self.builder.reset();

        let sb = self.builder.create_vector(with.address());

        let header = hashgraph::SignatureHeader::create(
            &mut self.builder,
            &hashgraph::SignatureHeaderArgs { signer: Some(sb) },
        );

        self.builder.finish(header, None);

        let header_bytes = self.builder.finished_data().to_vec();
        let header_hash = crate::crypto::hash::sha3(&header_bytes);
        self.builder.reset();

        self.sig_buf[65..].copy_from_slice(&header_hash);
        let signature = with.sign(&self.sig_buf);
        self.signatures.push((header_bytes, signature));

        self
    }

    pub fn build(&mut self) -> Result<Vec<u8>, SelfError> {
        if self.signatures.is_empty() {
            return Err(SelfError::HashgraphNotEnoughSigners);
        }

        let mut signatures = Vec::new();

        for signature in &self.signatures {
            let hb = self.builder.create_vector(&signature.0);
            let sb = self.builder.create_vector(&signature.1);

            signatures.push(hashgraph::Signature::create(
                &mut self.builder,
                &hashgraph::SignatureArgs {
                    header: Some(hb),
                    signature: Some(sb),
                },
            ));
        }

        let op_signatures = self.builder.create_vector(&signatures);
        let op_data = self.builder.create_vector(&self.operation);

        let signed_op = hashgraph::SignedOperation::create(
            &mut self.builder,
            &hashgraph::SignedOperationArgs {
                operation: Some(op_data),
                signatures: Some(op_signatures),
            },
        );

        self.builder.finish(signed_op, None);

        let signed_op_bytes = self.builder.finished_data().to_vec();

        Ok(signed_op_bytes)
    }
}

pub struct OperationBuilder<'a> {
    previous: Option<Vec<u8>>,
    sequence: Option<u32>,
    timestamp: Option<i64>,
    revoke: Vec<(Vec<u8>, Option<i64>)>,
    recover: Vec<Option<i64>>,
    deactivate: Vec<Option<i64>>,
    modify: Vec<(u64, Vec<u8>)>,
    grant_embedded: Vec<(u64, Vec<u8>)>,
    grant_referenced: Vec<(Method, u64, Vec<u8>, Vec<u8>)>,
    operation: Option<Vec<u8>>,
    signers: Vec<PublicKey>,
    signatures: Vec<(Vec<u8>, Vec<u8>)>,
    sig_buf: Vec<u8>,
    builder: flatbuffers::FlatBufferBuilder<'a>,
}

impl<'a> OperationBuilder<'a> {
    pub fn new() -> OperationBuilder<'a> {
        return OperationBuilder {
            previous: None,
            sequence: None,
            timestamp: None,
            revoke: Vec::new(),
            recover: Vec::new(),
            deactivate: Vec::new(),
            modify: Vec::new(),
            grant_embedded: Vec::new(),
            grant_referenced: Vec::new(),
            operation: None,
            signers: Vec::new(),
            signatures: Vec::new(),
            sig_buf: vec![0; 97],
            builder: flatbuffers::FlatBufferBuilder::with_capacity(1024),
        };
    }

    pub fn id(&mut self, id: &[u8]) -> &mut OperationBuilder<'a> {
        self.sig_buf[..33].copy_from_slice(id);
        self
    }

    pub fn sequence(&mut self, sequence: u32) -> &mut OperationBuilder<'a> {
        self.sequence = Some(sequence);
        self
    }

    pub fn timestamp(&mut self, timestamp: i64) -> &mut OperationBuilder<'a> {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn previous(&mut self, hash: &[u8]) -> &mut OperationBuilder<'a> {
        self.previous = Some(hash.to_vec());
        self
    }

    pub fn grant_embedded<T>(&mut self, pk: &[u8], roles: T) -> &mut OperationBuilder<'a>
    where
        T: RoleSet,
    {
        self.grant_embedded.push((roles.roles(), pk.to_owned()));
        self
    }

    pub fn grant_referenced<T>(
        &mut self,
        method: Method,
        controller: &[u8],
        pk: &[u8],
        roles: T,
    ) -> &mut OperationBuilder<'a>
    where
        T: RoleSet,
    {
        self.grant_referenced
            .push((method, roles.roles(), controller.to_owned(), pk.to_owned()));
        self
    }

    pub fn modify<T>(&mut self, pk: &[u8], roles: T) -> &mut OperationBuilder<'a>
    where
        T: RoleSet,
    {
        self.modify.push((roles.roles(), pk.to_owned()));
        self
    }

    pub fn revoke(&mut self, pk: &[u8], effective_from: Option<i64>) -> &mut OperationBuilder<'a> {
        self.revoke.push((pk.to_owned(), effective_from));
        self
    }

    pub fn recover(&mut self, effective_from: Option<i64>) -> &mut OperationBuilder<'a> {
        self.recover.push(effective_from);
        self
    }

    pub fn deactivate(&mut self, effective_from: Option<i64>) -> &mut OperationBuilder<'a> {
        self.deactivate.push(effective_from);
        self
    }

    pub fn sign(&mut self, with: &KeyPair) -> &mut OperationBuilder<'a> {
        if self.operation.is_none() {
            self.build_operation();
        }

        self.builder.reset();

        let sb = self.builder.create_vector(with.address());

        let header = hashgraph::SignatureHeader::create(
            &mut self.builder,
            &hashgraph::SignatureHeaderArgs { signer: Some(sb) },
        );

        self.builder.finish(header, None);

        let header_bytes = self.builder.finished_data().to_vec();
        let header_hash = crate::crypto::hash::sha3(&header_bytes);
        self.builder.reset();

        self.sig_buf[65..].copy_from_slice(&header_hash);
        let signature = with.sign(&self.sig_buf);
        self.signatures.push((header_bytes, signature));

        self
    }

    pub fn sign_with(&mut self, with: &PublicKey) -> &mut OperationBuilder<'a> {
        self.signers.push(with.clone());
        self
    }

    pub fn finish(&mut self) -> Operation<'a> {
        self.build_operation();

        let operation = self.operation.as_ref().unwrap().clone();
        let sequence = self.sequence.unwrap();
        let sig_buf = self.sig_buf.clone();
        let signers = self.signers.clone();
        let mut created = Vec::new();
        let mut updated = Vec::new();

        for modify in &self.modify {
            updated.push(modify.clone())
        }

        for grant in &self.grant_embedded {
            created.push(grant.clone())
        }

        Operation::new(sequence, operation, sig_buf, created, updated, signers)
    }

    pub fn build(&mut self) -> Result<Vec<u8>, SelfError> {
        // TODO call finish() to build an operation object
        // and then output the serialized operation
        if self.operation.is_none() {
            return Err(SelfError::HashgraphOperationMissing);
        }

        if self.signatures.is_empty() {
            return Err(SelfError::HashgraphNotEnoughSigners);
        }

        let mut signatures = Vec::new();

        for signature in &self.signatures {
            let hb = self.builder.create_vector(&signature.0);
            let sb = self.builder.create_vector(&signature.1);

            signatures.push(hashgraph::Signature::create(
                &mut self.builder,
                &hashgraph::SignatureArgs {
                    header: Some(hb),
                    signature: Some(sb),
                },
            ));
        }

        let op_signatures = self.builder.create_vector(&signatures);
        let op_data = self.builder.create_vector(self.operation.as_ref().unwrap());

        let signed_op = hashgraph::SignedOperation::create(
            &mut self.builder,
            &hashgraph::SignedOperationArgs {
                operation: Some(op_data),
                signatures: Some(op_signatures),
            },
        );

        self.builder.finish(signed_op, None);

        let signed_op_bytes = self.builder.finished_data().to_vec();

        Ok(signed_op_bytes)
    }

    fn build_operation(&mut self) {
        // TODO gracefully return error when optioned values are None
        let mut actions = Vec::new();

        for recover in &self.recover {
            let action = hashgraph::Action::create(
                &mut self.builder,
                &hashgraph::ActionArgs {
                    actionable: hashgraph::Actionable::Recover,
                    description: None,
                    description_type: hashgraph::Description::NONE,
                    roles: 0,
                    from: recover.unwrap_or(self.timestamp.unwrap()),
                },
            );

            actions.push(action);
        }

        for deactivate in &self.deactivate {
            let action = hashgraph::Action::create(
                &mut self.builder,
                &hashgraph::ActionArgs {
                    actionable: hashgraph::Actionable::Deactivate,
                    description: None,
                    description_type: hashgraph::Description::NONE,
                    roles: 0,
                    from: deactivate.unwrap_or(self.timestamp.unwrap()),
                },
            );

            actions.push(action);
        }

        for revoke in &self.revoke {
            let revoked_key = self.builder.create_vector(&revoke.0);

            let description = hashgraph::Reference::create(
                &mut self.builder,
                &hashgraph::ReferenceArgs {
                    method: hashgraph::Method::Aure,
                    id: Some(revoked_key),
                    controller: None,
                },
            );

            let action = hashgraph::Action::create(
                &mut self.builder,
                &hashgraph::ActionArgs {
                    actionable: hashgraph::Actionable::Revoke,
                    description: Some(description.as_union_value()),
                    description_type: hashgraph::Description::Reference,
                    roles: 0,
                    from: revoke.1.unwrap_or(self.timestamp.unwrap()),
                },
            );

            actions.push(action);
        }

        for modify in &self.modify {
            let modified_key = self.builder.create_vector(&modify.1);

            let description = hashgraph::Reference::create(
                &mut self.builder,
                &hashgraph::ReferenceArgs {
                    method: hashgraph::Method::Aure,
                    id: Some(modified_key),
                    controller: None,
                },
            );

            let action = hashgraph::Action::create(
                &mut self.builder,
                &hashgraph::ActionArgs {
                    actionable: hashgraph::Actionable::Modify,
                    description: Some(description.as_union_value()),
                    description_type: hashgraph::Description::Reference,
                    roles: modify.0,
                    from: self.timestamp.unwrap(),
                },
            );

            actions.push(action);
        }

        for grant in &self.grant_referenced {
            let granted_key = self.builder.create_vector(&grant.3);
            let controller = self.builder.create_vector(&grant.2);

            let description = hashgraph::Reference::create(
                &mut self.builder,
                &hashgraph::ReferenceArgs {
                    method: grant.0.into_method(),
                    id: Some(granted_key),
                    controller: Some(controller),
                },
            );

            let action = hashgraph::Action::create(
                &mut self.builder,
                &hashgraph::ActionArgs {
                    actionable: hashgraph::Actionable::Grant,
                    description: Some(description.as_union_value()),
                    description_type: hashgraph::Description::Reference,
                    roles: grant.1,
                    from: self.timestamp.unwrap(),
                },
            );

            actions.push(action);
        }

        for grant in &self.grant_embedded {
            let granted_key = self.builder.create_vector(&grant.1);

            let description = hashgraph::Embedded::create(
                &mut self.builder,
                &hashgraph::EmbeddedArgs {
                    id: Some(granted_key),
                    controller: None,
                },
            );

            let action = hashgraph::Action::create(
                &mut self.builder,
                &hashgraph::ActionArgs {
                    actionable: hashgraph::Actionable::Grant,
                    description: Some(description.as_union_value()),
                    description_type: hashgraph::Description::Embedded,
                    roles: grant.0,
                    from: self.timestamp.unwrap(),
                },
            );

            actions.push(action);
        }

        let actions_vec = self.builder.create_vector(&actions);
        let previous = self
            .previous
            .as_ref()
            .map(|hash| self.builder.create_vector(hash));

        let op = hashgraph::Operation::create(
            &mut self.builder,
            &hashgraph::OperationArgs {
                version: hashgraph::Version::V0,
                sequence: self.sequence.unwrap(),
                timestamp: self.timestamp.unwrap(),
                previous,
                actions: Some(actions_vec),
            },
        );

        self.builder.finish(op, None);

        // calculate hash over operation for signatures
        let op_bytes = self.builder.finished_data().to_vec();
        let op_hash = crate::crypto::hash::sha3(&op_bytes);
        self.builder.reset();

        // copy the operation hash to the signature buffer
        self.sig_buf[33..65].copy_from_slice(&op_hash);

        self.operation = Some(op_bytes);
    }
}

impl Default for OperationBuilder<'_> {
    fn default() -> Self {
        OperationBuilder::new()
    }
}
