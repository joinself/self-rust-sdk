use crate::{
    error::SelfError,
    keypair::signing::{KeyPair, PublicKey},
    protocol::hashgraph,
};

pub struct OperationBuilder<'a> {
    previous: Option<Vec<u8>>,
    sequence: Option<u32>,
    timestamp: Option<i64>,
    revoke: Vec<(PublicKey, Option<i64>)>,
    recover: Vec<Option<i64>>,
    grant_embedded: Vec<(hashgraph::Role, PublicKey)>,
    grant_referenced: Vec<(hashgraph::Method, hashgraph::Role, Vec<u8>, PublicKey)>,
    operation: Option<Vec<u8>>,
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
            grant_embedded: Vec::new(),
            grant_referenced: Vec::new(),
            operation: None,
            signatures: Vec::new(),
            sig_buf: vec![0; 96],
            builder: flatbuffers::FlatBufferBuilder::with_capacity(1024),
        };
    }

    pub fn id(&mut self, id: &[u8]) -> &mut OperationBuilder<'a> {
        self.sig_buf[..32].copy_from_slice(id);
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

    pub fn key_grant_embedded(
        &mut self,
        pk: &PublicKey,
        roles: hashgraph::Role,
    ) -> &mut OperationBuilder<'a> {
        self.grant_embedded.push((roles, pk.to_owned()));
        self
    }

    pub fn key_grant_referenced(
        &mut self,
        method: hashgraph::Method,
        controller: &[u8],
        pk: &PublicKey,
        roles: hashgraph::Role,
    ) -> &mut OperationBuilder<'a> {
        self.grant_referenced
            .push((method, roles, controller.to_owned(), pk.to_owned()));
        self
    }

    pub fn key_revoke(
        &mut self,
        pk: &PublicKey,
        effective_from: Option<i64>,
    ) -> &mut OperationBuilder<'a> {
        self.revoke.push((pk.to_owned(), effective_from));
        self
    }

    pub fn recover(&mut self, effective_from: Option<i64>) -> &mut OperationBuilder<'a> {
        self.recover.push(effective_from);
        self
    }

    pub fn sign(&mut self, kp: &KeyPair) -> &mut OperationBuilder<'a> {
        if self.operation.is_none() {
            self.build_operation();
        }

        self.builder.reset();

        let sb = self.builder.create_vector(&kp.id());

        let header = hashgraph::SignatureHeader::create(
            &mut self.builder,
            &hashgraph::SignatureHeaderArgs { signer: Some(sb) },
        );

        self.builder.finish(header, None);

        let header_bytes = self.builder.finished_data().to_vec();
        let header_hash = crate::crypto::hash::blake2b(&header_bytes);
        self.builder.reset();

        self.sig_buf[64..].copy_from_slice(&header_hash);
        let signature = kp.sign(&self.sig_buf);

        self.signatures.push((header_bytes, signature));

        self
    }

    pub fn build(&mut self) -> Result<Vec<u8>, SelfError> {
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
                    description_type: hashgraph::Description::Reference,
                    roles: 0,
                    from: recover.unwrap_or(self.timestamp.unwrap()),
                },
            );

            actions.push(action);
        }

        for revoke in &self.revoke {
            let revoked_key = self.builder.create_vector(&revoke.0.id());

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

        for grant in &self.grant_referenced {
            let granted_key = self.builder.create_vector(&grant.3.id());
            let controller = self.builder.create_vector(&grant.2);

            let description = hashgraph::Reference::create(
                &mut self.builder,
                &&&hashgraph::ReferenceArgs {
                    method: grant.0,
                    id: Some(granted_key),
                    controller: Some(controller),
                },
            );

            let action = hashgraph::Action::create(
                &mut self.builder,
                &hashgraph::ActionArgs {
                    actionable: hashgraph::Actionable::Revoke,
                    description: Some(description.as_union_value()),
                    description_type: hashgraph::Description::Reference,
                    roles: grant.1.bits(),
                    from: self.timestamp.unwrap(),
                },
            );

            actions.push(action);
        }

        for grant in &self.grant_embedded {
            let granted_key = self.builder.create_vector(&grant.1.id());

            let description = hashgraph::Embedded::create(
                &mut self.builder,
                &&hashgraph::EmbeddedArgs {
                    id: Some(granted_key),
                    controller: None,
                },
            );

            let action = hashgraph::Action::create(
                &mut self.builder,
                &hashgraph::ActionArgs {
                    actionable: hashgraph::Actionable::Revoke,
                    description: Some(description.as_union_value()),
                    description_type: hashgraph::Description::Reference,
                    roles: grant.0.bits(),
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
        let op_hash = crate::crypto::hash::blake2b(&op_bytes);
        self.builder.reset();

        // copy the operation hash to the signature buffer
        self.sig_buf[32..64].copy_from_slice(&op_hash);

        self.operation = Some(op_bytes);
    }
}

impl Default for OperationBuilder<'_> {
    fn default() -> Self {
        OperationBuilder::new()
    }
}
