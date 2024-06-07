use std::ops::Add;

use prost::Message;

use crate::credential;
use crate::object::{self, Object};
use crate::{error::SelfError, protocol::p2p};

use super::Content;

#[derive(Clone)]
pub struct CredentialVerificationRequest {
    verification_request: p2p::CredentialVerificationRequest,
}

impl CredentialVerificationRequest {
    pub fn credential_type(&self) -> &[String] {
        &self.verification_request.r#type
    }

    pub fn proof(&self) -> Result<Vec<credential::VerifiableCredential>, SelfError> {
        let mut credentials = Vec::new();

        for proof in &self.verification_request.proof {
            credentials.push(credential::VerifiableCredential::from_bytes(
                &proof.credential,
            )?);
        }

        Ok(credentials)
    }

    pub fn evidence(&self) -> Result<Vec<(String, object::Object)>, SelfError> {
        let mut objects = Vec::new();

        for evidence in &self.verification_request.evidence {
            let object = match &evidence.object {
                Some(object) => object,
                None => return Err(SelfError::ObjectKeyMissing),
            };

            objects.push((
                evidence.id.to_owned(),
                object::Object::new(
                    object.id.to_vec(),
                    object.key.to_vec(),
                    object.mime.to_string(),
                ),
            ));
        }

        Ok(objects)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.verification_request.encode_to_vec()
    }

    pub fn decode(content: &[u8]) -> Result<CredentialVerificationRequest, SelfError> {
        let verification_request =
            p2p::CredentialVerificationRequest::decode(content).map_err(|err| {
                println!("protobuf decode error: {}", err);
                SelfError::MessageEncodingInvalid
            })?;

        Ok(CredentialVerificationRequest {
            verification_request,
        })
    }
}

#[derive(Default)]
pub struct CredentialVerificationRequestBuilder {
    credential_type: Vec<String>,
    proof: Vec<credential::VerifiableCredential>,
    evidence: Vec<(String, object::Object)>,
    expires: i64,
}

impl CredentialVerificationRequestBuilder {
    pub fn new() -> CredentialVerificationRequestBuilder {
        CredentialVerificationRequestBuilder {
            credential_type: Vec::new(),
            proof: Vec::new(),
            evidence: Vec::new(),
            expires: crate::time::now()
                .add(std::time::Duration::from_secs(3600))
                .timestamp(),
        }
    }

    pub fn credential_type(
        &mut self,
        credential_type: Vec<String>,
    ) -> &mut CredentialVerificationRequestBuilder {
        self.credential_type = credential_type;
        self
    }

    pub fn proof(
        &mut self,
        verifiable_credential: credential::VerifiableCredential,
    ) -> &mut CredentialVerificationRequestBuilder {
        self.proof.push(verifiable_credential);
        self
    }

    pub fn evidence(
        &mut self,
        id: String,
        object: object::Object,
    ) -> &mut CredentialVerificationRequestBuilder {
        self.evidence.push((id, object));
        self
    }

    pub fn finish(&self) -> Result<Content, SelfError> {
        let mut evidence = Vec::new();
        let mut proof = Vec::new();

        for (identifier, object) in &self.evidence {
            let id = object.id().to_vec();
            let key = match object.key() {
                Some(key) => key.to_vec(),
                None => return Err(SelfError::ObjectKeyMissing),
            };
            let mime = object.mime().to_string();

            evidence.push(p2p::Evidence {
                id: identifier.clone(),
                object: Some(p2p::Object { id, key, mime }),
            })
        }

        for verifiable_credential in &self.proof {
            proof.push(p2p::Proof {
                credential: verifiable_credential.into_bytes()?,
            })
        }

        Ok(Content::CredentialVerificationRequest(
            CredentialVerificationRequest {
                verification_request: p2p::CredentialVerificationRequest {
                    header: Some(p2p::RequestHeader {
                        expires: self.expires,
                    }),
                    r#type: self.credential_type.clone(),
                    evidence,
                    proof,
                },
            },
        ))
    }
}
