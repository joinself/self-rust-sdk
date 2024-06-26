use std::ops::Add;

use prost::Message;

use crate::credential;
use crate::object;
use crate::{error::SelfError, protocol::p2p};

use super::{Content, ResponseStatus};

#[derive(Clone)]
pub struct CredentialVerificationEvidence {
    pub evidence_type: String,
    pub object: object::Object,
}

#[derive(Clone)]
pub struct CredentialVerificationRequest {
    verification_request: p2p::CredentialVerificationRequest,
}

impl CredentialVerificationRequest {
    pub fn credential_type(&self) -> &[String] {
        &self.verification_request.credential_type
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

    pub fn evidence(&self) -> Result<Vec<CredentialVerificationEvidence>, SelfError> {
        let mut objects = Vec::new();

        for evidence in &self.verification_request.evidence {
            let object = match &evidence.object {
                Some(object) => object,
                None => return Err(SelfError::ObjectKeyMissing),
            };

            objects.push(CredentialVerificationEvidence {
                evidence_type: evidence.id.to_owned(),
                object: object::Object::new(
                    object.id.to_vec(),
                    object.key.to_vec(),
                    object.mime.to_string(),
                ),
            });
        }

        Ok(objects)
    }

    pub fn expires(&self) -> i64 {
        if let Some(header) = self.verification_request.header.as_ref() {
            header.expires
        } else {
            0
        }
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
    evidence: Vec<CredentialVerificationEvidence>,
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
        evidence_type: String,
        object: object::Object,
    ) -> &mut CredentialVerificationRequestBuilder {
        self.evidence.push(CredentialVerificationEvidence {
            evidence_type,
            object,
        });
        self
    }

    pub fn expires(&mut self, expires: i64) -> &mut CredentialVerificationRequestBuilder {
        self.expires = expires;
        self
    }

    pub fn finish(&self) -> Result<Content, SelfError> {
        let mut evidence = Vec::new();
        let mut proof = Vec::new();

        for item in &self.evidence {
            let id = item.object.id().to_vec();
            let key = match item.object.key() {
                Some(key) => key.to_vec(),
                None => return Err(SelfError::ObjectKeyMissing),
            };
            let mime = item.object.mime().to_string();

            evidence.push(p2p::Evidence {
                id: item.evidence_type.clone(),
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
                    credential_type: self.credential_type.clone(),
                    evidence,
                    proof,
                },
            },
        ))
    }
}

#[derive(Clone)]
pub struct CredentialVerificationResponse {
    verification_response: p2p::CredentialVerificationResponse,
}

impl CredentialVerificationResponse {
    pub fn status(&self) -> ResponseStatus {
        match &self.verification_response.header {
            Some(header) => ResponseStatus::from(header.status()),
            None => ResponseStatus::Unknown,
        }
    }

    pub fn error_message(&self) -> Option<&str> {
        None
    }

    pub fn credentials(&self) -> Result<Vec<credential::VerifiableCredential>, SelfError> {
        let mut credentials = Vec::new();

        for verified_credential in &self.verification_response.credentials {
            credentials.push(credential::VerifiableCredential::from_bytes(
                verified_credential,
            )?);
        }

        Ok(credentials)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.verification_response.encode_to_vec()
    }

    pub fn decode(content: &[u8]) -> Result<CredentialVerificationResponse, SelfError> {
        let verification_response =
            p2p::CredentialVerificationResponse::decode(content).map_err(|err| {
                println!("protobuf decode error: {}", err);
                SelfError::MessageEncodingInvalid
            })?;

        Ok(CredentialVerificationResponse {
            verification_response,
        })
    }
}

#[derive(Default)]
pub struct CredentialVerificationResponseBuilder {
    credentials: Vec<credential::VerifiableCredential>,
    status: Option<ResponseStatus>,
    error_message: Option<String>,
}

impl CredentialVerificationResponseBuilder {
    pub fn new() -> CredentialVerificationResponseBuilder {
        CredentialVerificationResponseBuilder {
            credentials: Vec::new(),
            status: None,
            error_message: None,
        }
    }

    pub fn status(&mut self, status: ResponseStatus) -> &mut CredentialVerificationResponseBuilder {
        self.status = Some(status);
        self
    }

    pub fn error_message(
        &mut self,
        error_message: String,
    ) -> &mut CredentialVerificationResponseBuilder {
        self.error_message = Some(error_message);
        self
    }

    pub fn credential(
        &mut self,
        verifiable_credential: credential::VerifiableCredential,
    ) -> &mut CredentialVerificationResponseBuilder {
        self.credentials.push(verifiable_credential);
        self
    }

    pub fn finish(&self) -> Result<Content, SelfError> {
        let status = match &self.status {
            Some(status) => status.clone(),
            None => return Err(SelfError::MessageResponseStatusMissing),
        };

        let mut credentials = Vec::new();

        for verifiable_credential in &self.credentials {
            credentials.push(verifiable_credential.into_bytes()?)
        }

        Ok(Content::CredentialVerificationResponse(
            CredentialVerificationResponse {
                verification_response: p2p::CredentialVerificationResponse {
                    header: Some(p2p::ResponseHeader {
                        status: status.into(),
                    }),
                    credentials,
                },
            },
        ))
    }
}
