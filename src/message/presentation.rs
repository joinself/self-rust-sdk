use std::collections::HashMap;
use std::ops::Add;

use prost::Message;

use crate::credential;
use crate::credential::VerifiablePresentation;
use crate::{error::SelfError, protocol::p2p};

use super::{Content, ResponseStatus};

#[derive(Clone)]
pub struct CredentialPresentationDetail {
    pub credential_type: Vec<String>,
    pub subject: HashMap<String, String>,
}

#[derive(Clone)]
pub struct CredentialPresentationRequest {
    presentation_request: p2p::CredentialPresentationRequest,
}

impl CredentialPresentationRequest {
    pub fn presentation_type(&self) -> &[String] {
        &self.presentation_request.presentation_type
    }

    pub fn details(&self) -> Result<Vec<CredentialPresentationDetail>, SelfError> {
        let mut details = Vec::new();

        for detail in &self.presentation_request.details {
            let credential_type = detail.credential_type.to_vec();
            let subject: HashMap<String, String> = match serde_json::from_slice(&detail.subject) {
                Ok(subject) => subject,
                Err(_) => return Err(SelfError::MessagePresentationDetailInvalid),
            };

            details.push(CredentialPresentationDetail {
                credential_type,
                subject,
            });
        }

        Ok(details)
    }

    pub fn expires(&self) -> i64 {
        if let Some(header) = self.presentation_request.header.as_ref() {
            header.expires
        } else {
            0
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.presentation_request.encode_to_vec()
    }

    pub fn decode(content: &[u8]) -> Result<CredentialPresentationRequest, SelfError> {
        let presentation_request =
            p2p::CredentialPresentationRequest::decode(content).map_err(|err| {
                println!("protobuf decode error: {}", err);
                SelfError::MessageEncodingInvalid
            })?;

        Ok(CredentialPresentationRequest {
            presentation_request,
        })
    }
}

#[derive(Default)]
pub struct CredentialPresentationRequestBuilder {
    presentation_type: Vec<String>,
    details: Vec<CredentialPresentationDetail>,
    expires: i64,
}

impl CredentialPresentationRequestBuilder {
    pub fn new() -> CredentialPresentationRequestBuilder {
        CredentialPresentationRequestBuilder {
            presentation_type: Vec::new(),
            details: Vec::new(),
            expires: crate::time::now()
                .add(std::time::Duration::from_secs(3600))
                .timestamp(),
        }
    }

    pub fn presentation_type(
        &mut self,
        presentation_type: Vec<String>,
    ) -> &mut CredentialPresentationRequestBuilder {
        self.presentation_type = presentation_type;
        self
    }

    pub fn details(
        &mut self,
        detail: CredentialPresentationDetail,
    ) -> &mut CredentialPresentationRequestBuilder {
        self.details.push(detail);
        self
    }

    pub fn expires(&mut self, expires: i64) -> &mut CredentialPresentationRequestBuilder {
        self.expires = expires;
        self
    }

    pub fn finish(&self) -> Result<Content, SelfError> {
        let mut details = Vec::new();

        for detail in &self.details {
            details.push(p2p::PresentationDetails {
                credential_type: detail.credential_type.clone(),
                subject: serde_json::to_vec(&detail.subject)
                    .map_err(|_| SelfError::MessagePresentationDetailInvalid)?,
            })
        }

        Ok(Content::CredentialPresentationRequest(
            CredentialPresentationRequest {
                presentation_request: p2p::CredentialPresentationRequest {
                    header: Some(p2p::RequestHeader {
                        expires: self.expires,
                    }),
                    presentation_type: self.presentation_type.clone(),
                    details,
                },
            },
        ))
    }
}

#[derive(Clone)]
pub struct CredentialPresentationResponse {
    presentation_response: p2p::CredentialPresentationResponse,
}

impl CredentialPresentationResponse {
    pub fn status(&self) -> ResponseStatus {
        match &self.presentation_response.header {
            Some(header) => ResponseStatus::from(header.status()),
            None => ResponseStatus::Unknown,
        }
    }

    pub fn error_message(&self) -> Option<&str> {
        None
    }

    pub fn presentations(&self) -> Result<Vec<credential::VerifiablePresentation>, SelfError> {
        let mut presentations = Vec::new();

        for presentation in &self.presentation_response.presentations {
            presentations.push(VerifiablePresentation::from_bytes(presentation)?);
        }

        Ok(presentations)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.presentation_response.encode_to_vec()
    }

    pub fn decode(content: &[u8]) -> Result<CredentialPresentationResponse, SelfError> {
        let presentation_response =
            p2p::CredentialPresentationResponse::decode(content).map_err(|err| {
                println!("protobuf decode error: {}", err);
                SelfError::MessageEncodingInvalid
            })?;

        Ok(CredentialPresentationResponse {
            presentation_response,
        })
    }
}

#[derive(Default)]
pub struct CredentialPresentationResponseBuilder {
    presentations: Vec<credential::VerifiablePresentation>,
    status: Option<ResponseStatus>,
    error_message: Option<String>,
}

impl CredentialPresentationResponseBuilder {
    pub fn new() -> CredentialPresentationResponseBuilder {
        CredentialPresentationResponseBuilder {
            presentations: Vec::new(),
            status: None,
            error_message: None,
        }
    }

    pub fn status(&mut self, status: ResponseStatus) -> &mut CredentialPresentationResponseBuilder {
        self.status = Some(status);
        self
    }

    pub fn error_message(
        &mut self,
        error_message: String,
    ) -> &mut CredentialPresentationResponseBuilder {
        self.error_message = Some(error_message);
        self
    }

    pub fn presentation(
        &mut self,
        verifiable_presentation: credential::VerifiablePresentation,
    ) -> &mut CredentialPresentationResponseBuilder {
        self.presentations.push(verifiable_presentation);
        self
    }

    pub fn finish(&self) -> Result<Content, SelfError> {
        let status = match &self.status {
            Some(status) => status.clone(),
            None => return Err(SelfError::MessageResponseStatusMissing),
        };

        let mut presentations = Vec::new();

        for verifiable_presentation in &self.presentations {
            presentations.push(verifiable_presentation.into_bytes()?)
        }

        Ok(Content::CredentialPresentationResponse(
            CredentialPresentationResponse {
                presentation_response: p2p::CredentialPresentationResponse {
                    header: Some(p2p::ResponseHeader {
                        status: status.into(),
                    }),
                    presentations,
                },
            },
        ))
    }
}
