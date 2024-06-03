use prost::Message;

use crate::{error::SelfError, protocol::p2p};

pub struct CredentialVerificationRequest {
    verification_request: p2p::CredentialVerificationRequest,
}

impl CredentialVerificationRequest {

    pub fn encode(&self) -> Vec<u8> {
        self.verification_request.encode_to_vec()
    }

    pub fn decode(content: &[u8]) -> Result<CredentialVerificationRequest, SelfError> {
        let verification_request = p2p::CredentialVerificationRequest::decode(content).map_err(|err| {
            println!("protobuf decode error: {}", err);
            SelfError::MessageEncodingInvalid
        })?;

        Ok(CredentialVerificationRequest{
            verification_request
        })
    }
}

#[derive(Default)]
pub struct CredentialVerificationRequestBuilder {
    
}

impl CredentialVerificationRequestBuilder {
    pub fn new() -> CredentialVerificationRequestBuilder {
        CredentialVerificationRequestBuilder{

        }
    }

    pub fn finish(self) -> Result<CredentialVerificationRequest, SelfError> {
        Ok(CredentialVerificationRequest { 
            receipt: p2p::CredentialVerificationRequest { 
            }
        })
    }
}