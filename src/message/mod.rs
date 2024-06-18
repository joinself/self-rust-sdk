mod chat;
mod credential;
mod event;
mod receipt;

pub use self::chat::*;
pub use self::credential::*;
pub use self::event::*;
pub use self::receipt::*;

use crate::error::SelfError;
use crate::keypair::signing::PublicKey;
use crate::protocol::p2p;

#[derive(Clone)]
pub enum Content {
    Chat(Chat),
    Receipt(Receipt),
    CredentialVerificationRequest(CredentialVerificationRequest),
    CredentialVerificationResponse(CredentialVerificationResponse),
    CredentialPresentationRequest(CredentialPresentationRequest),
    CredentialPresentationResponse(CredentialPresentationResponse),
}

impl Content {
    pub fn decode(content_type: ContentType, content: &[u8]) -> Result<Content, SelfError> {
        let content = match content_type {
            ContentType::Chat => Content::Chat(Chat::decode(content)?),
            ContentType::CredentialVerificationRequest => Content::CredentialVerificationRequest(
                CredentialVerificationRequest::decode(content)?,
            ),
            ContentType::CredentialVerificationResponse => Content::CredentialVerificationResponse(
                CredentialVerificationResponse::decode(content)?,
            ),
            ContentType::CredentialPresentationRequest => Content::CredentialPresentationRequest(
                CredentialPresentationRequest::decode(content)?,
            ),
            ContentType::CredentialPresentationResponse => Content::CredentialPresentationResponse(
                CredentialPresentationResponse::decode(content)?,
            ),
            _ => return Err(SelfError::MessageContentUnknown),
        };

        Ok(content)
    }

    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        match self {
            Content::Chat(chat) => Ok(chat.encode()),
            Content::Receipt(receipt) => Ok(receipt.encode()),
            Content::CredentialVerificationRequest(request) => Ok(request.encode()),
            Content::CredentialVerificationResponse(response) => Ok(response.encode()),
            Content::CredentialPresentationRequest(request) => Ok(request.encode()),
            Content::CredentialPresentationResponse(response) => Ok(response.encode()),
        }
    }

    pub fn content_type(&self) -> ContentType {
        match *self {
            Content::Chat(_) => ContentType::Chat,
            Content::Receipt(_) => ContentType::Receipt,
            Content::CredentialVerificationRequest(_) => ContentType::CredentialVerificationRequest,
            Content::CredentialVerificationResponse(_) => {
                ContentType::CredentialVerificationResponse
            }
            Content::CredentialPresentationRequest(_) => ContentType::CredentialPresentationRequest,
            Content::CredentialPresentationResponse(_) => {
                ContentType::CredentialPresentationResponse
            }
        }
    }
}

pub enum ContentType {
    Unknown,
    Custom,
    Chat,
    Receipt,
    CredentialVerificationRequest,
    CredentialVerificationResponse,
    CredentialPresentationRequest,
    CredentialPresentationResponse,
}

impl From<p2p::ContentType> for ContentType {
    fn from(value: p2p::ContentType) -> Self {
        match value {
            p2p::ContentType::TypeCustom => ContentType::Custom,
            p2p::ContentType::TypeChat => ContentType::Chat,
            p2p::ContentType::TypeReceipt => ContentType::Receipt,
            p2p::ContentType::TypeCredentialVerificationRequest => {
                ContentType::CredentialVerificationRequest
            }
            p2p::ContentType::TypeCredentialVerificationResponse => {
                ContentType::CredentialVerificationResponse
            }
            p2p::ContentType::TypeCredentialPresentationRequest => {
                ContentType::CredentialPresentationRequest
            }
            p2p::ContentType::TypeCredentialPresentationResponse => {
                ContentType::CredentialPresentationResponse
            }
        }
    }
}

impl From<i32> for ContentType {
    fn from(value: i32) -> Self {
        let content_type = match p2p::ContentType::try_from(value) {
            Ok(content_type) => content_type,
            Err(_) => return ContentType::Unknown,
        };

        match content_type {
            p2p::ContentType::TypeCustom => ContentType::Custom,
            p2p::ContentType::TypeChat => ContentType::Chat,
            p2p::ContentType::TypeReceipt => ContentType::Receipt,
            p2p::ContentType::TypeCredentialVerificationRequest => {
                ContentType::CredentialVerificationRequest
            }
            p2p::ContentType::TypeCredentialVerificationResponse => {
                ContentType::CredentialVerificationResponse
            }
            p2p::ContentType::TypeCredentialPresentationRequest => {
                ContentType::CredentialPresentationRequest
            }
            p2p::ContentType::TypeCredentialPresentationResponse => {
                ContentType::CredentialPresentationResponse
            }
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<p2p::ContentType> for ContentType {
    fn into(self) -> p2p::ContentType {
        match self {
            ContentType::Unknown => unreachable!("not a possible selection"),
            ContentType::Custom => p2p::ContentType::TypeCustom,
            ContentType::Chat => p2p::ContentType::TypeChat,
            ContentType::Receipt => p2p::ContentType::TypeReceipt,
            ContentType::CredentialVerificationRequest => {
                p2p::ContentType::TypeCredentialVerificationRequest
            }
            ContentType::CredentialVerificationResponse => {
                p2p::ContentType::TypeCredentialVerificationResponse
            }
            ContentType::CredentialPresentationRequest => {
                p2p::ContentType::TypeCredentialPresentationRequest
            }
            ContentType::CredentialPresentationResponse => {
                p2p::ContentType::TypeCredentialPresentationResponse
            }
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<i32> for ContentType {
    fn into(self) -> i32 {
        match self {
            ContentType::Unknown => unreachable!("not a possible selection"),
            ContentType::Custom => p2p::ContentType::TypeCustom as i32,
            ContentType::Chat => p2p::ContentType::TypeChat as i32,
            ContentType::Receipt => p2p::ContentType::TypeReceipt as i32,
            ContentType::CredentialVerificationRequest => {
                p2p::ContentType::TypeCredentialVerificationRequest as i32
            }
            ContentType::CredentialVerificationResponse => {
                p2p::ContentType::TypeCredentialVerificationResponse as i32
            }
            ContentType::CredentialPresentationRequest => {
                p2p::ContentType::TypeCredentialPresentationRequest as i32
            }
            ContentType::CredentialPresentationResponse => {
                p2p::ContentType::TypeCredentialPresentationResponse as i32
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ResponseStatus {
    Unknown,
    Ok,
    Accepted,
    Created,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    NotAcceptable,
    Conflict,
}

#[allow(clippy::from_over_into)]
impl From<p2p::Status> for ResponseStatus {
    fn from(value: p2p::Status) -> ResponseStatus {
        match value {
            p2p::Status::Ok => ResponseStatus::Ok,
            p2p::Status::Accepted => ResponseStatus::Accepted,
            p2p::Status::Created => ResponseStatus::Created,
            p2p::Status::BadRequest => ResponseStatus::BadRequest,
            p2p::Status::Unauthorized => ResponseStatus::Unauthorized,
            p2p::Status::Forbidden => ResponseStatus::Forbidden,
            p2p::Status::NotFound => ResponseStatus::NotFound,
            p2p::Status::NotAcceptable => ResponseStatus::NotAcceptable,
            p2p::Status::Conflict => ResponseStatus::Conflict,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<p2p::Status> for ResponseStatus {
    fn into(self) -> p2p::Status {
        match self {
            ResponseStatus::Unknown => unreachable!("not a possible selection"),
            ResponseStatus::Ok => p2p::Status::Ok,
            ResponseStatus::Accepted => p2p::Status::Accepted,
            ResponseStatus::Created => p2p::Status::Created,
            ResponseStatus::BadRequest => p2p::Status::BadRequest,
            ResponseStatus::Unauthorized => p2p::Status::Unauthorized,
            ResponseStatus::Forbidden => p2p::Status::Forbidden,
            ResponseStatus::NotFound => p2p::Status::NotFound,
            ResponseStatus::NotAcceptable => p2p::Status::NotAcceptable,
            ResponseStatus::Conflict => p2p::Status::Conflict,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<i32> for ResponseStatus {
    fn into(self) -> i32 {
        match self {
            ResponseStatus::Unknown => unreachable!("not a possible selection"),
            ResponseStatus::Ok => p2p::Status::Ok as i32,
            ResponseStatus::Accepted => p2p::Status::Accepted as i32,
            ResponseStatus::Created => p2p::Status::Created as i32,
            ResponseStatus::BadRequest => p2p::Status::BadRequest as i32,
            ResponseStatus::Unauthorized => p2p::Status::Unauthorized as i32,
            ResponseStatus::Forbidden => p2p::Status::Forbidden as i32,
            ResponseStatus::NotFound => p2p::Status::NotFound as i32,
            ResponseStatus::NotAcceptable => p2p::Status::NotAcceptable as i32,
            ResponseStatus::Conflict => p2p::Status::Conflict as i32,
        }
    }
}

pub struct Message {
    id: Vec<u8>,
    from_address: PublicKey,
    to_address: PublicKey,
    content: Content,
    sequence: u64,
    timestamp: i64,
}

impl Message {
    pub fn new(
        id: Vec<u8>,
        from_address: PublicKey,
        to_address: PublicKey,
        content: Content,
        sequence: u64,
        timestamp: i64,
    ) -> Message {
        Message {
            id,
            from_address,
            to_address,
            content,
            sequence,
            timestamp,
        }
    }

    pub fn id(&self) -> &[u8] {
        &self.id
    }

    pub fn from_address(&self) -> &PublicKey {
        &self.from_address
    }

    pub fn to_address(&self) -> &PublicKey {
        &self.to_address
    }

    pub fn content_type(&self) -> ContentType {
        match self.content {
            Content::Chat(_) => ContentType::Chat,
            Content::Receipt(_) => ContentType::Receipt,
            Content::CredentialVerificationRequest(_) => ContentType::CredentialVerificationRequest,
            Content::CredentialVerificationResponse(_) => {
                ContentType::CredentialVerificationResponse
            }
            Content::CredentialPresentationRequest(_) => ContentType::CredentialPresentationRequest,
            Content::CredentialPresentationResponse(_) => {
                ContentType::CredentialPresentationResponse
            }
        }
    }

    pub fn content(&self) -> &Content {
        &self.content
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }
}
