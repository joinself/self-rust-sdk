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
use crate::time;

#[derive(Clone)]
pub enum Content {
    Chat(Chat),
    CredentialVerificationRequest(CredentialVerificationRequest),
}

impl Content {
    pub fn decode(content_type: ContentType, content: &[u8]) -> Result<Content, SelfError> {
        let content = match content_type {
            ContentType::Chat => Content::Chat(Chat::decode(content)?),
            _ => return Err(SelfError::MessageContentUnknown),
        };

        Ok(content)
    }

    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        match self {
            Content::Chat(chat) => Ok(chat.encode()),
            Content::CredentialVerificationRequest(request) => Ok(request.encode()),
        }
    }

    pub fn content_type(&self) -> ContentType {
        match *self {
            Content::Chat(_) => ContentType::Chat,
            Content::CredentialVerificationRequest(_) => ContentType::CredentailVerificationRequest,
        }
    }
}

pub enum ContentType {
    Unknown,
    Custom,
    Chat,
    Receipt,
    CredentailVerificationRequest,
    CredentailVerificationResponse,
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
                ContentType::CredentailVerificationRequest
            }
            p2p::ContentType::TypeCredentialVerificationResponse => {
                ContentType::CredentailVerificationResponse
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
                ContentType::CredentailVerificationRequest
            }
            p2p::ContentType::TypeCredentialVerificationResponse => {
                ContentType::CredentailVerificationResponse
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
            ContentType::CredentailVerificationRequest => {
                p2p::ContentType::TypeCredentialVerificationRequest
            }
            ContentType::CredentailVerificationResponse => {
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
            ContentType::CredentailVerificationRequest => {
                p2p::ContentType::TypeCredentialVerificationRequest as i32
            }
            ContentType::CredentailVerificationResponse => {
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

pub struct Message {
    id: Vec<u8>,
    sender: PublicKey,
    recipient: PublicKey,
    content: Content,
    timestamp: i64,
}

impl Message {
    pub fn new(
        id: Vec<u8>,
        sender: PublicKey,
        recipient: PublicKey,
        content: Content,
        timestamp: i64,
    ) -> Message {
        Message {
            id,
            sender,
            recipient,
            content,
            timestamp,
        }
    }

    pub fn id(&self) -> &[u8] {
        &self.id
    }

    pub fn sender(&self) -> &PublicKey {
        &self.sender
    }

    pub fn recipient(&self) -> &PublicKey {
        &self.recipient
    }

    pub fn content_type(&self) -> ContentType {
        match self.content {
            Content::Chat(_) => ContentType::Chat,
            Content::CredentialVerificationRequest(_) => ContentType::CredentailVerificationRequest,
        }
    }

    pub fn content(&self) -> &Content {
        &self.content
    }

    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }
}

#[derive(Default)]
pub struct MessageBuilder {
    id: Option<Vec<u8>>,
    sender: Option<PublicKey>,
    recipient: Option<PublicKey>,
    content: Option<Content>,
}

impl MessageBuilder {
    pub fn new() -> MessageBuilder {
        MessageBuilder {
            id: None,
            sender: None,
            recipient: None,
            content: None,
        }
    }

    pub fn id(&mut self, id: Vec<u8>) -> &mut MessageBuilder {
        self.id = Some(id);
        self
    }

    pub fn sender(&mut self, address: PublicKey) -> &mut MessageBuilder {
        self.sender = Some(address);
        self
    }

    pub fn recipient(&mut self, address: PublicKey) -> &mut MessageBuilder {
        self.recipient = Some(address);
        self
    }

    pub fn content(&mut self, content: Content) -> &mut MessageBuilder {
        self.content = Some(content);
        self
    }

    pub fn finish(self) -> Result<Message, SelfError> {
        let id = match self.id {
            Some(id) => id,
            None => return Err(SelfError::MessageContentMissing),
        };

        let sender = match self.sender {
            Some(sender) => sender,
            None => return Err(SelfError::MessageSenderMissing),
        };

        let recipient = match self.recipient {
            Some(recipient) => recipient,
            None => return Err(SelfError::MessageRecipientMissing),
        };

        let content = match self.content {
            Some(content) => content,
            None => return Err(SelfError::MessageContentMissing),
        };

        let timestamp = time::unix();

        Ok(Message {
            id,
            sender,
            recipient,
            content,
            timestamp,
        })
    }
}
