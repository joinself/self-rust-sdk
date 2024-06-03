mod chat;
mod receipt;

pub use self::chat::*;
pub use self::receipt::*;

use crate::error::SelfError;
use crate::keypair::signing::PublicKey;
use crate::protocol::p2p;
use crate::time;

#[derive(Clone)]
pub enum Content {
    Chat(Chat),
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
        }
    }

    pub fn content_type(&self) -> ContentType {
        match self {
            &Content::Chat(_) => ContentType::Chat,
        }
    }
}

pub enum ContentType {
    Unknown,
    Custom,
    Chat,
    Receipt,
    CredentailVerifyRequest,
    CredentailVerifyResponse,
    CredentialPresentationRequest,
    CredentialPresentationResponse,
}

impl From<p2p::ContentType> for ContentType {
    fn from(value: p2p::ContentType) -> Self {
        match value {
            p2p::ContentType::TypeCustom => ContentType::Custom,
            p2p::ContentType::TypeChat => ContentType::Chat,
            p2p::ContentType::TypeReceipt => ContentType::Receipt,
            p2p::ContentType::TypeCredentialVerifyRequest => ContentType::CredentailVerifyRequest,
            p2p::ContentType::TypeCredentialVerifyResponse => ContentType::CredentailVerifyResponse,
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
            p2p::ContentType::TypeCredentialVerifyRequest => ContentType::CredentailVerifyRequest,
            p2p::ContentType::TypeCredentialVerifyResponse => ContentType::CredentailVerifyResponse,
            p2p::ContentType::TypeCredentialPresentationRequest => {
                ContentType::CredentialPresentationRequest
            }
            p2p::ContentType::TypeCredentialPresentationResponse => {
                ContentType::CredentialPresentationResponse
            }
        }
    }
}

impl Into<p2p::ContentType> for ContentType {
    fn into(self) -> p2p::ContentType {
        match self {
            ContentType::Unknown => unreachable!("not a possible selection"),
            ContentType::Custom => p2p::ContentType::TypeCustom,
            ContentType::Chat => p2p::ContentType::TypeChat,
            ContentType::Receipt => p2p::ContentType::TypeReceipt,
            ContentType::CredentailVerifyRequest => p2p::ContentType::TypeCredentialVerifyRequest,
            ContentType::CredentailVerifyResponse => p2p::ContentType::TypeCredentialVerifyResponse,
            ContentType::CredentialPresentationRequest => {
                p2p::ContentType::TypeCredentialPresentationRequest
            }
            ContentType::CredentialPresentationResponse => {
                p2p::ContentType::TypeCredentialPresentationResponse
            }
        }
    }
}

impl Into<i32> for ContentType {
    fn into(self) -> i32 {
        match self {
            ContentType::Unknown => unreachable!("not a possible selection"),
            ContentType::Custom => p2p::ContentType::TypeCustom as i32,
            ContentType::Chat => p2p::ContentType::TypeChat as i32,
            ContentType::Receipt => p2p::ContentType::TypeReceipt as i32,
            ContentType::CredentailVerifyRequest => {
                p2p::ContentType::TypeCredentialVerifyRequest as i32
            }
            ContentType::CredentailVerifyResponse => {
                p2p::ContentType::TypeCredentialVerifyResponse as i32
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

pub struct Message<'m> {
    id: &'m [u8],
    sender: &'m PublicKey,
    recipient: &'m PublicKey,
    content: &'m Content,
    timestamp: i64,
}

impl<'m> Message<'m> {
    pub fn new(
        id: &'m [u8],
        sender: &'m PublicKey,
        recipient: &'m PublicKey,
        content: &'m Content,
        timestamp: i64,
    ) -> Message<'m> {
        Message {
            id,
            sender,
            recipient,
            content,
            timestamp,
        }
    }

    pub fn id(&self) -> &'m [u8] {
        self.id
    }

    pub fn sender(&self) -> &'m PublicKey {
        self.sender
    }

    pub fn recipient(&self) -> &'m PublicKey {
        self.recipient
    }

    pub fn content_type(&self) -> ContentType {
        match self.content {
            Content::Chat(_) => ContentType::Chat,
        }
    }

    pub fn content(&self) -> &Content {
        self.content
    }

    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }
}

#[derive(Default)]
pub struct MessageBuilder<'m> {
    id: Option<&'m [u8]>,
    sender: Option<&'m PublicKey>,
    recipient: Option<&'m PublicKey>,
    content: Option<&'m Content>,
}

impl<'m> MessageBuilder<'m> {
    pub fn new() -> MessageBuilder<'m> {
        MessageBuilder {
            id: None,
            sender: None,
            recipient: None,
            content: None,
        }
    }

    pub fn id(&mut self, id: &'m [u8]) -> &mut MessageBuilder<'m> {
        self.id = Some(id);
        self
    }

    pub fn sender(&mut self, address: &'m PublicKey) -> &mut MessageBuilder<'m> {
        self.sender = Some(address);
        self
    }

    pub fn recipient(&mut self, address: &'m PublicKey) -> &mut MessageBuilder<'m> {
        self.recipient = Some(address);
        self
    }

    pub fn content(&mut self, content: &'m Content) -> &mut MessageBuilder<'m> {
        self.content = Some(content);
        self
    }

    pub fn finish(self) -> Result<Message<'m>, SelfError> {
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
