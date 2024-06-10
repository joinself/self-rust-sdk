use prost::Message;

use crate::{error::SelfError, object, protocol::p2p};

use super::Content;

#[derive(Clone)]
pub struct Chat {
    chat: p2p::Chat,
}

impl Chat {
    pub fn message(&self) -> &str {
        &self.chat.message
    }

    pub fn referencing(&self) -> &[u8] {
        &self.chat.referencing
    }

    pub fn attachments(&self) -> Vec<object::Object> {
        self.chat
            .attachments
            .iter()
            .map(|o| object::Object::new(o.id.clone(), o.key.clone(), o.mime.clone()))
            .collect()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.chat.encode_to_vec()
    }

    pub fn decode(content: &[u8]) -> Result<Chat, SelfError> {
        let chat = p2p::Chat::decode(content).map_err(|err| {
            println!("protobuf decode error: {}", err);
            SelfError::MessageEncodingInvalid
        })?;

        Ok(Chat { chat })
    }
}

#[derive(Default)]
pub struct ChatBuilder {
    message: Option<String>,
    referencing: Option<Vec<u8>>,
    attachments: Vec<object::Object>,
}

impl ChatBuilder {
    pub fn new() -> ChatBuilder {
        ChatBuilder {
            message: None,
            referencing: None,
            attachments: Vec::new(),
        }
    }

    pub fn message(&mut self, message: &str) -> &mut ChatBuilder {
        self.message = Some(String::from(message));
        self
    }

    pub fn reference(&mut self, reference: &[u8]) -> &mut ChatBuilder {
        self.referencing = Some(reference.to_vec());
        self
    }

    pub fn attach(&mut self, attachment: object::Object) -> &mut ChatBuilder {
        self.attachments.push(attachment);
        self
    }

    pub fn finish(&self) -> Result<Content, SelfError> {
        let message = match &self.message {
            Some(message) => message.clone(),
            None => return Err(SelfError::MessageContentMissing),
        };

        let referencing = match &self.referencing {
            Some(referencing) => referencing.clone(),
            None => Vec::new(),
        };

        let mut attachments = Vec::new();

        for obj in &self.attachments {
            let key = match obj.key() {
                Some(key) => key,
                None => return Err(SelfError::ObjectKeyMissing),
            };

            attachments.push(p2p::Object {
                id: obj.id().to_vec(),
                key: key.to_vec(),
                mime: obj.mime().to_string(),
            });
        }

        Ok(Content::Chat(Chat {
            chat: p2p::Chat {
                message,
                referencing,
                attachments,
            },
        }))
    }
}
