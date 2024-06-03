use prost::Message;

use crate::{error::SelfError, protocol::p2p};

use super::Content;

#[derive(Clone)]
pub struct Chat {
    chat: p2p::Chat,
}

impl Chat {
    pub fn message(&self) -> &str {
        &self.chat.msg
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
}

impl ChatBuilder {
    pub fn new() -> ChatBuilder {
        ChatBuilder { message: None }
    }

    pub fn message(&mut self, message: &str) -> &mut ChatBuilder {
        self.message = Some(String::from(message));
        self
    }

    pub fn finish(&self) -> Result<Content, SelfError> {
        let message = match &self.message {
            Some(message) => message,
            None => return Err(SelfError::MessageContentMissing),
        };

        Ok(Content::Chat(Chat {
            chat: p2p::Chat {
                msg: message.clone(),
            },
        }))
    }
}
