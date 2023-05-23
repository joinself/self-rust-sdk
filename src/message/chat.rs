use serde::{Deserialize, Serialize};

use crate::error::SelfError;

pub enum Chat {
    Message(ChatMessage),
    Read(ChatRead),
    Delivered(ChatDelivered),
}

#[derive(Serialize, Deserialize)]
pub struct ChatMessage {
    pub mrf: Option<Vec<u8>>, // reference to previous message id, used for quotes
    pub msg: String,          // message
}

impl ChatMessage {
    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        let mut data = Vec::new();
        ciborium::ser::into_writer(self, &mut data).map_err(|_| SelfError::TokenEncodingInvalid)?;
        Ok(data)
    }

    pub fn decode(data: &[u8]) -> Result<ChatMessage, SelfError> {
        ciborium::de::from_reader(data).map_err(|_| SelfError::MessageDecodingInvalid)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ChatRead {
    pub rdm: Vec<Vec<u8>>, // ids of all read messages
}

impl ChatRead {
    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        let mut data = Vec::new();
        ciborium::ser::into_writer(self, &mut data).map_err(|_| SelfError::TokenEncodingInvalid)?;
        Ok(data)
    }

    pub fn decode(data: &[u8]) -> Result<ChatRead, SelfError> {
        ciborium::de::from_reader(data).map_err(|_| SelfError::MessageDecodingInvalid)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ChatDelivered {
    pub dlm: Vec<Vec<u8>>, // ids of all delivered messages
}

impl ChatDelivered {
    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        let mut data = Vec::new();
        ciborium::ser::into_writer(self, &mut data).map_err(|_| SelfError::TokenEncodingInvalid)?;
        Ok(data)
    }

    pub fn decode(data: &[u8]) -> Result<ChatDelivered, SelfError> {
        ciborium::de::from_reader(data).map_err(|_| SelfError::MessageDecodingInvalid)
    }
}
