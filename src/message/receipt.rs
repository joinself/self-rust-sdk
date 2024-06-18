use prost::Message;

use crate::{error::SelfError, message::Content, protocol::p2p};

#[derive(Clone)]
pub struct Receipt {
    receipt: p2p::Receipt,
}

impl Receipt {
    pub fn read(&self) -> &[Vec<u8>] {
        &self.receipt.read
    }

    pub fn delivered(&self) -> &[Vec<u8>] {
        &self.receipt.delivered
    }

    pub fn encode(&self) -> Vec<u8> {
        self.receipt.encode_to_vec()
    }

    pub fn decode(content: &[u8]) -> Result<Receipt, SelfError> {
        let receipt = p2p::Receipt::decode(content).map_err(|err| {
            println!("protobuf decode error: {}", err);
            SelfError::MessageEncodingInvalid
        })?;

        Ok(Receipt { receipt })
    }
}

#[derive(Default)]
pub struct ReceiptBuilder {
    read: Vec<Vec<u8>>,
    delivered: Vec<Vec<u8>>,
}

impl ReceiptBuilder {
    pub fn new() -> ReceiptBuilder {
        ReceiptBuilder {
            read: Vec::new(),
            delivered: Vec::new(),
        }
    }

    pub fn read(&mut self, read: Vec<u8>) -> &mut ReceiptBuilder {
        self.read.push(read);
        self
    }

    pub fn delivered(&mut self, delivered: Vec<u8>) -> &mut ReceiptBuilder {
        self.delivered.push(delivered);
        self
    }

    pub fn finish(&self) -> Result<Content, SelfError> {
        Ok(Content::Receipt(Receipt {
            receipt: p2p::Receipt {
                read: self.read.clone(),
                delivered: self.delivered.clone(),
            },
        }))
    }
}
