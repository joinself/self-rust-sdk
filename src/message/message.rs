use super::SignedMessage;
use crate::identifier::Identifier;

pub struct Message {
    pub id: Vec<u8>,
    pub to: Identifier,
    pub from: Identifier,
    pub message_type: String,
    pub signed_message: SignedMessage,
}
