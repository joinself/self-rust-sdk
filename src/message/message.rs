use super::SignedMessage;
use crate::identifier::Identifier;

pub struct Message {
    id: Vec<u8>,
    to: Identifier,
    from: Identifier,
    message_type: String,
    signed_message: SignedMessage,
}
