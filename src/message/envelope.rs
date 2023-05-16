use super::Content;
use crate::identifier::Identifier;

pub struct Envelope {
    pub to: Identifier,
    pub from: Identifier,
    pub sequence: u64,
    pub content: Content,
}
