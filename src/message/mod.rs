mod message;
pub use self::message::*;

pub fn random_id() -> Vec<u8> {
    return crate::crypto::random::vec(20);
}
