pub mod account;
pub mod hash;
pub mod omemo;
pub mod random;
pub mod session;

pub fn random_id() -> Vec<u8> {
    return crate::crypto::random::vec(20);
}
