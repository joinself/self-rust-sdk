pub mod account;
pub mod hash;
pub mod omemo;
pub mod pow;
pub mod random;
pub mod session;

pub fn random_id() -> Vec<u8> {
    crate::crypto::random::vec(20)
}
