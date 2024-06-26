pub mod aead;
pub mod e2e;
pub mod hash;
pub mod pow;
pub mod random;

pub fn random_id() -> Vec<u8> {
    crate::crypto::random::vec(20)
}
