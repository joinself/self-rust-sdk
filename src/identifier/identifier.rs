use crate::error::SelfError;
use crate::keypair::{
    signing::{KeyPair, PublicKey},
    Algorithm,
};

pub enum Identifier {
    Owned(KeyPair),
    Referenced(PublicKey),
}

impl Identifier {
    pub fn from_bytes(id: &[u8]) -> Result<Identifier, SelfError> {
        let pk = PublicKey::from_bytes(id, Algorithm::Ed25519)?;
        return Ok(Identifier::Referenced(pk));
    }

    pub fn id(&self) -> Vec<u8> {
        return match self {
            Self::Owned(kp) => kp.id(),
            Self::Referenced(pk) => pk.id(),
        };
    }

    pub fn public_key(&self) -> PublicKey {
        return match self {
            Self::Owned(kp) => kp.public(),
            Self::Referenced(pk) => pk.clone(),
        };
    }
}
