use hex::ToHex;

use crate::error::SelfError;
use crate::keypair::{
    signing::{KeyPair, PublicKey},
    Algorithm,
};

use std::fmt;

#[derive(Clone)]
pub enum Identifier {
    Owned(KeyPair),
    Referenced(PublicKey),
}

impl Identifier {
    pub fn from_bytes(id: &[u8]) -> Result<Identifier, SelfError> {
        let pk = PublicKey::from_bytes(id, Algorithm::Ed25519)?;
        Ok(Identifier::Referenced(pk))
    }

    pub fn id(&self) -> Vec<u8> {
        match self {
            Self::Owned(kp) => kp.id(),
            Self::Referenced(pk) => pk.id(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Owned(kp) => kp.public(),
            Self::Referenced(pk) => pk.clone(),
        }
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Identifier::Owned(_) => f
                .debug_struct("Owned")
                .field("id", &self.id().encode_hex::<String>())
                .finish(),
            Identifier::Referenced(_) => f
                .debug_struct("Referenced")
                .field("id", &self.id().encode_hex::<String>())
                .finish(),
        }
    }
}

impl std::hash::Hash for Identifier {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        state.write(&self.id());
        state.finish();
    }
}

impl PartialEq for Identifier {
    fn eq(&self, other: &Identifier) -> bool {
        self.public_key().matches(&other.id())
    }
}

impl Eq for Identifier {}
