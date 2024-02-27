use crate::error::SelfError;
use crate::keypair::signing::PublicKey;

use hex::ToHex;

use std::fmt;

use super::Address;

#[derive(Clone)]
pub enum Identifier {
    Aure(PublicKey),
    Key(PublicKey),
}

impl Identifier {
    pub fn from_did(did: &str) -> Result<Identifier, SelfError> {
        if let Some(encoded_identifier) = did.strip_prefix("aure:") {
            let decoded_identifier = hex::decode(encoded_identifier).map_err(|_| SelfError::IdentifierEncodingInvalid )?;
            let public_key = PublicKey::from_address(&decoded_identifier)?;
            return Ok(Identifier::Aure(public_key))
        }

        if let Some(encoded_identifier) = did.strip_prefix("key:") {
            let decoded_identifier = hex::decode(encoded_identifier).map_err(|_| SelfError::IdentifierEncodingInvalid )?;
            let public_key = PublicKey::from_address(&decoded_identifier)?;
            return Ok(Identifier::Key(public_key))
        }

        return Err(SelfError::IdentifierMethodUnsupported)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Aure(pk) => pk.address(),
            Self::Key(pk) => pk.address(),
        }
    }

    pub fn to_address(&self) -> Address {
        match self {
            Self::Aure(pk) => Address::from_public_key(pk),
            Self::Key(pk) => Address::from_public_key(pk),
        }
    }

    pub fn to_public_key(&self) -> PublicKey {
        match self {
            Self::Aure(pk) => pk.clone(),
            Self::Key(pk) => pk.clone(),
        }
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Identifier::Aure(pk) => f
                .debug_struct("Aure")
                .field("id", &self.to_vec().encode_hex::<String>())
                .finish(),
            Identifier::Key(_) => f
                .debug_struct("Key")
                .field("id", &self.to_vec().encode_hex::<String>())
                .finish(),
        }
    }
}

impl std::hash::Hash for Identifier {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        state.write(&self.to_vec());
        state.finish();
    }
}

impl PartialEq for Identifier {
    fn eq(&self, other: &Identifier) -> bool {
        self.to_vec().eq(&other.to_vec())
    }
}

impl Eq for Identifier {}