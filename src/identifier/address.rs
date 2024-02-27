use crate::error::SelfError;
use crate::keypair::signing::PublicKey;

use hex::ToHex;

use std::fmt;

#[derive(Clone)]
pub struct Address {
    public_key: PublicKey,
}

impl Address {

    pub fn from_bytes(bytes: &[u8]) -> Result<Address, SelfError> {
        let public_key = PublicKey::from_address(bytes)?;
        Ok(Address{public_key})
    }

    pub fn from_public_key(public_key: &PublicKey) -> Address {
        Address{public_key: public_key.clone()}
    }
    
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.public_key.to_address_bytes()
    }

}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f
            .debug_struct("Address")
            .field("id", &self.to_vec().encode_hex::<String>())
            .finish()
    }
}

impl std::hash::Hash for Address {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        state.write(&self.to_vec());
        state.finish();
    }
}

impl PartialEq for Address {
    fn eq(&self, other: &Address) -> bool {
        self.to_vec().eq(&other.to_vec())
    }
}

impl Eq for Address {}