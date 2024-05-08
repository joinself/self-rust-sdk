use std::fmt;

use crate::{error::SelfError, hashgraph, keypair::signing};

pub struct Address {
    method: hashgraph::Method,
    address: signing::PublicKey,
    key: Option<signing::PublicKey>
}

impl Address {
    pub fn decode(did: &str) -> Result<Address, SelfError> {
        if !did.starts_with("did:") {
            return Err(SelfError::DIDAddressInvalidScheme)
        }

        // TODO very crude, would be better to scan through
        let segments = did.split(":").collect::<Vec<&str>>();

        if segments.len() != 3 {
            return Err(SelfError::DIDAddressInvalid)
        }



        Ok(Address{

        })
    }

    pub fn aure(address: &signing::PublicKey) -> Address {
        Address{
            method: hashgraph::Method::Aure,
            address: address.to_owned(),
            key: None,
        }
    }

    pub fn key(address: &signing::PublicKey) -> Address {
        Address{
            method: hashgraph::Method::Key,
            address: address.to_owned(),
            key: None,
        }
    }

    pub fn 

    pub fn with_key(&mut self, key: signing::PublicKey) -> &mut Address {
        self.key = Some(key);
        self
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.method {
            hashgraph::Method::Aure => {
                if let Some(key) = &self.key {
                    write!(f, "did:aure:{}#{}", self.address.to_hex(), key.to_hex())
                } else {
                    write!(f, "did:aure:{}", self.address.to_hex())
                }
            },
            hashgraph::Method::Key => {
                // TODO this is incorrect encoding, we need to use multibase
                // (base-58) and whatever mutlicodec value corresponds to ed25519
                write!(f, "did:key:{}", self.address.to_hex())
            },
        }
    }
}