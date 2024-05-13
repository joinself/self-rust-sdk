use std::fmt;

use crate::{
    error::SelfError,
    hashgraph,
    keypair::{self, signing},
};

#[derive(Clone)]
pub struct Address {
    method: hashgraph::Method,
    address: signing::PublicKey,
    signing_key: Option<signing::PublicKey>,
}

impl Address {
    pub fn decode(did: &str) -> Result<Address, SelfError> {
        let mut delimiters = vec![0, 0, 0, did.len()];
        let mut p = 0;

        for (i, c) in did.chars().enumerate() {
            if c == ':' && p < 2 {
                delimiters[p] = i;
                p += 1;
            } else if c == '#' && p == 2 {
                delimiters[p] = i;
            } else if c == '?' {
                delimiters[3] = i;
                break;
            }
        }

        if delimiters[0] == 0 || delimiters[1] == 0 {
            return Err(SelfError::DIDAddressInvalid);
        }

        if &did[0..delimiters[0]] != "did" {
            return Err(SelfError::DIDAddressSchemeInvalid);
        }

        match &did[delimiters[0] + 1..delimiters[1]] {
            "key" => Address::decode_method_key(did, &delimiters),
            "aure" => Address::decode_method_aure(did, &delimiters),
            _ => Err(SelfError::DIDAddressMethodInvalid),
        }
    }

    fn decode_method_key(did: &str, delimiters: &[usize]) -> Result<Address, SelfError> {
        if delimiters[2] > 0 {
            return Err(SelfError::DIDAddressInvalid);
        }

        if did.chars().nth(delimiters[1] + 1).ne(&Some('z')) {
            return Err(SelfError::DIDAddressInvalid);
        }

        let mut decoded_key = match bs58::decode(&did[delimiters[1] + 2..delimiters[3]]).into_vec()
        {
            Ok(decoded_key) => decoded_key,
            Err(_) => return Err(SelfError::DIDAddressInvalid),
        };

        if decoded_key.len() != 34 {
            return Err(SelfError::DIDAddressInvalid);
        }

        match decoded_key[0] {
            0xed => decoded_key[1] = keypair::Algorithm::Ed25519 as u8,
            _ => return Err(SelfError::DIDAddressInvalid),
        };

        Ok(Address {
            method: hashgraph::Method::Key,
            address: signing::PublicKey::from_bytes(&decoded_key[1..34])?,
            signing_key: None,
        })
    }

    fn decode_method_aure(did: &str, delimiters: &[usize]) -> Result<Address, SelfError> {
        if delimiters[2] > 0 {
            return Ok(Address {
                method: hashgraph::Method::Aure,
                address: signing::PublicKey::from_hex(
                    did[delimiters[1] + 1..delimiters[2]].as_bytes(),
                )?,
                signing_key: Some(signing::PublicKey::from_hex(
                    did[delimiters[2] + 1..delimiters[3]].as_bytes(),
                )?),
            });
        }

        Ok(Address {
            method: hashgraph::Method::Aure,
            address: signing::PublicKey::from_hex(
                did[delimiters[1] + 1..delimiters[3]].as_bytes(),
            )?,
            signing_key: None,
        })
    }

    pub fn aure(address: &signing::PublicKey) -> Address {
        Address {
            method: hashgraph::Method::Aure,
            address: address.to_owned(),
            signing_key: None,
        }
    }

    pub fn key(address: &signing::PublicKey) -> Address {
        Address {
            method: hashgraph::Method::Key,
            address: address.to_owned(),
            signing_key: None,
        }
    }

    pub fn method(&self) -> &hashgraph::Method {
        &self.method
    }

    pub fn address(&self) -> &signing::PublicKey {
        &self.address
    }

    pub fn signing_key(&self) -> Option<&signing::PublicKey> {
        match self.method {
            hashgraph::Method::Key => Some(&self.address),
            hashgraph::Method::Aure => self.signing_key.as_ref(),
        }
    }

    pub fn with_signing_key(&mut self, key: &signing::PublicKey) -> &mut Address {
        if self.method != hashgraph::Method::Key {
            self.signing_key = Some(key.clone());
        }
        self
    }

    pub fn base_address(&self) -> String {
        match self.method {
            hashgraph::Method::Aure => {
                format!("did:aure:{}", self.address.to_hex())
            }
            _ => self.to_string(),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.method {
            hashgraph::Method::Aure => {
                if let Some(key) = &self.signing_key {
                    write!(f, "did:aure:{}#{}", self.address.to_hex(), key.to_hex())
                } else {
                    write!(f, "did:aure:{}", self.address.to_hex())
                }
            }
            hashgraph::Method::Key => {
                // TODO we only support ed25519 keys, handle this properly
                assert_eq!(self.address.address()[0], keypair::Algorithm::Ed25519 as u8);

                let mut key = vec![0; 34];
                key[0] = 0xed;
                key[1] = 0x01;
                key[2..34].copy_from_slice(self.address.public_key_bytes());

                write!(f, "did:key:z{}", bs58::encode(key).into_string())
            }
        }
    }
}

impl std::hash::Hash for Address {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        state.write_u16(self.method.clone() as u16);
        state.write(self.address().address());
        if let Some(signing_key) = &self.signing_key {
            state.write(signing_key.address());
        }
        state.finish();
    }
}

impl PartialEq for Address {
    fn eq(&self, other: &Address) -> bool {
        self.address.eq(other.address()) && self.signing_key.eq(&other.signing_key)
    }
}

impl Eq for Address {}

#[cfg(test)]
mod tests {
    use super::Address;

    use crate::keypair::signing;

    #[test]
    fn did_address_key_generate() {
        let identifier_key =
            signing::PublicKey::from_bytes(&[0; 33]).expect("failed to parse public key");

        let did_key = Address::key(&identifier_key).to_string();
        assert_eq!(
            did_key,
            "did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP"
        );
    }

    #[test]
    fn did_address_key_decode() {
        let identifier_key = signing::KeyPair::new();

        let did_key = Address::key(identifier_key.public()).to_string();
        let address = Address::decode(&did_key).expect("failed to decode key");

        let signing_public_key = address.signing_key().expect("no signing key found");
        assert_eq!(signing_public_key.address(), identifier_key.address());
    }

    #[test]
    fn did_address_aure_generate() {
        let identifier_key =
            signing::PublicKey::from_bytes(&[0; 33]).expect("failed to parse public key");
        let signing_key =
            signing::PublicKey::from_bytes(&[0; 33]).expect("failed to parse public key");

        let did_key = Address::aure(&identifier_key).to_string();
        assert_eq!(
            did_key,
            "did:aure:000000000000000000000000000000000000000000000000000000000000000000"
        );

        let did_key = Address::aure(&identifier_key)
            .with_signing_key(&signing_key)
            .to_string();
        assert_eq!(did_key, "did:aure:000000000000000000000000000000000000000000000000000000000000000000#000000000000000000000000000000000000000000000000000000000000000000");
    }

    #[test]
    fn did_address_aure_decode() {
        let identifier_key = signing::KeyPair::new();
        let signing_key = signing::KeyPair::new();

        let did_key = Address::aure(identifier_key.public()).to_string();
        let address = Address::decode(&did_key).expect("failed to decode key");

        let identifier_public_key = address.address();
        assert_eq!(identifier_public_key.address(), identifier_key.address());
        assert!(address.signing_key().is_none());

        let did_key = Address::aure(identifier_key.public())
            .with_signing_key(signing_key.public())
            .to_string();
        let address = Address::decode(&did_key).expect("failed to decode key");

        let identifier_public_key = address.address();
        assert_eq!(identifier_public_key.address(), identifier_key.address());

        let signing_public_key = address.signing_key().expect("no signing key found");
        assert_eq!(signing_public_key.address(), signing_key.address());
    }
}
