use serde::{Deserialize, Serialize};

use crate::error::SelfError;
use crate::keypair::Algorithm;

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyPair {
    public_key: PublicKey,
    secret_key: SecretKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicKey {
    id: Option<String>,
    algorithm: Algorithm,
    bytes: Vec<u8>,
}

impl PublicKey {
    pub fn import(
        id: &str,
        algorithm: Algorithm,
        public_key: &str,
    ) -> Result<PublicKey, SelfError> {
        let decoded_public_key = match base64::decode_config(public_key, base64::URL_SAFE_NO_PAD) {
            Ok(decoded_public_key) => decoded_public_key,
            Err(_) => return Err(SelfError::KeyPairDecodeInvalidData),
        };

        if decoded_public_key.len() != 32 {
            return Err(SelfError::KeyPairPublicKeyInvalidLength);
        }

        return Ok(PublicKey {
            id: Some(String::from(id)),
            algorithm: algorithm,
            bytes: decoded_public_key,
        });
    }

    pub fn id(&self) -> String {
        if self.id.is_some() {
            return self.id.as_ref().unwrap().clone();
        }

        return base64::encode_config(&self.bytes, base64::URL_SAFE_NO_PAD);
    }

    pub fn to_vec(&self) -> Vec<u8> {
        return self.bytes.clone();
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecretKey {
    bytes: Vec<u8>,
}

impl KeyPair {
    pub fn new() -> KeyPair {
        let kp = dryoc::kx::KeyPair::gen_with_defaults();

        return KeyPair {
            public_key: PublicKey {
                id: None,
                algorithm: Algorithm::Curve25519,
                bytes: kp.public_key.to_vec(),
            },
            secret_key: SecretKey {
                bytes: kp.secret_key.to_vec(),
            },
        };
    }

    pub fn decode(encoded_keypair: &[u8]) -> Result<KeyPair, SelfError> {
        return match serde_cbor::from_slice(encoded_keypair) {
            Ok(keypair) => Ok(keypair),
            Err(_) => Err(SelfError::KeyPairDecodeInvalidData),
        };
    }

    pub fn encode(&self) -> Vec<u8> {
        return serde_cbor::to_vec(self).unwrap();
    }

    pub fn import(&self, legacy_keypair: &str) -> Result<KeyPair, SelfError> {
        let (key_id, encoded_seed) = match legacy_keypair.split_once(':') {
            Some((first, last)) => (first, last),
            None => return Err(SelfError::KeyPairDecodeInvalidData),
        };

        let seed = match base64::decode(encoded_seed) {
            Ok(seed) => seed,
            Err(_) => return Err(SelfError::KeyPairDecodeInvalidData),
        };

        let kp = dryoc::sign::SigningKeyPair::<dryoc::sign::PublicKey, dryoc::sign::SecretKey>::from_seed(&seed);

        return Ok(KeyPair {
            public_key: PublicKey {
                id: Some(String::from(key_id)),
                algorithm: Algorithm::Curve25519,
                bytes: kp.public_key.to_vec(),
            },
            secret_key: SecretKey {
                bytes: kp.secret_key.to_vec(),
            },
        });
    }

    pub fn id(&self) -> String {
        if self.public_key.id.is_some() {
            return self.public_key.id.as_ref().unwrap().clone();
        }

        return base64::encode_config(&self.public_key.bytes, base64::URL_SAFE_NO_PAD);
    }

    pub fn algorithm(&self) -> Algorithm {
        return self.public_key.algorithm;
    }

    pub fn public(&self) -> PublicKey {
        return self.public_key.clone();
    }

    pub fn to_vec(&self) -> Vec<u8> {
        return self.secret_key.bytes.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        let skp = KeyPair::new();
        assert_eq!(skp.public().to_vec().len(), 32);
    }

    #[test]
    fn encode_decode() {
        let skp = KeyPair::new();
        assert_eq!(skp.public().to_vec().len(), 32);

        // encode and decode the keypair
        let encoded_skp = skp.encode();
        KeyPair::decode(&encoded_skp).unwrap();
    }
}
