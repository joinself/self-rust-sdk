use dryoc::{
    sign::{Message, PublicKey, SecretKey, Signature, SignedMessage, SigningKeyPair},
    types::StackByteArray,
};
use serde::{Deserialize, Serialize};

use crate::error::SelfError;

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyPair {
    id: Option<String>,
    keypair_type: KeyPairType,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum KeyPairType {
    Ed25519,
    Curve25519,
}

impl KeyPair {
    pub fn new(keypair_type: KeyPairType) -> KeyPair {
        match keypair_type {
            KeyPairType::Ed25519 => {
                let kp = dryoc::sign::SigningKeyPair::gen_with_defaults();

                return KeyPair {
                    id: None,
                    keypair_type: KeyPairType::Ed25519,
                    public_key: kp.public_key.to_vec(),
                    secret_key: kp.secret_key.to_vec(),
                };
            }
            KeyPairType::Curve25519 => {
                let kp = dryoc::keypair::KeyPair::gen_with_defaults();

                return KeyPair {
                    id: None,
                    keypair_type: KeyPairType::Curve25519,
                    public_key: kp.public_key.to_vec(),
                    secret_key: kp.secret_key.to_vec(),
                };
            }
        }
    }

    pub fn from_public_key(
        id: &str,
        keypair_type: KeyPairType,
        public_key: &str,
    ) -> Result<KeyPair, SelfError> {
        // TODO keypair should probably be split into different types (public/private)?
        let decoded_public_key = match base64::decode_config(public_key, base64::URL_SAFE_NO_PAD) {
            Ok(decoded_public_key) => decoded_public_key,
            Err(_) => return Err(SelfError::KeyPairDecodeInvalidData),
        };

        if decoded_public_key.len() != 32 {
            return Err(SelfError::SiggraphActionPublicKeyLengthBad);
        }

        return Ok(KeyPair {
            id: Some(String::from(id)),
            keypair_type: keypair_type,
            public_key: decoded_public_key,
            secret_key: Vec::new(),
        });
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

        let kp = dryoc::sign::SigningKeyPair::<PublicKey, SecretKey>::from_seed(&seed);

        return Ok(KeyPair {
            id: Some(String::from(key_id)),
            keypair_type: KeyPairType::Ed25519,
            public_key: kp.public_key.to_vec(),
            secret_key: kp.secret_key.to_vec(),
        });
    }

    pub fn id(&self) -> String {
        if self.id.is_some() {
            return self.id.as_ref().unwrap().clone();
        }

        return base64::encode_config(&self.public_key, base64::URL_SAFE_NO_PAD);
    }

    pub fn keypair_type(&self) -> KeyPairType {
        return self.keypair_type;
    }

    pub fn public(&self) -> Vec<u8> {
        return self.public_key.clone();
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SelfError> {
        if self.secret_key.len() < 1 {
            return Err(SelfError::KeyPairSignMissingSingingKey);
        }

        if self.keypair_type != KeyPairType::Ed25519 {
            return Err(SelfError::KeyPairSignWrongKeypairType);
        }

        return match SigningKeyPair::<PublicKey, SecretKey>::from_slices(
            &self.public_key,
            &self.secret_key,
        ) {
            Ok(kp) => match kp.sign_with_defaults(message) {
                Ok(signed_message) => {
                    let (sig, _) = signed_message.into_parts();
                    return Ok(sig.to_vec());
                }
                Err(_) => Err(SelfError::KeyPairSignFailure),
            },
            Err(_) => Err(SelfError::KeyPairSignFailure),
        };
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let sm =
            match SignedMessage::<Signature, Message>::from_bytes(&[signature, message].concat()) {
                Ok(sm) => sm,
                Err(err) => {
                    println!("{}", err);
                    return false;
                }
            };

        let mut sba = StackByteArray::new();
        sba.copy_from_slice(&self.public_key);
        let pk = PublicKey::from(sba);

        match sm.verify(&pk) {
            Ok(_) => return true,
            Err(_) => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        let skp = KeyPair::new(KeyPairType::Ed25519);
        assert_eq!(skp.public().len(), 32);

        let ekp = KeyPair::new(KeyPairType::Curve25519);
        assert_eq!(ekp.public().len(), 32);
    }

    #[test]
    fn sign_verify() {
        let skp = KeyPair::new(KeyPairType::Ed25519);
        assert_eq!(skp.public().len(), 32);

        // sign some data
        let message = "hello".as_bytes();
        let signature = skp.sign(message).unwrap();
        assert!(signature.len() == 64);

        // verify the signature
        assert!(skp.verify(message, &signature));

        // verify a bad signature
        let mut bad_signature = signature.clone();
        bad_signature[0] = 100;
        assert!(!skp.verify(message, &bad_signature));

        // verify a bad message
        let bad_message = "goodbye".as_bytes();
        assert!(!skp.verify(bad_message, &signature));

        // try and sign a message with a curve25519 encryption key
        let ekp = KeyPair::new(KeyPairType::Curve25519);
        let signature_result = ekp.sign(message);
        assert!(signature_result.is_err());
    }

    #[test]
    fn encode_decode() {
        let skp = KeyPair::new(KeyPairType::Ed25519);
        assert_eq!(skp.public().len(), 32);

        // sign some data
        let message = "hello".as_bytes();
        let signature = skp.sign(message).unwrap();
        assert!(signature.len() == 64);

        // encode and decode the keypair
        let encoded_skp = skp.encode();
        let decoded_skp = KeyPair::decode(&encoded_skp).unwrap();

        // verify the signature
        assert!(decoded_skp.verify(message, &signature));
    }
}
