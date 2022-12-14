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

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        unsafe {
            return sodium_sys::crypto_sign_ed25519_verify_detached(
                signature.as_ptr(),
                message.as_ptr(),
                message.len() as u64,
                self.bytes.as_ptr(),
            ) == 0;
        }
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
        let mut ed25519_pk =
            vec![0u8; sodium_sys::crypto_sign_PUBLICKEYBYTES as usize].into_boxed_slice();
        let mut ed25519_sk =
            vec![0u8; sodium_sys::crypto_sign_SECRETKEYBYTES as usize].into_boxed_slice();

        unsafe {
            sodium_sys::crypto_sign_keypair(ed25519_pk.as_mut_ptr(), ed25519_sk.as_mut_ptr());
        }

        return KeyPair {
            public_key: PublicKey {
                id: None,
                algorithm: Algorithm::Ed25519,
                bytes: ed25519_pk.to_vec(),
            },
            secret_key: SecretKey {
                bytes: ed25519_sk.to_vec(),
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

        let mut ed25519_pk =
            vec![0u8; sodium_sys::crypto_sign_PUBLICKEYBYTES as usize].into_boxed_slice();
        let mut ed25519_sk =
            vec![0u8; sodium_sys::crypto_sign_SECRETKEYBYTES as usize].into_boxed_slice();

        unsafe {
            sodium_sys::crypto_sign_seed_keypair(
                ed25519_pk.as_mut_ptr(),
                ed25519_sk.as_mut_ptr(),
                seed.as_ptr(),
            );
        }

        return Ok(KeyPair {
            public_key: PublicKey {
                id: Some(String::from(key_id)),
                algorithm: Algorithm::Ed25519,
                bytes: ed25519_pk.to_vec(),
            },
            secret_key: SecretKey {
                bytes: ed25519_sk.to_vec(),
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

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut signature = vec![0u8; sodium_sys::crypto_sign_BYTES as usize].into_boxed_slice();

        unsafe {
            sodium_sys::crypto_sign_ed25519_detached(
                signature.as_mut_ptr(),
                &mut (signature.len() as u64),
                message.as_ptr(),
                message.len() as u64,
                self.secret_key.bytes.as_ptr(),
            );
        }

        return signature.to_vec();
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
    fn sign_verify() {
        let skp = KeyPair::new();
        assert_eq!(skp.public().to_vec().len(), 32);

        // sign some data
        let message = "hello".as_bytes();
        let signature = skp.sign(message);
        assert!(signature.len() == 64);

        // verify the signature
        assert!(skp.public().verify(message, &signature));

        // verify a bad signature
        let mut bad_signature = signature.clone();
        bad_signature[0] = 100;
        assert!(!skp.public().verify(message, &bad_signature));

        // verify a bad message
        let bad_message = "goodbye".as_bytes();
        assert!(!skp.public().verify(bad_message, &signature));
    }

    #[test]
    fn encode_decode() {
        let skp = KeyPair::new();
        assert_eq!(skp.public().to_vec().len(), 32);

        // sign some data
        let message = "hello".as_bytes();
        let signature = skp.sign(message);
        assert!(signature.len() == 64);

        // encode and decode the keypair
        let encoded_skp = skp.encode();
        let decoded_skp = KeyPair::decode(&encoded_skp).unwrap();

        // verify the signature
        assert!(decoded_skp.public().verify(message, &signature));
    }

    #[test]
    fn generate_ed25519_and_curve25519_keypair() {
        let mut ed25519_pk =
            vec![0u8; sodium_sys::crypto_sign_PUBLICKEYBYTES as usize].into_boxed_slice();
        let mut ed25519_sk =
            vec![0u8; sodium_sys::crypto_sign_SECRETKEYBYTES as usize].into_boxed_slice();

        unsafe {
            sodium_sys::crypto_sign_keypair(ed25519_pk.as_mut_ptr(), ed25519_sk.as_mut_ptr());
        }

        let mut curve25519_sk =
            vec![0u8; sodium_sys::crypto_sign_PUBLICKEYBYTES as usize].into_boxed_slice();
        let mut curve25519_pk =
            vec![0u8; sodium_sys::crypto_sign_SECRETKEYBYTES as usize].into_boxed_slice();

        unsafe {
            sodium_sys::crypto_sign_ed25519_sk_to_curve25519(
                curve25519_sk.as_mut_ptr(),
                ed25519_sk.as_ptr(),
            );
            sodium_sys::crypto_sign_ed25519_pk_to_curve25519(
                curve25519_pk.as_mut_ptr(),
                ed25519_pk.as_ptr(),
            );
        }
    }
}
