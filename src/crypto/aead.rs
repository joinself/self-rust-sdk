use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};

use crate::error::SelfError;

pub fn aes_gcm_encrypt(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, data).expect("failed to encrypt");
    let key: [u8; 32] = key.into();

    // prepend the nonce to the ciphertext for convenience
    let mut combined = vec![0; nonce.len() + ciphertext.len()];
    combined[..nonce.len()].copy_from_slice(&nonce);
    combined[nonce.len()..].copy_from_slice(&ciphertext);

    (key.to_vec(), combined)
}

pub fn aes_gcm_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, SelfError> {
    if data.len() < 13 || key.len() != 32 {
        return Err(SelfError::CryptoAEADDecryptFailed);
    }

    let cipher = Aes256Gcm::new(key.into());

    match cipher.decrypt(data[0..12].into(), &data[12..]) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => Err(SelfError::CryptoAEADDecryptFailed),
    }
}
