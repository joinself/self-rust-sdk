use crate::crypto;
use crate::error::SelfError;

pub struct Object {
    id: Vec<u8>,
    mime: String,
    key: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
}

impl Object {
    pub fn new(id: Vec<u8>, key: Vec<u8>, mime: String) -> Object {
        Object {
            id,
            mime,
            key: Some(key),
            data: None,
        }
    }

    pub fn from_bytes(mime: String, data: Vec<u8>) -> Object {
        let (key, data) = crypto::aead::aes_gcm_encrypt(&data);
        let id = crypto::hash::sha3(&data);

        Object {
            id,
            mime,
            key: Some(key),
            data: Some(data),
        }
    }

    pub fn id(&self) -> &[u8] {
        &self.id
    }

    pub fn mime(&self) -> &str {
        &self.mime
    }

    pub fn key(&self) -> Option<&[u8]> {
        self.key.as_deref()
    }

    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    pub fn decrypt(&mut self, data: Vec<u8>) -> Result<(), SelfError> {
        let key = match &self.key {
            Some(key) => key,
            None => return Err(SelfError::ObjectKeyMissing),
        };

        self.data = Some(crypto::aead::aes_gcm_decrypt(&data, key)?);

        Ok(())
    }

    pub fn decrypt_with_key(&mut self, data: Vec<u8>, key: Vec<u8>) -> Result<(), SelfError> {
        self.data = Some(crypto::aead::aes_gcm_decrypt(&data, &key)?);
        self.key = Some(key);

        Ok(())
    }
}
