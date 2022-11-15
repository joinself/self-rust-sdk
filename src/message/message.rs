use crate::error::SelfError;
use crate::keypair::{KeyPair, KeyPairType};
use std::collections::HashMap;
use std::time::Duration;

use serde_json::{json, Value};
use uuid::Builder;

pub struct Message {
    payload: HashMap<String, serde_json::Value>,
    signatures: Vec<Signature>,
}

struct Signature {
    hdr: String,
    sig: String,
}

impl Message {
    pub fn new(typ: &str, iss: &str, sub: &str, exp: Option<Duration>, unix: bool) -> Message {
        let mut m = Message {
            payload: HashMap::new(),
            signatures: Vec::new(),
        };

        let mut rng_bytes: [u8; 16] = [0; 16];
        dryoc::rng::copy_randombytes(&mut rng_bytes);

        let jti = Builder::from_random_bytes(rng_bytes)
            .into_uuid()
            .to_string();

        // add default fields
        m.payload
            .insert(String::from("typ"), Value::from(String::from(typ)));
        m.payload
            .insert(String::from("iss"), Value::from(String::from(iss)));
        m.payload
            .insert(String::from("sub"), Value::from(String::from(sub)));
        m.payload
            .insert(String::from("typ"), Value::from(String::from(typ)));
        m.payload
            .insert(String::from("jti"), Value::from(String::from(jti)));

        let now = crate::time::time::now();

        if unix {
            m.payload
                .insert(String::from("iat"), Value::from(now.timestamp()));
            if exp.is_some() {
                let exp = (now + chrono::Duration::from_std(exp.unwrap()).unwrap()).timestamp();
                m.payload.insert(String::from("exp"), Value::from(exp));
            }
        } else {
            m.payload
                .insert(String::from("iat"), Value::from(now.to_rfc3339()));
            if exp.is_some() {
                let exp = (now + chrono::Duration::from_std(exp.unwrap()).unwrap()).to_rfc3339();
                m.payload.insert(String::from("exp"), Value::from(exp));
            }
        }

        return m;
    }

    pub fn from_bytes(data: &[u8]) -> Result<Message, SelfError> {
        let m = Message {
            payload: HashMap::new(),
            signatures: Vec::new(),
        };

        // TODO  implement this

        return Ok(m);
    }

    pub fn add_field_int(&mut self, key: &str, value: i32) {
        self.payload.insert(String::from(key), Value::from(value));
    }

    pub fn add_field_string(&mut self, key: &str, value: &str) {
        self.payload
            .insert(String::from(key), Value::from(String::from(value)));
    }

    pub fn add_field_object(&mut self, key: &str, value: Value) {
        self.payload.insert(String::from(key), value);
    }

    pub fn sign(&mut self, signing_key: &KeyPair) -> Result<(), SelfError> {
        if signing_key.keypair_type() != KeyPairType::Ed25519 {
            return Err(SelfError::MessageSigningKeyInvalid);
        }

        let protected = json!({
            "kid": signing_key.id(),
            "alg": "EdDSA",
        })
        .to_string();

        let payload = match serde_json::to_string(&self.payload) {
            Ok(payload) => payload,
            Err(_) => return Err(SelfError::MessageEncodingInvalid),
        };

        let encoded_payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
        let encoded_protected = base64::encode_config(protected, base64::URL_SAFE_NO_PAD);

        let signed_data = format!("{}.{}", encoded_protected, encoded_payload);

        let signature = match signing_key.sign(signed_data.as_bytes()) {
            Ok(signature) => signature,
            Err(err) => return Err(err),
        };

        let encoded_signature = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);

        self.signatures.push(Signature {
            hdr: encoded_protected,
            sig: encoded_signature,
        });

        return Ok(());
    }

    pub fn to_jws(&mut self) -> Result<String, SelfError> {
        if self.signatures.len() < 1 {
            return Err(SelfError::MessageNoSignature);
        }

        let payload = match serde_json::to_string(&self.payload) {
            Ok(payload) => payload,
            Err(_) => return Err(SelfError::MessageEncodingInvalid),
        };

        let encoded_payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);

        if self.signatures.len() == 1 {
            let jws = json!({
                "payload": encoded_payload,
                "protected": self.signatures[0].hdr,
                "signature": self.signatures[0].sig,
            });

            return Ok(jws.to_string());
        }

        let mut signatures: Vec<Value> = Vec::new();

        for signature in self.signatures.iter_mut() {
            signatures.push(json!({
                "signature": signature.sig,
                "protected": signature.hdr,
            }))
        }

        let jws = json!({
            "payload": encoded_payload,
            "signatures": signatures,
        });

        return Ok(jws.to_string());
    }

    pub fn to_jwt(&self) -> Result<String, SelfError> {
        if self.signatures.len() < 1 {
            return Err(SelfError::MessageNoSignature);
        }

        let payload = match serde_json::to_string(&self.payload) {
            Ok(payload) => payload,
            Err(_) => return Err(SelfError::MessageEncodingInvalid),
        };

        let encoded_payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
        return Ok(format!(
            "{}.{}.{}",
            self.signatures[0].hdr, encoded_payload, self.signatures[0].sig
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_jws() {
        let mut m = Message::new("auth.token", "me", "me", None, true);

        // try to encode with no signatures
        assert!(m.to_jws().is_err());

        // attempt to sign with an encryption key
        let kp = KeyPair::new(KeyPairType::Curve25519);
        assert!(m.sign(&kp).is_err());

        // add a valid signature
        let kp = KeyPair::new(KeyPairType::Ed25519);
        assert!(m.sign(&kp).is_ok());

        // encode to jws
        let jws = m.to_jws();
        assert!(jws.is_ok());

        println!("{}", jws.unwrap());
    }

    #[test]
    fn to_jwt() {
        let mut m = Message::new("auth.token", "me", "me", None, true);

        // try to encode with no signatures
        assert!(m.to_jws().is_err());

        // attempt to sign with an encryption key
        let kp = KeyPair::new(KeyPairType::Curve25519);
        assert!(m.sign(&kp).is_err());

        // add a valid signature
        let kp = KeyPair::new(KeyPairType::Ed25519);
        assert!(m.sign(&kp).is_ok());

        // encode to jwt
        let jwt = m.to_jws();
        assert!(jwt.is_ok());

        println!("{}", jwt.unwrap());
    }
}
