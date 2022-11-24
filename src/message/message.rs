use crate::error::SelfError;
use crate::keypair::{KeyPair, KeyPairType};
use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use uuid::Builder;

#[derive(Serialize, Deserialize)]
pub struct Message {
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    payload: HashMap<String, serde_json::Value>,
    #[serde(
        serialize_with = "as_base64",
        deserialize_with = "protected_from_base64"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    protected: Option<HashMap<String, serde_json::Value>>,
    #[serde(
        serialize_with = "as_base64",
        deserialize_with = "signature_from_base64"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Vec<u8>>,
    signatures: Vec<Signature>,
}

#[derive(Serialize, Deserialize)]
struct Signature {
    protected: String,
    signature: String,
}

fn as_base64<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    let json = serde_json::to_string(buffer).unwrap();
    let encoded_json = base64::encode_config(&json, base64::URL_SAFE_NO_PAD);
    serializer.serialize_str(&encoded_json)
}

fn from_base64<'de, D>(deserializer: D) -> Result<HashMap<String, serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        serde_json::from_str(&string).map_err(|err| Error::custom(err.to_string()))
    })
}

fn protected_from_base64<'de, D>(
    deserializer: D,
) -> Result<Option<HashMap<String, serde_json::Value>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        serde_json::from_str(&string).map_err(|err| Error::custom(err.to_string()))
    })
}

fn signature_from_base64<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        serde_json::from_str(&string).map_err(|err| Error::custom(err.to_string()))
    })
}

impl Message {
    pub fn new(typ: &str, iss: &str, sub: &str, exp: Option<Duration>, unix: bool) -> Message {
        let mut m = Message {
            payload: HashMap::new(),
            protected: None,
            signature: None,
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

    pub fn new_without_defaults() -> Message {
        return Message {
            payload: HashMap::new(),
            protected: None,
            signature: None,
            signatures: Vec::new(),
        };
    }

    pub fn from_bytes(data: &[u8]) -> Result<Message, SelfError> {
        let m: Message = match serde_json::from_slice(data) {
            Ok(m) => m,
            Err(_) => return Err(SelfError::MessageEncodingInvalid),
        };

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
            protected: encoded_protected,
            signature: encoded_signature,
        });

        return Ok(());
    }

    pub fn verify(&self, signing_key: KeyPair) -> Result<(), SelfError> {
        if signing_key.keypair_type() != KeyPairType::Ed25519 {
            return Err(SelfError::MessageSigningKeyInvalid);
        }

        if self.protected.is_some() {
            let protected = self.protected.as_ref().unwrap();
            if protected["kid"] != signing_key.id() {
                return Err(SelfError::MessageSignatureKeypairMismatch);
            }
        }

        return Ok(()); 
    }

    pub fn to_jws(&mut self) -> Result<String, SelfError> {
        if self.signatures.len() < 1 {
            return Err(SelfError::MessageNoSignature);
        }

        let json = match serde_json::to_string(self) {
            Ok(json) => json,
            Err(_) => return Err(SelfError::MessageEncodingInvalid),
        };

        return Ok(json);
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
            self.signatures[0].protected, encoded_payload, self.signatures[0].signature
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
