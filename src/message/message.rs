use crate::error::SelfError;
use crate::keypair::signing::{KeyPair, PublicKey};
use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use uuid::Builder;

#[derive(Serialize, Deserialize, Clone)]
pub struct Message {
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    payload: BTreeMap<String, serde_json::Value>,
    #[serde(
        default,
        serialize_with = "as_base64",
        deserialize_with = "protected_optional_from_base64",
        skip_serializing_if = "Option::is_none"
    )]
    protected: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    signatures: Vec<Signature>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Signature {
    #[serde(
        default,
        serialize_with = "as_base64",
        deserialize_with = "protected_from_base64"
    )]
    pub protected: BTreeMap<String, serde_json::Value>,
    pub signature: String,
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

fn from_base64<'de, D>(deserializer: D) -> Result<BTreeMap<String, serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        let decoded_json = match base64::decode_config(string, base64::URL_SAFE_NO_PAD) {
            Ok(decoded_json) => decoded_json,
            Err(err) => return Err(Error::custom(err.to_string())),
        };
        serde_json::from_slice(&decoded_json).map_err(|err| Error::custom(err.to_string()))
    })
}

fn protected_from_base64<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        let decoded_json = match base64::decode_config(string, base64::URL_SAFE_NO_PAD) {
            Ok(decoded_json) => decoded_json,
            Err(err) => return Err(Error::custom(err.to_string())),
        };
        serde_json::from_slice(&decoded_json).map_err(|err| Error::custom(err.to_string()))
    })
}

fn protected_optional_from_base64<'de, D>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, serde_json::Value>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        let decoded_json = match base64::decode_config(string, base64::URL_SAFE_NO_PAD) {
            Ok(decoded_json) => decoded_json,
            Err(err) => return Err(Error::custom(err.to_string())),
        };
        serde_json::from_slice(&decoded_json).map_err(|err| Error::custom(err.to_string()))
    })
}

impl Message {
    pub fn new(typ: &str, iss: &str, sub: &str, exp: Option<Duration>, unix: bool) -> Message {
        let mut m = Message {
            payload: BTreeMap::new(),
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

        let now = crate::time::now();

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
            payload: BTreeMap::new(),
            protected: None,
            signature: None,
            signatures: Vec::new(),
        };
    }

    pub fn new_from_payload<T: Serialize>(custom_payload: &T) -> Result<Message, SelfError> {
        // TODO this is not the right way to do this, but
        // the most convenient/fastest way for now.
        // Investigate if generic payload is possible,
        // with a default of BTreeMap<String, Value>

        let encoded_custom_payload = match serde_json::to_vec(custom_payload) {
            Ok(encoded_custom_payload) => encoded_custom_payload,
            Err(_) => return Err(SelfError::MessageEncodingInvalid),
        };

        let payload: BTreeMap<String, Value> = match serde_json::from_slice(&encoded_custom_payload)
        {
            Ok(payload) => payload,
            Err(_) => return Err(SelfError::MessageDecodingInvalid),
        };

        return Ok(Message {
            payload: payload,
            protected: None,
            signature: None,
            signatures: Vec::new(),
        });
    }

    pub fn to_custom_payload<T>(&self) -> Result<T, SelfError>
    where
        T: for<'a> Deserialize<'a>,
    {
        let encoded_payload = match serde_json::to_vec(&self.payload) {
            Ok(encoded_payload) => encoded_payload,
            Err(_) => return Err(SelfError::MessageEncodingInvalid),
        };

        let decoded_payload: T = match serde_json::from_slice(&encoded_payload) {
            Ok(decoded_payload) => decoded_payload,
            Err(_) => return Err(SelfError::MessageDecodingInvalid),
        };

        return Ok(decoded_payload);
    }

    pub fn from_jws(data: &[u8]) -> Result<Message, SelfError> {
        let m: Message = match serde_json::from_slice(data) {
            Ok(m) => m,
            Err(err) => {
                println!("json error: {}", err);
                return Err(SelfError::MessageDecodingInvalid);
            }
        };

        if m.signatures.len() < 1 {
            if m.protected.is_none() {
                return Err(SelfError::MessageNoProtected);
            }

            if m.signature.is_none() {
                return Err(SelfError::MessageNoSignature);
            }
        }

        return Ok(m);
    }

    pub fn from_jwt(data: &[u8]) -> Result<Message, SelfError> {
        // TODO better way to do this?
        let parts = data
            .split(|byte| *byte == ".".as_bytes()[0])
            .collect::<Vec<&[u8]>>();

        if parts.len() < 3 {
            return Err(SelfError::MessageDecodingInvalid);
        }

        let protected = base64::decode_config(parts[0], base64::URL_SAFE_NO_PAD)
            .map_err(|_| SelfError::MessageDecodingInvalid)?;
        let payload = base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)
            .map_err(|_| SelfError::MessageDecodingInvalid)?;

        let mut m = Message::new_without_defaults();

        m.protected =
            serde_json::from_slice(&protected).map_err(|_| SelfError::MessageDecodingInvalid)?;
        m.payload =
            serde_json::from_slice(&payload).map_err(|_| SelfError::MessageDecodingInvalid)?;
        m.signature = Some(
            String::from_utf8(parts[2].to_vec()).map_err(|_| SelfError::MessageDecodingInvalid)?,
        );

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

    pub fn add_field_raw_json(&mut self, key: &str, value: &[u8]) -> Result<(), SelfError> {
        let decoded_value: Value = match serde_json::from_slice(value) {
            Ok(decoded_value) => decoded_value,
            Err(_) => return Err(SelfError::MessageDecodingInvalid),
        };

        self.payload.insert(String::from(key), decoded_value);

        return Ok(());
    }

    pub fn get_field(&self, key: &str) -> Option<&Value> {
        return self.payload.get(key);
    }

    pub fn sign(&mut self, signing_key: &KeyPair) -> Result<(), SelfError> {
        let mut protected = BTreeMap::new();
        protected.insert(String::from("kid"), Value::String(signing_key.id()));
        protected.insert(String::from("alg"), Value::String(String::from("EdDSA")));

        let payload = match serde_json::to_string(&self.payload) {
            Ok(payload) => payload,
            Err(_) => return Err(SelfError::MessageEncodingInvalid),
        };

        let encoded_payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
        let encoded_protected = base64::encode_config(
            serde_json::to_vec(&protected).unwrap(),
            base64::URL_SAFE_NO_PAD,
        );

        let message = format!("{}.{}", encoded_protected, encoded_payload);

        let signature = match signing_key.sign(message.as_bytes()) {
            Ok(signature) => signature,
            Err(err) => return Err(err),
        };

        let encoded_signature = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);

        self.signatures.push(Signature {
            protected: protected,
            signature: encoded_signature,
        });

        return Ok(());
    }

    pub fn verify(&self, signing_key: &PublicKey) -> Result<(), SelfError> {
        if self.protected.is_some() {
            let protected = self.protected.as_ref().unwrap();
            if protected["kid"] != signing_key.id() {
                return Err(SelfError::MessageSignatureKeypairMismatch);
            }

            let encoded_signature = self.signature.as_ref().unwrap();

            let decoded_signature =
                match base64::decode_config(encoded_signature, base64::URL_SAFE_NO_PAD) {
                    Ok(decoded_signature) => decoded_signature,
                    Err(_) => return Err(SelfError::MessageSignatureEncodingInvalid),
                };

            let payload = serde_json::to_string(&self.payload).unwrap();
            let protected = serde_json::to_string(&self.protected).unwrap();

            let encoded_payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
            let encoded_protected = base64::encode_config(protected, base64::URL_SAFE_NO_PAD);
            let message = format!("{}.{}", encoded_protected, encoded_payload);

            if !signing_key.verify(message.as_bytes(), &decoded_signature) {
                return Err(SelfError::MessageSignatureInvalid);
            }

            return Ok(());
        }

        for s in &self.signatures {
            if s.protected["kid"] != signing_key.id() {
                continue;
            }

            let decoded_signature =
                match base64::decode_config(&s.signature, base64::URL_SAFE_NO_PAD) {
                    Ok(decoded_signature) => decoded_signature,
                    Err(_) => return Err(SelfError::MessageSignatureEncodingInvalid),
                };

            let payload = serde_json::to_string(&self.payload).unwrap();
            let protected = serde_json::to_string(&s.protected).unwrap();

            let encoded_payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
            let encoded_protected = base64::encode_config(protected, base64::URL_SAFE_NO_PAD);
            let message = format!("{}.{}", encoded_protected, encoded_payload);

            if !signing_key.verify(message.as_bytes(), &decoded_signature) {
                return Err(SelfError::MessageSignatureInvalid);
            }

            return Ok(());
        }

        return Err(SelfError::MessageSignatureKeypairMismatch);
    }

    pub fn signing_key_ids(&self) -> Option<Vec<String>> {
        let mut kids = Vec::new();

        if self.protected.is_some() {
            let kid = &self.protected.as_ref().unwrap()["kid"];

            if kid.is_string() {
                kids.push(String::from(kid.as_str().unwrap()));
            }
        }

        for sig in &self.signatures {
            let kid = &sig.protected["kid"];

            if kid.is_string() {
                kids.push(String::from(kid.as_str().unwrap()));
            }
        }

        if kids.len() < 1 {
            return None;
        }

        return Some(kids);
    }

    pub fn signatures(&self) -> Vec<Signature> {
        if self.protected.is_some() && self.signature.is_some() {
            return vec![Signature {
                protected: self.protected.as_ref().unwrap().clone(),
                signature: self.signature.as_ref().unwrap().clone(),
            }];
        }

        return self.signatures.clone();
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

        let protected = serde_json::to_vec(&self.signatures[0].protected).unwrap();

        let encoded_payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
        let encoded_protected = base64::encode_config(protected, base64::URL_SAFE_NO_PAD);

        return Ok(format!(
            "{}.{}.{}",
            encoded_protected, encoded_payload, self.signatures[0].signature
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

        // add a valid signature
        let kp = KeyPair::new();
        assert!(m.sign(&kp).is_ok());

        // encode to jws
        let jws = m.to_jws().unwrap();

        // decode from jws
        let bytes = jws.as_bytes();

        let m = Message::from_jws(bytes).unwrap();
        m.verify(&kp.public()).unwrap();
        assert_eq!(m.signing_key_ids().unwrap().len(), 1);
    }

    #[test]
    fn to_jwt() {
        let mut m = Message::new("auth.token", "me", "me", None, true);

        // try to encode with no signatures
        assert!(m.to_jws().is_err());

        // add a valid signature
        let kp = KeyPair::new();
        assert!(m.sign(&kp).is_ok());

        // encode to jwt
        let jwt = m.to_jws();
        assert!(jwt.is_ok());
    }
}
