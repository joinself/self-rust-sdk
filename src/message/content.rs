use crate::error::SelfError;

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Content {
    typ: Option<String>,
    sub: Option<Vec<u8>>,
    aud: Option<Vec<u8>>,
    cti: Option<Vec<u8>>,
    iat: Option<i64>,
    exp: Option<i64>,
    content: Option<Vec<u8>>,
}

impl Content {
    pub fn new() -> Content {
        Content {
            typ: None,
            sub: None,
            aud: None,
            cti: None,
            iat: None,
            exp: None,
            content: None,
        }
    }

    pub fn decode(data: &[u8]) -> Result<Content, SelfError> {
        let c: Content =
            ciborium::de::from_reader(data).map_err(|_| SelfError::MessagePayloadInvalid)?;
        Ok(c)
    }

    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        let mut encoded_c = Vec::new();

        ciborium::ser::into_writer(self, &mut encoded_c)
            .map_err(|_| SelfError::MessageEncodingInvalid)?;

        Ok(encoded_c)
    }

    pub fn validate(&self) -> Result<(), SelfError> {
        /*
        if let Some(cti) = &self.cti {

        } else {
            // invalid cti
        }

        */
        Ok(())
    }

    pub fn audience_set(&mut self, aud: &[u8]) {
        self.aud = Some(aud.to_vec());
    }

    pub fn audience_get(&self) -> Option<Vec<u8>> {
        self.aud.clone()
    }

    pub fn subject_set(&mut self, sub: &[u8]) {
        self.sub = Some(sub.to_vec());
    }

    pub fn subject_get(&self) -> Option<Vec<u8>> {
        self.sub.clone()
    }

    pub fn cti_set(&mut self, cti: &[u8]) {
        self.cti = Some(cti.to_vec());
    }

    pub fn cti_get(&self) -> Option<Vec<u8>> {
        self.cti.clone()
    }

    pub fn type_set(&mut self, typ: &str) {
        self.typ = Some(typ.to_string());
    }

    pub fn type_get(&self) -> Option<String> {
        self.typ.clone()
    }

    pub fn issued_at_set(&mut self, iat: i64) {
        self.iat = Some(iat);
    }

    pub fn issued_at_get(&self) -> Option<i64> {
        self.iat
    }

    pub fn expires_at_set(&mut self, exp: i64) {
        self.exp = Some(exp);
    }

    pub fn expires_at_get(&self) -> Option<i64> {
        self.exp
    }

    pub fn content_set(&mut self, content: &[u8]) {
        self.content = Some(content.to_vec());
    }

    pub fn content_get(&self) -> Option<Vec<u8>> {
        self.content.clone()
    }
}

impl Default for Content {
    fn default() -> Self {
        Content::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    #[test]
    fn audience() {
        let mut m = Content::new();

        m.audience_set(&[0; 32]);

        // encode to c
        let c = m.encode().unwrap();

        // decode from c
        let m = Content::decode(&c).unwrap();
        assert!(m.audience_get().unwrap().len() == 32);
    }

    #[test]
    fn subject() {
        let mut m = Content::new();

        m.subject_set(&[0; 32]);

        // encode to c
        let c = m.encode().unwrap();

        // decode from c
        let m = Content::decode(&c).unwrap();
        assert!(m.subject_get().unwrap().len() == 32);
    }

    #[test]
    fn cti() {
        let mut m = Content::new();

        m.cti_set(&[0; 20]);

        // encode to c
        let c = m.encode().unwrap();

        // decode from c
        let m = Content::decode(&c).unwrap();
        assert!(m.cti_get().unwrap().len() == 20);
    }

    #[test]
    fn message_type() {
        let mut m = Content::new();

        m.type_set("connections.req");

        // encode to c
        let c = m.encode().unwrap();

        // decode from c
        let m = Content::decode(&c).unwrap();
        assert_eq!(m.type_get().unwrap(), "connections.req");
    }

    #[test]
    fn issued_at() {
        let mut m = Content::new();

        m.issued_at_set(101);

        // encode to c
        let c = m.encode().unwrap();

        // decode from c
        let m = Content::decode(&c).unwrap();
        assert_eq!(m.issued_at_get().unwrap(), 101);
    }

    #[test]
    fn expires_at() {
        let mut m = Content::new();

        m.expires_at_set(101);

        // encode to c
        let c = m.encode().unwrap();

        // decode from c
        let m = Content::decode(&c).unwrap();

        assert_eq!(m.expires_at_get().unwrap(), 101);
    }

    #[test]
    fn content() {
        let mut m = Content::new();

        // add a field to the payload
        let mut content = Vec::new();
        let content_data = vec![(Value::from("my_field"), Value::from(128))];
        ciborium::ser::into_writer(&Value::Map(content_data), &mut content).unwrap();

        // set content and sign
        m.content_set(&content);

        // encode to c
        let c = m.encode().unwrap();

        // decode from c
        let m = Content::decode(&c).unwrap();

        // decode the content
        let content = m.content_get().unwrap();
        let content_data: Value = ciborium::de::from_reader(&content[..]).unwrap();
        let content_map = content_data.as_map().unwrap();
        assert!(content_map.len() == 1);

        let key = content_map[0].0.as_text().unwrap();
        let value: i64 = content_map[0].1.as_integer().unwrap().try_into().unwrap();
        assert_eq!(key, "my_field");
        assert_eq!(value, 128);
    }
}
