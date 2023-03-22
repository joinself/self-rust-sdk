use crate::error::SelfError;
use crate::keypair::signing::{KeyPair, PublicKey};

use ciborium::value::Value;
use coset::{iana, CborSerializable, CoseSignatureBuilder, Label, ProtectedHeader};

enum HeaderLabel {
    Iat = 100,
    Exp,
}

#[derive(Clone)]
pub struct Message {
    payload: Vec<(Value, Value)>,
    signatures: Vec<Signature>,
}

#[derive(Clone)]
pub struct Signature {
    pub iss: PublicKey,
    pub iat: Option<i64>,
    pub exp: Option<i64>,
    pub protected: Vec<(Label, Value)>,
    pub signature: Vec<u8>,
}

impl Message {
    pub fn new() -> Message {
        return Message {
            payload: Vec::new(),
            signatures: Vec::new(),
        };
    }

    pub fn decode(data: &[u8]) -> Result<Message, SelfError> {
        let sm: coset::CoseSign = match coset::CoseSign::from_slice(data) {
            Ok(sm) => sm,
            Err(err) => {
                println!("cbor error: {}", err);
                return Err(SelfError::MessageDecodingInvalid);
            }
        };

        let mut m = Message::new();

        // validate signatures
        for (index, sig) in sm.signatures.iter().enumerate() {
            if sig.protected.is_empty() {
                return Err(SelfError::MessageNoProtected);
            }

            let alg = match sig.protected.header.alg.as_ref() {
                Some(alg) => alg,
                None => return Err(SelfError::MessageUnsupportedSignatureAlgorithm),
            };

            if !alg.eq(&coset::Algorithm::Assigned(coset::iana::Algorithm::EdDSA)) {
                return Err(SelfError::MessageUnsupportedSignatureAlgorithm);
            }

            let signer = PublicKey::from_bytes(
                &sig.protected.header.key_id,
                crate::keypair::Algorithm::Ed25519,
            )?;

            sm.verify_signature(index, &Vec::new(), |sig, data| {
                if signer.verify(data, sig) {
                    return Ok(());
                }
                return Err(());
            })
            .map_err(|_| SelfError::MessageSignatureInvalid)?;

            let mut msig = Signature {
                iss: signer,
                iat: None,
                exp: None,
                protected: Vec::new(),
                signature: sig.signature.clone(),
            };

            for (key, value) in &sig.protected.header.rest {
                msig.protected.push((key.to_owned(), value.to_owned()));
            }

            m.signatures.push(msig);
        }

        let encoded_payload = match sm.payload {
            Some(payload) => payload,
            None => return Err(SelfError::MessageNoPayload),
        };

        let payload: Value = match ciborium::de::from_reader(encoded_payload.as_slice()) {
            Ok(payload) => payload,
            Err(_) => return Err(SelfError::MessageDecodingInvalid),
        };

        let payload_content = match payload.as_map() {
            Some(payload_content) => payload_content,
            None => return Err(SelfError::MessagePayloadInvalid),
        };

        for (key, value) in payload_content {
            m.payload.push((key.to_owned(), value.to_owned()));
        }

        // TODO validate standard fields (if they exist)

        return Ok(m);
    }

    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        // construct and encode the payload
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&self.payload, &mut payload).unwrap();

        let mut sm = coset::CoseSignBuilder::new().payload(payload);

        for sig in &self.signatures {
            // construct a header for the signer
            let mut header = coset::HeaderBuilder::new()
                .algorithm(iana::Algorithm::EdDSA)
                .key_id(sig.iss.id());

            if let Some(iat) = sig.iat {
                header = header.value(HeaderLabel::Iat as i64, Value::from(iat));
            }

            if let Some(exp) = sig.exp {
                header = header.value(HeaderLabel::Exp as i64, Value::from(exp));
            }

            /*
            // TODO find the correct way to map any remaining protected fields
            // to the signature
            for (key, value) in &sig.protected {
                header = header.(key., value);
            }
            */

            let signature = CoseSignatureBuilder::new()
                .protected(header.build())
                .signature(sig.signature.clone())
                .build();

            sm = sm.add_signature(signature);
        }

        let signed_message = sm
            .build()
            .to_vec()
            .map_err(|_| SelfError::MessageEncodingInvalid)?;

        return Ok(signed_message);
    }

    pub fn sign(&mut self, signer: &KeyPair, exp: Option<i64>) {
        // construct and encode the payload
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&self.payload, &mut payload).unwrap();

        let iat = crate::time::unix();

        // construct a header for the signer
        let mut header = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .value(HeaderLabel::Iat as i64, Value::from(iat))
            .key_id(signer.id());

        if let Some(exp) = exp {
            header = header.value(HeaderLabel::Exp as i64, Value::from(exp));
        }

        let signature = coset::sig_structure_data(
            coset::SignatureContext::CoseSignature,
            ProtectedHeader {
                original_data: None,
                header: coset::HeaderBuilder::new().build(),
            },
            Some(ProtectedHeader {
                original_data: None,
                header: header.build(),
            }),
            &Vec::new(),
            payload.as_ref(),
        );

        self.signatures.push(Signature {
            iss: signer.public(),
            iat: Some(iat),
            exp: exp,
            protected: Vec::new(),
            signature: signature,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    #[test]
    fn to_cws() {
        println!("new message");
        let mut m = Message::new();

        // add a field to the payload
        m.payload.push((Value::from("typ"), Value::from(1)));

        // add a valid signature
        let kp = KeyPair::new();
        println!("sign");
        m.sign(&kp, None);

        println!("encode");
        // encode to cws
        let cws = m.encode().unwrap();

        println!("decode");
        // decode from cws
        let m = Message::decode(&cws).unwrap();

        println!("done");
        // check payload field exists
        assert!(m.payload.len() == 1);
        assert!(m.signatures.len() == 1);
    }

    /*
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
    */
}
