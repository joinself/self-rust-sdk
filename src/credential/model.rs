use std::collections::HashMap;

use chrono::prelude::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json;

use crate::credential::did::Address;
use crate::error::SelfError;
use crate::keypair::signing::{KeyPair, PublicKey};
use crate::time::{datetime, decode_datetime};

pub const CONTEXT_DEFAULT: &[&str] = &["https://www.w3.org/ns/credentials/v2"];
pub const CREDENTIAL_DEFAULT: &[&str] = &["VerifiableCredential"];
pub const CREDENTIAL_PASSPORT: &[&str] = &["VerifiableCredential", "PassportCredential"];
pub const CREDENTIAL_LIVENESS: &[&str] = &["VerifiableCredential", "LivenessCredential"];
pub const CREDENTIAL_PROFILE_IMAGE: &[&str] = &["VerifiableCredential", "ProfileImageCredential"];
pub const CREDENTIAL_APPLICATION_PUBLISHER: &[&str] =
    &["VerifiableCredential", "ApplicationPublisherCredential"];
pub const CRYPTO_SUITE_DEFAULT: &str = "jcs-eddsa-2022";
pub const PROOF_TYPE_DATA_INTEGRITY: &str = "DataIntegrityProof";
pub const PURPOSE_ASSERTION: &str = "assertionMethod";

#[derive(Default)]
pub struct CredentialBuilder {
    pub id: Option<String>,
    pub context: Option<Vec<String>>,
    pub credential_type: Option<Vec<String>>,
    pub credential_subject: HashMap<String, String>,
    pub issuer: Option<String>,
    pub valid_from: Option<String>,
    signer: Option<PublicKey>,
    issued: Option<DateTime<Utc>>,
}

impl CredentialBuilder {
    pub fn new() -> CredentialBuilder {
        CredentialBuilder::default()
    }

    pub fn id(&mut self, id: String) -> &mut CredentialBuilder {
        self.id = Some(id);
        self
    }

    pub fn context(&mut self, context: Vec<String>) -> &mut CredentialBuilder {
        self.context = Some(context);
        self
    }

    pub fn credential_type(&mut self, credential_type: Vec<String>) -> &mut CredentialBuilder {
        self.credential_type = Some(credential_type);
        self
    }

    // TODO this api is limiting and prevents expression of multiple subjects
    pub fn credential_subject(&mut self, subject: &Address) -> &mut CredentialBuilder {
        self.credential_subject
            .insert(String::from("id"), subject.to_string());
        self
    }

    // TODO this api is limiting as it prevents structured claim data and different data types
    // consider accepting any type that implements Serializable and Deserializable?
    pub fn credential_subject_claim(&mut self, key: &str, value: &str) -> &mut CredentialBuilder {
        self.credential_subject
            .insert(String::from(key), String::from(value));
        self
    }

    pub fn issuer(&mut self, issuer: &Address) -> &mut CredentialBuilder {
        self.issuer = Some(issuer.to_string());
        self
    }

    pub fn valid_from(&mut self, valid_from: DateTime<Utc>) -> &mut CredentialBuilder {
        self.valid_from = Some(datetime(valid_from));
        self
    }

    pub fn sign_with(&mut self, signer: &PublicKey, at: DateTime<Utc>) -> &mut CredentialBuilder {
        self.signer = Some(signer.to_owned());
        self.issued = Some(at);
        self
    }

    pub fn finish(&self) -> Result<Credential, SelfError> {
        // TODO this kind of sucks as we're copying data 3 times,
        // but it ensures that our public api's make sense :facepalm:

        let id = self.id.clone();

        let context = match &self.context {
            Some(context) => context.clone(),
            None => return Err(SelfError::CredentialContextMissing),
        };

        let credential_type = match &self.credential_type {
            Some(credential_type) => credential_type.clone(),
            None => return Err(SelfError::CredentialTypeMissing),
        };

        if !self.credential_subject.contains_key("id") {
            return Err(SelfError::CredentialSubjectMissing);
        }

        let credential_subject = self.credential_subject.clone();

        let issuer = match &self.issuer {
            Some(issuer) => issuer.clone(),
            None => return Err(SelfError::CredentialIssuerMissing),
        };

        let valid_from = match &self.valid_from {
            Some(valid_from) => valid_from.clone(),
            None => return Err(SelfError::CredentialValidFromMissing),
        };

        let signer = match &self.signer {
            Some(signer) => Some(signer.clone()),
            None => return Err(SelfError::CredentialSignerMissing),
        };

        let issued = match self.issued {
            Some(issued) => Some(issued),
            None => return Err(SelfError::CredentialIssuedMissing),
        };

        Ok(Credential {
            id,
            context,
            credential_type,
            credential_subject,
            issuer,
            valid_from,
            signer,
            issued,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct Credential {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "@context")]
    context: Vec<String>,
    #[serde(rename = "type")]
    credential_type: Vec<String>,
    #[serde(rename = "credentialSubject")]
    credential_subject: HashMap<String, String>,
    issuer: String,
    #[serde(rename = "validFrom")]
    valid_from: String,
    #[serde(skip)]
    signer: Option<PublicKey>,
    #[serde(skip)]
    issued: Option<DateTime<Utc>>,
}

impl Credential {
    pub fn sign(
        &self,
        signer: &KeyPair,
        at: DateTime<Utc>,
    ) -> Result<VerifiableCredential, SelfError> {
        let jcs_data = match serde_jcs::to_vec(self) {
            Ok(jcs_data) => jcs_data,
            Err(_) => return Err(SelfError::CredentialEncodingInvalid),
        };

        let signature = bs58::encode(signer.sign(&jcs_data));

        Ok(VerifiableCredential {
            id: self.id.clone(),
            context: self.context.clone(),
            credential_type: self.credential_type.clone(),
            credential_subject: self.credential_subject.clone(),
            issuer: self.issuer.clone(),
            valid_from: self.valid_from.clone(),
            proof: Proof {
                cryptosuite: CRYPTO_SUITE_DEFAULT.to_string(),
                proof_type: PROOF_TYPE_DATA_INTEGRITY.to_string(),
                proof_purpose: PURPOSE_ASSERTION.to_string(),
                proof_value: signature.into_string(),
                created: datetime(at),
                verification_method: format!("{}#{}", self.issuer, signer.public().to_hex())
                    .to_string(),
            },
        })
    }

    pub fn signer(&self) -> Option<(&PublicKey, &DateTime<Utc>)> {
        if self.signer.is_none() || self.issued.is_none() {
            return None;
        }

        return Some((self.signer.as_ref().unwrap(), self.issued.as_ref().unwrap()));
    }
}

#[derive(Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "@context")]
    context: Vec<String>,
    #[serde(rename = "type")]
    credential_type: Vec<String>,
    #[serde(rename = "credentialSubject")]
    credential_subject: HashMap<String, String>,
    issuer: String,
    #[serde(rename = "validFrom")]
    valid_from: String,
    proof: Proof,
}

impl VerifiableCredential {
    pub fn from_bytes(bytes: &[u8]) -> Result<VerifiableCredential, SelfError> {
        serde_json::from_slice(bytes).map_err(|_| SelfError::CredentialEncodingInvalid)
    }

    pub fn into_bytes(&self) -> Result<Vec<u8>, SelfError> {
        serde_json::to_vec(self).map_err(|_| SelfError::CredentialEncodingInvalid)
    }

    pub fn credential_type(&self) -> &[String] {
        &self.credential_type
    }

    pub fn credential_subject(&self) -> Result<Address, SelfError> {
        match self.credential_subject.get("id") {
            Some(id) => Address::decode(id),
            None => Err(SelfError::CredentialSubjectMissing),
        }
    }

    pub fn credential_subject_claim(&self, key: &str) -> Option<&String> {
        self.credential_subject.get(key)
    }

    pub fn issuer(&self) -> Result<Address, SelfError> {
        Address::decode(&self.issuer)
    }

    pub fn valid_from(&self) -> Result<DateTime<Utc>, SelfError> {
        decode_datetime(&self.valid_from)
    }

    pub fn created(&self) -> Result<DateTime<Utc>, SelfError> {
        decode_datetime(&self.proof.created)
    }

    pub fn signing_key(&self) -> Result<PublicKey, SelfError> {
        match Address::decode(&self.proof.verification_method)?.signing_key() {
            Some(signer) => Ok(signer.to_owned()),
            None => Err(SelfError::CredentialSignerMissing),
        }
    }

    pub fn validate(&mut self) -> Result<(), SelfError> {
        // TODO validate this without allocating a bunch of objects
        // we then throw away :/

        if self.context.is_empty() {
            return Err(SelfError::CredentialContextMissing);
        }

        if !self.context.contains(&CONTEXT_DEFAULT[0].to_string()) {
            return Err(SelfError::CredentialContextMissing);
        }

        if self.credential_type.is_empty() {
            return Err(SelfError::CredentialTypeMissing);
        }

        if self.credential_type.first().unwrap() != CREDENTIAL_DEFAULT[0] {
            return Err(SelfError::CredentialTypeMissing);
        }

        let signature = match bs58::decode(&self.proof.proof_value[1..]).into_vec() {
            Ok(signature) => signature,
            Err(_) => return Err(SelfError::CredentialSignatureInvalid),
        };

        self.valid_from()?;
        let issuer = self.issuer()?;
        let signing_key = self.signing_key()?;

        if issuer.address().ne(&signing_key) {
            return Err(SelfError::CredentialSignerMismatch);
        }

        // TODO this copying is really not ideal...
        let credential = Credential {
            id: self.id.clone(),
            context: self.context.clone(),
            credential_type: self.credential_type.clone(),
            credential_subject: self.credential_subject.clone(),
            issuer: self.issuer.clone(),
            valid_from: self.valid_from.clone(),
            signer: None,
            issued: None,
        };

        let jcs_data = match serde_jcs::to_vec(&credential) {
            Ok(jcs_data) => jcs_data,
            Err(_) => return Err(SelfError::CredentialEncodingInvalid),
        };

        if !signing_key.verify(&jcs_data, &signature) {
            return Err(SelfError::CredentialSignatureInvalid);
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct Proof {
    #[serde(rename = "type")]
    proof_type: String,
    #[serde(rename = "proofPurpose")]
    proof_purpose: String,
    #[serde(rename = "proofValue")]
    proof_value: String,
    cryptosuite: String,
    created: String,
    #[serde(rename = "verificationMethod")]
    verification_method: String,
}

pub fn default(default: &[&str]) -> Vec<String> {
    default
        .iter()
        .map(|v| String::from(*v))
        .collect::<Vec<String>>()
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound;

    use crate::{
        credential::{
            did::Address, VerifiableCredential, CRYPTO_SUITE_DEFAULT, PROOF_TYPE_DATA_INTEGRITY,
            PURPOSE_ASSERTION,
        },
        keypair::signing::KeyPair,
        time::now,
    };

    use super::{default, CredentialBuilder, CONTEXT_DEFAULT, CREDENTIAL_DEFAULT};

    #[test]
    fn credential_issue() {
        let issuer_key = KeyPair::new();
        let subject_key = KeyPair::new();
        let assertion_key = KeyPair::new();
        let subject_identifier = Address::key(subject_key.public());
        let issuer_identifier = Address::aure(issuer_key.public());

        let credential = CredentialBuilder::new()
            .context(default(CONTEXT_DEFAULT))
            .credential_type(default(CREDENTIAL_DEFAULT))
            .credential_subject(&subject_identifier)
            .credential_subject_claim("alumniOf", "Harvard")
            .issuer(&issuer_identifier)
            .valid_from(now())
            .sign_with(assertion_key.public(), now())
            .finish()
            .expect("failed to create credential");

        let signer = credential.signer().expect("signer not set");
        assert_eq!(signer.0, assertion_key.public());

        let verifiable_credential = credential
            .sign(&assertion_key, now())
            .expect("credential sign failed");
        assert_eq!(
            verifiable_credential.proof.cryptosuite,
            CRYPTO_SUITE_DEFAULT
        );
        assert_eq!(
            verifiable_credential.proof.proof_type,
            PROOF_TYPE_DATA_INTEGRITY
        );
        assert_eq!(verifiable_credential.proof.proof_purpose, PURPOSE_ASSERTION);
        assert_eq!(
            verifiable_credential.proof.verification_method,
            format!(
                "did:aure:{}#{}",
                issuer_key.public().to_hex(),
                assertion_key.public().to_hex()
            )
        );
    }

    #[test]
    fn credential_verify() {
        let issuer_key = KeyPair::new();
        let subject_key = KeyPair::new();
        let assertion_key = KeyPair::new();
        let subject_identifier = Address::key(subject_key.public());
        let issuer_identifier = Address::aure(issuer_key.public());
        let current_time = now();

        let credential = CredentialBuilder::new()
            .context(default(CONTEXT_DEFAULT))
            .credential_type(default(CREDENTIAL_DEFAULT))
            .credential_subject(&subject_identifier)
            .credential_subject_claim("alumniOf", "Harvard")
            .issuer(&issuer_identifier)
            .valid_from(current_time)
            .sign_with(assertion_key.public(), current_time)
            .finish()
            .expect("failed to create credential");

        let signer = credential.signer().expect("signer not set");
        assert_eq!(signer.0, assertion_key.public());

        let verifiable_credential = credential
            .sign(&assertion_key, now())
            .expect("credential sign failed");

        let encoded_credential = verifiable_credential
            .into_bytes()
            .expect("failed to encode credential");

        let verifiable_credential = VerifiableCredential::from_bytes(&encoded_credential)
            .expect("failed to decode credential");

        assert_eq!(
            verifiable_credential.credential_type(),
            ["VerifiableCredential"]
        );

        assert_eq!(
            verifiable_credential
                .credential_subject()
                .expect("bad credential subject")
                .to_string(),
            subject_identifier.to_string(),
        );

        assert_eq!(
            verifiable_credential.credential_subject_claim("alumniOf"),
            Some(&String::from("Harvard")),
        );

        assert_eq!(
            verifiable_credential
                .issuer()
                .expect("bad credential issuer")
                .to_string(),
            issuer_identifier.to_string(),
        );

        assert_eq!(
            verifiable_credential
                .valid_from()
                .expect("bad valid from timestamp"),
            current_time.trunc_subsecs(0),
        );

        assert_eq!(
            verifiable_credential.signing_key().expect("invalid signer"),
            assertion_key.public().to_owned(),
        );

        assert_eq!(
            verifiable_credential
                .created()
                .expect("bad created timestamp"),
            current_time.trunc_subsecs(0),
        );
    }

    // TODO add more tests for invalid credential validation and parsing
}
