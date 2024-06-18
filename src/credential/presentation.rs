use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use std::collections::HashSet;

use crate::credential::{
    model::VerifiableCredential, Address, CONTEXT_DEFAULT, CRYPTO_SUITE_DEFAULT,
    PRESENTATION_DEFAULT, PROOF_TYPE_DATA_INTEGRITY, PURPOSE_ASSERTION,
};
use crate::error::SelfError;
use crate::hashgraph;
use crate::keypair::signing::KeyPair;
use crate::time::datetime;

#[derive(Default)]
pub struct PresentationBuilder {
    id: Option<String>,
    context: Option<Vec<String>>,
    presentation_type: Option<Vec<String>>,
    holder: Option<String>,
    credentails: Vec<VerifiableCredential>,
}

impl PresentationBuilder {
    pub fn new() -> PresentationBuilder {
        PresentationBuilder::default()
    }

    pub fn id(&mut self, id: String) -> &mut PresentationBuilder {
        self.id = Some(id);
        self
    }

    pub fn context(&mut self, context: Vec<String>) -> &mut PresentationBuilder {
        self.context = Some(context);
        self
    }

    pub fn presentation_type(
        &mut self,
        presentation_type: Vec<String>,
    ) -> &mut PresentationBuilder {
        self.presentation_type = Some(presentation_type);
        self
    }

    pub fn credential_add(&mut self, credential: VerifiableCredential) -> &mut PresentationBuilder {
        self.credentails.push(credential);
        self
    }

    pub fn holder(&mut self, holder: &Address) -> &mut PresentationBuilder {
        self.holder = Some(holder.to_string());
        self
    }

    pub fn finish(&self) -> Result<Presentation, SelfError> {
        let id = self.id.clone();
        let credentials = self.credentails.clone();

        let presentation_type = match &self.presentation_type {
            Some(presentation_type) => presentation_type.clone(),
            None => return Err(SelfError::PresentationTypeMissing),
        };

        let context = match &self.context {
            Some(context) => context.clone(),
            None => return Err(SelfError::PresentationContextMissing),
        };

        let holder = match &self.holder {
            Some(holder) => holder.clone(),
            None => return Err(SelfError::PresentationHolderMissing),
        };

        let mut signers = Vec::new();

        let subject = Address::decode(&holder)?;
        signers.push(subject);

        for credential in &self.credentails {
            let subject = credential.credential_subject()?;
            signers.push(subject);
        }

        Ok(Presentation {
            id,
            context,
            presentation_type,
            credentials,
            holder,
            signers,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Presentation {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "@context")]
    context: Vec<String>,
    #[serde(rename = "type")]
    presentation_type: Vec<String>,
    holder: String,
    #[serde(rename = "verifiableCredential")]
    credentials: Vec<VerifiableCredential>,
    #[serde(skip)]
    signers: Vec<Address>,
}

impl Presentation {
    pub fn sign(
        &self,
        signers: &[(&Address, &KeyPair)],
        at: DateTime<Utc>,
    ) -> Result<VerifiablePresentation, SelfError> {
        let jcs_data = match serde_jcs::to_vec(self) {
            Ok(jcs_data) => jcs_data,
            Err(_) => return Err(SelfError::PresentationEncodingInvalid),
        };

        let mut proof = Vec::new();

        let holder = Address::decode(&self.holder)?;

        for (issuer, signer) in signers {
            let signature = bs58::encode(signer.sign(&jcs_data));

            let verification_method = match issuer.method() {
                hashgraph::Method::Key => {
                    let signing_key = match issuer.signing_key() {
                        Some(signing_key) => signing_key,
                        None => return Err(SelfError::PresentationSignerMismatch),
                    };

                    if issuer.address().ne(holder.address()) && signer.public().ne(signing_key) {
                        return Err(SelfError::PresentationSignerMismatch);
                    }

                    issuer.to_string()
                }
                hashgraph::Method::Aure => {
                    format!("{}#{}", issuer.base_address(), signer.public().to_hex()).to_string()
                }
            };

            proof.push(Proof {
                cryptosuite: CRYPTO_SUITE_DEFAULT.to_string(),
                proof_type: PROOF_TYPE_DATA_INTEGRITY.to_string(),
                proof_purpose: PURPOSE_ASSERTION.to_string(),
                proof_value: format!("z{}", signature.into_string()),
                created: datetime(at),
                verification_method,
            });
        }

        Ok(VerifiablePresentation {
            id: self.id.clone(),
            context: self.context.clone(),
            presentation_type: self.presentation_type.clone(),
            credentials: self.credentials.clone(),
            holder: self.holder.clone(),
            proof,
        })
    }

    pub fn required_signers(&self) -> &[Address] {
        &self.signers
    }
}

#[derive(Serialize, Deserialize)]
pub struct VerifiablePresentation {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "@context")]
    context: Vec<String>,
    #[serde(rename = "type")]
    presentation_type: Vec<String>,
    holder: String,
    #[serde(rename = "verifiableCredential")]
    credentials: Vec<VerifiableCredential>,
    proof: Vec<Proof>,
}

impl VerifiablePresentation {
    pub fn from_bytes(bytes: &[u8]) -> Result<VerifiablePresentation, SelfError> {
        serde_json::from_slice(bytes).map_err(|_| SelfError::PresentationEncodingInvalid)
    }

    pub fn into_bytes(&self) -> Result<Vec<u8>, SelfError> {
        serde_json::to_vec(self).map_err(|_| SelfError::PresentationEncodingInvalid)
    }

    pub fn presentation_type(&self) -> &[String] {
        &self.presentation_type
    }

    pub fn holder(&self) -> Result<Address, SelfError> {
        Address::decode(&self.holder)
    }

    pub fn credentials(&self) -> &[VerifiableCredential] {
        &self.credentials
    }

    pub fn signers(&self) -> Result<Vec<Address>, SelfError> {
        let mut signers = Vec::new();

        for proof in &self.proof {
            let signer = Address::decode(&proof.verification_method)?;
            signers.push(signer);
        }

        Ok(signers)
    }

    pub fn validate(&self) -> Result<(), SelfError> {
        if self.context.is_empty() {
            return Err(SelfError::PresentationContextMissing);
        }

        if !self.context.contains(&CONTEXT_DEFAULT[0].to_string()) {
            return Err(SelfError::PresentationContextMissing);
        }

        if self.presentation_type.is_empty() {
            return Err(SelfError::PresentationTypeMissing);
        }

        if self.presentation_type.first().unwrap() != PRESENTATION_DEFAULT[0] {
            return Err(SelfError::PresentationTypeMissing);
        }

        let holder = self.holder()?;

        let presentation = Presentation {
            id: self.id.clone(),
            context: self.context.clone(),
            presentation_type: self.presentation_type.clone(),
            credentials: self.credentials.clone(),
            holder: self.holder.clone(),
            signers: Vec::new(),
        };

        let jcs_data = match serde_jcs::to_vec(&presentation) {
            Ok(jcs_data) => jcs_data,
            Err(_) => return Err(SelfError::CredentialEncodingInvalid),
        };

        let mut signers = HashSet::new();
        let mut holder_signature = false;

        for proof in &self.proof {
            let signature = match bs58::decode(&proof.proof_value[1..]).into_vec() {
                Ok(signature) => signature,
                Err(_) => return Err(SelfError::PresentationSignatureInvalid),
            };

            let signer = Address::decode(&proof.verification_method)?;

            if signer.address().eq(holder.address()) {
                holder_signature = true;
            }

            let signing_key = match signer.signing_key() {
                Some(signer) => signer.to_owned(),
                None => return Err(SelfError::PresentationSignerMissing),
            };

            if !signing_key.verify(&jcs_data, &signature) {
                return Err(SelfError::PresentationSignatureInvalid);
            }

            signers.insert(signer.address().to_owned());
        }

        // check every credential subject has signed, as well as the holder
        if !holder_signature {
            return Err(SelfError::PresentationSignerMissing);
        }

        for credential in &self.credentials {
            let subject = credential.credential_subject()?;
            if !signers.contains(subject.address()) {
                return Err(SelfError::PresentationSignerMissing);
            }
        }

        // TODO check credential type matches presentation type...

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Proof {
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

#[cfg(test)]
mod tests {

    use crate::credential::{
        default, Address, CredentialBuilder, CONTEXT_DEFAULT, CREDENTIAL_DEFAULT,
        CRYPTO_SUITE_DEFAULT, PRESENTATION_DEFAULT, PROOF_TYPE_DATA_INTEGRITY, PURPOSE_ASSERTION,
    };
    use crate::keypair::signing::KeyPair;
    use crate::time::now;

    use super::{PresentationBuilder, VerifiablePresentation};

    #[test]
    fn presentation_issue() {
        // issue a couple of credentials issued to differnt link keys
        let issuer_identifier_key = KeyPair::new();
        let issuer_assertion_key = KeyPair::new();
        let subject_identifier_key = KeyPair::new();
        let subject_assertion_key = KeyPair::new();
        let subject_a_key = KeyPair::new();
        let subject_b_key = KeyPair::new();
        let subject_identifier = Address::aure(subject_identifier_key.public());
        let mut subject_with_key_identifier = Address::aure(subject_identifier_key.public());
        subject_with_key_identifier.with_signing_key(subject_assertion_key.public());
        let subject_a_identifier = Address::key(subject_a_key.public());
        let subject_b_identifier = Address::key(subject_b_key.public());
        let issuer_identifier = Address::aure(issuer_identifier_key.public());

        let credential = CredentialBuilder::new()
            .context(default(CONTEXT_DEFAULT))
            .credential_type(default(CREDENTIAL_DEFAULT))
            .credential_subject(&subject_a_identifier)
            .credential_subject_claim("alumniOf", "Harvard")
            .issuer(&issuer_identifier)
            .valid_from(now())
            .sign_with(issuer_assertion_key.public(), now())
            .finish()
            .expect("failed to create credential");

        let verifiable_credential_a = credential
            .sign(&issuer_assertion_key, now())
            .expect("credential sign failed");

        let credential = CredentialBuilder::new()
            .context(default(CONTEXT_DEFAULT))
            .credential_type(default(CREDENTIAL_DEFAULT))
            .credential_subject(&subject_b_identifier)
            .credential_subject_claim("gradePointAverage", "3.9")
            .issuer(&issuer_identifier)
            .valid_from(now())
            .sign_with(issuer_assertion_key.public(), now())
            .finish()
            .expect("failed to create credential");

        let verifiable_credential_b = credential
            .sign(&issuer_assertion_key, now())
            .expect("credential sign failed");

        // create a presentation for these two separate credentails
        // as the subjects main identifier
        let presentation = PresentationBuilder::new()
            .context(default(CONTEXT_DEFAULT))
            .presentation_type(default(PRESENTATION_DEFAULT))
            .holder(&subject_identifier)
            .credential_add(verifiable_credential_a)
            .credential_add(verifiable_credential_b)
            .finish()
            .expect("failed to create presentation");

        // sign the presentation
        let signers = &[
            (&subject_with_key_identifier, &subject_assertion_key),
            (&subject_a_identifier, &subject_a_key),
            (&subject_b_identifier, &subject_b_key),
        ];

        let current_time = now();

        let verifiable_presentation = presentation
            .sign(signers, current_time)
            .expect("failed to create verifiable presentation");

        assert_eq!(verifiable_presentation.credentials.len(), 2,);

        assert_eq!(verifiable_presentation.proof.len(), 3,);

        assert_eq!(
            verifiable_presentation.proof[0].cryptosuite,
            CRYPTO_SUITE_DEFAULT,
        );
        assert_eq!(
            verifiable_presentation.proof[0].proof_type,
            PROOF_TYPE_DATA_INTEGRITY
        );
        assert_eq!(
            verifiable_presentation.proof[0].proof_purpose,
            PURPOSE_ASSERTION
        );
        assert_eq!(
            verifiable_presentation.proof[0].verification_method,
            format!(
                "did:aure:{}#{}",
                subject_identifier_key.public().to_hex(),
                subject_assertion_key.public().to_hex(),
            )
        );

        assert_eq!(
            verifiable_presentation.proof[1].cryptosuite,
            CRYPTO_SUITE_DEFAULT,
        );
        assert_eq!(
            verifiable_presentation.proof[1].proof_type,
            PROOF_TYPE_DATA_INTEGRITY
        );
        assert_eq!(
            verifiable_presentation.proof[1].proof_purpose,
            PURPOSE_ASSERTION
        );
        assert_eq!(
            verifiable_presentation.proof[1].verification_method,
            subject_a_identifier.to_string(),
        );

        assert_eq!(
            verifiable_presentation.proof[2].cryptosuite,
            CRYPTO_SUITE_DEFAULT,
        );
        assert_eq!(
            verifiable_presentation.proof[2].proof_type,
            PROOF_TYPE_DATA_INTEGRITY
        );
        assert_eq!(
            verifiable_presentation.proof[2].proof_purpose,
            PURPOSE_ASSERTION
        );
        assert_eq!(
            verifiable_presentation.proof[2].verification_method,
            subject_b_identifier.to_string(),
        );
    }

    #[test]
    fn presentation_validate() {
        // issue a couple of credentials issued to differnt link keys
        let issuer_identifier_key = KeyPair::new();
        let issuer_assertion_key = KeyPair::new();
        let subject_identifier_key = KeyPair::new();
        let subject_assertion_key = KeyPair::new();
        let subject_a_key = KeyPair::new();
        let subject_b_key = KeyPair::new();
        let subject_identifier = Address::aure(subject_identifier_key.public());
        let mut subject_with_key_identifier = Address::aure(subject_identifier_key.public());
        subject_with_key_identifier.with_signing_key(subject_assertion_key.public());
        let subject_a_identifier = Address::key(subject_a_key.public());
        let subject_b_identifier = Address::key(subject_b_key.public());
        let issuer_identifier = Address::aure(issuer_identifier_key.public());

        let credential = CredentialBuilder::new()
            .context(default(CONTEXT_DEFAULT))
            .credential_type(default(CREDENTIAL_DEFAULT))
            .credential_subject(&subject_a_identifier)
            .credential_subject_claim("alumniOf", "Harvard")
            .issuer(&issuer_identifier)
            .valid_from(now())
            .sign_with(issuer_assertion_key.public(), now())
            .finish()
            .expect("failed to create credential");

        let verifiable_credential_a = credential
            .sign(&issuer_assertion_key, now())
            .expect("credential sign failed");

        let credential = CredentialBuilder::new()
            .context(default(CONTEXT_DEFAULT))
            .credential_type(default(CREDENTIAL_DEFAULT))
            .credential_subject(&subject_b_identifier)
            .credential_subject_claim("gradePointAverage", "3.9")
            .issuer(&issuer_identifier)
            .valid_from(now())
            .sign_with(issuer_assertion_key.public(), now())
            .finish()
            .expect("failed to create credential");

        let verifiable_credential_b = credential
            .sign(&issuer_assertion_key, now())
            .expect("credential sign failed");

        // create a presentation for these two separate credentails
        // as the subjects main identifier
        let presentation = PresentationBuilder::new()
            .context(default(CONTEXT_DEFAULT))
            .presentation_type(default(PRESENTATION_DEFAULT))
            .holder(&subject_identifier)
            .credential_add(verifiable_credential_a)
            .credential_add(verifiable_credential_b)
            .finish()
            .expect("failed to create presentation");

        // sign the presentation
        let signers = &[
            (&subject_with_key_identifier, &subject_assertion_key),
            (&subject_a_identifier, &subject_a_key),
            (&subject_b_identifier, &subject_b_key),
        ];

        let current_time = now();

        let verifiable_presentation = presentation
            .sign(signers, current_time)
            .expect("failed to create verifiable presentation");

        let encoded_presentation = verifiable_presentation
            .into_bytes()
            .expect("failed to encode presentation");

        let verifiable_presentation = VerifiablePresentation::from_bytes(&encoded_presentation)
            .expect("failed to decode presentation");

        verifiable_presentation
            .validate()
            .expect("failed to validate presentation");
    }

    // TODO add more tests for invalid credential validation and parsing
}
