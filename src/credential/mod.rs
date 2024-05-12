mod did;
mod model;
mod presentation;

pub use self::did::*;
pub use self::model::*;
pub use self::presentation::*;

pub const CONTEXT_DEFAULT: &[&str] = &["https://www.w3.org/ns/credentials/v2"];
pub const CREDENTIAL_DEFAULT: &[&str] = &["VerifiableCredential"];
pub const CREDENTIAL_PASSPORT: &[&str] = &["VerifiableCredential", "PassportCredential"];
pub const CREDENTIAL_LIVENESS: &[&str] = &["VerifiableCredential", "LivenessCredential"];
pub const CREDENTIAL_PROFILE_IMAGE: &[&str] = &["VerifiableCredential", "ProfileImageCredential"];
pub const CREDENTIAL_APPLICATION_PUBLISHER: &[&str] =
    &["VerifiableCredential", "ApplicationPublisherCredential"];
pub const CRYPTO_SUITE_DEFAULT: &str = "jcs-eddsa-2022";
pub const PRESENTATION_DEFAULT: &[&str] = &["VerifiablePresentation"];
pub const PRESENTATION_PASSPORT: &[&str] = &["VerifiablePresentation", "PassportPresentation"];
pub const PRESENTATION_LIVENESS: &[&str] = &["VerifiablePresentation", "LivenessPresentation"];
pub const PRESENTATION_PROFILE_IMAGE: &[&str] =
    &["VerifiablePresentation", "ProfileImagePresentation"];
pub const PRESENTATION_APPLICATION_PUBLISHER: &[&str] =
    &["VerifiablePresentation", "ApplicationPublisherPresentation"];
pub const PROOF_TYPE_DATA_INTEGRITY: &str = "DataIntegrityProof";
pub const PURPOSE_ASSERTION: &str = "assertionMethod";
