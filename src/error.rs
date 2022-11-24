use std::fmt;

#[derive(Debug)]
pub enum SelfError {
    KeyPairDecodeInvalidData,
    KeyPairSignFailure,
    KeyPairSignMissingSingingKey,
    KeyPairSignWrongKeypairType,
    MessageNoSignature,
    MessageEncodingInvalid,
    MessageDecodingInvalid,
    MessageSigningKeyInvalid,
    MessageSignatureKeypairMismatch,
    MessageUnsupportedSignatureAlgorithm,
    RestRequestURLInvalid,
    RestRequestUnknown,
    RestRequestInvalid,
    RestRequestRedirected,
    RestRequestConnectionFailed,
    RestRequestConnectionTimeout,
    SiggraphActionKeyIDInvalid,
    SiggraphActionPublicKeyLengthBad,
    SiggraphActionPublicKeyEncodingBad,
    SiggraphActionRoleMissing,
    SiggraphActionDeviceIDMissing,
    SiggraphActionEffectiveFromInvalid,
    SiggraphOperationSequenceOutOfOrder,
    SiggraphOperationPreviousSignatureInvalid,
    SiggraphOperationTimestampInvalid,
    SiggraphOperationSigningKeyInvalid,
    SiggraphOperationSignatureInvalid,
    SiggraphOperationNOOP,
    SiggraphOperationJSONInvalid,
}

impl std::error::Error for SelfError {}

impl fmt::Display for SelfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SelfError::KeyPairDecodeInvalidData => write!(f, "Could not decode keypair"),
            SelfError::KeyPairSignFailure => write!(f, "Signing failed"),
            SelfError::KeyPairSignWrongKeypairType => {
                write!(f, "Keypair cannot be used to sign messages")
            }
            SelfError::KeyPairSignMissingSingingKey => write!(
                f,
                "Keypair cannot be used to sign as its missing it's secret key component"
            ),
            SelfError::MessageNoSignature => write!(f, "Message has no signature"),
            SelfError::MessageEncodingInvalid => {
                write!(f, "Message could not be encoded to valid json")
            }
            SelfError::MessageDecodingInvalid => {
                write!(f, "Message could not be decoded from invalid json")
            }
            SelfError::MessageSigningKeyInvalid => {
                write!(f, "Message can only be signed with an ed25519 keypair")
            }
            SelfError::MessageSignatureKeypairMismatch => write!(f, "Message signature was not signed with the provided key"),
            SelfError::MessageUnsupportedSignatureAlgorithm => {
                write!(f, "Message signature algorithm not supported")
            }
            SelfError::RestRequestUnknown => write!(f, "HTTP request failed with unknown error"),
            SelfError::RestRequestInvalid => write!(f, "HTTP request invalid"),
            SelfError::RestRequestRedirected => {
                write!(f, "HTTP request was redirected too many times")
            }
            SelfError::RestRequestURLInvalid => write!(f, "URL is invalid"),
            SelfError::RestRequestConnectionFailed => write!(f, "HTTP request connection failed"),
            SelfError::RestRequestConnectionTimeout => write!(f, "HTTP request connection timeout"),
            SelfError::SiggraphActionKeyIDInvalid => write!(f, "Siggraph action contains an invalid key identifier"),
            SelfError::SiggraphActionPublicKeyLengthBad => write!(f, "Siggraph public key length is invalid"),
            SelfError::SiggraphActionPublicKeyEncodingBad => write!(f, "Siggraph public key is not a valid base64 url encoded string"),
            SelfError::SiggraphActionRoleMissing => write!(f, "Siggraph action is missing a type"),
            SelfError::SiggraphActionDeviceIDMissing => write!(f, "Siggraph action is missing a device id"),
            SelfError::SiggraphActionEffectiveFromInvalid => write!(f, "Sigraph action effective from timestamp is invalid"),
            SelfError::SiggraphOperationSequenceOutOfOrder => write!(f, "Signature graph contains an operation sequence that is out of order"),
            SelfError::SiggraphOperationPreviousSignatureInvalid => write!(f, "Signature graph contains an operation that specifies an invalid previous operatation signature"),
            SelfError::SiggraphOperationTimestampInvalid => write!(f, "Signature graph contains an operation with a timestamp that is the same or before the previous operations timestamp"),
            SelfError::SiggraphOperationSigningKeyInvalid => write!(f, "Signature graph contains an operation that has been signed with a key that cannot be found"),
            SelfError::SiggraphOperationSignatureInvalid => write!(f, "Signature graph contains an operation that has an invalid signature"),
            SelfError::SiggraphOperationNOOP => write!(f, "Signature graph contains an operation with no valid actions"),
            SelfError::SiggraphOperationJSONInvalid => write!(f, "Signature graph operation is not valid json"),
        }
    }
}
