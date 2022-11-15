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
    MessageUnsupportedSignatureAlgorithm,
    RestRequestURLInvalid,
    RestRequestUnknown,
    RestRequestInvalid,
    RestRequestRedirected,
    RestRequestConnectionFailed,
    RestRequestConnectionTimeout,
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
        }
    }
}
