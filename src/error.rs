use std::fmt;

#[derive(Debug)]
pub enum SelfError {
    KeyPairDecodeInvalidData,
    KeyPairSignFailure,
    KeyPairSignMissingSingingKey,
    KeyPairSignWrongKeypairType,
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
        }
    }
}
