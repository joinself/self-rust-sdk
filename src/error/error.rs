use std::fmt;

#[derive(Debug, PartialEq)]
pub enum SelfError {
    AccountNotConfigured,
    CryptoBadLegacyAccountPickle,
    CryptoBadMessageFormat,
    CryptoBadMessageKeyID,
    CryptoBadMessageMac,
    CryptoBadMessageVersion,
    CryptoBadSessionKey,
    CryptoBadSignature,
    CryptoCorruptedPickle,
    CryptoGroupMessageInvalid,
    CryptoInputBufferTooSmall,
    CryptoInvalidBase64,
    CryptoNotEnoughRandom,
    CryptoOutputBufferTooSmall,
    CryptoPickleExtraData,
    CryptoSasTheirKeyNotSet,
    CryptoUnknown,
    CryptoUnknownGroupParticipant,
    CryptoUnknownMessageIndex,
    CryptoUnknownPickleVersion,
    CrytpoBadAccountKey,
    KeychainKeyExists,
    KeychainKeyNotFound,
    KeyPairConversionFailed,
    KeyPairDataIncorrectLength,
    KeyPairDecodeInvalidData,
    KeyPairPublicKeyInvalidLength,
    KeyPairSignFailure,
    KeyPairSignMissingSingingKey,
    KeyPairSignWrongKeypairType,
    MessageDecodingInvalid,
    MessageEncodingInvalid,
    MessageNoPayload,
    MessageNoProtected,
    MessageNoSignature,
    MessagePayloadInvalid,
    MessageSignatureEncodingInvalid,
    MessageSignatureInvalid,
    MessageSignatureKeypairMismatch,
    MessageSigningKeyInvalid,
    MessageUnsupportedSignatureAlgorithm,
    MessagingDestinationUnknown,
    MessagingGroupUnknown,
    RestRequestConnectionFailed,
    RestRequestConnectionTimeout,
    RestRequestInvalid,
    RestRequestRedirected,
    RestRequestUnknown,
    RestRequestURLInvalid,
    SiggraphActionDeviceIDMissing,
    SiggraphActionEffectiveFromInvalid,
    SiggraphActionInvalidKeyRevocation,
    SiggraphActionKeyAlreadyRevoked,
    SiggraphActionKeyDuplicate,
    SiggraphActionKeyIDInvalid,
    SiggraphActionKeyMissing,
    SiggraphActionMultipleActiveDeviceKeys,
    SiggraphActionMultipleActiveRecoveryKeys,
    SiggraphActionPublicKeyEncodingBad,
    SiggraphActionPublicKeyLengthBad,
    SiggraphActionRoleMissing,
    SiggraphActionSigningKeyInvalid,
    SiggraphActionUnknown,
    SiggraphOperationAccountRecoveryActionInvalid,
    SiggraphOperationDecodingInvalid,
    SiggraphOperationNOOP,
    SiggraphOperationNotEnoughSigners,
    SiggraphOperationNotSigned,
    SiggraphOperationNoValidKeys,
    SiggraphOperationNoValidRecoveryKey,
    SiggraphOperationPreviousHashInvalid,
    SiggraphOperationPreviousHashMissing,
    SiggraphOperationSequenceOutOfOrder,
    SiggraphOperationSignatureHeaderInvalid,
    SiggraphOperationSignatureHeaderMissing,
    SiggraphOperationSignatureInvalid,
    SiggraphOperationSignatureKeyRevoked,
    SiggraphOperationSignatureSignerMissing,
    SiggraphOperationSigningKeyInvalid,
    SiggraphOperationTimestampInvalid,
    SiggraphOperationVersionInvalid,
    StorageConnectionFailed,
    StorageSessionNotFound,
    StorageTableCreationFailed,
    StorageTransactionCommitFailed,
    StorageTransactionCreationFailed,
    StorageTransactionRollbackFailed,
    TokenEncodingInvalid,
    WebsocketProtocolEncodingInvalid,
    WebsocketProtocolErrorUnknown,
    WebsocketSenderIdentifierNotOwned,
    WebsocketTokenUnsupported,
}

impl std::error::Error for SelfError {}

impl fmt::Display for SelfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SelfError::AccountNotConfigured => write!(f, "Account has not been configured"),
            SelfError::CryptoBadLegacyAccountPickle => write!(f, "Crypto attempt to unpickle an account which uses pickle version 1"),
            SelfError::CryptoBadMessageFormat => write!(f, "Crypto message couldn't be decoded"),
            SelfError::CryptoBadMessageKeyID => write!(f, "Crypto message references an unknown key id"),
            SelfError::CryptoBadMessageMac => write!(f, "Crypto message couldn't be decrypted"),
            SelfError::CryptoBadMessageVersion => write!(f, "Crypto message version is unsupported"),
            SelfError::CryptoBadSessionKey => write!(f, "Crypto attempt to initialise an inboud group session from an invalid session key"),
            SelfError::CryptoBadSignature => write!(f, "Crypto received message had a bad signature"),
            SelfError::CryptoCorruptedPickle => write!(f, "Crypto pickle object couldn't be decoded"),
            SelfError::CryptoGroupMessageInvalid => write!(f, "Crypto group message encoding is invalid"),
            SelfError::CryptoInputBufferTooSmall => write!(f, "Crypto function was provided an input buffer that's too small"),
            SelfError::CryptoInvalidBase64 => write!(f, "Crypto input was invalid base64"),
            SelfError::CryptoNotEnoughRandom => write!(f, "Crypto function was provided a random buffer that's too small"),
            SelfError::CryptoOutputBufferTooSmall => write!(f, "Crypto function was provided an output buffer that's too small"),
            SelfError::CryptoPickleExtraData => write!(f, "Crypto pickled object was decoded successfully, but it contained junk data at the end"),
            SelfError::CryptoSasTheirKeyNotSet => write!(f, "Crypto sas doesn't have their key set"),
            SelfError::CryptoUnknown => write!(f, "Crypto unknown error"),
            SelfError::CryptoUnknownGroupParticipant => write!(f, "Crypto unknown group participant"),
            SelfError::CryptoUnknownMessageIndex => write!(f, "Crypto attempt to decode a message whose index is earlier than our earliest known session key"),
            SelfError::CryptoUnknownPickleVersion => write!(f, "Crypto pickled object is too new"),
            SelfError::CrytpoBadAccountKey => write!(f, "Crypto supplied account key is invalid"),
            SelfError::KeychainKeyExists => write!(f, "Keychain key already exists"),
            SelfError::KeychainKeyNotFound => write!(f, "Keychain key not found"),
            SelfError::KeyPairConversionFailed => write!(f, "Keypair conversion failed"),
            SelfError::KeyPairDataIncorrectLength => write!(f, "Keypair public or secret key data length is incorrect"),
            SelfError::KeyPairDecodeInvalidData => write!(f, "Keypair could not be decoded"),
            SelfError::KeyPairPublicKeyInvalidLength => write!(f, "Keypair public key is an incorrect length"),
            SelfError::KeyPairSignFailure => write!(f, "Keypair signing failed"),
            SelfError::KeyPairSignMissingSingingKey => write!(f, "Keypair cannot be used to sign as its missing it's secret key component"),
            SelfError::KeyPairSignWrongKeypairType => write!(f, "Keypair cannot be used to sign messages"),
            SelfError::MessageDecodingInvalid => write!(f, "Message could not be decoded from invalid cbor"),
            SelfError::MessageEncodingInvalid => write!(f, "Message could not be encoded to valid cbor"),
            SelfError::MessageNoPayload => write!(f, "Message has no payload"),
            SelfError::MessageNoProtected => write!(f, "Message has no protected header"),
            SelfError::MessageNoSignature => write!(f, "Message has no signature"),
            SelfError::MessagePayloadInvalid => write!(f, "Message payload is not a map"),
            SelfError::MessageSignatureEncodingInvalid => write!(f, "Message signature is not valid base64"),
            SelfError::MessageSignatureInvalid => write!(f, "Message signature invalid"),
            SelfError::MessageSignatureKeypairMismatch => write!(f, "Message signature was not signed with the provided key"),
            SelfError::MessageSigningKeyInvalid => write!(f, "Message can only be signed with an ed25519 keypair"),
            SelfError::MessageUnsupportedSignatureAlgorithm => write!(f, "Message signature algorithm not supported"),
            SelfError::MessagingDestinationUnknown => write!(f, "Messaging destination or recipient unknown"),
            SelfError::MessagingGroupUnknown => write!(f, "Messaging group not found"),
            SelfError::RestRequestConnectionFailed => write!(f, "HTTP request connection failed"),
            SelfError::RestRequestConnectionTimeout => write!(f, "HTTP request connection timeout"),
            SelfError::RestRequestInvalid => write!(f, "HTTP request invalid"),
            SelfError::RestRequestRedirected => write!(f, "HTTP request was redirected too many times"),
            SelfError::RestRequestUnknown => write!(f, "HTTP request failed with unknown error"),
            SelfError::RestRequestURLInvalid => write!(f, "URL is invalid"),
            SelfError::SiggraphActionDeviceIDMissing => write!(f, "Siggraph action is missing a device id"),
            SelfError::SiggraphActionEffectiveFromInvalid => write!(f, "Sigraph action effective from timestamp is invalid"),
            SelfError::SiggraphActionInvalidKeyRevocation => write!(f, "Siggraph root operation contains an invalid key revocation"),
            SelfError::SiggraphActionKeyAlreadyRevoked => write!(f, "Siggraph action revokes a key that has already been revoked"),
            SelfError::SiggraphActionKeyDuplicate => write!(f, "Siggraph action adds a key with a key identifier that already exists"),
            SelfError::SiggraphActionKeyIDInvalid => write!(f, "Siggraph action contains an invalid key identifier"),
            SelfError::SiggraphActionKeyMissing => write!(f, "Siggraph action refers to a key that does not exist"),
            SelfError::SiggraphActionMultipleActiveDeviceKeys => write!(f, "Siggraph action cannot add another key for a device that is already active"),
            SelfError::SiggraphActionMultipleActiveRecoveryKeys => write!(f, "Siggraph action cannot add another recovery key when there is already one active"),
            SelfError::SiggraphActionPublicKeyEncodingBad => write!(f, "Siggraph public key is not a valid base64 url encoded string"),
            SelfError::SiggraphActionPublicKeyLengthBad => write!(f, "Siggraph public key length is invalid"),
            SelfError::SiggraphActionRoleMissing => write!(f, "Siggraph action is missing a type"),
            SelfError::SiggraphActionSigningKeyInvalid => write!(f, "Siggraph action is not signed by a key that does not exist"),
            SelfError::SiggraphActionUnknown => write!(f, "Siggraph action is of an unknown type"),
            SelfError::SiggraphOperationAccountRecoveryActionInvalid => write!(f, "Siggraph account recovery operation does not invalidate the existing recovery key"),
            SelfError::SiggraphOperationDecodingInvalid => write!(f, "Siggraph operation is not valid json"),
            SelfError::SiggraphOperationNOOP => write!(f, "Siggraph contains an operation with no valid actions"),
            SelfError::SiggraphOperationNotEnoughSigners => write!(f, "Siggraph operation does not meet the minimum number of required signatures"),
            SelfError::SiggraphOperationNotSigned => write!(f, "Siggraph operation cannot be verified as it has no signature"),
            SelfError::SiggraphOperationNoValidKeys => write!(f, "Siggraph operation leaves no active or valid keys"),
            SelfError::SiggraphOperationNoValidRecoveryKey => write!(f, "Siggraph operation leaves no active recovery key"),
            SelfError::SiggraphOperationPreviousHashInvalid => write!(f, "Siggraph contains an operation that specifies a previous hash that does not match the hash of the last operation"),
            SelfError::SiggraphOperationPreviousHashMissing => write!(f, "Siggraph contains an operation that specifies an invalid previous operatation hash"),
            SelfError::SiggraphOperationSequenceOutOfOrder => write!(f, "Siggraph contains an operation sequence that is out of order"),
            SelfError::SiggraphOperationSignatureHeaderInvalid => write!(f, "Siggraph operation has a signature with an invalid header"),
            SelfError::SiggraphOperationSignatureHeaderMissing => write!(f, "Siggraph operation has a signature that is missing a required header"),
            SelfError::SiggraphOperationSignatureInvalid => write!(f, "Siggraph contains an operation that has an invalid signature"),
            SelfError::SiggraphOperationSignatureKeyRevoked => write!(f, "Siggraph operation was signed with a key that was invalid for that time period"),
            SelfError::SiggraphOperationSignatureSignerMissing => write!(f, "Siggraph operation signature header is missing a signer"),
            SelfError::SiggraphOperationSigningKeyInvalid => write!(f, "Siggraph contains an operation that has been signed with a key that cannot be found"),
            SelfError::SiggraphOperationTimestampInvalid => write!(f, "Siggraph contains an operation with a timestamp that is the same or before the previous operations timestamp"),
            SelfError::SiggraphOperationVersionInvalid => write!(f, "Siggraph operation version invalid"),
            SelfError::StorageConnectionFailed => write!(f, "Storage connection failed"),
            SelfError::StorageSessionNotFound => write!(f, "Session not found"),
            SelfError::StorageTableCreationFailed => write!(f, "Storage table creation failed"),
            SelfError::StorageTransactionCommitFailed => write!(f, "Storage transaction commit failed"),
            SelfError::StorageTransactionCreationFailed => write!(f, "Storage transaction creation failed"),
            SelfError::StorageTransactionRollbackFailed => write!(f, "Storage transaction rollback failed"),
            SelfError::TokenEncodingInvalid => write!(f, "Token could not be encoded"),
            SelfError::WebsocketProtocolEncodingInvalid => write!(f, "Websocket protocol event could not be decoded"),
            SelfError::WebsocketProtocolErrorUnknown => write!(f, "Websocket protocol error code is unknown"),
            SelfError::WebsocketSenderIdentifierNotOwned => write!(f, "Websocket cannot send from an identifier that does not belong to this account"),
            SelfError::WebsocketTokenUnsupported => write!(f, "Websocket send attempted with an unsupported token"),
        }
    }
}
