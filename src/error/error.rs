use std::fmt;

#[derive(Debug, PartialEq)]
pub enum SelfError {
    AccountNotConfigured,
    CryptoBadAccountKey,
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
    CryptoUnknownSession,
    HashgraphDeactivated,
    HashgraphDuplicateAction,
    HashgraphDuplicateKey,
    HashgraphDuplicateSigner,
    HashgraphInvalidControllerLength,
    HashgraphInvalidEmbeddedDescription,
    HashgraphInvalidKeyLength,
    HashgraphInvalidKeyReuse,
    HashgraphInvalidModify,
    HashgraphInvalidPreviousHash,
    HashgraphInvalidRecover,
    HashgraphInvalidRevocationTimestamp,
    HashgraphInvalidRevoke,
    HashgraphInvalidSignature,
    HashgraphInvalidSignatureHeader,
    HashgraphInvalidSignatureLength,
    HashgraphInvalidSignerLength,
    HashgraphInvalidState,
    HashgraphInvalidTimestamp,
    HashgraphKeyAlreadyRevoked,
    HashgraphModifyNOOP,
    HashgraphMultiRoleKeyViolation,
    HashgraphNoActiveKeys,
    HashgraphNoRolesAssigned,
    HashgraphNotEnoughSigners,
    HashgraphOperationInvalid,
    HashgraphOperationMissing,
    HashgraphOperationNOOP,
    HashgraphOperationSequenceOutOfOrder,
    HashgraphOperationUnauthorized,
    HashgraphOperationUnsigned,
    HashgraphOperationVersionInvalid,
    HashgraphReferencedDescriptionNotFound,
    HashgraphSelfSignatureRequired,
    HashgraphSignerRoleInvalid,
    HashgraphSignerUnknown,
    HashgraphSigningKeyRevoked,
    KeychainKeyExists,
    KeychainKeyNotFound,
    KeyPairConversionFailed,
    KeyPairDataIncorrectLength,
    KeyPairDecodeInvalidData,
    KeyPairPublicKeyInvalidLength,
    KeyPairSignFailure,
    KeyPairSignMissingSingingKey,
    KeyPairSignWrongKeypairType,
    MessageContentMissing,
    MessageCTIMissing,
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
    RestResponseBadRequest,
    RestResponseConflict,
    RestResponseNotFound,
    RestResponseUnauthorized,
    RestResponseUnexpected,
    RestResposeBodyInvalid,
    StorageConnectionFailed,
    StorageSessionNotFound,
    StorageTableCreationFailed,
    StorageTransactionCommitFailed,
    StorageTransactionCreationFailed,
    StorageTransactionRollbackFailed,
    TokenEncodingInvalid,
    TokenSignatureInvalid,
    TokenTypeInvalid,
    TokenVersionInvalid,
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
            SelfError::CryptoBadAccountKey => write!(f, "Crypto supplied account key is invalid"),
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
            SelfError::CryptoUnknownSession => write!(f, "Crypto received a non-one time message, but there is no existing session to decrypt it with"),
            SelfError::HashgraphDeactivated => write!(f, "Hashgraph has been deactivated and cannot be updated"),
            SelfError::HashgraphDuplicateAction => write!(f, "Hashgraph operation performs more than one action on a key"),
            SelfError::HashgraphDuplicateKey => write!(f, "Hashgraph operation adds a key that already exists"),
            SelfError::HashgraphDuplicateSigner => write!(f, "Hashgraph operation has been signed by the same key more than once"),
            SelfError::HashgraphInvalidControllerLength => write!(f, "Hashgraph controller length invalid"),
            SelfError::HashgraphInvalidEmbeddedDescription => write!(f, "Hashgraph embedded key usage invalid"),
            SelfError::HashgraphInvalidKeyLength => write!(f, "Hashgraph key identifier length invalid"),
            SelfError::HashgraphInvalidKeyReuse => write!(f, "Hashgraph key cannot be assigned additional roles"),
            SelfError::HashgraphInvalidModify => write!(f, "Hashgraph modify action not permitted in initial operation"),
            SelfError::HashgraphInvalidPreviousHash => write!(f, "Hashgraph operation specifies a previous hash that does not match"),
            SelfError::HashgraphInvalidRecover => write!(f, "Hashgraph recover action not permitted in initial operation"),
            SelfError::HashgraphInvalidRevocationTimestamp => write!(f, "Hashgraph revocation timestamp before the target keys creation"),
            SelfError::HashgraphInvalidRevoke => write!(f, "Hashgraph revoke action not permitted in initial operation"),
            SelfError::HashgraphInvalidSignature => write!(f, "Hashgraph operation signature could not be verified"),
            SelfError::HashgraphInvalidSignatureHeader => write!(f, "Hashgraph signature header must be specified"),
            SelfError::HashgraphInvalidSignatureLength => write!(f, "Hashgraph signature length invalid"),
            SelfError::HashgraphInvalidSignerLength => write!(f, "Hashgraph signer length invalid"),
            SelfError::HashgraphInvalidState => write!(f, "Hashgraph is in an invalid state"),
            SelfError::HashgraphInvalidTimestamp => write!(f, "Hashgraph operation timestamp is before the previous operations"),
            SelfError::HashgraphKeyAlreadyRevoked => write!(f, "Hashgraph action revokes an already revoked key"),
            SelfError::HashgraphModifyNOOP => write!(f, "Hashgraph action makes no modification"),
            SelfError::HashgraphMultiRoleKeyViolation => write!(f, "Hashgraph key is not permitted to be assigned to multiple roles"),
            SelfError::HashgraphNoActiveKeys => write!(f, "Hashgraph has no active keys"),
            SelfError::HashgraphNoRolesAssigned => write!(f, "Hashgraph key has no roles assigned"),
            SelfError::HashgraphNotEnoughSigners => write!(f, "Hashgraph operation has not been signed by a sufficient amount of keys"),
            SelfError::HashgraphOperationInvalid => write!(f, "Hashgraph operation invalid"),
            SelfError::HashgraphOperationMissing => write!(f, "Hashgraph operation state has not been specified"),
            SelfError::HashgraphOperationNOOP => write!(f, "Hashgraph operation has no actions"),
            SelfError::HashgraphOperationSequenceOutOfOrder => write!(f, "Hashgraph operation sequence out of order"),
            SelfError::HashgraphOperationUnauthorized => write!(f, "Hashgraph operation must be signed by a key with the correct invocation role"),
            SelfError::HashgraphOperationUnsigned => write!(f, "Hashgraph operation must be signed by an existing valid key"),
            SelfError::HashgraphOperationVersionInvalid => write!(f, "Hashgraph operation version invalid"),
            SelfError::HashgraphReferencedDescriptionNotFound => write!(f, "Hashgraph action references a key that cannot be found"),
            SelfError::HashgraphSelfSignatureRequired => write!(f, "Hashgraph action adds a key that has not signed the operation"),
            SelfError::HashgraphSignerRoleInvalid => write!(f, "Hashgraph operation has been signed by a key that does not have the invocation role"),
            SelfError::HashgraphSignerUnknown => write!(f, "Hashgraph operation has been signed by an unknown key"),
            SelfError::HashgraphSigningKeyRevoked => write!(f, "Hashgraph operation has been signed by a key that has been revoked"),
            SelfError::KeychainKeyExists => write!(f, "Keychain key already exists"),
            SelfError::KeychainKeyNotFound => write!(f, "Keychain key not found"),
            SelfError::KeyPairConversionFailed => write!(f, "Keypair conversion failed"),
            SelfError::KeyPairDataIncorrectLength => write!(f, "Keypair public or secret key data length is incorrect"),
            SelfError::KeyPairDecodeInvalidData => write!(f, "Keypair could not be decoded"),
            SelfError::KeyPairPublicKeyInvalidLength => write!(f, "Keypair public key is an incorrect length"),
            SelfError::KeyPairSignFailure => write!(f, "Keypair signing failed"),
            SelfError::KeyPairSignMissingSingingKey => write!(f, "Keypair cannot be used to sign as its missing it's secret key component"),
            SelfError::KeyPairSignWrongKeypairType => write!(f, "Keypair cannot be used to sign messages"),
            SelfError::MessageContentMissing => write!(f, "Message is missing content field"),
            SelfError::MessageCTIMissing => write!(f, "Message is missing cti field"),
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
            SelfError::RestRequestURLInvalid => write!(f, "HTTP request URL is invalid"),
            SelfError::RestResponseBadRequest => write!(f, "HTTP response bad request"),
            SelfError::RestResposeBodyInvalid => write!(f, "HTTP response body encoding invalid"),
            SelfError::RestResponseConflict => write!(f, "HTTP response conflict"),
            SelfError::RestResponseNotFound => write!(f, "HTTP response not found"),
            SelfError::RestResponseUnauthorized => write!(f, "HTTP response unauthorized"),
            SelfError::RestResponseUnexpected => write!(f, "HTTP reponse status was unexpected"),
            SelfError::StorageConnectionFailed => write!(f, "Storage connection failed"),
            SelfError::StorageSessionNotFound => write!(f, "Session not found"),
            SelfError::StorageTableCreationFailed => write!(f, "Storage table creation failed"),
            SelfError::StorageTransactionCommitFailed => write!(f, "Storage transaction commit failed"),
            SelfError::StorageTransactionCreationFailed => write!(f, "Storage transaction creation failed"),
            SelfError::StorageTransactionRollbackFailed => write!(f, "Storage transaction rollback failed"),
            SelfError::TokenEncodingInvalid => write!(f, "Token could not be encoded"),
            SelfError::TokenSignatureInvalid => write!(f, "Token signature invalid"),
            SelfError::TokenTypeInvalid => write!(f, "Token type invalid or unsupported"),
            SelfError::TokenVersionInvalid => write!(f, "Token version not supported"),
            SelfError::WebsocketProtocolEncodingInvalid => write!(f, "Websocket protocol event could not be decoded"),
            SelfError::WebsocketProtocolErrorUnknown => write!(f, "Websocket protocol error code is unknown"),
            SelfError::WebsocketSenderIdentifierNotOwned => write!(f, "Websocket cannot send from an identifier that does not belong to this account"),
            SelfError::WebsocketTokenUnsupported => write!(f, "Websocket send attempted with an unsupported token"),
        }
    }
}
