use crate::{
    error::SelfError,
    keypair::signing::{KeyPair, PublicKey},
};

use serde::{Deserialize, Serialize};

// const FLAG_DELEGATION_PERMIT: u8 = 1 << 1;
const FLAG_BEARER_PROMISCUOUS: u8 = 1 << 2;

const TOKEN_VERSION_1: u8 = 1;

const TOKEN_KIND_AUTHENTICATION: u8 = 1;
const TOKEN_KIND_AUTHORIZATION: u8 = 2;
const TOKEN_KIND_NOTIFICATION: u8 = 3;
const TOKEN_KIND_SUBSCRIPTION: u8 = 4;
const TOKEN_KIND_DELEGATION: u8 = 5;

const SIGNER_ALG_ED25519: u8 = 1;

#[derive(Clone, Serialize, Deserialize)]
pub enum Token {
    Authentication(Authentication),
    Authorization(Authorization),
    Notification(Notification),
    Subscription(Subscription),
    Delegation(Delegation),
}

impl Token {
    pub fn kind(&self) -> u8 {
        match self {
            Token::Authentication(_) => TOKEN_KIND_AUTHENTICATION,
            Token::Authorization(_) => TOKEN_KIND_AUTHORIZATION,
            Token::Notification(_) => TOKEN_KIND_NOTIFICATION,
            Token::Subscription(_) => TOKEN_KIND_SUBSCRIPTION,
            Token::Delegation(_) => TOKEN_KIND_DELEGATION,
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Token, SelfError> {
        if bytes[0] != TOKEN_VERSION_1 {
            return Err(SelfError::TokenVersionInvalid);
        }

        // TODO proper token validation
        Ok(match bytes[1] {
            TOKEN_KIND_AUTHENTICATION => Token::Authentication(Authentication {
                token: bytes.to_vec(),
            }),
            TOKEN_KIND_AUTHORIZATION => Token::Authorization(Authorization {
                token: bytes.to_vec(),
            }),
            TOKEN_KIND_NOTIFICATION => Token::Notification(Notification {
                token: bytes.to_vec(),
            }),
            TOKEN_KIND_SUBSCRIPTION => Token::Subscription(Subscription {
                token: bytes.to_vec(),
            }),
            TOKEN_KIND_DELEGATION => Token::Delegation(Delegation {
                token: bytes.to_vec(),
            }),
            _ => return Err(SelfError::TokenTypeInvalid),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, SelfError> {
        Ok(match self {
            Token::Authentication(auth) => auth.token.to_vec(),
            Token::Authorization(auth) => auth.token.to_vec(),
            Token::Notification(notif) => notif.token.to_vec(),
            Token::Subscription(sub) => sub.token.to_vec(),
            Token::Delegation(del) => del.token.to_vec(),
        })
    }

    pub fn version(&self) -> u8 {
        match self {
            Token::Authentication(auth) => auth.token[0],
            Token::Authorization(auth) => auth.token[0],
            Token::Notification(notif) => notif.token[0],
            Token::Subscription(sub) => sub.token[0],
            Token::Delegation(del) => del.token[0],
        }
    }

    pub fn id(&self) -> Vec<u8> {
        match self {
            Token::Authentication(auth) => auth.token[6..26].to_vec(),
            Token::Authorization(auth) => auth.token[6..26].to_vec(),
            Token::Notification(notif) => notif.token[6..26].to_vec(),
            Token::Subscription(sub) => sub.token[6..26].to_vec(),
            Token::Delegation(del) => del.token[6..26].to_vec(),
        }
    }
}

/// Authentication generated by an identifier to authenticate an action it is performing,
/// such as makign an http request. The authentication token includes a signature over arbitrary
/// data that is not included in the token itself, but inferred from the context in which it is used
/// authentication token format and fields
// | version | type | flags | nonce | exipry | signer alg | signer | signature |
// | 1. version (1 byte)
// | 2. type (1 byte)
// | 3. flag options (4 bytes)
// | 4. nonce (20 bytes)
// | 5. expiry timestamp seconds (8 bytes)
// | 6. signer algorithm (1 byte)
// | 7. signer (32 bytes)
// | 9. signature over above fields (64 bytes)
#[derive(Clone, Serialize, Deserialize)]
pub struct Authentication {
    pub token: Vec<u8>,
}

impl Authentication {
    pub fn new(issued_by: &KeyPair, expires: i64, signed_data: &[u8]) -> Authentication {
        let mut token = vec![0; 1 + 1 + 20 + 4 + 8 + 33 + 64];

        token[0] = TOKEN_VERSION_1;
        token[1] = TOKEN_KIND_AUTHENTICATION;
        crate::crypto::random::read_bytes(&mut token[6..26]);
        token[26..34].copy_from_slice(&expires.to_le_bytes());
        token[34..67].copy_from_slice(&issued_by.address());

        // concatonate the tokens data and the data that is needed to be signed
        // and sign the resulting buffer
        let mut signature_buf = vec![0; (token.len() - 64) + signed_data.len()];
        signature_buf[0..67].copy_from_slice(&token[0..67]);
        signature_buf[67..].copy_from_slice(signed_data);

        let signature = issued_by.sign(&signature_buf);
        token[67..].copy_from_slice(&signature);

        Authentication { token }
    }
}

/// Authorization generated by an identifier to permit it's bearer to perform certain actions
/// such as sending a message, acquire a prekey or prove a relationship. Can be resticted to use
/// by a single identifier or by any identitfier that bears the token
/// authorization token format and fields
// | version | type | flags | nonce | exipry | signer alg | signer | bearer (optional) | signature |
// | 1. version (1 byte)
// | 2. type (1 byte)
// | 3. flag options (4 bytes)
// | 4. nonce (20 bytes)
// | 5. expiry timestamp seconds (8 bytes)
// | 6. signer algorithm (1 byte)
// | 7. signer (32 bytes)
// | 8. bearer (32 bytes, [optional, not required if FLAG_BEARER_PROMISCUOUS is set])
// | 9. signature over above fields (64 bytes)
#[derive(Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub token: Vec<u8>,
}

impl Authorization {
    pub fn new(
        issued_by: &KeyPair,
        intended_for: Option<&PublicKey>,
        expires: i64,
    ) -> Authorization {
        if let Some(for_identifier) = intended_for {
            let mut token = vec![0; 1 + 1 + 4 + 20 + 8 + 33 + 33 + 1 + 64];
            let mut options: i32 = 0;
            options |= FLAG_BEARER_PROMISCUOUS as i32;

            token[0] = TOKEN_VERSION_1;
            token[1] = TOKEN_KIND_AUTHORIZATION;
            token[2..6].copy_from_slice(&options.to_le_bytes());
            crate::crypto::random::read_bytes(&mut token[6..26]);
            token[26..34].copy_from_slice(&expires.to_le_bytes());
            token[34..67].copy_from_slice(issued_by.address());
            token[67..100].copy_from_slice(for_identifier.address());

            let signature = issued_by.sign(&token[0..100]);
            token[100..164].copy_from_slice(&signature);

            Authorization { token }
        } else {
            let mut token = vec![0; 1 + 1 + 4 + 20 + 8 + 33 + 1 + 64];

            token[0] = TOKEN_VERSION_1;
            token[1] = TOKEN_KIND_AUTHORIZATION;
            crate::crypto::random::read_bytes(&mut token[6..26]);
            token[26..34].copy_from_slice(&expires.to_le_bytes());
            token[34..67].copy_from_slice(issued_by.address());

            let signature = issued_by.sign(&token[0..67]);
            token[67..131].copy_from_slice(&signature);

            Authorization { token }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Notification {
    pub token: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub token: Vec<u8>,
}

impl Delegation {
    pub fn signer(&self) -> PublicKey {
        PublicKey::from_bytes(&self.token[35..67]).expect("already validated public key")
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub token: Vec<u8>,
}

impl Subscription {
    pub fn signer(&self) -> PublicKey {
        PublicKey::from_bytes(&self.token[35..67]).expect("already validated public key")
    }

    pub fn bearer(&self) -> PublicKey {
        PublicKey::from_bytes(&self.token[35..67]).expect("already validated public key")
    }
}
