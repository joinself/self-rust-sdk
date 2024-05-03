use crate::protocol::hashgraph::Role;

#[repr(u64)]
pub enum KeyRole {
    Verification = Role::Verification.bits(), // defines the key as a verification method, allowing the key to assume multiple roles
    Assertion = Role::Assertion.bits(), // defines the key as an assertion method, used for signing and verifying credentials
    Authentication = Role::Authentication.bits(), // defines the key as an authentication method, used for authenticating messages and requests
    Delegation = Role::Delegation.bits(), // defines the key as a delegation method, used for delegating control on behalf of the identity
    Invocation = Role::Invocation.bits(), // defines the key as a invocation method, used for authorizing updates to the identities document
    KeyAgreement = Role::KeyAgreement.bits(), // defines the key as a key agreement method, used for establishing shared secrets and public key encryption
    Messaging = Role::Messaging.bits(), // defines the key as a messaging address, used for sending and receiving messages
}

#[allow(dead_code)]
#[repr(u64)]
pub enum KeyPurpose {
    Verification = Role::Verification.bits(), // defines the key as a verification method, allowing the key to assume multiple roles
    Assertion = Role::Assertion.bits(), // defines the key as an assertion method, used for signing and verifying credentials
    Authentication = Role::Authentication.bits(), // defines the key as an authentication method, used for authenticating messages and requests
    Delegation = Role::Delegation.bits(), // defines the key as a delegation method, used for delegating control on behalf of the identity
    Invocation = Role::Invocation.bits(), // defines the key as a invocation method, used for authorizing updates to the identities document
    KeyAgreement = Role::KeyAgreement.bits(), // defines the key as a key agreement method, used for establishing shared secrets and public key encryption
    Messaging = Role::Messaging.bits(), // defines the key as a messaging address, used for sending and receiving messages
    Inbox = 1 << 7, // defines the key as an inbox key, used to represent the the address of an inbox used to receive messages
    Identifier = 1 << 8, // defines the key as an identifier key, used to represent the address of an identity (not valid as a role for an identity document)
    Link = 1 << 9, // defines the key as a link secret key, used to proove ownership of a fact without (not valid as a role for an identity document)
    Push = 1 << 10, // defines the key as a push key, used to encrypt and decrypt push notification payloads (not valid as a role for an identity document)
}

impl std::ops::BitOr for KeyPurpose {
    type Output = u64;

    fn bitor(self, rhs: Self) -> Self::Output {
        self as u64 | rhs as u64
    }
}
