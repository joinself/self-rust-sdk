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
