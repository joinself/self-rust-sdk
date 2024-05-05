use crate::protocol::hashgraph;

#[derive(Clone)]
#[repr(u64)]
pub enum Role {
    Verification = hashgraph::Role::Verification.bits(), // defines the key as a verification method, allowing the key to assume multiple roles
    Assertion = hashgraph::Role::Assertion.bits(), // defines the key as an assertion method, used for signing and verifying credentials
    Authentication = hashgraph::Role::Authentication.bits(), // defines the key as an authentication method, used for authenticating messages and requests
    Delegation = hashgraph::Role::Delegation.bits(), // defines the key as a delegation method, used for delegating control on behalf of the identity
    Invocation = hashgraph::Role::Invocation.bits(), // defines the key as a invocation method, used for authorizing updates to the identities document
    KeyAgreement = hashgraph::Role::KeyAgreement.bits(), // defines the key as a key agreement method, used for establishing shared secrets and public key encryption
    Messaging = hashgraph::Role::Messaging.bits(), // defines the key as a messaging address, used for sending and receiving messages
}

pub trait RoleSet {
    fn roles(&self) -> u64;
}

impl RoleSet for Role {
    fn roles(&self) -> u64 {
        (*self).to_owned() as u64
    }
}

impl RoleSet for u64 {
    fn roles(&self) -> u64 {
        self.to_owned()
    }
}

impl std::ops::BitOr for Role {
    type Output = u64;

    fn bitor(self, rhs: Self) -> Self::Output {
        self as u64 | rhs as u64
    }
}

impl std::ops::BitOr<u64> for Role {
    type Output = u64;

    fn bitor(self, rhs: u64) -> Self::Output {
        self as u64 | rhs
    }
}

impl std::ops::BitOr<Role> for u64 {
    type Output = u64;

    fn bitor(self, rhs: Role) -> Self::Output {
        self | rhs as u64
    }
}

#[repr(u16)]
pub enum Method {
    Aure = hashgraph::Method::Aure.0,
    Key = hashgraph::Method::Key.0,
}

impl Method {
    pub fn into_method(&self) -> hashgraph::Method {
        match self {
            Method::Aure => hashgraph::Method::Aure,
            Method::Key => hashgraph::Method::Key,
        }
    }

    pub fn from_u16(method: u16) -> Method {
        match method {
            0 => Method::Aure,
            1 => Method::Key,
            _ => unreachable!(),
        }
    }
}
