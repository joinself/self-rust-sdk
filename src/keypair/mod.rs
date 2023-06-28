pub mod exchange;
pub mod signing;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Algorithm {
    Ed25519,
    Curve25519,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Usage {
    Group,
    Identifier,
    Link,
    Messaging,
    Recovery,
}

impl Usage {
    pub fn kind(&self) -> u8 {
        match *self {
            Usage::Group => 1,
            Usage::Identifier => 2,
            Usage::Link => 3,
            Usage::Messaging => 4,
            Usage::Recovery => 5,
        }
    }
}
