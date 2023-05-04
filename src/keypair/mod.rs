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
    Identifier,
    Link,
    Messaging,
    Recovery,
}

impl Usage {
    pub fn kind(&self) -> u8 {
        match *self {
            Usage::Identifier => 1,
            Usage::Link => 2,
            Usage::Messaging => 3,
            Usage::Recovery => 4,
        }
    }
}
