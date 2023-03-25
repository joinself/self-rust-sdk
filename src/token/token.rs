use crate::identifier::Identifier;

pub enum Token {
    Authorization(Authorization),
    Notification(Notification),
    Subscription(Subscription),
    Delegation(Delegation),
}

pub struct Authorization {
    pub token: Vec<u8>,
}

pub struct Notification {
    pub token: Vec<u8>,
}

pub struct Delegation {
    pub token: Vec<u8>,
    pub issuer: Identifier,
}

pub struct Subscription {
    pub token: Vec<u8>,
}
