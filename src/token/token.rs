use crate::identifier::Identifier;

#[derive(Clone)]
pub enum Token {
    Authorization(Authorization),
    Notification(Notification),
    Subscription(Subscription),
    Delegation(Delegation),
}

#[derive(Clone)]
pub struct Authorization {
    pub token: Vec<u8>,
}

#[derive(Clone)]
pub struct Notification {
    pub token: Vec<u8>,
}

#[derive(Clone)]
pub struct Delegation {
    pub token: Vec<u8>,
    pub issuer: Identifier,
}

#[derive(Clone)]
pub struct Subscription {
    pub token: Vec<u8>,
}
