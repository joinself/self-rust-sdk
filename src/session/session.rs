use crate::crypto::session;
use crate::identifier::Identifier;
use crate::token::Token;

use std::sync::{Arc, Mutex};

pub struct Session {
    pub as_id: Identifier,
    pub with_id: Identifier,
    pub authorization: Option<Token>,
    pub notification: Option<Token>,
    pub sequence: u64,
    pub session: Arc<Mutex<session::Session>>,
}

impl Session {
    pub fn new(
        as_id: Identifier,
        with_id: Identifier,
        session: Arc<Mutex<session::Session>>,
    ) -> Session {
        Session {
            as_id,
            with_id,
            authorization: None,
            notification: None,
            sequence: 0,
            session,
        }
    }

    pub fn send_as(&self) -> Vec<u8> {
        self.as_id.public_key().id()
    }

    pub fn send_to(&self) -> Vec<u8> {
        self.with_id.public_key().id()
    }

    pub fn next_sequence(&mut self) -> u64 {
        let sequence = self.sequence;
        self.sequence += 1;
        sequence
    }
}
