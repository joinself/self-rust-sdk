use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use crate::crypto::session::Session;

pub struct Group {
    id: String,
    participants: Vec<Participant>,
}

struct Participant {
    id: String,
    session: Session,
}

#[derive(Serialize, Deserialize)]
struct GroupMessage {
    pub recipients: HashMap<String, Message>,
    pub ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct Message {
    pub mtype: i64,
    pub ciphertext: String,
}

impl Group {
    pub fn new(id: &str) -> Group {
        return Group {
            id: String::from(id),
            participants: Vec::new(),
        };
    }

    pub fn add_participant(&mut self, id: String, session: Session) {
        self.participants.push(Participant { id, session });
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) {}
}
