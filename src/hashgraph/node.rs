use std::cell::RefCell;
use std::rc::Rc;

use crate::keypair::signing::PublicKey;
use crate::protocol::hashgraph::Role;

#[derive(Debug)]
pub struct RoleEntry {
    pub role: Role,
    pub from: i64,
}

#[derive(Debug)]
pub struct Node {
    pub roles: Vec<RoleEntry>,
    pub sequence: u32,
    pub controller: Option<Vec<u8>>,
    pub created_at: i64,
    pub revoked_at: i64,
    pub public_key: PublicKey,
    pub incoming: Vec<Rc<RefCell<Node>>>,
    pub outgoing: Vec<Rc<RefCell<Node>>>,
}

impl Node {
    pub fn collect(&self) -> Vec<Rc<RefCell<Node>>> {
        let mut nodes: Vec<Rc<RefCell<Node>>> = Vec::new();

        for node in &self.outgoing {
            nodes.push(node.clone());
            nodes.append(&mut node.borrow().collect());
        }

        nodes
    }

    pub fn has_roles(&self, roles: Role) -> bool {
        match self.roles.last() {
            Some(role) => role & roles != 0,
            None => false,
        }
    }

    pub fn has_roles_at(&self, roles: Role, timeframe: i64) -> bool {
        match self.roles_at(timeframe) {
            Some(role) => role & roles != 0,
            None => false,
        }
    }

    pub fn valid_at(&self, timeframe: i64) -> bool {
        match self.roles_at(timeframe) {
            Some(role) => true,
            None => false,
        }
    }

    fn roles_at(&self, timeframe: i64) -> Option<&RoleEntry> {
        for entry in self.roles.iter().rev() {
            if entry.from <= timeframe {
                return Some(entry);
            }
        }

        None
    }
}
