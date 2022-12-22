use chrono::{DateTime, NaiveDateTime, Utc};
use std::cell::RefCell;
use std::rc::Rc;

use crate::keypair::signing::PublicKey;
use crate::siggraph::action::KeyRole;

#[derive(Debug)]
pub struct Node {
    pub kid: String,
    pub did: Option<String>,
    pub typ: KeyRole,
    pub seq: i32,
    pub pk: PublicKey,
    pub ca: i64,
    pub ra: i64,
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

        return nodes;
    }

    pub fn created_at(&self) -> Option<DateTime<Utc>> {
        if self.ca == 0 {
            return None;
        }

        if self.ca > i32::MAX as i64 {
            return Some(DateTime::from_utc(
                NaiveDateTime::from_timestamp(self.ca / 1000, 0),
                Utc,
            ));
        }

        return Some(DateTime::from_utc(
            NaiveDateTime::from_timestamp(self.ca, 0),
            Utc,
        ));
    }

    pub fn revoked_at(&self) -> Option<DateTime<Utc>> {
        if self.ra == 0 {
            return None;
        }

        if self.ra > i32::MAX as i64 {
            return Some(DateTime::from_utc(
                NaiveDateTime::from_timestamp(self.ra / 1000, 0),
                Utc,
            ));
        }

        return Some(DateTime::from_utc(
            NaiveDateTime::from_timestamp(self.ra, 0),
            Utc,
        ));
    }
}
