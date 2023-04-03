use crate::crypto::omemo;
use crate::error::SelfError;
use crate::identifier::Identifier;
use crate::storage::Storage;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct Group {
    storage: Storage,
    gcache: Mutex<HashMap<Identifier, Arc<Mutex<omemo::Group>>>>,
}

impl Group {
    pub fn new(storage: Storage) -> Group {
        Group {
            storage,
            gcache: Mutex::new(HashMap::new()),
        }
    }

    fn get(&mut self, group: &Identifier) -> Result<Arc<Mutex<omemo::Group>>, SelfError> {
        let gcache = self.gcache.lock().expect("gcache lock failed");

        // lookup or load omemo group from group cache
        if let Some(grp) = gcache.get(group) {
            return Ok(grp.clone());
        };

        match self.storage.transaction(|txn| {
            let mut statement = txn
                .prepare("SELECT id FROM messaging_groups WHERE group = ?1")
                .expect("failed to prepare statement");

            let mut rows = match statement.query([group.id()]) {
                Ok(rows) => rows,
                Err(_) => return false,
            };

            let rows = rows.next().map_err(|_| SelfError::MessagingGroupUnknown)?;

            let mut statement = txn
                .prepare("SELECT * FROM messaging_members WHERE identity = ?1")
                .expect("failed to prepare statement");

            let mut rows = match statement.query([group.id()]) {
                Ok(rows) => rows,
                Err(_) => return false,
            };

            let row = match rows.next() {
                Ok(row) => match row {
                    Some(row) => row,
                    None => return false,
                },
                Err(_) => return false,
            };

            let identity: Vec<u8> = row.get(0).unwrap();
            let session: Vec<u8> = row.get(1).unwrap();

            Group::new(&identity);

            // TODO load group members and their sessions

            return true;
        }) {
            Ok(()) => return None,
            Err(_) => return None,
        };

        None
    }

    fn create(&mut self, group: &Identifier, owner: &Identifier) -> Result<(), SelfError> {
        self.storage.transaction(|txn| {
            return txn
                .execute(
                    "INSERT INTO messaging_groups (identity, owner) VALUES (?1, ?2)",
                    (group.id(), owner.id()),
                )
                .is_ok();
        })
    }

    fn add(&mut self, group: &Identifier, member: &Identifier) -> Result<(), SelfError> {
        /*
        // lookup or load group from omemo group cache
        if let Some(grp) = self.gcache.get_mut(group) {
            grp.add_participant(id, session);
        };

        self.storage.transaction(|txn| {
            return txn
                .execute(
                    "INSERT INTO messaging_members (identity, owner) VALUES (?1, ?2)",
                    (group.id(), owner.id()),
                )
                .is_ok();
        })
        */
        Ok(())
    }

    fn remove(&mut self, group: &Identifier, member: &Identifier) -> Result<(), SelfError> {
        /*
        self.storage.transaction(|txn| {
            return txn
                .execute(
                    "INSERT INTO messaging_members (identity, owner) VALUES (?1, ?2)",
                    (group.id(), owner.id()),
                )
                .is_ok();
        })
        */
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn create() {}
}
