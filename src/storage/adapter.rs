use rusqlite::{Connection, Result, Transaction};

use crate::crypto::{account::Account, omemo::Group, session::Session};
use crate::error::SelfError;
use crate::identifier::Identifier;
use crate::keypair::signing::{KeyPair, PublicKey};
use crate::protocol::siggraph::KeyRole;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct Storage {
    conn: Connection,
    lock: Mutex<()>,
    gcache: HashMap<Identifier, Arc<Mutex<Group>>>,
    kcache: HashMap<Identifier, Arc<KeyPair>>,
    scache: HashMap<Identifier, Arc<Mutex<Session>>>,
}

// This whole implementation is horrible and only temporary
// mutiple tables and caches are accessed for some higher level
// operations that also require atomicity via a single transaction
impl Storage {
    pub fn new() -> Result<Storage, SelfError> {
        let conn = Connection::open_in_memory().map_err(|_| SelfError::StorageConnectionFailed)?;

        /*
        let conn = Connection::open("/tmp/test.db").map_err(|_| SelfError::StorageConnectionFailed)?;
        conn.pragma_update(None, "synchronous", &"NORMAL").unwrap();
        conn.pragma_update(None, "journal_mode", &"WAL").unwrap();
        conn.pragma_update(None, "temp_store", &"MEMORY").unwrap();
        */

        let mut storage = Storage {
            conn,
            lock: Mutex::new(()),
            gcache: HashMap::new(),
            kcache: HashMap::new(),
            scache: HashMap::new(),
        };

        storage.setup_identifiers_table()?;
        storage.setup_keypairs_table()?;
        storage.setup_operations_table()?;
        storage.setup_connections_table()?;
        storage.setup_sessions_table()?;
        storage.setup_tokens_table()?;
        storage.setup_members_table()?;
        storage.setup_credentials_table()?;
        storage.setup_inbox_table()?;
        storage.setup_outbox_table()?;

        Ok(storage)
    }

    fn setup_identifiers_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE identifiers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    identifier BLOB NOT NULL
                );
                CREATE UNIQUE INDEX idx_identifiers_identifier
                ON identifiers (identifier);",
                (),
            )
            .map_err(|err| {
                println!("sql error: {}", err);
                SelfError::StorageTableCreationFailed
            })?;

        Ok(())
    }

    fn setup_keypairs_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE keypairs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    for_identifier INTEGER NOT NULL,
                    role INTEGER NOT NULL,
                    keypair BLOB NOT NULL,
                    olm_account BLOB
                );
                CREATE UNIQUE INDEX idx_keypairs_for_identifier
                ON keypairs (for_identifier);",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    fn setup_operations_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    on_identifier INTEGER NOT NULL,
                    sequence INTEGER NOT NULL,
                    operation BLOB NOT NULL
                );
                CREATE UNIQUE INDEX idx_operations_operation
                ON operations (on_identifier, sequence);",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    fn setup_connections_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    as_identifier INTEGER NOT NULL,
                    with_identifier INTEGER NOT NULL,
                    connected_on INTEGER NOT NULL
                );
                CREATE UNIQUE INDEX idx_connections_connection
                ON connections (as_identifier, with_identifier);",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    fn setup_sessions_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    as_identifier INTEGER NOT NULL,
                    with_identifier INTEGER NOT NULL,
                    sequence_tx INTEGER,
                    sequence_rx INTEGER,
                    olm_session BLOB NOT NULL
                );
                CREATE UNIQUE INDEX idx_sessions_with_identifier
                ON sessions (as_identifier, with_identifier);",
                (),
            )
            .map_err(|err| {
                println!("sql error: {}", err);
                SelfError::StorageTableCreationFailed
            })?;

        Ok(())
    }

    fn setup_tokens_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_identifier INTEGER NOT NULL,
                    purpose INTEGER NOT NULL,
                    token BLOB NOT NULL
                );
                CREATE UNIQUE INDEX idx_tokens_from
                ON tokens (from_identifier, purpose);",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    fn setup_members_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_identifier INTEGER NOT NULL,
                    member_identifier INTEGER NOT NULL
                );
                CREATE UNIQUE INDEX idx_members_membership
                ON members (group_identifier, member_identifier);",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    fn setup_credentials_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_identifier INTEGER NOT NULL,
                    about_identifier INTEGER NOT NULL,
                    credential BLOB NOT NULL
                );",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    fn setup_inbox_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE inbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session INTEGER NOT NULL,
                    sequence INTEGER NOT NULL,
                    message INTEGER NOT NULL
                );",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    fn setup_outbox_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session INTEGER NOT NULL,
                    sequence INTEGER NOT NULL,
                    message INTEGER NOT NULL
                );",
                (),
            )
            .map_err(|_| SelfError::StorageTableCreationFailed)?;

        Ok(())
    }

    pub fn transaction<F>(&mut self, execute: F) -> Result<(), SelfError>
    where
        F: FnOnce(&Transaction) -> bool,
    {
        let mut txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        if !execute(&mut txn) {
            txn.rollback()
                .map_err(|_| SelfError::StorageTransactionRollbackFailed)?;
        } else {
            txn.commit()
                .map_err(|_| SelfError::StorageTransactionCommitFailed)?;
        };

        Ok(())
    }

    fn identifier_create(&mut self, identifier: &Identifier) -> Result<(), SelfError> {
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        if txn
            .execute(
                "INSERT INTO identifiers (identifier) VALUES (?1)",
                [identifier.id()],
            )
            .is_err()
        {
            return Err(SelfError::StorageTransactionCommitFailed);
        }

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)
    }

    pub fn keypair_get(&mut self, identifier: &Identifier) -> Result<Arc<KeyPair>, SelfError> {
        // check if the key exists in the cache
        if let Some(kp) = self.kcache.get(identifier) {
            return Ok(kp.clone());
        };

        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        let mut statement = txn
            .prepare(
                "SELECT keypair FROM identifiers
            INNER JOIN sessions ON
                keypairs.for_identifier = identifiers.id
			WHERE identifier = ?1",
            )
            .expect("failed to prepare statement");

        let mut rows = match statement.query([identifier.id()]) {
            Ok(rows) => rows,
            Err(_) => return Err(SelfError::StorageTransactionCommitFailed),
        };

        let row = match rows.next() {
            Ok(row) => match row {
                Some(row) => row,
                None => return Err(SelfError::KeychainKeyNotFound),
            },
            Err(_) => return Err(SelfError::StorageTransactionCommitFailed),
        };

        let kp_encoded: Vec<u8> = row.get(3).unwrap();
        let kp = KeyPair::decode(&kp_encoded)?;
        let keypair = Arc::new(kp);

        self.kcache.insert(identifier.clone(), keypair.clone());

        Ok(keypair)
    }

    pub fn keypair_create(
        &mut self,
        role: KeyRole,
        keypair: &KeyPair,
        account: Option<Account>,
    ) -> Result<(), SelfError> {
        let identifier = Identifier::Owned(keypair.to_owned());

        // check if the key exists in the cache
        if self.kcache.contains_key(&identifier) {
            return Err(SelfError::KeychainKeyExists);
        };

        // create the identifier
        self.identifier_create(&identifier)?;

        // create the keypair
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        if let Some(olm_account) = account {
            txn.execute(
                "INSERT INTO keypairs (for_identifier, role, keypair, olm_account) 
                VALUES (
                    (SELECT id FROM identifiers WHERE identifier=?1),
                    ?2,
                    ?3,
                    ?4
                );",
                (
                    identifier.id(),
                    role.0,
                    &keypair.encode(),
                    olm_account.pickle(None)?,
                ),
            )
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;
        } else {
            txn.execute(
                "INSERT INTO keypairs (for_identifier, role, keypair) 
                VALUES (
                    (SELECT id FROM identifiers WHERE identifier=?1),
                    ?2,
                    ?3
                );",
                (identifier.id(), role.0, &keypair.encode()),
            )
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;
        }

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        self.kcache.insert(identifier, Arc::new(keypair.clone()));

        Ok(())
    }

    pub fn session_get(
        &mut self,
        with_identifier: &Identifier,
    ) -> Result<Arc<Mutex<Session>>, SelfError> {
        // check if the session exists in the cache
        if let Some(session) = self.scache.get(with_identifier) {
            return Ok(session.clone());
        };

        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        let mut statement = txn
            .prepare(
                "SELECT olm_session FROM identifiers
                INNER JOIN sessions ON
                    sessions.with_identifier = identifiers.id
				WHERE identifier = ?1",
            )
            .expect("failed to prepare statement");

        let mut rows = match statement.query([with_identifier.id()]) {
            Ok(rows) => rows,
            Err(_) => return Err(SelfError::MessagingDestinationUnknown),
        };

        let row = match rows.next() {
            Ok(row) => match row {
                Some(row) => row,
                None => return Err(SelfError::StorageSessionNotFound),
            },
            Err(_) => return Err(SelfError::MessagingDestinationUnknown),
        };

        let mut session_encoded: Vec<u8> = row.get(0).unwrap();

        // TODO handle encryption for values
        let session = Session::from_pickle(&mut session_encoded, None)?;
        let s = Arc::new(Mutex::new(session));
        self.scache.insert(with_identifier.clone(), s.clone());

        Ok(s)
    }

    pub fn session_create(
        &mut self,
        as_identifier: &Identifier,
        with_identifier: &Identifier,
        session: Session,
    ) -> Result<(), SelfError> {
        // check if the session exists in the cache
        if self.scache.contains_key(with_identifier) {
            return Err(SelfError::KeychainKeyExists);
        };

        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        // TODO handle encryption for values
        let session_encoded = session.pickle(None)?;

        txn.execute(
            "INSERT INTO sessions (as_identifier, with_identifier, olm_session)
                VALUES (
                    (SELECT id FROM identifiers WHERE identifier=?1),
                    (SELECT id FROM identifiers WHERE identifier=?2),
                    ?3
                );",
            (as_identifier.id(), with_identifier.id(), session_encoded),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        self.scache
            .insert(with_identifier.clone(), Arc::new(Mutex::new(session)));

        Ok(())
    }

    fn group_get(&mut self, group: &Identifier) -> Result<Arc<Mutex<Group>>, SelfError> {
        // lookup or load omemo group from group cache
        if let Some(grp) = self.gcache.get(group) {
            return Ok(grp.clone());
        };

        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        let mut statement = txn
            .prepare(
                "SELECT i2.identifier, i3.identifier, s1.olm_session FROM members
                JOIN identifiers i1 ON
                    i1.id = members.group_identifier
                JOIN identifiers i2 ON
                    i2.id = members.member_identifier
                JOIN sessions s1 ON
                    i2.id = s1.with_identifier
				JOIN identifiers i3 ON
                    i3.id = s1.as_identifier
				WHERE i1.identifier = ?1",
            )
            .expect("failed to prepare statement");

        let mut rows = match statement.query([group.id()]) {
            Ok(rows) => rows,
            Err(_) => return Err(SelfError::MessagingDestinationUnknown),
        };

        let mut members = Vec::new();
        let mut as_identifier: Option<Vec<u8>> = None;

        while let Some(row) = rows
            .next()
            .map_err(|_| SelfError::MessagingDestinationUnknown)?
        {
            let with_identifier: Vec<u8> = row.get(0).unwrap();
            let mut session: Vec<u8> = row.get(2).unwrap();

            if as_identifier.is_none() {
                as_identifier = row.get(1).unwrap();
            }

            let public_key =
                PublicKey::from_bytes(&with_identifier, crate::keypair::Algorithm::Ed25519)?;

            members.push((
                Identifier::Referenced(public_key),
                Session::from_pickle(&mut session, None),
            ))
        }

        let identifier = match as_identifier {
            Some(identifier) => identifier,
            None => return Err(SelfError::MessagingDestinationUnknown),
        };

        let grp = Group::new(&identifier);

        for member in &members {
            // TODO check session cache for session over using
            // session loaded from db

            grp.add_participant(member.0, session)
        }

        let group = Arc::new(Mutex::new());

        // TODO load group members and their sessions

        Ok(group)
    }

    fn member_add(&mut self, group: &Identifier, member: &Identifier) -> Result<(), SelfError> {
        /*
        // lookup or load group from omemo group cache
        if let Some(grp) = self.gcache.get_mut(group) {
            grp.add_participant(id, session);
        };

        self.storage.transaction(|txn| {
            return txn
                .execute(
                    "INSERT INTO members (identity, owner) VALUES (?1, ?2)",
                    (group.id(), owner.id()),
                )
                .is_ok();
        })
        */
        Ok(())
    }

    fn member_remove(&mut self, group: &Identifier, member: &Identifier) -> Result<(), SelfError> {
        /*
        self.storage.transaction(|txn| {
            return txn
                .execute(
                    "INSERT INTO members (identity, owner) VALUES (?1, ?2)",
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
    use super::*;

    #[test]
    fn transaction() {
        let mut storage = Storage::new().expect("failed to create transaction");

        let (alice_id, bob_id) = (0, 1);

        // create an identifier for alice and bob
        storage
            .transaction(|txn| {
                txn.execute(
                    "INSERT INTO identifiers (identifier) VALUES (?1), (?2)",
                    (b"alice", b"bob"),
                )
                .is_ok()
            })
            .expect("failed to create transaction");

        // create a session
        storage
            .transaction(|txn| {
                txn.execute(
                    "INSERT INTO sessions (as_identifier, with_identifier, olm_session) VALUES (?1, ?2, ?3)",
                    (alice_id, bob_id, b"session-with-bob"),
                ).is_ok()
            })
            .expect("failed to create transaction");

        // load a session
        storage
            .transaction(|txn| {
                let mut statement = txn
                    .prepare("SELECT * FROM sessions WHERE with_identifier = ?1")
                    .expect("failed to prepare statement");

                let mut rows = statement.query([bob_id]).expect("failed to execute query");
                let row = rows.next().expect("no rows found").unwrap();

                let identity: i32 = row.get(2).unwrap();
                let session: Vec<u8> = row.get(5).unwrap();

                assert_eq!(identity, bob_id);
                assert_eq!(session, b"session-with-bob");

                true
            })
            .expect("failed to create transaction");
    }

    #[test]
    fn keypair_create_and_get() {
        let kp = KeyPair::new();
        let mut storage = Storage::new().expect("storage failed");

        let msg = vec![8; 128];
        let sig = kp.sign(&msg);

        storage
            .keypair_create(KeyRole::Signing, &kp, None)
            .expect("failed to create keypair");

        let kp = storage
            .keypair_get(&Identifier::Owned(kp))
            .expect("failed to get keypair");

        assert!(kp.public().verify(&msg, &sig));
    }

    #[test]
    fn session_create_and_get() {
        let mut storage = Storage::new().expect("storage failed");

        let alice_skp = crate::keypair::signing::KeyPair::new();
        let alice_ekp = crate::keypair::exchange::KeyPair::new();
        let alice_ed25519_pk = alice_skp.public();
        let alice_curve25519_pk = alice_ekp.public();
        let mut alice_acc = crate::crypto::account::Account::new(alice_skp, alice_ekp);

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ekp = crate::keypair::exchange::KeyPair::new();
        let bob_ed25519_pk = bob_skp.public();
        let bob_curve25519_pk = bob_ekp.public();
        let mut bob_acc = crate::crypto::account::Account::new(bob_skp, bob_ekp);

        let alice_identifier = Identifier::Referenced(alice_ed25519_pk);
        let bob_identifier = Identifier::Referenced(bob_ed25519_pk);

        storage
            .identifier_create(&alice_identifier)
            .expect("failed to create alice identifier");
        storage
            .identifier_create(&bob_identifier)
            .expect("failed to create bob identifier");

        alice_acc
            .generate_one_time_keys(10)
            .expect("failed to generate one time keys");

        let alices_one_time_keys: HashMap<String, serde_json::Value> =
            serde_json::from_slice(&alice_acc.one_time_keys())
                .expect("failed to load alices one time keys");

        let alices_one_time_key = alices_one_time_keys
            .get("curve25519")
            .and_then(|keys| keys.as_object()?.get("AAAAAQ"))
            .unwrap()
            .as_str()
            .unwrap();

        // encrypt a message from bob with a new session to alice
        let mut bobs_session_with_alice = bob_acc
            .create_outbound_session(&alice_curve25519_pk, alices_one_time_key.as_bytes())
            .expect("failed to create outbound session");

        let (mtype, mut bobs_message_to_alice_1) = bobs_session_with_alice
            .encrypt("hello alice, pt1".as_bytes())
            .expect("failed to encrypt message to alice");

        assert_eq!(mtype, 0);

        // store bobs session with alice
        storage
            .session_create(&bob_identifier, &alice_identifier, bobs_session_with_alice)
            .expect("failed to create session");

        // create alices session with bob from bobs first message
        let mut alices_session_with_bob = alice_acc
            .create_inbound_session(&bob_curve25519_pk, &bobs_message_to_alice_1)
            .expect("failed to create inbound session");

        // remove the one time key from alices account
        alice_acc
            .remove_one_time_keys(&alices_session_with_bob)
            .expect("failed to remove session");

        // decrypt the message from bob
        let plaintext = alices_session_with_bob
            .decrypt(mtype, &mut bobs_message_to_alice_1)
            .expect("failed to decrypt bobs message");

        assert_eq!(&plaintext, "hello alice, pt1".as_bytes());

        // send a response message to bob
        let (mtype, mut alices_message_to_bob_1) = alices_session_with_bob
            .encrypt("hey bob".as_bytes())
            .expect("failed to encrypt message to bob");

        assert_eq!(mtype, 1);

        // load bobs session with alice
        let bobs_session_with_alice_arc = storage
            .session_get(&alice_identifier)
            .expect("failed to get session");

        let bobs_session_with_alice_lock = bobs_session_with_alice_arc.as_ref().lock();

        let mut bobs_session_with_alice =
            bobs_session_with_alice_lock.expect("failed to lock session");

        // decrypt alices response
        let plaintext = bobs_session_with_alice
            .decrypt(mtype, &mut alices_message_to_bob_1)
            .expect("failed to decrypt message from alice");

        assert_eq!(&plaintext, "hey bob".as_bytes());
    }
}
