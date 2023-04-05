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
    // lock: Mutex<()>,
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
            //lock: Mutex::new(()),
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
            .map_err(|err| {
                println!("sql error: {}", err);
                SelfError::StorageTableCreationFailed
            })?;

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
            .map_err(|err| {
                println!("sql error: {}", err);
                SelfError::StorageTableCreationFailed
            })?;

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
            .map_err(|err| {
                println!("sql error: {}", err);
                SelfError::StorageTableCreationFailed
            })?;

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
                    olm_session BLOB
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
            .map_err(|err| {
                println!("sql error: {}", err);
                SelfError::StorageTableCreationFailed
            })?;

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
            .map_err(|err| {
                println!("sql error: {}", err);
                SelfError::StorageTableCreationFailed
            })?;

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
            .map_err(|err| {
                println!("sql error: {}", err);
                SelfError::StorageTableCreationFailed
            })?;

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
            .map_err(|err| {
                println!("sql error: {}", err);
                SelfError::StorageTableCreationFailed
            })?;

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
            .map_err(|err| {
                println!("sql error: {}", err);
                SelfError::StorageTableCreationFailed
            })?;

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
                [&identifier.id()],
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

        let mut rows = match statement.query([&identifier.id()]) {
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
                    &identifier.id(),
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
                (&identifier.id(), role.0, &keypair.encode()),
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

        let mut rows = match statement.query([&with_identifier.id()]) {
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
        session: Option<Session>,
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
        if let Some(s) = session {
            let session_encoded = s.pickle(None)?;

            txn.execute(
                "INSERT INTO sessions (as_identifier, with_identifier, olm_session)
                VALUES (
                    (SELECT id FROM identifiers WHERE identifier=?1),
                    (SELECT id FROM identifiers WHERE identifier=?2),
                    ?3
                );",
                (&as_identifier.id(), &with_identifier.id(), session_encoded),
            )
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

            self.scache
                .insert(with_identifier.clone(), Arc::new(Mutex::new(s)));

            txn.commit()
                .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

            return Ok(());
        }
        txn.execute(
            "INSERT INTO sessions (as_identifier, with_identifier)
            VALUES (
                (SELECT id FROM identifiers WHERE identifier=?1),
                (SELECT id FROM identifiers WHERE identifier=?2)
            );",
            (&as_identifier.id(), &with_identifier.id()),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    pub fn group_get(&mut self, group: &Identifier) -> Result<Arc<Mutex<Group>>, SelfError> {
        // lookup or load omemo group from group cache
        if let Some(grp) = self.gcache.get(group) {
            return Ok(grp.clone());
        };

        let mut members = Vec::new();
        let mut as_identifier: Option<Vec<u8>> = None;

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

        let mut rows = match statement.query([&group.id()]) {
            Ok(rows) => rows,
            Err(_) => return Err(SelfError::MessagingDestinationUnknown),
        };

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

            let identifier = Identifier::Referenced(public_key);

            let session = match self.scache.get(&identifier) {
                Some(session) => session.clone(),
                None => {
                    let s = Arc::new(Mutex::new(Session::from_pickle(&mut session, None)?));
                    self.scache.insert(identifier, s.clone());
                    s.clone()
                }
            };

            members.push((with_identifier, session))
        }

        let identifier = match as_identifier {
            Some(identifier) => identifier,
            None => return Err(SelfError::MessagingDestinationUnknown),
        };

        let mut omemo_group = Group::new(&identifier);

        for member in &members {
            omemo_group.add_participant(&member.0, member.1.clone());
        }

        // TODO avoid the need for locking the group
        // by implementing a read only copy of the
        // group members list via a concurrent hashmap
        // like dashmap or a lock free linked list
        let grp = Arc::new(Mutex::new(omemo_group));
        self.gcache.insert(group.clone(), grp.clone());

        Ok(grp)
    }

    pub fn member_add(&mut self, group: &Identifier, member: &Identifier) -> Result<(), SelfError> {
        // check the session exists and assume it's been pre-created
        // before adding a member to the group
        let session = self.session_get(member)?;

        // create the membership
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        txn.execute(
            "INSERT INTO members (group_identifier, member_identifier) 
                VALUES (
                    (SELECT id FROM identifiers WHERE identifier=?1),
                    (SELECT id FROM identifiers WHERE identifier=?2)
                );",
            (&group.id(), &member.id()),
        )
        .expect("hello?");
        //.map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        // if the group exists, update the member list
        if let Some(grp) = self.gcache.get(group) {
            grp.lock().unwrap().add_participant(&member.id(), session);
        }

        Ok(())
    }

    pub fn member_remove(
        &mut self,
        group: &Identifier,
        member: &Identifier,
    ) -> Result<(), SelfError> {
        // remove the membership
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        txn.execute(
            "DELETE FROM members (group_identifier, member_identifier) 
                JOIN identifiers i1 ON
                    i1.id = members.group_identifier
                JOIN identifiers i2 ON
                    i2.id = members.member_identifier
                WHERE i1.identifier = ?1 AND i2.identifier = ?2;",
            (&group.id(), &member.id()),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        // if the group exists, update the member list
        if let Some(grp) = self.gcache.get(group) {
            grp.lock().unwrap().remove_participant(&member.id());
        }

        Ok(())
    }

    pub fn outbox_queue(
        &mut self,
        recipient: &Identifier,
        sequence: i64,
        ciphertext: &[u8],
    ) -> Result<(), SelfError> {
        // add the encrypted message to the outbox
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        txn.execute(
            "INSERT INTO outbox (session, sequence, message)
                VALUES (
                    (
                        SELECT sessions.id FROM sessions
                        JOIN identifiers i1 ON
                            i1.id = sessions.with_identifier
                        WHERE i1.identifier=?1
                    ),
                    ?2,
                    ?3
                );",
            (&recipient.id(), sequence, ciphertext),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    pub fn outbox_next(&mut self) -> Result<Option<(Identifier, i64, Vec<u8>)>, SelfError> {
        // get the next item in the outbox to be sent to the server
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        let mut statement = txn
            .prepare(
                "SELECT i1.identifier, sequence, message FROM outbox
                JOIN sessions s1 ON
                    s1.id = outbox.session
                JOIN identifiers i1 ON
                    i1.id = s1.with_identifier
                ORDER BY outbox.id ASC LIMIT 1;",
            )
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        let mut rows = match statement.query([]) {
            Ok(rows) => rows,
            Err(_) => return Err(SelfError::StorageTransactionCommitFailed),
        };

        let row = match rows.next() {
            Ok(row) => match row {
                Some(row) => row,
                None => return Ok(None),
            },
            Err(_) => return Err(SelfError::StorageTransactionCommitFailed),
        };

        let session: Vec<u8> = row.get(0).unwrap();
        let sequence: i64 = row.get(1).unwrap();
        let message: Vec<u8> = row.get(2).unwrap();

        let public_key = PublicKey::from_bytes(&session, crate::keypair::Algorithm::Ed25519)?;

        Ok(Some((
            Identifier::Referenced(public_key),
            sequence,
            message,
        )))
    }

    pub fn outbox_dequeue(
        &mut self,
        recipient: &Identifier,
        sequence: i64,
    ) -> Result<(), SelfError> {
        // remove the messaage from the outbox once it has been confirmed as received by the server
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        txn.execute(
            "DELETE FROM outbox WHERE session = (
                SELECT sessions.id FROM sessions
                JOIN identifiers i1 ON
                    i1.id = sessions.with_identifier
                WHERE i1.identifier=?1
            ) AND sequence = ?2;",
            (&recipient.id(), sequence),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    pub fn inbox_queue(
        &mut self,
        sender: &Identifier,
        sequence: i64,
        plaintext: &[u8],
    ) -> Result<(), SelfError> {
        // add the encrypted message to the inbox
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        txn.execute(
            "INSERT INTO inbox (session, sequence, message)
                VALUES (
                    (
                        SELECT sessions.id FROM sessions
                        JOIN identifiers i1 ON
                            i1.id = sessions.with_identifier
                        WHERE i1.identifier=?1
                    ),
                    ?2,
                    ?3
                );",
            (&sender.id(), sequence, plaintext),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    pub fn inbox_next(&mut self) -> Result<Option<(Identifier, i64, Vec<u8>)>, SelfError> {
        // get the next item in the inbox to be sent to the server
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        let mut statement = txn
            .prepare(
                "SELECT i1.identifier, sequence, message FROM inbox
                JOIN sessions s1 ON
                    s1.id = inbox.session
                JOIN identifiers i1 ON
                    i1.id = s1.with_identifier
                ORDER BY inbox.id ASC LIMIT 1;",
            )
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        let mut rows = match statement.query([]) {
            Ok(rows) => rows,
            Err(_) => return Err(SelfError::StorageTransactionCommitFailed),
        };

        let row = match rows.next() {
            Ok(row) => match row {
                Some(row) => row,
                None => return Ok(None),
            },
            Err(_) => return Err(SelfError::StorageTransactionCommitFailed),
        };

        let session: Vec<u8> = row.get(0).unwrap();
        let sequence: i64 = row.get(1).unwrap();
        let message: Vec<u8> = row.get(2).unwrap();

        let public_key = PublicKey::from_bytes(&session, crate::keypair::Algorithm::Ed25519)?;

        Ok(Some((
            Identifier::Referenced(public_key),
            sequence,
            message,
        )))
    }

    pub fn inbox_dequeue(
        &mut self,
        recipient: &Identifier,
        sequence: i64,
    ) -> Result<(), SelfError> {
        // remove the messaage from the inbox once it has been confirmed as received by the server
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        txn.execute(
            "DELETE FROM inbox WHERE session = (
                SELECT sessions.id FROM sessions
                JOIN identifiers i1 ON
                    i1.id = sessions.with_identifier
                WHERE i1.identifier=?1
            ) AND sequence = ?2;",
            (&recipient.id(), sequence),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    pub fn encrypt_and_queue(
        &mut self,
        recipient: &Identifier,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SelfError> {
        let grp = self.group_get(recipient)?;
        let mut grp_lock = grp.lock().unwrap();
        let gm = grp_lock.encrypt_group_message(plaintext)?;

        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        for m in &gm.recipients() {
            let mid = Identifier::Referenced(PublicKey::from_bytes(
                m,
                crate::keypair::Algorithm::Ed25519,
            )?);

            let olm_session = self.scache.get(&mid).unwrap();
            let olm_session_encoded = olm_session.lock().unwrap().pickle(None)?;

            txn.execute(
                "UPDATE sessions
                SET sequence_tx = ?2, olm_session = ?3
                WHERE id = (
                    SELECT sessions.id FROM sessions
                    JOIN identifiers i1 ON
                        i1.id = sessions.with_identifier
                    WHERE i1.identifier = ?1
                );",
                (&recipient.id(), 0, olm_session_encoded),
            )
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;
        }

        let message = gm.encode();

        // TODO set the correct sequence here!
        txn.execute(
            "INSERT INTO outbox (session, sequence, message)
            VALUES (
                (
                    SELECT sessions.id FROM sessions
                    JOIN identifiers i1 ON
                        i1.id = sessions.with_identifier
                    WHERE i1.identifier=?1
                ),
                ?2,
                ?3
            );",
            (&recipient.id(), 0, &message),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(message)
    }

    /*
    pub fn decrypt_and_queue(
        &mut self,
        sender: &Identifier,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SelfError> {
        //let grp = self.group_get(sender)?;
        //let mut grp_lock = grp.lock().unwrap();
        //let gm = grp_lock.decrypt_group_message(ciphertext)?;
        Ok(Vec::new())
    }
     */
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
            .session_create(
                &bob_identifier,
                &alice_identifier,
                Some(bobs_session_with_alice),
            )
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

    #[test]
    fn member_create_and_remove() {
        let mut storage = Storage::new().expect("storage failed");

        let group_skp = crate::keypair::signing::KeyPair::new();
        let group_ed25519_pk = group_skp.public();

        let alice_skp = crate::keypair::signing::KeyPair::new();
        let alice_ekp = crate::keypair::exchange::KeyPair::new();
        let alice_ed25519_pk = alice_skp.public();
        let alice_curve25519_pk = alice_ekp.public();
        let mut alice_acc = crate::crypto::account::Account::new(alice_skp, alice_ekp);

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ekp = crate::keypair::exchange::KeyPair::new();
        let bob_ed25519_pk = bob_skp.public();
        let mut bob_acc = crate::crypto::account::Account::new(bob_skp, bob_ekp);

        let carol_skp = crate::keypair::signing::KeyPair::new();
        let carol_ekp = crate::keypair::exchange::KeyPair::new();
        let carol_ed25519_pk = carol_skp.public();
        let carol_curve25519_pk = carol_ekp.public();
        let mut carol_acc = crate::crypto::account::Account::new(carol_skp, carol_ekp);

        let alice_identifier = Identifier::Referenced(alice_ed25519_pk);
        let bob_identifier = Identifier::Referenced(bob_ed25519_pk);
        let carol_identifier = Identifier::Referenced(carol_ed25519_pk);
        let group_identifier = Identifier::Referenced(group_ed25519_pk);

        // create all identifiers
        storage
            .identifier_create(&alice_identifier)
            .expect("failed to create alice identifier");

        storage
            .identifier_create(&bob_identifier)
            .expect("failed to create bob identifier");

        storage
            .identifier_create(&carol_identifier)
            .expect("failed to create bob identifier");

        storage
            .identifier_create(&group_identifier)
            .expect("failed to create bob identifier");

        // create alice and carols one time keys
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

        carol_acc
            .generate_one_time_keys(10)
            .expect("failed to generate one time keys");

        let carols_one_time_keys: HashMap<String, serde_json::Value> =
            serde_json::from_slice(&carol_acc.one_time_keys())
                .expect("failed to load alices one time keys");

        let carols_one_time_key = carols_one_time_keys
            .get("curve25519")
            .and_then(|keys| keys.as_object()?.get("AAAAAQ"))
            .unwrap()
            .as_str()
            .unwrap();

        // create bob a new session with alice and carol
        let bobs_session_with_alice = bob_acc
            .create_outbound_session(&alice_curve25519_pk, alices_one_time_key.as_bytes())
            .expect("failed to create outbound session");

        let bobs_session_with_carol = bob_acc
            .create_outbound_session(&carol_curve25519_pk, carols_one_time_key.as_bytes())
            .expect("failed to create outbound session");

        storage
            .session_create(
                &bob_identifier,
                &alice_identifier,
                Some(bobs_session_with_alice),
            )
            .expect("failed to create alices session");

        storage
            .session_create(
                &bob_identifier,
                &carol_identifier,
                Some(bobs_session_with_carol),
            )
            .expect("failed to create carols session");

        // add alice and carol as members to a group
        storage
            .member_add(&group_identifier, &alice_identifier)
            .expect("failed to add alice as member");

        storage
            .member_add(&group_identifier, &carol_identifier)
            .expect("failed to add alice as member");

        // get the group and encrypt a message
        let group = storage
            .group_get(&group_identifier)
            .expect("failed to get group");
        let group_message = group
            .lock()
            .unwrap()
            .encrypt(b"hello")
            .expect("failed to encrypt");

        // check the group message contains alice and carols identifier
        let alice_id = alice_identifier.id();
        let bob_id = bob_identifier.id();
        let carol_id = carol_identifier.id();

        let gm = crate::crypto::omemo::GroupMessage::decode(&group_message)
            .expect("failed to decode group message");

        let recipients = gm.recipients();
        assert_eq!(recipients.len(), 2);
        assert!(recipients.contains(&alice_id));
        assert!(recipients.contains(&carol_id));

        // it should not contain bobs identifier
        assert!(!recipients.contains(&bob_id));
    }

    #[test]
    fn outbox_queue_and_dequeue() {
        let mut storage = Storage::new().expect("storage failed");

        let alice_skp = crate::keypair::signing::KeyPair::new();
        let alice_ed25519_pk = alice_skp.public();

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ed25519_pk = bob_skp.public();

        let carol_skp = crate::keypair::signing::KeyPair::new();
        let carol_ed25519_pk = carol_skp.public();

        let group_skp = crate::keypair::signing::KeyPair::new();
        let group_ed25519_pk = group_skp.public();

        let alice_identifier = Identifier::Referenced(alice_ed25519_pk);
        let bob_identifier = Identifier::Referenced(bob_ed25519_pk);
        let carol_identifier = Identifier::Referenced(carol_ed25519_pk);
        let group_identifier = Identifier::Referenced(group_ed25519_pk);

        // create all identifiers
        storage
            .identifier_create(&alice_identifier)
            .expect("failed to create alice identifier");

        storage
            .identifier_create(&bob_identifier)
            .expect("failed to create bob identifier");

        storage
            .identifier_create(&carol_identifier)
            .expect("failed to create bob identifier");

        storage
            .identifier_create(&group_identifier)
            .expect("failed to create bob identifier");

        storage
            .session_create(&bob_identifier, &alice_identifier, Some(Session::new()))
            .expect("failed to create alices session");

        storage
            .session_create(&bob_identifier, &carol_identifier, Some(Session::new()))
            .expect("failed to create carols session");

        // create a group session for tracking offsets
        storage
            .session_create(&bob_identifier, &group_identifier, None)
            .expect("failed to create group session");

        // add alice and carol as members to a group
        storage
            .member_add(&group_identifier, &alice_identifier)
            .expect("failed to add alice as member");

        storage
            .member_add(&group_identifier, &carol_identifier)
            .expect("failed to add alice as member");

        // queue a message intended for the group
        storage
            .outbox_queue(&group_identifier, 0, b"hello everyone")
            .expect("failed to queue outbox message");

        let next_item = storage
            .outbox_next()
            .expect("failed to get next outbox item");

        assert!(next_item.is_some());

        let (session_identifier, sequence, message) = next_item.expect("next item isn't a tuple?");
        assert!(group_identifier.eq(&session_identifier));
        assert_eq!(sequence, 0);
        assert_eq!(message, b"hello everyone");

        // we have not dequeued the item yet, so it should return the same item again
        let next_item = storage
            .outbox_next()
            .expect("failed to get next outbox item");

        assert!(next_item.is_some());

        let (session_identifier, sequence, message) = next_item.expect("next item isn't a tuple?");
        assert!(group_identifier.eq(&session_identifier));
        assert_eq!(sequence, 0);
        assert_eq!(message, b"hello everyone");

        // dequeue the item
        storage
            .outbox_dequeue(&group_identifier, sequence)
            .expect("dequeue failed");

        // there should be no items left in the queue
        let next_item = storage
            .outbox_next()
            .expect("failed to get next outbox item");

        assert!(next_item.is_none());
    }

    #[test]
    fn inbox_queue_and_dequeue() {
        let mut storage = Storage::new().expect("storage failed");

        let alice_skp = crate::keypair::signing::KeyPair::new();
        let alice_ed25519_pk = alice_skp.public();

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ed25519_pk = bob_skp.public();

        let carol_skp = crate::keypair::signing::KeyPair::new();
        let carol_ed25519_pk = carol_skp.public();

        let group_skp = crate::keypair::signing::KeyPair::new();
        let group_ed25519_pk = group_skp.public();

        let alice_identifier = Identifier::Referenced(alice_ed25519_pk);
        let bob_identifier = Identifier::Referenced(bob_ed25519_pk);
        let carol_identifier = Identifier::Referenced(carol_ed25519_pk);
        let group_identifier = Identifier::Referenced(group_ed25519_pk);

        // create all identifiers
        storage
            .identifier_create(&alice_identifier)
            .expect("failed to create alice identifier");

        storage
            .identifier_create(&bob_identifier)
            .expect("failed to create bob identifier");

        storage
            .identifier_create(&carol_identifier)
            .expect("failed to create bob identifier");

        storage
            .identifier_create(&group_identifier)
            .expect("failed to create bob identifier");

        storage
            .session_create(&bob_identifier, &alice_identifier, Some(Session::new()))
            .expect("failed to create alices session");

        storage
            .session_create(&bob_identifier, &carol_identifier, Some(Session::new()))
            .expect("failed to create carols session");

        // create a group session for tracking offsets
        storage
            .session_create(&bob_identifier, &group_identifier, None)
            .expect("failed to create group session");

        // add alice and carol as members to a group
        storage
            .member_add(&group_identifier, &alice_identifier)
            .expect("failed to add alice as member");

        storage
            .member_add(&group_identifier, &carol_identifier)
            .expect("failed to add alice as member");

        // queue a message intended for the group
        storage
            .inbox_queue(&group_identifier, 0, b"hello everyone")
            .expect("failed to queue inbox message");

        let next_item = storage.inbox_next().expect("failed to get next inbox item");

        assert!(next_item.is_some());

        let (session_identifier, sequence, message) = next_item.expect("next item isn't a tuple?");
        assert!(group_identifier.eq(&session_identifier));
        assert_eq!(sequence, 0);
        assert_eq!(message, b"hello everyone");

        // we have not dequeued the item yet, so it should return the same item again
        let next_item = storage.inbox_next().expect("failed to get next inbox item");

        assert!(next_item.is_some());

        let (session_identifier, sequence, message) = next_item.expect("next item isn't a tuple?");
        assert!(group_identifier.eq(&session_identifier));
        assert_eq!(sequence, 0);
        assert_eq!(message, b"hello everyone");

        // dequeue the item
        storage
            .inbox_dequeue(&group_identifier, sequence)
            .expect("dequeue failed");

        // there should be no items left in the queue
        let next_item = storage.inbox_next().expect("failed to get next inbox item");

        assert!(next_item.is_none());
    }

    #[test]
    fn encrypt_and_queue() {
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
        let bobs_session_with_alice = bob_acc
            .create_outbound_session(&alice_curve25519_pk, alices_one_time_key.as_bytes())
            .expect("failed to create outbound session");

        // store bobs session with alice
        storage
            .session_create(
                &bob_identifier,
                &alice_identifier,
                Some(bobs_session_with_alice),
            )
            .expect("failed to create session");

        // setup a group 1-1 with alice
        storage
            .member_add(&alice_identifier, &alice_identifier)
            .expect("failed to create 1-1 group with alice");

        // encrypt and queue two messages to alice
        let bobs_message_to_alice_1 = storage
            .encrypt_and_queue(&alice_identifier, b"hello alice pt1")
            .expect("failed to encrypt and queue");

        let bobs_message_to_alice_2 = storage
            .encrypt_and_queue(&alice_identifier, b"hello alice pt2")
            .expect("failed to encrypt and queue");

        // create alices session with bob from bobs first message
        let gm = crate::crypto::omemo::GroupMessage::decode(&bobs_message_to_alice_1)
            .expect("failed to decode group message");

        let one_time_message = gm
            .one_time_key_message(&alice_identifier.id())
            .expect("one time key message missing");

        let alices_session_with_bob = alice_acc
            .create_inbound_session(&bob_curve25519_pk, &one_time_message)
            .expect("failed to create inbound session");

        // remove the one time key from alices account
        alice_acc
            .remove_one_time_keys(&alices_session_with_bob)
            .expect("failed to remove session");

        // create alices group with bob
        let mut group = Group::new(&alice_identifier.id());
        group.add_participant(
            &bob_identifier.id(),
            Arc::new(Mutex::new(alices_session_with_bob)),
        );

        // decrypt the first message from bob
        let plaintext = group
            .decrypt(&bob_identifier.id(), &bobs_message_to_alice_1)
            .expect("failed to decrypt bobs message");

        assert_eq!(&plaintext, "hello alice pt1".as_bytes());

        // decrypt the second message from bob
        let plaintext = group
            .decrypt(&bob_identifier.id(), &bobs_message_to_alice_2)
            .expect("failed to decrypt bobs message");

        assert_eq!(&plaintext, "hello alice pt2".as_bytes());
    }
}
