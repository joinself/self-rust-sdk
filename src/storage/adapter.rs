use rusqlite::{Connection, Result, Transaction};

use crate::crypto::{
    account::Account,
    omemo::{Group, GroupMessage},
    session::{self, Session},
};
use crate::error::SelfError;
use crate::identifier::Identifier;
use crate::keypair::signing::{KeyPair, PublicKey};
use crate::keypair::Usage;
use crate::token::Token;
use crate::transport::websocket::Subscription;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub struct Storage {
    conn: Connection,
    acache: HashMap<Identifier, Rc<RefCell<Account>>>,
    gcache: HashMap<Identifier, Rc<RefCell<Group>>>,
    kcache: HashMap<Identifier, Rc<KeyPair>>,
    scache: HashMap<(Identifier, Identifier), Rc<RefCell<Session>>>,
}

// This whole implementation is horrible and only temporary...
// mutiple tables and caches are accessed for some higher level
// operations that also require atomicity via a single transaction
impl Storage {
    pub fn new(_storage_path: &str, _encryption_key: &[u8]) -> Result<Storage, SelfError> {
        let conn = Connection::open_in_memory().map_err(|_| SelfError::StorageConnectionFailed)?;

        /*
        let conn = Connection::open("/tmp/test.db").map_err(|_| SelfError::StorageConnectionFailed)?;
        conn.pragma_update(None, "synchronous", &"NORMAL").unwrap();
        conn.pragma_update(None, "journal_mode", &"WAL").unwrap();
        conn.pragma_update(None, "temp_store", &"MEMORY").unwrap();
        */

        let mut storage = Storage {
            conn,
            acache: HashMap::new(),
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
                    usage INTEGER NOT NULL,
                    persistent BOOL NOT NULL,
                    revoked_at INTEGER,
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
                    via_identifier INTEGER NOT NULL,
                    with_identifier INTEGER NOT NULL,
                    connected_on INTEGER NOT NULL
                );
                CREATE UNIQUE INDEX idx_connections_connection
                ON connections (as_identifier, via_identifier, with_identifier);",
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
                    for_identifier INTEGER NOT NULL,
                    purpose INTEGER NOT NULL,
                    token BLOB NOT NULL
                );
                CREATE UNIQUE INDEX idx_tokens_from
                ON tokens (from_identifier, for_identifier, purpose);",
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
                    connection INTEGER NOT NULL,
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
                    connection INTEGER NOT NULL,
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

    pub fn identifier_create(&mut self, identifier: &Identifier) -> Result<(), SelfError> {
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

    pub fn keypair_get(&mut self, identifier: &Identifier) -> Result<Rc<KeyPair>, SelfError> {
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
                "SELECT keypair FROM keypairs
                INNER JOIN identifiers ON
                    keypairs.for_identifier = identifiers.id
                WHERE identifiers.identifier = ?1;",
            )
            .expect("failed to prepare statement");

        let mut rows = match statement.query([&identifier.id()]) {
            Ok(rows) => rows,
            Err(err) => {
                println!("{}", err);
                return Err(SelfError::StorageTransactionCommitFailed);
            }
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
        let keypair = Rc::new(kp);

        self.kcache.insert(identifier.clone(), keypair.clone());

        Ok(keypair)
    }

    pub fn keypair_create(
        &mut self,
        usage: Usage,
        keypair: &KeyPair,
        account: Option<Account>,
        persistent: bool,
    ) -> Result<(), SelfError> {
        let identifier = Identifier::Owned(keypair.to_owned());

        // check if the key exists in the cache
        if self.kcache.contains_key(&identifier) {
            return Err(SelfError::KeychainKeyExists);
        };

        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        // create an record for the identifier we are creating a session with
        txn.execute(
            "INSERT INTO identifiers (identifier) VALUES (?1);",
            [&identifier.id()],
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        // create the keypair
        if let Some(olm_account) = account {
            txn.execute(
                "INSERT INTO keypairs (for_identifier, usage, persistent, keypair, olm_account) 
                VALUES (
                    (SELECT id FROM identifiers WHERE identifier=?1),
                    ?2,
                    ?3,
                    ?4,
                    ?5
                );",
                (
                    &identifier.id(),
                    usage.kind(),
                    persistent,
                    &keypair.encode(),
                    olm_account.pickle(None)?,
                ),
            )
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;
        } else {
            txn.execute(
                "INSERT INTO keypairs (for_identifier, usage, persistent, keypair) 
                VALUES (
                    (SELECT id FROM identifiers WHERE identifier=?1),
                    ?2,
                    ?3,
                    ?4
                );",
                (
                    &identifier.id(),
                    usage.kind(),
                    persistent,
                    &keypair.encode(),
                ),
            )
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;
        }

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        self.kcache.insert(identifier, Rc::new(keypair.clone()));

        Ok(())
    }

    pub fn keypair_list(
        &mut self,
        usage: Option<Usage>,
        persistent: bool,
    ) -> Result<Vec<KeyPair>, SelfError> {
        let mut keypairs = Vec::new();

        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        if let Some(usage) = usage {
            let mut statement = txn
                .prepare(
                    "SELECT keypair FROM keypairs
                    WHERE usage = ?1 AND persistent = ?2;",
                )
                .expect("failed to prepare statement");

            let mut rows = match statement.query((usage.kind(), persistent)) {
                Ok(rows) => rows,
                Err(_) => return Err(SelfError::StorageTransactionCommitFailed),
            };

            while let Some(row) = rows
                .next()
                .map_err(|_| SelfError::StorageTransactionCommitFailed)?
            {
                // let for_identifier: Vec<u8> = row.get(0).unwrap();
                let keypair: Vec<u8> = row.get(0).unwrap();
                let keypair = KeyPair::decode(&keypair)?;
                keypairs.push(keypair);
            }
        } else {
            let mut statement = txn
                .prepare(
                    "SELECT keypair FROM keypairs
                    WHERE persistent = ?1;",
                )
                .expect("failed to prepare statement");

            let mut rows = match statement.query([persistent]) {
                Ok(rows) => rows,
                Err(_) => return Err(SelfError::StorageTransactionCommitFailed),
            };

            while let Some(row) = rows
                .next()
                .map_err(|_| SelfError::StorageTransactionCommitFailed)?
            {
                // let for_identifier: Vec<u8> = row.get(0).unwrap();
                let keypair: Vec<u8> = row.get(0).unwrap();
                let keypair = KeyPair::decode(&keypair)?;
                keypairs.push(keypair);
            }
        }

        Ok(keypairs)
    }

    pub fn subscription_list(&mut self) -> Result<Vec<Subscription>, SelfError> {
        let mut subscriptions = Vec::new();

        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        // get all subscriptions that don't require a token
        let mut statement = txn
            .prepare(
                "SELECT keypair FROM keypairs
                WHERE usage = ?1;",
            )
            .expect("failed to prepare statement");

        let mut rows = match statement.query([Usage::Messaging.kind()]) {
            Ok(rows) => rows,
            Err(_) => return Err(SelfError::MessagingDestinationUnknown),
        };

        while let Some(row) = rows
            .next()
            .map_err(|_| SelfError::MessagingDestinationUnknown)?
        {
            let keypair: Vec<u8> = row.get(0).unwrap();
            let keypair = KeyPair::decode(&keypair)?;

            // TODO correctly load 'from' value
            subscriptions.push(Subscription {
                to_identifier: Identifier::Owned(keypair),
                as_identifier: None,
                from: 0,
                token: None,
            });
        }

        // get all subscriptions that require a token (groups)
        let mut statement = txn
            .prepare(
                "SELECT i1.identifier, k1.keypair, token FROM tokens
                JOIN identifiers i1 ON
                    i1.id = tokens.from_identifier
                JOIN keypairs k1 ON
                    k1.id = tokens.for_identifier
                WHERE purpose = ?1",
            )
            .expect("failed to prepare statement");

        let mut rows = match statement
            .query([Token::Subscription(crate::token::Subscription { token: Vec::new() }).kind()])
        {
            Ok(rows) => rows,
            Err(_) => return Err(SelfError::MessagingDestinationUnknown),
        };

        while let Some(row) = rows
            .next()
            .map_err(|_| SelfError::MessagingDestinationUnknown)?
        {
            let to_identifier: Vec<u8> = row.get(0).unwrap();
            let keypair: Vec<u8> = row.get(1).unwrap();
            let token: Vec<u8> = row.get(2).unwrap();

            let keypair = KeyPair::decode(&keypair)?;
            let token = Token::decode(&token)?;

            let to_identifier = Identifier::Referenced(PublicKey::from_bytes(
                &to_identifier,
                crate::keypair::Algorithm::Ed25519,
            )?);

            // TODO de-duplicate keypair serialisation
            // TODO correctly load 'from' value
            subscriptions.push(Subscription {
                to_identifier,
                as_identifier: Some(Identifier::Owned(keypair)),
                from: 0,
                token: Some(token),
            })
        }

        Ok(subscriptions)
    }

    pub fn token_create(
        &mut self,
        from_identifier: &Identifier,
        for_identifier: &Identifier,
        token: Token,
    ) -> Result<(), SelfError> {
        // create the token
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        let mut encoded_token = Vec::new();
        ciborium::ser::into_writer(&token, &mut encoded_token)
            .map_err(|_| SelfError::TokenEncodingInvalid)?;

        txn.execute(
            "INSERT INTO tokens (from_identifier, purpose, token) 
            VALUES (
                (SELECT id FROM identifiers WHERE identifier=?1),
                (SELECT id FROM identifiers WHERE identifier=?2),
                ?3,
                ?4
            );",
            (
                &from_identifier.id(),
                &for_identifier.id(),
                token.kind(),
                &encoded_token,
            ),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    pub fn connection_add(
        &mut self,
        as_identifier: &Identifier,
        with_identifier: &Identifier,
        via_identifier: Option<&Identifier>,
        one_time_key: Option<&[u8]>,
    ) -> Result<(), SelfError> {
        // get the next item in the inbox to be sent to the server
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        txn.execute(
            "INSERT INTO connections (as_identifier, with_identifier, via_identifier)
            VALUES (
                (
                    SELECT identifiers.id FROM identifiers
                    WHERE identifiers.identifier = ?1
                ),
                (
                    SELECT identifiers.id FROM identifiers
                    WHERE identifiers.identifier = ?2
                ),
                (
                    SELECT identifiers.id FROM identifiers
                    WHERE identifiers.identifier = ?3
                )
            );",
            (
                &as_identifier.id(),
                &via_identifier.unwrap_or(with_identifier).id(),
                &with_identifier.id(),
            ),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        if let (one_time_key) = one_time_key {}

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    pub fn connection_remove(
        &mut self,
        as_identifier: &Identifier,
        with_identifier: &Identifier,
        via_identifier: Option<&Identifier>,
    ) -> Result<(), SelfError> {
        Ok(())
    }

    pub fn inbox_next(&mut self) -> Result<Option<(Identifier, u64, Vec<u8>)>, SelfError> {
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
        let sequence: u64 = row.get(1).unwrap();
        let message: Vec<u8> = row.get(2).unwrap();

        let public_key = PublicKey::from_bytes(&session, crate::keypair::Algorithm::Ed25519)?;

        Ok(Some((
            Identifier::Referenced(public_key),
            sequence,
            message,
        )))
    }

    pub fn outbox_next(&mut self) -> Result<Option<(Identifier, u64, Vec<u8>)>, SelfError> {
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
        let sequence: u64 = row.get(1).unwrap();
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
        sequence: u64,
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

    pub fn outbox_dequeue(
        &mut self,
        recipient: &Identifier,
        sequence: u64,
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

    fn inbox_queue(
        &mut self,
        txn: &mut Transaction,
        sender: &Identifier,
        recipient: &Identifier,
        sequence: u64,
        plaintext: &[u8],
    ) -> Result<(), SelfError> {
        txn.execute(
            "INSERT INTO inbox (connection, sequence, message)
            VALUES (
                (
                    SELECT connections.id FROM connections
                    JOIN identifiers i1 ON
                        i1.id = connections.with_identifier
                    JOIN identifiers i2 ON
                        i2.id = connections.via_identifier
                    WHERE i1.identifier=?1
                ),
                ?2,
                ?3
            );",
            (&sender.id(), &recipient.id(), sequence, plaintext),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    fn outbox_queue(
        &mut self,
        txn: &mut Transaction,
        sender: &Identifier,
        recipient: &Identifier,
        sequence: u64,
        ciphertext: &[u8],
    ) -> Result<(), SelfError> {
        txn.execute(
            "INSERT INTO outbox (connection, sequence, message)
            VALUES (
                (
                    SELECT connections.id FROM connections
                    JOIN identifiers i1 ON
                        i1.id = connections.as_identifier
                    JOIN identifiers i2 ON
                        i2.id = connections.with_identifier
                    WHERE i1.identifier = ?1 AND i2.identifier = ?2
                ),
                ?2,
                ?3
            );",
            (&sender.id(), &recipient.id(), sequence, ciphertext),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    pub fn encrypt_and_queue(
        &mut self,
        recipient: &Identifier,
        plaintext: &[u8],
    ) -> Result<(Identifier, u64, Vec<u8>), SelfError> {
        let mut txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        // encrypt the message
        let result = self.encrypt_for(&mut txn, recipient, plaintext)?;

        // queue it in the outbox
        self.outbox_queue(&mut txn, &result.0, recipient, result.1, &result.2)?;

        // commit the transaction
        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(result)
    }

    pub fn decrypt_and_queue(
        &mut self,
        sender: &Identifier,
        recipient: &Identifier,
        subscriber: Option<&Identifier>,
        sequence: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SelfError> {
        let mut txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        // decrypt from
        let plaintext = self.decrypt_from(&mut txn, sender, recipient, subscriber, ciphertext)?;

        // queue to inbox
        self.inbox_queue(&mut txn, sender, recipient, sequence, &plaintext)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(plaintext)
    }

    pub fn encrypt_for(
        &mut self,
        txn: &mut Transaction,
        recipient: &Identifier,
        plaintext: &[u8],
    ) -> Result<(Identifier, u64, Vec<u8>), SelfError> {
        // search cache for group
        let mut group = match self.group_get(txn, recipient)? {
            Some(group) => group.as_ref().borrow(),
            None => return Err(SelfError::MessagingDestinationUnknown),
        };

        // encrypt the group message
        let ciphertext = group.encrypt(plaintext)?;

        // update each session in the group
        for session in group.participants() {
            self.session_update(txn, session)?;
        }

        // update connection transmit sequence
        self.metrics_update_sequence(txn, &group.as_identifier(), recipient, group.sequence())?;

        Ok((group.as_identifier(), group.sequence(), ciphertext))
    }

    pub fn decrypt_from(
        &mut self,
        txn: &mut Transaction,
        sender: &Identifier,
        recipient: &Identifier,
        subscriber: Option<&Identifier>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SelfError> {
        let mut group_message = GroupMessage::decode(ciphertext)?;

        let as_identifier = subscriber.unwrap_or(recipient);
        let session_identifier = (as_identifier.clone(), sender.clone());

        let session = match self.scache.get(&session_identifier) {
            Some(session) => {
                // the senders session is in the cache! check if this is a one time key message
                if let Some(one_time_message) = group_message.one_time_key_message(recipient) {
                    // see if this one time message matches the existing session
                    if !session
                        .as_ref()
                        .borrow()
                        .matches_inbound_session(&one_time_message)?
                    {
                        // this is a new inbound session, so lets create a new inbound session and
                        // update the existing one
                        let account_rc = self.account_get(txn, recipient)?;
                        let mut account = account_rc.as_ref().borrow();
                        let new_session =
                            account.create_inbound_session(sender.clone(), ciphertext)?;

                        // remove the one time keys used to create the session and update the account
                        account.remove_one_time_keys(&new_session);
                        self.account_update(txn, &account_rc)?;

                        session.replace(new_session);
                    }
                }

                session.clone()
            }
            None => {
                // attempt load the session from the database
                match self.session_get(txn, &session_identifier)? {
                    Some(session) => session.clone(),
                    None => {
                        // the senders session is in the cache! check if this is a one time key message
                        match group_message.one_time_key_message(recipient) {
                            Some(one_time_message) => {
                                // this is a new inbound session, so lets create a new inbound session and
                                // update the existing one
                                let account_rc = self.account_get(txn, recipient)?;
                                let mut account = account_rc.as_ref().borrow();
                                let inbound_session =
                                    account.create_inbound_session(sender.clone(), ciphertext)?;

                                // remove the one time keys used to create the session and update the account
                                account.remove_one_time_keys(&inbound_session);
                                self.account_update(txn, &account_rc)?;

                                let session = Rc::new(RefCell::new(inbound_session));
                                self.session_create(txn, &session)?;
                                session
                            }
                            None => return Err(SelfError::CryptoUnknownSession),
                        }
                    }
                }
            }
        };

        // construct a temporary group to decrypt the message with
        let mut group = Group::new(recipient.clone(), 0);
        group.add_participant(session.clone());

        let plaintext = group.decrypt_group_message(sender, &mut group_message);
        self.session_update(txn, &session);

        plaintext
    }

    fn group_get(
        &mut self,
        txn: &mut Transaction,
        group_identifier: &Identifier,
    ) -> Result<Option<Rc<RefCell<Group>>>, SelfError> {
        // check the cache first to determine if there is an existing group that can be reused to send messages
        if let Some(group) = self.gcache.get(group_identifier) {
            return Ok(Some(group.clone()));
        };

        let mut sessions = Vec::new();

        // query all connections for the destination that matches the 'via' identifier
        // and join all matching sessions
        let mut statement = txn
            .prepare(
                "SELECT i2.identifier, i3.identifier, s1.sequence_tx, s1.sequence_rx, s1.olm_session FROM connections
                JOIN identifiers i1 ON
                    i1.id = connections.via_identifier
                JOIN identifiers i2 ON
                    i2.id = connections.as_identifier
                JOIN identifiers i3 ON
                    i3.id = connections.with_identifier
                JOIN sessions s1 ON
                    i2.id = s1.as_identifier AND i3.id = s1.with_identifier
                WHERE i1.identifier = ?1;",
            )
            .expect("failed to prepare statement");

        let mut rows = match statement.query([&group_identifier.id()]) {
            Ok(rows) => rows,
            Err(_) => return Err(SelfError::MessagingDestinationUnknown),
        };

        // loop over all connections and build list of sessions that comprise the group
        while let Some(row) = rows
            .next()
            .map_err(|_| SelfError::MessagingDestinationUnknown)?
        {
            let as_identifier: Vec<u8> = row.get(0).unwrap();
            let with_identifier: Vec<u8> = row.get(1).unwrap();
            let sequence_tx: u64 = row.get(2).unwrap();
            let sequence_rx: u64 = row.get(3).unwrap();
            let mut session: Vec<u8> = row.get(4).unwrap();

            let as_identifier = Identifier::Referenced(PublicKey::from_bytes(
                &as_identifier,
                crate::keypair::Algorithm::Ed25519,
            )?);

            let with_identifier = Identifier::Referenced(PublicKey::from_bytes(
                &with_identifier,
                crate::keypair::Algorithm::Ed25519,
            )?);

            let session_identifier = (as_identifier.clone(), with_identifier.clone());

            // check to see if we have an existing session in our cache that we can use directly
            let session = self
                .scache
                .get(&session_identifier)
                .unwrap_or({
                    // if there is no session in the cache, use the session from the query and add it to the cache
                    let s = Rc::new(RefCell::new(Session::from_pickle(
                        as_identifier.clone(),
                        with_identifier.clone(),
                        sequence_tx,
                        sequence_rx,
                        &mut session,
                        None,
                    )?));

                    self.scache.insert(session_identifier, s.clone());

                    &s
                })
                .clone();

            sessions.push(session)
        }

        if let Some(session) = sessions.first() {
            // get the latest sequence number for sending messages to the group
            let sequence = self.metrics_get_sequence(
                txn,
                session.as_ref().borrow().as_identifier(),
                session.as_ref().borrow().with_identifier(),
            )?;

            let group = Rc::new(RefCell::new(Group::new(
                session.as_ref().borrow().as_identifier().clone(),
                sequence,
            )));

            self.gcache.insert(group_identifier.clone(), group.clone());

            return Ok(Some(group));
        }

        Ok(None)
    }

    fn account_get(
        &mut self,
        txn: &mut Transaction,
        account_identifier: &Identifier,
    ) -> Result<Rc<RefCell<Account>>, SelfError> {
        if let Some(account) = self.acache.get(account_identifier) {
            return Ok(account.clone());
        };

        let mut statement = txn
            .prepare(
                "SELECT olm_account from keypairs
                JOIN identifiers i1 ON
                    i1.id = keypairs.for_identifier
                WHERE i1.identifier = ?1 AND olm_account != NULL;",
            )
            .expect("failed to prepare statement");

        let mut rows = match statement.query([&account_identifier.id()]) {
            Ok(rows) => rows,
            Err(_) => return Err(SelfError::MessagingDestinationUnknown),
        };

        if let Some(row) = rows
            .next()
            .map_err(|err| SelfError::StorageTransactionCommitFailed)?
        {
            let mut encoded_account: Vec<u8> = row.get(0).unwrap();
            let account = Rc::new(RefCell::new(Account::from_pickle(
                account_identifier.clone(),
                &mut encoded_account,
                None,
            )?));
            self.acache
                .insert(account_identifier.clone(), account.clone());
            return Ok(account);
        }

        return Err(SelfError::MessagingDestinationUnknown);
    }

    fn account_update(
        &mut self,
        txn: &mut Transaction,
        account: &Rc<RefCell<Account>>,
    ) -> Result<(), SelfError> {
        let account = account.as_ref().borrow();
        let encoded_account = account.pickle(None)?;

        txn.execute(
            "UPDATE keypairs
                SET olm_account = ?2
                JOIN identifiers i1 ON
                    i1.id = keypairs.for_identifier
                WHERE i1.identifier = ?1;",
            (&account.identifier().id(), &encoded_account),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    fn session_get(
        &mut self,
        txn: &mut Transaction,
        session_identifier: &(Identifier, Identifier),
    ) -> Result<Option<Rc<RefCell<Session>>>, SelfError> {
        let mut statement = txn
            .prepare(
                "SELECT s1.sequence_tx, s1.sequence_rx, s1.olm_session FROM connections
                JOIN identifiers i1 ON
                    i1.id = connections.as_identifier
                JOIN identifiers i2 ON
                    i2.id = connections.with_identifier
                JOIN sessions s1 ON
                    i1.id = s1.as_identifier AND i2.id = s1.with_identifier
                WHERE i1.identifier = ?1 AND i2.identifier = ?2;",
            )
            .expect("failed to prepare statement");

        let mut rows =
            match statement.query([&session_identifier.0.id(), &session_identifier.1.id()]) {
                Ok(rows) => rows,
                Err(_) => return Err(SelfError::MessagingDestinationUnknown),
            };

        if let Ok(row) = rows.next() {
            if let Some(row) = row {
                let sequence_tx: u64 = row.get(0).unwrap();
                let sequence_rx: u64 = row.get(1).unwrap();
                let mut encoded_session: Vec<u8> = row.get(2).unwrap();

                let session = Rc::new(RefCell::new(Session::from_pickle(
                    session_identifier.0.clone(),
                    session_identifier.1.clone(),
                    sequence_tx,
                    sequence_rx,
                    &mut encoded_session,
                    None,
                )?));

                self.scache
                    .insert(session_identifier.clone(), session.clone());

                return Ok(Some(session));
            }
        }

        return Ok(None);
    }

    fn session_create(
        &mut self,
        txn: &mut Transaction,
        session: &Rc<RefCell<Session>>,
    ) -> Result<(), SelfError> {
        let session_ref = session.as_ref().borrow();
        let encoded_session = session_ref.pickle(None)?;
        let session_identifier = (
            session_ref.as_identifier().clone(),
            session_ref.with_identifier().clone(),
        );

        txn.execute(
            "INSERT INTO sessions (as_identifier, with_identifier, sequence_tx, sequence_rx, olm_session)
            VALUES (
                (SELECT id FROM identifiers WHERE identifier=?1),
                (SELECT id FROM identifiers WHERE identifier=?2),
                ?3,
                ?4
                ?5
            );",
            (
                &session_ref.as_identifier().id(),
                &session_ref.with_identifier().id(),
                session_ref.sequence_tx(),
                session_ref.sequence_rx(),
                encoded_session,
            ),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        self.scache.insert(session_identifier, session.clone());

        Ok(())
    }

    fn session_update(
        &mut self,
        txn: &mut Transaction,
        session: &Rc<RefCell<Session>>,
    ) -> Result<(), SelfError> {
        let session = session.as_ref().borrow();
        let encoded_session = session.pickle(None)?;

        txn.execute(
            "UPDATE sessions
            SET sequence_tx = ?3, sequence_rx = ?4, olm_session = ?5
            JOIN identifiers i1 ON
                i1.id = sessions.as_identifier
            JOIN identifiers i2 ON
                i2.id = sessions.with_identifier
            WHERE i1.identifier = ?1 AND i2.identifier = ?2;",
            (
                &session.as_identifier().id(),
                &session.with_identifier().id(),
                session.sequence_tx(),
                session.sequence_rx(),
                encoded_session,
            ),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    fn metrics_get_sequence(
        &mut self,
        txn: &mut Transaction,
        as_identifier: &Identifier,
        with_identifier: &Identifier,
    ) -> Result<u64, SelfError> {
        // get the metrcis (transmission sequence) for the recipient group
        let mut statement = txn
            .prepare(
                "SELECT sequence FROM metrics
                JOIN identifiers i1 ON
                    i1.id = metrics.as_identifier
                JOIN identifiers i2 ON
                    i2.id = metrics.with_identifier
                WHERE i1.identifier = ?1 AND i2.identifier = ?2;",
            )
            .expect("failed to prepare statement");

        let mut rows = match statement.query([&as_identifier.id(), &with_identifier.id()]) {
            Ok(rows) => rows,
            Err(_) => return Err(SelfError::MessagingDestinationUnknown),
        };

        match rows.next() {
            Ok(row) => match row {
                Some(row) => row
                    .get(0)
                    .map_err(|_| SelfError::StorageTransactionCommitFailed),
                None => Err(SelfError::MessagingDestinationUnknown),
            },
            Err(_) => Err(SelfError::StorageTransactionCommitFailed),
        }
    }

    fn metrics_update_sequence(
        &mut self,
        txn: &mut Transaction,
        as_identifier: &Identifier,
        with_identifier: &Identifier,
        sequence: u64,
    ) -> Result<(), SelfError> {
        txn.execute(
            "UPDATE metrics
            SET sequence = ?3
            JOIN identifiers i1 ON
                i1.id = metrics.as_identifier
            JOIN identifiers i2 ON
                i2.id = metrics.with_identifier
            WHERE i1.identifier = ?1 AND i2.identifier = ?2;",
            (&as_identifier.id(), &with_identifier.id(), sequence),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction() {
        let mut storage =
            super::Storage::new("/tmp/test.db", b"12345").expect("failed to create transaction");

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
        let mut storage = super::Storage::new("/tmp/test.db", b"12345").expect("storage failed");

        let msg = vec![8; 128];
        let sig = kp.sign(&msg);

        storage
            .keypair_create(Usage::Messaging, &kp, None, false)
            .expect("failed to create keypair");

        let kp = storage
            .keypair_get(&Identifier::Owned(kp))
            .expect("failed to get keypair");

        assert!(kp.public().verify(&msg, &sig));
    }

    #[test]
    fn outbox_queue_and_dequeue() {
        let mut storage = super::Storage::new("/tmp/test.db", b"12345").expect("storage failed");

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
            .expect("failed to create carol identifier");

        storage
            .identifier_create(&group_identifier)
            .expect("failed to create group identifier");

        // create a connection for the group
        storage
            .connection_add(&alice_identifier, &group_identifier, None, None)
            .expect("failed to create alices connection with group");

        // create connections with members of the group
        storage
            .connection_add(
                &alice_identifier,
                &bob_identifier,
                Some(&group_identifier),
                None,
            )
            .expect("failed to create alices group connection with bob");

        storage
            .connection_add(
                &alice_identifier,
                &carol_identifier,
                Some(&group_identifier),
                None,
            )
            .expect("failed to create alices group connection with carol");

        storage
            .transaction(|mut txn| {
                // queue a message intended for the group
                storage
                    .outbox_queue(
                        &mut txn,
                        &alice_identifier,
                        &group_identifier,
                        0,
                        b"hello everyone",
                    )
                    .expect("failed to queue");

                true
            })
            .expect("failed to queue outbox");

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
        let mut storage = super::Storage::new("/tmp/test.db", b"12345").expect("storage failed");

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

        // create a connection for the group
        storage
            .connection_add(&alice_identifier, &group_identifier, None, None)
            .expect("failed to create alices connection with group");

        // create connections with members of the group
        storage
            .connection_add(
                &alice_identifier,
                &bob_identifier,
                Some(&group_identifier),
                None,
            )
            .expect("failed to create alices group connection with bob");

        storage
            .connection_add(
                &alice_identifier,
                &carol_identifier,
                Some(&group_identifier),
                None,
            )
            .expect("failed to create alices group connection with carol");

        // queue a message intended for the group
        storage
            .transaction(|mut txn| {
                storage
                    .inbox_queue(
                        &mut txn,
                        &alice_identifier,
                        &group_identifier,
                        0,
                        b"hello everyone",
                    )
                    .expect("failed to queue inbox message");
                true
            })
            .expect("failed to queue inbox");

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
        let mut storage = super::Storage::new("/tmp/test.db", b"12345").expect("storage failed");

        let alice_skp = crate::keypair::signing::KeyPair::new();
        let alice_ekp = crate::keypair::exchange::KeyPair::new();
        let alice_ed25519_pk = alice_skp.public();
        let alice_curve25519_pk = alice_ekp.public();
        let mut alice_acc = crate::crypto::account::Account::new(alice_skp, alice_ekp);

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ekp = crate::keypair::exchange::KeyPair::new();
        let bob_ed25519_pk = bob_skp.public();
        let bob_curve25519_pk = bob_ekp.public();
        let bob_skp_clone = bob_skp.clone();
        let mut bob_acc = crate::crypto::account::Account::new(bob_skp, bob_ekp);

        let alice_identifier = Identifier::Referenced(alice_ed25519_pk);
        let bob_identifier = Identifier::Referenced(bob_ed25519_pk);

        storage
            .keypair_create(Usage::Messaging, &bob_skp_clone, None, true)
            .expect("failed to create bob keypair");
        storage
            .identifier_create(&alice_identifier)
            .expect("failed to create alice identifier");

        alice_acc
            .generate_one_time_keys(10)
            .expect("failed to generate one time keys");

        let alices_one_time_keys = alice_acc.one_time_keys();

        // create bobs connection with alice and create a session from the one time key
        storage
            .connection_add(
                &bob_identifier,
                &alice_identifier,
                None,
                Some(&alices_one_time_keys[0]),
            )
            .expect("failed to create bobs connection with alice");

        // encrypt and queue two messages to alice
        let (_, _, bobs_message_to_alice_1) = storage
            .encrypt_and_queue(&alice_identifier, b"hello alice pt1")
            .expect("failed to encrypt and queue");

        let (_, _, bobs_message_to_alice_2) = storage
            .encrypt_and_queue(&alice_identifier, b"hello alice pt2")
            .expect("failed to encrypt and queue");

        // create alices session with bob from bobs first message
        let gm = crate::crypto::omemo::GroupMessage::decode(&bobs_message_to_alice_1)
            .expect("failed to decode group message");

        let one_time_message = gm
            .one_time_key_message(&alice_identifier)
            .expect("one time key message missing");

        let alices_session_with_bob = alice_acc
            .create_inbound_session(bob_identifier.clone(), &one_time_message)
            .expect("failed to create inbound session");

        // remove the one time key from alices account
        alice_acc
            .remove_one_time_keys(&alices_session_with_bob)
            .expect("failed to remove session");

        // create alices group with bob
        let mut group = Group::new(alice_identifier.clone(), 0);
        group.add_participant(Rc::new(RefCell::new(alices_session_with_bob)));

        // decrypt the first message from bob
        let plaintext = group
            .decrypt(&bob_identifier, &bobs_message_to_alice_1)
            .expect("failed to decrypt bobs message");

        assert_eq!(&plaintext, "hello alice pt1".as_bytes());

        // decrypt the second message from bob
        let plaintext = group
            .decrypt(&bob_identifier, &bobs_message_to_alice_2)
            .expect("failed to decrypt bobs message");

        assert_eq!(&plaintext, "hello alice pt2".as_bytes());
    }

    #[test]
    fn decrypt_and_queue() {
        let mut storage = super::Storage::new("/tmp/test.db", b"12345").expect("storage failed");

        let alice_skp = crate::keypair::signing::KeyPair::new();
        let alice_ekp = crate::keypair::exchange::KeyPair::new();
        let alice_ed25519_pk = alice_skp.public();
        let alice_curve25519_pk = alice_ekp.public();
        let mut alice_acc = crate::crypto::account::Account::new(alice_skp, alice_ekp);

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ekp = crate::keypair::exchange::KeyPair::new();
        let bob_ed25519_pk = bob_skp.public();
        let bob_curve25519_pk = bob_ekp.public();
        let bob_skp_clone = bob_skp.clone();
        let mut bob_acc = crate::crypto::account::Account::new(bob_skp, bob_ekp);

        let alice_identifier = Identifier::Referenced(alice_ed25519_pk);
        let bob_identifier = Identifier::Referenced(bob_ed25519_pk);

        storage
            .keypair_create(Usage::Messaging, &bob_skp_clone, None, true)
            .expect("failed to create alice identifier");
        storage
            .identifier_create(&alice_identifier)
            .expect("failed to create alice identifier");

        alice_acc
            .generate_one_time_keys(10)
            .expect("failed to generate one time keys");

        let alices_one_time_keys = alice_acc.one_time_keys();

        // create bobs connection with alice and create a session from the one time key
        storage
            .connection_add(
                &bob_identifier,
                &alice_identifier,
                None,
                Some(&alices_one_time_keys[0]),
            )
            .expect("failed to create bobs connection with alice");

        // encrypt and queue two messages to alice
        let (_, _, bobs_message_to_alice_1) = storage
            .encrypt_and_queue(&alice_identifier, b"hello alice pt1")
            .expect("failed to encrypt and queue");

        // create alices session with bob from bobs first message
        let gm = crate::crypto::omemo::GroupMessage::decode(&bobs_message_to_alice_1)
            .expect("failed to decode group message");

        let one_time_message = gm
            .one_time_key_message(&alice_identifier)
            .expect("one time key message missing");

        let alices_session_with_bob = alice_acc
            .create_inbound_session(bob_identifier.clone(), &one_time_message)
            .expect("failed to create inbound session");

        // remove the one time key from alices account
        alice_acc
            .remove_one_time_keys(&alices_session_with_bob)
            .expect("failed to remove session");

        // create alices group with bob
        let mut group = Group::new(alice_identifier.clone(), 0);
        group.add_participant(Rc::new(RefCell::new(alices_session_with_bob)));

        // decrypt the first message from bob
        let plaintext = group
            .decrypt(&bob_identifier, &bobs_message_to_alice_1)
            .expect("failed to decrypt bobs message");

        assert_eq!(&plaintext, "hello alice pt1".as_bytes());

        // encrypt a message for bob
        let ciphertext = group
            .encrypt(b"hello bob")
            .expect("failed to encrypt message for bob");

        // decrypt message for bob
        let plaintext = storage
            .decrypt_and_queue(&alice_identifier, &bob_identifier, None, 1, &ciphertext)
            .expect("failed to decrypt message from alice");
        assert_eq!(plaintext, b"hello bob");
    }

    #[test]
    fn receive_message_from_new_identifier() {}

    #[test]
    fn receive_message_from_existing_identifier() {}

    #[test]
    fn receive_group_message_from_identifier() {}
}
