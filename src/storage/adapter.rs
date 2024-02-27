use rusqlite::{Connection, Result, Transaction};

use crate::crypto::{
    account::Account,
    omemo::{Group, GroupMessage},
    session::Session,
};
use crate::error::SelfError;
use crate::identifier::Address;
use crate::keypair::signing::{KeyPair, PublicKey};
use crate::keypair::Usage;
use crate::token::Token;
use crate::transport::websocket::Subscription;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

pub type QueuedInboxMessage = (Address, Address, Address, u64, Vec<u8>);
pub type QueuedOutboxMessage = (Address, Address, u64, Vec<u8>);

pub struct Storage {
    conn: Connection,
    acache: HashMap<Address, Rc<RefCell<Account>>>,
    gcache: HashMap<Address, Rc<RefCell<Group>>>,
    kcache: HashMap<Address, Arc<KeyPair>>,
    scache: HashMap<(Address, Address), Rc<RefCell<Session>>>,
}

// TODO verify this is actually safe
// storage is always used with an arc + mutex, so it should be safe to use
// any values returned are either retured as owned obhjects, or are wrapped
// with an arc (such as keypairs)
unsafe impl Send for Storage {}

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

        storage.setup_addresss_table()?;
        storage.setup_keypairs_table()?;
        storage.setup_operations_table()?;
        storage.setup_connections_table()?;
        storage.setup_sessions_table()?;
        storage.setup_tokens_table()?;
        storage.setup_credentials_table()?;
        storage.setup_metrics_table()?;
        storage.setup_inbox_table()?;
        storage.setup_outbox_table()?;

        Ok(storage)
    }

    fn setup_addresss_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE addresses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address BLOB NOT NULL
                );
                CREATE UNIQUE INDEX idx_addresss_address
                ON addresses (address);",
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
                    for_address INTEGER NOT NULL,
                    usage INTEGER NOT NULL,
                    persistent BOOL NOT NULL,
                    revoked_at INTEGER,
                    keypair BLOB NOT NULL,
                    olm_account BLOB
                );
                CREATE UNIQUE INDEX idx_keypairs_for_address
                ON keypairs (for_address);",
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
                    on_address INTEGER NOT NULL,
                    sequence INTEGER NOT NULL,
                    operation BLOB NOT NULL
                );
                CREATE UNIQUE INDEX idx_operations_operation
                ON operations (on_address, sequence);",
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
                    as_address INTEGER NOT NULL,
                    via_address INTEGER NOT NULL,
                    with_address INTEGER NOT NULL
                );
                CREATE UNIQUE INDEX idx_connections_connection
                ON connections (as_address, via_address, with_address);",
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
                    as_address INTEGER NOT NULL,
                    with_address INTEGER NOT NULL,
                    sequence_tx INTEGER NOT NULL,
                    sequence_rx INTEGER NOT NULL,
                    olm_session BLOB NOT NULL
                );
                CREATE UNIQUE INDEX idx_sessions_with_address
                ON sessions (as_address, with_address);",
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
                    from_address INTEGER NOT NULL,
                    for_address INTEGER,
                    purpose INTEGER NOT NULL,
                    expires INTEGER NOT NULL,
                    token BLOB NOT NULL
                );
                CREATE UNIQUE INDEX idx_tokens_from
                ON tokens (from_address, for_address, purpose);",
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
                    from_address INTEGER NOT NULL,
                    about_address INTEGER NOT NULL,
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

    fn setup_metrics_table(&mut self) -> Result<(), SelfError> {
        self.conn
            .execute(
                "CREATE TABLE metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    as_address INTEGER NOT NULL,
                    with_address INTEGER NOT NULL,
                    sequence INTEGER NOT NULL
                );
                CREATE UNIQUE INDEX idx_metrics_for
                ON tokens (as_address, with_address);",
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
        F: FnOnce(&mut Transaction) -> bool,
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

    pub fn keypair_get(&mut self, address: &Address) -> Result<Arc<KeyPair>, SelfError> {
        // check if the key exists in the cache
        if let Some(kp) = self.kcache.get(address) {
            return Ok(kp.clone());
        };

        let mut txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        let keypair = keypair_get(&mut txn, &mut self.kcache, address)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(keypair)
    }

    pub fn keypair_create(
        &mut self,
        usage: Usage,
        keypair: &KeyPair,
        account: Option<Account>,
        persistent: bool,
    ) -> Result<(), SelfError> {
        let address = Address::from_public_key(&keypair.public());

        // check if the key exists in the cache
        if self.kcache.contains_key(&address) {
            return Err(SelfError::KeychainKeyExists);
        };

        let mut txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        // create an record for the address we are creating a keypair with
        address_create(&mut txn, &address)?;

        // create the keypair
        if let Some(olm_account) = account {
            txn.execute(
                "INSERT INTO keypairs (for_address, usage, persistent, keypair, olm_account) 
                VALUES (
                    (SELECT id FROM addresses WHERE address=?1),
                    ?2,
                    ?3,
                    ?4,
                    ?5
                );",
                (
                    &address.to_vec(),
                    usage.kind(),
                    persistent,
                    &keypair.encode(),
                    olm_account.pickle(None)?,
                ),
            )
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;
        } else {
            txn.execute(
                "INSERT INTO keypairs (for_address, usage, persistent, keypair) 
                VALUES (
                    (SELECT id FROM addresses WHERE address=?1),
                    ?2,
                    ?3,
                    ?4
                );",
                (
                    &address.to_vec(),
                    usage.kind(),
                    persistent,
                    &keypair.encode(),
                ),
            )
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;
        }

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        self.kcache.insert(address, Arc::new(keypair.clone()));

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
                // let for_address: Vec<u8> = row.get(0).unwrap();
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
                // let for_address: Vec<u8> = row.get(0).unwrap();
                let keypair: Vec<u8> = row.get(0).unwrap();
                let keypair = KeyPair::decode(&keypair)?;
                keypairs.push(keypair);
            }
        }

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

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
                to_address: Address::from_public_key(&keypair.public()),
                as_address: keypair,
                from: 0,
                token: None,
            });
        }

        // get all subscriptions that require a token (groups)
        let mut statement = txn
            .prepare(
                "SELECT i1.address, k1.keypair, token FROM tokens
                JOIN addresses i1 ON
                    i1.id = tokens.from_address
                JOIN keypairs k1 ON
                    k1.id = tokens.for_address
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
            let to_address: Vec<u8> = row.get(0).unwrap();
            let keypair: Vec<u8> = row.get(1).unwrap();
            let token: Vec<u8> = row.get(2).unwrap();

            let keypair = KeyPair::decode(&keypair)?;
            let token = Token::decode(&token)?;

            let to_address = Address::from_bytes(&to_address)?;

            // TODO de-duplicate keypair serialisation
            // TODO correctly load 'from' value
            subscriptions.push(Subscription {
                to_address,
                as_address: keypair,
                from: 0,
                token: Some(token),
            })
        }

        Ok(subscriptions)
    }

    pub fn token_create(
        &mut self,
        from_address: &Address,
        for_address: Option<&Address>,
        expires: i64,
        token: &Token,
    ) -> Result<(), SelfError> {
        // create the token
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        let mut encoded_token = Vec::new();
        ciborium::ser::into_writer(&token, &mut encoded_token)
            .map_err(|_| SelfError::TokenEncodingInvalid)?;

        if let Some(for_address) = for_address {
            txn.execute(
                "INSERT INTO tokens (from_address, for_address, purpose, expires, token) 
                VALUES (
                    (SELECT id FROM addresses WHERE address=?1),
                    (SELECT id FROM addresses WHERE address=?2),
                    ?3,
                    ?4,
                    ?5
                );",
                (
                    &from_address.to_vec(),
                    &for_address.to_vec(),
                    token.kind(),
                    expires,
                    &encoded_token,
                ),
            )
            .expect("f");
            //.map_err(|_| SelfError::StorageTransactionCommitFailed)?;
        } else {
            txn.execute(
                "INSERT INTO tokens (from_address, purpose, expires, token) 
                VALUES (
                    (SELECT id FROM addresses WHERE address=?1),
                    ?2,
                    ?3,
                    ?4
                );",
                (&from_address.to_vec(), token.kind(), expires, &encoded_token),
            )
            .expect("f");
            //.map_err(|_| SelfError::StorageTransactionCommitFailed)?;
        }

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    pub fn connection_add(
        &mut self,
        as_address: &Address,
        with_address: &Address,
        via_address: Option<&Address>,
        one_time_key: Option<&[u8]>,
    ) -> Result<(), SelfError> {
        // get the next item in the inbox to be sent to the server
        let mut txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        connection_add(
            &mut txn,
            &mut self.acache,
            &mut self.scache,
            as_address,
            with_address,
            via_address,
            one_time_key,
        )?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    pub fn inbox_next(&mut self) -> Result<Option<QueuedInboxMessage>, SelfError> {
        // get the next item in the inbox to be sent to the server
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        let mut statement = txn
            .prepare(
                "SELECT i1.address, i2.address, i3.address, sequence, message FROM inbox
                JOIN connections c1 ON
                    c1.id = inbox.connection
                JOIN addresses i1 ON
                    i1.id = c1.as_address
                JOIN addresses i2 ON
                    i2.id = c1.with_address
                JOIN addresses i3 ON
                    i3.id = c1.via_address
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

        let as_address: Vec<u8> = row.get(0).unwrap();
        let with_address: Vec<u8> = row.get(1).unwrap();
        let via_address: Vec<u8> = row.get(2).unwrap();
        let sequence: u64 = row.get(3).unwrap();
        let message: Vec<u8> = row.get(4).unwrap();

        let as_address =
            PublicKey::from_bytes(&as_address, crate::keypair::Algorithm::Ed25519)?;
        let with_address =
            PublicKey::from_bytes(&with_address, crate::keypair::Algorithm::Ed25519)?;
        let via_address =
            PublicKey::from_bytes(&via_address, crate::keypair::Algorithm::Ed25519)?;

        Ok(Some((
            Address::from_public_key(&as_address),
            Address::from_public_key(&with_address),
            Address::from_public_key(&via_address),
            sequence,
            message,
        )))
    }

    pub fn outbox_next(&mut self) -> Result<Option<QueuedOutboxMessage>, SelfError> {
        // get the next item in the outbox to be sent to the server
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        let mut statement = txn
            .prepare(
                "SELECT i1.address, i2.address, sequence, message FROM outbox
                JOIN connections c1 ON
                    c1.id = outbox.connection
                JOIN addresses i1 ON
                    i1.id = c1.as_address
                JOIN addresses i2 ON
                    i2.id = c1.via_address
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

        let as_address: Vec<u8> = row.get(0).unwrap();
        let via_address: Vec<u8> = row.get(1).unwrap();
        let sequence: u64 = row.get(2).unwrap();
        let message: Vec<u8> = row.get(3).unwrap();

        let as_address =
            PublicKey::from_bytes(&as_address, crate::keypair::Algorithm::Ed25519)?;
        let via_address =
            PublicKey::from_bytes(&via_address, crate::keypair::Algorithm::Ed25519)?;

        Ok(Some((
            Address::from_public_key(&as_address),
            Address::from_public_key(&via_address),
            sequence,
            message,
        )))
    }

    pub fn inbox_dequeue(
        &mut self,
        sender: &Address,
        recipient: &Address,
        subscriber: Option<Address>,
        sequence: u64,
    ) -> Result<(), SelfError> {
        let via_address = if subscriber.is_some() {
            recipient
        } else {
            sender
        };

        // remove the messaage from the inbox once it has been confirmed as received by the server
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        txn.execute(
            "DELETE FROM inbox WHERE connection = (
                SELECT connections.id FROM connections
                JOIN addresses i1 ON
                    i1.id = connections.as_address
                JOIN addresses i2 ON
                    i2.id = connections.with_address
                JOIN addresses i3 ON
                    i3.id = connections.via_address
                WHERE i1.address = ?1 AND i2.address = ?2 AND i3.address = ?3
            ) AND sequence = ?4;",
            (
                &subscriber.as_ref().unwrap_or(recipient).to_vec(),
                &sender.to_vec(),
                via_address.to_vec(),
                sequence,
            ),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    pub fn outbox_dequeue(
        &mut self,
        sender: &Address,
        recipient: &Address,
        sequence: u64,
    ) -> Result<(), SelfError> {
        // remove the messaage from the outbox once it has been confirmed as received by the server
        let txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        txn.execute(
            "DELETE FROM outbox WHERE connection = (
                SELECT connections.id FROM connections
                JOIN addresses i1 ON
                    i1.id = connections.as_address
                JOIN addresses i2 ON
                    i2.id = connections.via_address
                WHERE i1.address = ?1 AND i2.address = ?2
            ) AND sequence = ?3;",
            (&sender.to_vec(), &recipient.to_vec(), sequence),
        )
        .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(())
    }

    pub fn encrypt_and_queue(
        &mut self,
        recipient: &Address,
        plaintext: &[u8],
    ) -> Result<(Address, u64, Vec<u8>), SelfError> {
        let mut txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        // encrypt the message
        let result = encrypt_for(
            &mut txn,
            &mut self.gcache,
            &mut self.kcache,
            &mut self.scache,
            recipient,
            plaintext,
        )?;

        // queue it in the outbox
        outbox_queue(&mut txn, &result.0, recipient, result.1, &result.2)?;

        // commit the transaction
        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(result)
    }

    pub fn decrypt_and_queue(
        &mut self,
        sender: &Address,
        recipient: &Address,
        subscriber: Option<Address>,
        sequence: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SelfError> {
        let mut txn = self
            .conn
            .transaction()
            .map_err(|_| SelfError::StorageTransactionCreationFailed)?;

        // decrypt from
        let plaintext = decrypt_from(
            &mut txn,
            &mut self.acache,
            &mut self.scache,
            sender,
            recipient,
            subscriber.clone(),
            ciphertext,
        )?;

        // queue to inbox
        inbox_queue(
            &mut txn, sender, recipient, subscriber, sequence, &plaintext,
        )?;

        txn.commit()
            .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

        Ok(plaintext)
    }
}

fn address_create(txn: &mut Transaction, address: &Address) -> Result<(), SelfError> {
    txn.execute(
        "INSERT OR IGNORE INTO addresses (address) VALUES (?1)",
        [&address.to_vec()],
    )
    .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

    Ok(())
}

fn connection_add(
    txn: &mut Transaction,
    acache: &mut HashMap<Address, Rc<RefCell<Account>>>,
    scache: &mut HashMap<(Address, Address), Rc<RefCell<Session>>>,
    as_address: &Address,
    with_address: &Address,
    via_address: Option<&Address>,
    one_time_key: Option<&[u8]>,
) -> Result<(), SelfError> {
    address_create(txn, with_address)?;

    if let Some(via_address) = via_address {
        address_create(txn, via_address)?;
    }

    txn.execute(
        "INSERT INTO connections (as_address, with_address, via_address)
        VALUES (
            (
                SELECT addresses.id FROM addresses
                WHERE addresses.address = ?1
            ),
            (
                SELECT addresses.id FROM addresses
                WHERE addresses.address = ?2
            ),
            (
                SELECT addresses.id FROM addresses
                WHERE addresses.address = ?3
            )
        );",
        (
            &as_address.to_vec(),
            &with_address.to_vec(),
            &via_address.unwrap_or(with_address).to_vec(),
        ),
    )
    .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

    if let Some(one_time_key) = one_time_key {
        let account_rc = account_get(txn, acache, as_address)?;

        let mut account = account_rc.as_ref().borrow_mut();
        let session = account.create_outbound_session(with_address.clone(), one_time_key)?;
        drop(account);

        account_update(txn, &account_rc)?;
        session_create(txn, scache, &Rc::new(RefCell::new(session)))?;
    }

    // if this is an address we will send messages to directly, then create a
    // metrics entry for it to track send sequence
    if via_address.unwrap_or(with_address) == with_address {
        metrics_create(txn, as_address, with_address)?;
    }

    Ok(())
}

fn inbox_queue(
    txn: &mut Transaction,
    sender: &Address,
    recipient: &Address,
    subscriber: Option<Address>,
    sequence: u64,
    plaintext: &[u8],
) -> Result<(), SelfError> {
    let via_address = if subscriber.is_some() {
        recipient
    } else {
        sender
    };

    txn.execute(
        "INSERT INTO inbox (connection, sequence, message)
        VALUES (
            (
                SELECT connections.id FROM connections
                JOIN addresses i1 ON
                    i1.id = connections.as_address
                JOIN addresses i2 ON
                    i2.id = connections.with_address
                JOIN addresses i3 ON
                    i3.id = connections.via_address
                WHERE i1.address = ?1 AND i2.address = ?2 AND i3.address = ?3
            ),
            ?4,
            ?5
        );",
        (
            &subscriber.as_ref().unwrap_or(recipient).to_vec(),
            &sender.to_vec(),
            via_address.to_vec(),
            sequence,
            plaintext,
        ),
    )
    .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

    Ok(())
}

fn outbox_queue(
    txn: &mut Transaction,
    sender: &Address,
    recipient: &Address,
    sequence: u64,
    ciphertext: &[u8],
) -> Result<(), SelfError> {
    txn.execute(
        "INSERT INTO outbox (connection, sequence, message)
        VALUES (
            (
                SELECT connections.id FROM connections
                JOIN addresses i1 ON
                    i1.id = connections.as_address
                JOIN addresses i2 ON
                    i2.id = connections.via_address
                WHERE i1.address = ?1 AND i2.address = ?2
            ),
            ?3,
            ?4
        );",
        (&sender.to_vec(), &recipient.to_vec(), sequence, ciphertext),
    )
    .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

    Ok(())
}

fn encrypt_for(
    txn: &mut Transaction,
    gcache: &mut HashMap<Address, Rc<RefCell<Group>>>,
    kcache: &mut HashMap<Address, Arc<KeyPair>>,
    scache: &mut HashMap<(Address, Address), Rc<RefCell<Session>>>,
    recipient: &Address,
    plaintext: &[u8],
) -> Result<(Address, u64, Vec<u8>), SelfError> {
    // search cache for group
    let group = match group_get(txn, gcache, kcache, scache, recipient)? {
        Some(group) => group,
        None => return Err(SelfError::MessagingDestinationUnknown),
    };

    let mut group = group.as_ref().borrow_mut();

    // encrypt the group message
    let ciphertext = group.encrypt(plaintext)?;

    // update each session in the group
    for session in group.participants() {
        session_update(txn, session)?;
    }

    // update connection transmit sequence
    metrics_update_sequence(txn, &group.to_vec(), recipient, group.sequence())?;

    Ok((group.as_address(), group.sequence(), ciphertext))
}

fn decrypt_from(
    txn: &mut Transaction,
    acache: &mut HashMap<Identifier, Rc<RefCell<Account>>>,
    scache: &mut HashMap<(Identifier, Identifier), Rc<RefCell<Session>>>,
    sender: &Identifier,
    recipient: &Identifier,
    subscriber: Option<Identifier>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, SelfError> {
    let mut group_message = GroupMessage::decode(ciphertext)?;

    let via_address = subscriber.clone().and(Some(recipient));
    let as_address = subscriber.unwrap_or(recipient.clone());
    let session_address = (as_address.clone(), sender.clone());

    let session = match scache.get(&session_address) {
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
                    let account_rc = account_get(txn, acache, recipient)?;
                    let mut account = account_rc.as_ref().borrow_mut();

                    let new_session =
                        account.create_inbound_session(sender.clone(), &one_time_message)?;

                    // remove the one time keys used to create the session and update the account
                    account.remove_one_time_keys(&new_session)?;
                    drop(account);

                    account_update(txn, &account_rc)?;

                    session.replace(new_session);
                }
            }

            session.clone()
        }
        None => {
            // attempt load the session from the database
            match session_get(txn, scache, &session_address)? {
                Some(session) => session,
                None => {
                    // the senders session is in the cache! check if this is a one time key message
                    match group_message.one_time_key_message(recipient) {
                        Some(one_time_message) => {
                            // this is a new inbound session, so lets create a new inbound session and
                            // update the existing one
                            let account_rc = account_get(txn, acache, recipient)?;
                            let mut account = account_rc.as_ref().borrow_mut();

                            let inbound_session = account
                                .create_inbound_session(sender.clone(), &one_time_message)?;

                            // remove the one time keys used to create the session and update the account
                            account.remove_one_time_keys(&inbound_session)?;
                            drop(account);

                            account_update(txn, &account_rc)?;

                            let session = Rc::new(RefCell::new(inbound_session));

                            session_create(txn, scache, &session)?;

                            // create a connection for the new sender (not implicitly accepted...)
                            connection_add(
                                txn,
                                acache,
                                scache,
                                &as_address,
                                sender,
                                via_address,
                                None,
                            )?;

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

    if plaintext.is_ok() {
        // only update the session if decryption was successful
        session_update(txn, &session)?;
    }

    plaintext
}

fn group_get(
    txn: &mut Transaction,
    gcache: &mut HashMap<Identifier, Rc<RefCell<Group>>>,
    kcache: &mut HashMap<Identifier, Arc<KeyPair>>,
    scache: &mut HashMap<(Identifier, Identifier), Rc<RefCell<Session>>>,
    group_address: &Identifier,
) -> Result<Option<Rc<RefCell<Group>>>, SelfError> {
    // check the cache first to determine if there is an existing group that can be reused to send messages
    if let Some(group) = gcache.get(group_address) {
        return Ok(Some(group.clone()));
    };

    let sessions = group_get_session(txn, scache, group_address)?;

    if let Some(session) = sessions.first() {
        // get the latest sequence number for sending messages to the group
        let sequence = metrics_get_sequence(
            txn,
            session.as_ref().borrow().as_address(),
            session.as_ref().borrow().with_address(),
        )?;

        let session_address = session.as_ref().borrow().as_address().clone();

        let as_address = match session_address {
            Identifier::Owned(_) => session_address,
            Identifier::Referenced(_) => Identifier::Owned(
                keypair_get(txn, kcache, &session_address)?
                    .as_ref()
                    .clone(),
            ),
        };

        let mut group = Group::new(as_address, sequence);

        for s in &sessions {
            group.add_participant(s.clone());
        }

        let group = Rc::new(RefCell::new(group));

        gcache.insert(group_address.clone(), group.clone());

        return Ok(Some(group));
    }

    Ok(None)
}

fn group_get_session(
    txn: &mut Transaction,
    scache: &mut HashMap<(Identifier, Identifier), Rc<RefCell<Session>>>,
    group_address: &Identifier,
) -> Result<Vec<Rc<RefCell<Session>>>, SelfError> {
    let mut sessions = Vec::new();

    // query all connections for the destination that matches the 'via' address
    // and join all matching sessions
    let mut statement = txn
        .prepare(
            "SELECT i2.address, i3.address, s1.sequence_tx, s1.sequence_rx, s1.olm_session FROM connections
            JOIN addresses i1 ON
                i1.id = connections.via_address
            JOIN addresses i2 ON
                i2.id = connections.as_address
            JOIN addresses i3 ON
                i3.id = connections.with_address
            JOIN sessions s1 ON
                i2.id = s1.as_address AND i3.id = s1.with_address
            WHERE i1.address = ?1;",
        )
        .expect("failed to prepare statement");

    let mut rows = match statement.query([&group_address.id()]) {
        Ok(rows) => rows,
        Err(_) => return Err(SelfError::MessagingDestinationUnknown),
    };

    // loop over all connections and build list of sessions that comprise the group
    while let Some(row) = rows
        .next()
        .map_err(|_| SelfError::MessagingDestinationUnknown)?
    {
        let as_address: Vec<u8> = row.get(0).unwrap();
        let with_address: Vec<u8> = row.get(1).unwrap();
        let sequence_tx: u64 = row.get(2).unwrap();
        let sequence_rx: u64 = row.get(3).unwrap();
        let mut olm_session: Vec<u8> = row.get(4).unwrap();

        let as_address = Identifier::Referenced(PublicKey::from_bytes(
            &as_address,
            crate::keypair::Algorithm::Ed25519,
        )?);

        let with_address = Identifier::Referenced(PublicKey::from_bytes(
            &with_address,
            crate::keypair::Algorithm::Ed25519,
        )?);

        let session_address = (as_address.clone(), with_address.clone());

        // check to see if we have an existing session in our cache that we can use directly
        let session = scache.get(&session_address);

        let session = match session {
            Some(session) => session.clone(),
            None => {
                // if there is no session in the cache, use the session from the query and add it to the cache
                let s = Rc::new(RefCell::new(Session::from_pickle(
                    as_address.clone(),
                    with_address.clone(),
                    sequence_tx,
                    sequence_rx,
                    &mut olm_session,
                    None,
                )?));

                scache.insert(session_address, s.clone());

                s
            }
        };

        sessions.push(session)
    }

    Ok(sessions)
}

fn account_get(
    txn: &mut Transaction,
    acache: &mut HashMap<Identifier, Rc<RefCell<Account>>>,
    account_address: &Identifier,
) -> Result<Rc<RefCell<Account>>, SelfError> {
    if let Some(account) = acache.get(account_address) {
        return Ok(account.clone());
    };

    let mut statement = txn
        .prepare(
            "SELECT olm_account from keypairs
            JOIN addresses i1 ON
                i1.id = keypairs.for_address
            WHERE i1.address = ?1;",
        )
        .expect("failed to prepare statement");

    let mut rows = match statement.query([&account_address.id()]) {
        Ok(rows) => rows,
        Err(_) => return Err(SelfError::MessagingDestinationUnknown),
    };

    if let Some(row) = rows
        .next()
        .map_err(|_err| SelfError::StorageTransactionCommitFailed)?
    {
        let mut encoded_account: Vec<u8> = row.get(0).unwrap();

        let account = Rc::new(RefCell::new(Account::from_pickle(
            account_address.clone(),
            &mut encoded_account,
            None,
        )?));

        acache.insert(account_address.clone(), account.clone());

        return Ok(account);
    }

    Err(SelfError::MessagingDestinationUnknown)
}

fn account_update(txn: &mut Transaction, account: &Rc<RefCell<Account>>) -> Result<(), SelfError> {
    let account = account.as_ref().borrow();
    let encoded_account = account.pickle(None)?;

    txn.execute(
        "UPDATE keypairs
        SET olm_account = ?2
        WHERE for_address = (SELECT id FROM addresses WHERE address=?1);",
        (&account.address().id(), &encoded_account),
    )
    .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

    Ok(())
}

fn keypair_get(
    txn: &mut Transaction,
    kcache: &mut HashMap<Identifier, Arc<KeyPair>>,
    address: &Identifier,
) -> Result<Arc<KeyPair>, SelfError> {
    // check if the key exists in the cache
    if let Some(kp) = kcache.get(address) {
        return Ok(kp.clone());
    };

    let mut statement = txn
        .prepare(
            "SELECT keypair FROM keypairs
            INNER JOIN addresses ON
                keypairs.for_address = addresses.id
            WHERE addresses.address = ?1;",
        )
        .expect("failed to prepare statement");

    let mut rows = match statement.query([&address.id()]) {
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
    let keypair = Arc::new(kp);

    kcache.insert(address.clone(), keypair.clone());

    Ok(keypair)
}

fn session_get(
    txn: &mut Transaction,
    scache: &mut HashMap<(Identifier, Identifier), Rc<RefCell<Session>>>,
    session_address: &(Identifier, Identifier),
) -> Result<Option<Rc<RefCell<Session>>>, SelfError> {
    let mut statement = txn
        .prepare(
            "SELECT s1.sequence_tx, s1.sequence_rx, s1.olm_session FROM connections
            JOIN addresses i1 ON
                i1.id = connections.as_address
            JOIN addresses i2 ON
                i2.id = connections.with_address
            JOIN sessions s1 ON
                i1.id = s1.as_address AND i2.id = s1.with_address
            WHERE i1.address = ?1 AND i2.address = ?2;",
        )
        .expect("failed to prepare statement");

    let mut rows = match statement.query([&session_address.0.id(), &session_address.1.id()]) {
        Ok(rows) => rows,
        Err(_) => return Err(SelfError::MessagingDestinationUnknown),
    };

    if let Ok(Some(row)) = rows.next() {
        let sequence_tx: u64 = row.get(0).unwrap();
        let sequence_rx: u64 = row.get(1).unwrap();
        let mut encoded_session: Vec<u8> = row.get(2).unwrap();

        let session = Rc::new(RefCell::new(Session::from_pickle(
            session_address.0.clone(),
            session_address.1.clone(),
            sequence_tx,
            sequence_rx,
            &mut encoded_session,
            None,
        )?));

        scache.insert(session_address.clone(), session.clone());

        return Ok(Some(session));
    }

    Ok(None)
}

fn session_create(
    txn: &mut Transaction,
    scache: &mut HashMap<(Identifier, Identifier), Rc<RefCell<Session>>>,
    session: &Rc<RefCell<Session>>,
) -> Result<(), SelfError> {
    let session_ref = session.as_ref().borrow();
    let encoded_session = session_ref.pickle(None)?;
    let session_address = (
        session_ref.as_address().clone(),
        session_ref.with_address().clone(),
    );

    address_create(txn, session_ref.with_address())?;

    txn.execute(
        "INSERT INTO sessions (as_address, with_address, sequence_tx, sequence_rx, olm_session)
        VALUES (
            (SELECT id FROM addresses WHERE address=?1),
            (SELECT id FROM addresses WHERE address=?2),
            ?3,
            ?4,
            ?5
        );",
        (
            &session_ref.as_address().id(),
            &session_ref.with_address().id(),
            session_ref.sequence_tx(),
            session_ref.sequence_rx(),
            encoded_session,
        ),
    ).map_err(|_| SelfError::StorageTransactionCommitFailed)?;

    scache.insert(session_address, session.clone());

    Ok(())
}

fn session_update(txn: &mut Transaction, session: &Rc<RefCell<Session>>) -> Result<(), SelfError> {
    let session = session.as_ref().borrow();
    let encoded_session = session.pickle(None)?;

    txn.execute(
        "UPDATE sessions
        SET sequence_tx = ?3, sequence_rx = ?4, olm_session = ?5
        WHERE as_address = (SELECT id FROM addresses WHERE address=?1)
        AND with_address = (SELECT id FROM addresses WHERE address=?2);",
        (
            &session.as_address().id(),
            &session.with_address().id(),
            session.sequence_tx(),
            session.sequence_rx(),
            encoded_session,
        ),
    )
    .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

    Ok(())
}

fn metrics_create(
    txn: &mut Transaction,
    as_address: &Identifier,
    with_address: &Identifier,
) -> Result<(), SelfError> {
    txn.execute(
        "INSERT INTO metrics (as_address, with_address, sequence)
            VALUES(
                (SELECT id FROM addresses WHERE address = ?1),
                (SELECT id FROM addresses WHERE address = ?2),
                0
            );",
        (&as_address.id(), &with_address.id()),
    )
    .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

    Ok(())
}

fn metrics_get_sequence(
    txn: &mut Transaction,
    as_address: &Identifier,
    with_address: &Identifier,
) -> Result<u64, SelfError> {
    // get the metrcis (transmission sequence) for the recipient group
    let mut statement = txn
        .prepare(
            "SELECT sequence FROM metrics
            JOIN addresses i1 ON
                i1.id = metrics.as_address
            JOIN addresses i2 ON
                i2.id = metrics.with_address
            WHERE i1.address = ?1 AND i2.address = ?2;",
        )
        .expect("failed to prepare statement");

    let mut rows = match statement.query([&as_address.id(), &with_address.id()]) {
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
    txn: &mut Transaction,
    as_address: &Identifier,
    with_address: &Identifier,
    sequence: u64,
) -> Result<(), SelfError> {
    txn.execute(
        "UPDATE metrics
        SET sequence = ?3
        WHERE as_address = (SELECT id FROM addresses WHERE address=?1)
        AND with_address = (SELECT id FROM addresses WHERE address=?2);",
        (&as_address.id(), &with_address.id(), sequence),
    )
    .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction() {
        let mut storage =
            super::Storage::new("/tmp/test.db", b"12345").expect("failed to create transaction");

        let (alice_id, bob_id) = (0, 1);

        // create an address for alice and bob
        storage
            .transaction(|txn| {
                txn.execute(
                    "INSERT INTO addresses (address) VALUES (?1), (?2)",
                    (b"alice", b"bob"),
                )
                .is_ok()
            })
            .expect("failed to create transaction");

        // create a session
        storage
            .transaction(|txn| {
                txn.execute(
                    "INSERT INTO sessions (as_address, with_address, sequence_tx, sequence_rx, olm_session) VALUES (?1, ?2, 0, 0, ?3)",
                    (alice_id, bob_id, b"session-with-bob"),
                ).is_ok()
            })
            .expect("failed to create transaction");

        // load a session
        storage
            .transaction(|txn| {
                let mut statement = txn
                    .prepare("SELECT with_address, olm_session FROM sessions WHERE with_address = ?1")
                    .expect("failed to prepare statement");

                let mut rows = statement.query([bob_id]).expect("failed to execute query");
                let row = rows.next().expect("no rows found").unwrap();

                let address: i32 = row.get(0).unwrap();
                let session: Vec<u8> = row.get(1).unwrap();

                assert_eq!(address, bob_id);
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
        let alice_ekp = alice_skp.to_exchange_key().expect("conversion failed");
        let alice_ed25519_pk = alice_skp.public();
        let alice_acc = Account::new(alice_skp.clone(), alice_ekp);

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ed25519_pk = bob_skp.public();

        let carol_skp = crate::keypair::signing::KeyPair::new();
        let carol_ed25519_pk = carol_skp.public();

        let group_skp = crate::keypair::signing::KeyPair::new();
        let group_ed25519_pk = group_skp.public();

        let alice_address = Identifier::Referenced(alice_ed25519_pk);
        let bob_address = Identifier::Referenced(bob_ed25519_pk);
        let carol_address = Identifier::Referenced(carol_ed25519_pk);
        let group_address = Identifier::Referenced(group_ed25519_pk);

        storage
            .keypair_create(Usage::Messaging, &alice_skp, Some(alice_acc), true)
            .expect("failed to create bob keypair");

        // create a connection for the group
        storage
            .connection_add(&alice_address, &group_address, None, None)
            .expect("failed to create alices connection with group");

        // create connections with members of the group
        storage
            .connection_add(
                &alice_address,
                &bob_address,
                Some(&group_address),
                None,
            )
            .expect("failed to create alices group connection with bob");

        storage
            .connection_add(
                &alice_address,
                &carol_address,
                Some(&group_address),
                None,
            )
            .expect("failed to create alices group connection with carol");

        storage
            .transaction(|txn| {
                // queue a message intended for the group
                outbox_queue(
                    txn,
                    &alice_address,
                    &group_address,
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

        let (as_address, via_address, sequence, message) =
            next_item.expect("next item isn't a tuple?");
        assert!(alice_address.eq(&as_address));
        assert!(group_address.eq(&via_address));
        assert_eq!(sequence, 0);
        assert_eq!(message, b"hello everyone");

        // we have not dequeued the item yet, so it should return the same item again
        let next_item = storage
            .outbox_next()
            .expect("failed to get next outbox item");

        assert!(next_item.is_some());

        let (as_address, via_address, sequence, message) =
            next_item.expect("next item isn't a tuple?");
        assert!(alice_address.eq(&as_address));
        assert!(group_address.eq(&via_address));
        assert_eq!(sequence, 0);
        assert_eq!(message, b"hello everyone");

        // dequeue the item
        storage
            .outbox_dequeue(&alice_address, &group_address, sequence)
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
        let alice_ekp = alice_skp.to_exchange_key().expect("conversion failed");
        let alice_ed25519_pk = alice_skp.public();
        let alice_acc = Account::new(alice_skp.clone(), alice_ekp);

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ed25519_pk = bob_skp.public();

        let carol_skp = crate::keypair::signing::KeyPair::new();
        let carol_ed25519_pk = carol_skp.public();

        let group_skp = crate::keypair::signing::KeyPair::new();
        let group_ed25519_pk = group_skp.public();

        let alice_address = Identifier::Referenced(alice_ed25519_pk);
        let bob_address = Identifier::Referenced(bob_ed25519_pk);
        let carol_address = Identifier::Referenced(carol_ed25519_pk);
        let group_address = Identifier::Referenced(group_ed25519_pk);

        // create alices keypair
        storage
            .keypair_create(Usage::Messaging, &alice_skp, Some(alice_acc), true)
            .expect("failed to create bob keypair");

        // create a connection for the group
        storage
            .connection_add(&alice_address, &group_address, None, None)
            .expect("failed to create alices connection with group");

        // create connections with members of the group
        storage
            .connection_add(
                &alice_address,
                &bob_address,
                Some(&group_address),
                None,
            )
            .expect("failed to create alices group connection with bob");

        storage
            .connection_add(
                &alice_address,
                &carol_address,
                Some(&group_address),
                None,
            )
            .expect("failed to create alices group connection with carol");

        // queue a message intended for the group
        storage
            .transaction(|txn| {
                inbox_queue(
                    txn,
                    &bob_address,
                    &group_address,
                    Some(alice_address.clone()),
                    0,
                    b"hello everyone",
                )
                .expect("failed to queue inbox message");
                true
            })
            .expect("failed to queue inbox");

        let next_item = storage.inbox_next().expect("failed to get next inbox item");

        assert!(next_item.is_some());

        let (as_address, with_address, via_address, sequence, message) =
            next_item.expect("next item isn't a tuple?");
        assert!(alice_address.eq(&as_address));
        assert!(bob_address.eq(&with_address));
        assert!(group_address.eq(&via_address));
        assert_eq!(sequence, 0);
        assert_eq!(message, b"hello everyone");

        // we have not dequeued the item yet, so it should return the same item again
        let next_item = storage.inbox_next().expect("failed to get next inbox item");

        assert!(next_item.is_some());

        let (as_address, with_address, via_address, sequence, message) =
            next_item.expect("next item isn't a tuple?");
        assert!(alice_address.eq(&as_address));
        assert!(bob_address.eq(&with_address));
        assert!(group_address.eq(&via_address));
        assert_eq!(sequence, 0);
        assert_eq!(message, b"hello everyone");

        // dequeue the item
        storage
            .inbox_dequeue(
                &bob_address,
                &group_address,
                Some(alice_address),
                sequence,
            )
            .expect("dequeue failed");

        // there should be no items left in the queue
        let next_item = storage.inbox_next().expect("failed to get next inbox item");

        assert!(next_item.is_none());
    }

    #[test]
    fn encrypt_and_queue() {
        let mut storage = super::Storage::new("/tmp/test.db", b"12345").expect("storage failed");

        let alice_skp = crate::keypair::signing::KeyPair::new();
        let alice_ekp = alice_skp.to_exchange_key().expect("conversion failed");
        let alice_ed25519_pk = alice_skp.public();
        let mut alice_acc = crate::crypto::account::Account::new(alice_skp, alice_ekp);

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ekp = bob_skp.to_exchange_key().expect("conversion failed");
        let bob_ed25519_pk = bob_skp.public();
        let bob_acc = crate::crypto::account::Account::new(bob_skp.clone(), bob_ekp);

        let alice_address = Identifier::Referenced(alice_ed25519_pk);
        let bob_address = Identifier::Referenced(bob_ed25519_pk);

        storage
            .keypair_create(Usage::Messaging, &bob_skp, Some(bob_acc), true)
            .expect("failed to create bob keypair");

        alice_acc
            .generate_one_time_keys(10)
            .expect("failed to generate one time keys");

        let alices_one_time_keys = alice_acc.one_time_keys();

        // create bobs connection with alice and create a session from the one time key
        storage
            .connection_add(
                &bob_address,
                &alice_address,
                None,
                Some(&alices_one_time_keys[0]),
            )
            .expect("failed to create bobs connection with alice");

        // encrypt and queue two messages to alice
        let (_, _, bobs_message_to_alice_1) = storage
            .encrypt_and_queue(&alice_address, b"hello alice pt1")
            .expect("failed to encrypt and queue");

        let (_, _, bobs_message_to_alice_2) = storage
            .encrypt_and_queue(&alice_address, b"hello alice pt2")
            .expect("failed to encrypt and queue");

        // create alices session with bob from bobs first message
        let gm = crate::crypto::omemo::GroupMessage::decode(&bobs_message_to_alice_1)
            .expect("failed to decode group message");

        let one_time_message = gm
            .one_time_key_message(&alice_address)
            .expect("one time key message missing");

        let alices_session_with_bob = alice_acc
            .create_inbound_session(bob_address.clone(), &one_time_message)
            .expect("failed to create inbound session");

        // remove the one time key from alices account
        alice_acc
            .remove_one_time_keys(&alices_session_with_bob)
            .expect("failed to remove session");

        // create alices group with bob
        let mut group = Group::new(alice_address.clone(), 0);
        group.add_participant(Rc::new(RefCell::new(alices_session_with_bob)));

        // decrypt the first message from bob
        let plaintext = group
            .decrypt(&bob_address, &bobs_message_to_alice_1)
            .expect("failed to decrypt bobs message");

        assert_eq!(&plaintext, "hello alice pt1".as_bytes());

        // decrypt the second message from bob
        let plaintext = group
            .decrypt(&bob_address, &bobs_message_to_alice_2)
            .expect("failed to decrypt bobs message");

        assert_eq!(&plaintext, "hello alice pt2".as_bytes());
    }

    #[test]
    fn decrypt_and_queue() {
        let mut storage = super::Storage::new("/tmp/test.db", b"12345").expect("storage failed");

        let alice_skp = crate::keypair::signing::KeyPair::new();
        let alice_ekp = alice_skp.to_exchange_key().expect("conversion failed");
        let alice_ed25519_pk = alice_skp.public();
        let mut alice_acc = crate::crypto::account::Account::new(alice_skp, alice_ekp);

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ekp = bob_skp.to_exchange_key().expect("conversion failed");
        let bob_ed25519_pk = bob_skp.public();
        let bob_acc = crate::crypto::account::Account::new(bob_skp.clone(), bob_ekp);

        let alice_address = Identifier::Referenced(alice_ed25519_pk);
        let bob_address = Identifier::Referenced(bob_ed25519_pk);

        storage
            .keypair_create(Usage::Messaging, &bob_skp, Some(bob_acc), true)
            .expect("failed to create alice address");

        alice_acc
            .generate_one_time_keys(10)
            .expect("failed to generate one time keys");

        let alices_one_time_keys = alice_acc.one_time_keys();

        // create bobs connection with alice and create a session from the one time key
        storage
            .connection_add(
                &bob_address,
                &alice_address,
                None,
                Some(&alices_one_time_keys[0]),
            )
            .expect("failed to create bobs connection with alice");

        // encrypt and queue two messages to alice
        let (_, _, bobs_message_to_alice_1) = storage
            .encrypt_and_queue(&alice_address, b"hello alice pt1")
            .expect("failed to encrypt and queue");

        // create alices session with bob from bobs first message
        let gm = crate::crypto::omemo::GroupMessage::decode(&bobs_message_to_alice_1)
            .expect("failed to decode group message");

        let one_time_message = gm
            .one_time_key_message(&alice_address)
            .expect("one time key message missing");

        let alices_session_with_bob = alice_acc
            .create_inbound_session(bob_address.clone(), &one_time_message)
            .expect("failed to create inbound session");

        // remove the one time key from alices account
        alice_acc
            .remove_one_time_keys(&alices_session_with_bob)
            .expect("failed to remove session");

        // create alices group with bob
        let mut group = Group::new(alice_address.clone(), 0);
        group.add_participant(Rc::new(RefCell::new(alices_session_with_bob)));

        // decrypt the first message from bob
        let plaintext = group
            .decrypt(&bob_address, &bobs_message_to_alice_1)
            .expect("failed to decrypt bobs message");

        assert_eq!(&plaintext, "hello alice pt1".as_bytes());

        // encrypt a message for bob
        let alices_message_for_bob = group
            .encrypt(b"hello bob")
            .expect("failed to encrypt message for bob");

        // decrypt message for bob
        let plaintext = storage
            .decrypt_and_queue(
                &alice_address,
                &bob_address,
                None,
                1,
                &alices_message_for_bob,
            )
            .expect("failed to decrypt message from alice");
        assert_eq!(plaintext, b"hello bob");
    }

    #[test]
    fn receive_message_from_new_address() {}

    #[test]
    fn receive_message_from_existing_address() {}

    #[test]
    fn receive_group_message_from_address() {}
}
