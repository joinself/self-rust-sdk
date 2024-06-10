use crate::error::SelfError;
use crate::storage::Transaction;

pub trait KeyPair {
    fn address(&self) -> &[u8];
    fn encode(&self) -> Vec<u8>;
    fn decode(d: &[u8]) -> Self;
}

#[repr(u8)]
pub enum Event {
    Commit,
    KeyPackage,
    Message,
    Proposal,
    Welcome,
    Invalid,
}

impl Event {
    fn to_u8(&self) -> u8 {
        match self {
            Event::Commit => 0,
            Event::KeyPackage => 1,
            Event::Message => 2,
            Event::Proposal => 3,
            Event::Welcome => 4,
            Event::Invalid => 255,
        }
    }

    fn from_u8(event: u8) -> Event {
        match event {
            0 => Event::Commit,
            1 => Event::KeyPackage,
            2 => Event::Message,
            3 => Event::Proposal,
            4 => Event::Welcome,
            _ => Event::Invalid,
        }
    }
}

#[repr(u8)]
pub enum Token {
    Authentication,
    Send,
    Push,
    Subscription,
    Delegation,
    Invalid,
}

impl Token {
    fn to_u8(&self) -> u8 {
        match self {
            Token::Authentication => 0,
            Token::Send => 1,
            Token::Push => 2,
            Token::Subscription => 3,
            Token::Delegation => 4,
            Token::Invalid => 255,
        }
    }

    #[allow(dead_code)]
    fn from_u8(event: u8) -> Token {
        match event {
            0 => Token::Authentication,
            1 => Token::Send,
            2 => Token::Push,
            3 => Token::Subscription,
            4 => Token::Delegation,
            _ => Token::Invalid,
        }
    }
}

pub struct QueuedMessage {
    pub event: Event,
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
    pub message: Vec<u8>,
    pub sequence: u64,
}

pub fn address_create(txn: &Transaction, address: &[u8]) -> Result<(), SelfError> {
    txn.prepare("INSERT OR IGNORE INTO addresses (address) VALUES (?1)")?
        .bind_blob(1, address)?
        .execute()
}

pub fn credential_type_create(txn: &Transaction, credential_type: &[u8]) -> Result<(), SelfError> {
    txn.prepare("INSERT OR IGNORE INTO credential_types (type) VALUES (?1)")?
        .bind_blob(1, credential_type)?
        .execute()
}

pub fn credential_store(
    txn: &Transaction,
    issuer_address: &[u8],
    bearer_address: &[u8],
    credential_type: &[u8],
    credential: &[u8],
) -> Result<(), SelfError> {
    credential_type_create(txn, credential_type)?;

    txn.prepare(
        "INSERT INTO credentials (issuer_address, bearer_address, credential_type, credential)
        VALUES (
            (SELECT id FROM addresses WHERE address=?1),
            (SELECT id FROM addresses WHERE address=?2),
            (SELECT id FROM credential_types WHERE type=?3),
            ?4
        );",
    )?
    .bind_blob(1, issuer_address)?
    .bind_blob(2, bearer_address)?
    .bind_blob(3, credential_type)?
    .bind_blob(4, credential)?
    .execute()
}

pub fn credential_lookup_by_bearer(
    txn: &Transaction,
    bearer_address: &[u8],
) -> Result<Vec<Vec<u8>>, SelfError> {
    let stmt = txn.prepare(
        "SELECT credential FROM credentials
        INNER JOIN addresses a1 ON
            credentials.issuer_address = a1.id
        INNER JOIN addresses a2 ON
            credentials.bearer_address = a2.id
        INNER JOIN credential_types c1 ON
            credentials.credential_type = c1.id
        WHERE a2.address = ?1;",
    )?;

    stmt.bind_blob(1, bearer_address)?;

    let mut credentials = Vec::new();

    while stmt.step()? {
        if let Some(credential) = stmt.column_blob(0)? {
            credentials.push(credential);
        }
    }

    Ok(credentials)
}

pub fn credential_lookup_by_issuer(
    txn: &Transaction,
    issuer_address: &[u8],
) -> Result<Vec<Vec<u8>>, SelfError> {
    let stmt = txn.prepare(
        "SELECT credential FROM credentials
        INNER JOIN addresses a1 ON
            credentials.issuer_address = a1.id
        INNER JOIN addresses a2 ON
            credentials.bearer_address = a2.id
        INNER JOIN credential_types c1 ON
            credentials.credential_type = c1.id
        WHERE a1.address = ?1;",
    )?;

    stmt.bind_blob(1, issuer_address)?;

    let mut credentials = Vec::new();

    while stmt.step()? {
        if let Some(credential) = stmt.column_blob(0)? {
            credentials.push(credential);
        }
    }

    Ok(credentials)
}

pub fn credential_lookup_by_credential_type(
    txn: &Transaction,
    credential_type: &[u8],
) -> Result<Vec<Vec<u8>>, SelfError> {
    let stmt = txn.prepare(
        "SELECT credential FROM credentials
        INNER JOIN addresses a1 ON
            credentials.issuer_address = a1.id
        INNER JOIN addresses a2 ON
            credentials.bearer_address = a2.id
        INNER JOIN credential_types c1 ON
            credentials.credential_type = c1.id
        WHERE c1.type = ?1;",
    )?;

    stmt.bind_blob(1, credential_type)?;

    let mut credentials = Vec::new();

    while stmt.step()? {
        if let Some(credential) = stmt.column_blob(0)? {
            credentials.push(credential);
        }
    }

    Ok(credentials)
}

pub fn identity_create(
    txn: &Transaction,
    address: &[u8],
    status: u8,
    discovered_at: i64,
) -> Result<(), SelfError> {
    address_create(txn, address)?;

    txn.prepare(
        "INSERT INTO identities (address, status, discovered_at, synced_at)
        VALUES (
            (SELECT id FROM addresses WHERE address=?1),
            ?2,
            ?3,
            ?4
        );",
    )?
    .bind_blob(1, address)?
    .bind_integer(2, status as i64)?
    .bind_integer(3, discovered_at)?
    .bind_integer(4, discovered_at)?
    .execute()
}

pub fn identity_synced_at(txn: &Transaction, address: &[u8]) -> Result<Option<i64>, SelfError> {
    let stmt = txn.prepare(
        "SELECT synced_at FROM identities
        INNER JOIN addresses ON
            identities.address = addresses.id
        WHERE addresses.address = ?1;",
    )?;

    stmt.bind_blob(1, address)?;

    if !stmt.step()? {
        return Ok(None);
    }

    stmt.column_integer(0)
}

pub fn identity_status(txn: &Transaction, address: &[u8]) -> Result<Option<i64>, SelfError> {
    let stmt = txn.prepare(
        "SELECT status FROM identities
        INNER JOIN addresses ON
            identities.address = addresses.id
        WHERE addresses.address = ?1;",
    )?;

    stmt.bind_blob(1, address)?;

    if !stmt.step()? {
        return Ok(None);
    }

    stmt.column_integer(0)
}

pub fn identity_sync(txn: &Transaction, address: &[u8], synced_at: i64) -> Result<(), SelfError> {
    txn.prepare(
        "UPDATE identities SET synced_at = ?1
        WHERE address = (SELECT id FROM addresses WHERE address=?2);",
    )?
    .bind_integer(1, synced_at)?
    .bind_blob(2, address)?
    .execute()
}

pub fn identity_operation_create(
    txn: &Transaction,
    address: &[u8],
    sequence: u32,
    operation: &[u8],
) -> Result<(), SelfError> {
    address_create(txn, address)?;

    txn.prepare(
        "INSERT INTO identity_operations (address, sequence, operation)
        VALUES (
            (SELECT id FROM addresses WHERE address=?1),
            ?2,
            ?3
        );",
    )?
    .bind_blob(1, address)?
    .bind_integer(2, sequence as i64)?
    .bind_blob(3, operation)?
    .execute()
}

pub fn identity_operation_log(
    txn: &Transaction,
    address: &[u8],
) -> Result<Vec<Vec<u8>>, SelfError> {
    let stmt = txn.prepare(
        "SELECT operation FROM identity_operations
        INNER JOIN addresses ON
            identity_operations.address = addresses.id
        WHERE addresses.address = ?1
        ORDER BY SEQUENCE ASC;",
    )?;

    stmt.bind_blob(1, address)?;

    let mut logs = Vec::new();

    while stmt.step()? {
        if let Some(log) = stmt.column_blob(0)? {
            logs.push(log);
        }
    }

    Ok(logs)
}

pub fn keypair_create<K>(
    txn: &Transaction,
    keypair: K,
    roles: u64,
    created_at: i64,
) -> Result<(), SelfError>
where
    K: KeyPair,
{
    address_create(txn, keypair.address())?;

    txn.prepare(
        "INSERT INTO keypairs (address, roles, created_at, keypair) 
        VALUES (
            (SELECT id FROM addresses WHERE address=?1),
            ?2,
            ?3,
            ?4
        );",
    )?
    .bind_blob(1, keypair.address())?
    .bind_integer(2, roles as i64)?
    .bind_integer(3, created_at)?
    .bind_blob(4, &keypair.encode())?
    .execute()
}

pub fn keypair_lookup<K>(txn: &Transaction, address: &[u8]) -> Result<Option<K>, SelfError>
where
    K: KeyPair,
{
    let stmt = txn.prepare(
        "SELECT keypair FROM keypairs
        INNER JOIN addresses ON
            keypairs.address = addresses.id
        WHERE addresses.address = ?1;",
    )?;

    stmt.bind_blob(1, address)?;

    if !stmt.step()? {
        return Ok(None);
    }

    stmt.column_blob(0).map(|c| c.map(|k| K::decode(&k)))
}

pub fn keypair_lookup_with<K>(
    txn: &Transaction,
    address: &[u8],
    roles: u64,
) -> Result<Option<K>, SelfError>
where
    K: KeyPair,
{
    let stmt = txn.prepare(
        "SELECT keypair FROM keypairs
        INNER JOIN addresses ON
            keypairs.address = addresses.id
        WHERE addresses.address = ?1 AND keypairs.roles & ?2 = ?2;;",
    )?;

    stmt.bind_blob(1, address)?;
    stmt.bind_integer(2, roles as i64)?;

    if !stmt.step()? {
        return Ok(None);
    }

    stmt.column_blob(0).map(|c| c.map(|k| K::decode(&k)))
}

pub fn keypair_assign(txn: &Transaction, address: &[u8], roles: u64) -> Result<(), SelfError> {
    txn.prepare(
        "UPDATE keypairs SET roles = ?1
        WHERE keypairs.address = (SELECT id FROM addresses WHERE address = ?2);",
    )?
    .bind_integer(1, roles as i64)?
    .bind_blob(2, address)?
    .execute()
}

pub fn keypair_associate(
    txn: &Transaction,
    identity_address: &[u8],
    keypair_address: &[u8],
    sequence: u32,
) -> Result<(), SelfError> {
    txn.prepare(
        "INSERT INTO keypair_associations (identity_address, keypair_address, sequence)
        VALUES(
            (SELECT id FROM addresses WHERE address=?1),
            (SELECT id FROM addresses WHERE address=?2),
            ?3
        );",
    )?
    .bind_blob(1, identity_address)?
    .bind_blob(2, keypair_address)?
    .bind_integer(3, sequence as i64)?
    .execute()
}

pub fn keypair_associated_with<K>(
    txn: &Transaction,
    identity_address: &[u8],
    roles: u64,
) -> Result<Vec<K>, SelfError>
where
    K: KeyPair,
{
    let stmt = txn.prepare(
        "SELECT k1.keypair, k1.roles FROM keypair_associations
        JOIN keypairs k1 ON
            k1.address = keypair_associations.keypair_address
        JOIN identities i1 ON
            i1.address = keypair_associations.identity_address
        JOIN addresses a1 ON
            i1.address = a1.id
        WHERE a1.address = ?1 AND k1.roles & ?2 = ?2;",
    )?;

    stmt.bind_blob(1, identity_address)?;
    stmt.bind_integer(2, roles as i64)?;

    let mut keypairs = Vec::new();

    while stmt.step()? {
        if let Some(keypair) = stmt.column_blob(0).map(|c| c.map(|k| K::decode(&k)))? {
            keypairs.push(keypair);
        }
    }

    Ok(keypairs)
}

pub fn keypair_assigned_to(
    txn: &Transaction,
    keypair_address: &[u8],
) -> Result<Option<Vec<u8>>, SelfError> {
    let stmt = txn.prepare(
        "SELECT a2.address FROM keypair_associations
        JOIN keypairs k1 ON
            k1.address = keypair_associations.keypair_address
        JOIN identities i1 ON
            i1.address = keypair_associations.identity_address
        JOIN addresses a1 ON
            i1.address = a1.id
        JOIN addresses a2 ON
            k1.address = a2.id
        WHERE a1.address = ?1;",
    )?;

    stmt.bind_blob(1, keypair_address)?;

    if !stmt.step()? {
        return Ok(None);
    }

    stmt.column_blob(0)
}

pub fn keypair_identifiers(txn: &Transaction) -> Result<Vec<Vec<u8>>, SelfError> {
    let mut identifiers = Vec::new();

    let stmt = txn.prepare(
        "SELECT DISTINCT a1.address FROM keypair_associations
        JOIN keypairs k1 ON
            k1.address = keypair_associations.keypair_address
        JOIN identities i1 ON
            i1.address = keypair_associations.identity_address
        JOIN addresses a1 ON
            i1.address = a1.id
        JOIN addresses a2 ON
            k1.address = a2.id;",
    )?;

    while stmt.step()? {
        if let Some(identifier) = stmt.column_blob(0)? {
            identifiers.push(identifier);
        }
    }

    Ok(identifiers)
}

pub fn object_create(
    txn: &Transaction,
    hash: &[u8],
    key: &[u8],
    data: &[u8],
) -> Result<(), SelfError> {
    txn.prepare(
        "INSERT OR IGNORE INTO objects (hash, key, data) 
        VALUES (
            ?1,
            ?2,
            ?3
        );",
    )?
    .bind_blob(1, hash)?
    .bind_blob(2, key)?
    .bind_blob(3, data)?
    .execute()
}

#[allow(clippy::type_complexity)]
pub fn object_lookup(
    txn: &Transaction,
    hash: &[u8],
) -> Result<Option<(Vec<u8>, Vec<u8>)>, SelfError> {
    let stmt = txn.prepare(
        "SELECT key, data FROM objects
        WHERE hash = ?1;",
    )?;

    stmt.bind_blob(1, hash)?;

    if !stmt.step()? {
        return Ok(None);
    }

    let key = stmt.column_blob(0)?.expect("key was null");
    let data = stmt.column_blob(1)?.expect("data was null");

    Ok(Some((key, data)))
}

pub fn group_create(
    txn: &Transaction,
    group_address: &[u8],
    purpose: u64,
) -> Result<(), SelfError> {
    address_create(txn, group_address)?;

    txn.prepare(
        "INSERT INTO groups (address, purpose)
        VALUES(
            (SELECT id FROM addresses WHERE address=?1),
            ?2
        );",
    )?
    .bind_blob(1, group_address)?
    .bind_integer(2, purpose as i64)?
    .execute()
}

pub fn group_with(
    txn: &Transaction,
    member_address: &[u8],
    purpose: u64,
) -> Result<Option<Vec<u8>>, SelfError> {
    let stmt = txn.prepare(
        "SELECT a1.address FROM groups
        JOIN members m1 ON
            m1.group_id = groups.id
        JOIN addresses a1 ON
            a1.id = groups.address
        JOIN addresses a2 ON
            a2.id = m1.member_address
        WHERE a2.address = ?1 AND groups.purpose = ?2;",
    )?;

    stmt.bind_blob(1, member_address)?;
    stmt.bind_integer(2, purpose as i64)?;

    if !stmt.step()? {
        return Ok(None);
    }

    stmt.column_blob(0)
}

pub fn group_as(txn: &Transaction, group_address: &[u8]) -> Result<Option<Vec<u8>>, SelfError> {
    // these two queries are suboptimal
    // as we could just return these in one
    // however, this is more composable
    // for other usecases
    let stmt = txn.prepare(
        "SELECT a2.address FROM groups
        JOIN members m1 ON
            m1.group_id = groups.id
        JOIN keypairs k1 ON
            k1.address = a2.id
        JOIN addresses a1 ON
            a1.id = groups.address
        JOIN addresses a2 ON
            a2.id = m1.member_address
        WHERE a1.address = ?1;",
    )?;

    stmt.bind_blob(1, group_address)?;

    if !stmt.step()? {
        return Ok(None);
    }

    stmt.column_blob(0)
}

pub fn group_as_with_purpose(
    txn: &Transaction,
    group_address: &[u8],
    purpose: u64,
) -> Result<Option<Vec<u8>>, SelfError> {
    // these two queries are suboptimal
    // as we could just return these in one
    // however, this is more composable
    // for other usecases
    let stmt = txn.prepare(
        "SELECT a2.address FROM groups
        JOIN members m1 ON
            m1.group_id = groups.id
        JOIN keypairs k1 ON
            k1.address = a2.id
        JOIN addresses a1 ON
            a1.id = groups.address
        JOIN addresses a2 ON
            a2.id = m1.member_address
        WHERE a1.address = ?1 AND groups.purpose = ?2;",
    )?;

    stmt.bind_blob(1, group_address)?;
    stmt.bind_integer(2, purpose as i64)?;

    if !stmt.step()? {
        return Ok(None);
    }

    stmt.column_blob(0)
}

pub fn group_member_add(
    txn: &Transaction,
    group_address: &[u8],
    member_address: &[u8],
) -> Result<(), SelfError> {
    address_create(txn, member_address)?;

    let stmt = txn.prepare(
        "INSERT INTO members (group_id, member_address)
        VALUES(
            (SELECT groups.id FROM groups
                JOIN addresses a1 ON
                    a1.id = groups.address 
                WHERE a1.address=?1),
            (SELECT id FROM addresses WHERE address=?2)
        );",
    )?;

    stmt.bind_blob(1, group_address)?
        .bind_blob(2, member_address)?
        .execute()
}

pub fn token_create(
    txn: &Transaction,
    kind: Token,
    from_address: &[u8],
    to_address: &[u8],
    for_address: &[u8],
    token: &[u8],
) -> Result<(), SelfError> {
    let stmt = txn.prepare(
        "INSERT INTO tokens (from_address, to_address, for_address, kind, token)
        VALUES(
            (SELECT id FROM addresses WHERE address=?1),
            (SELECT id FROM addresses WHERE address=?2),
            (SELECT id FROM addresses WHERE address=?3),
            ?4,
            ?5
        );",
    )?;

    stmt.bind_blob(1, from_address)?;
    stmt.bind_blob(2, to_address)?;
    stmt.bind_blob(3, for_address)?;
    stmt.bind_integer(4, kind.to_u8() as i64)?;
    stmt.bind_blob(5, token)?;

    Ok(())
}

pub fn inbox_queue(
    txn: &Transaction,
    event: Event,
    sender: &[u8],
    recipient: &[u8],
    message: &[u8],
    sequence: u64,
) -> Result<(), SelfError> {
    txn.prepare(
        "INSERT INTO inbox (event, sender, recipient, message, sequence)
        VALUES (
            ?1,
            (SELECT id FROM addresses WHERE address=?2),
            (SELECT id FROM addresses WHERE address=?3),
            ?4,
            ?5
        );",
    )?
    .bind_integer(1, event.to_u8() as i64)?
    .bind_blob(2, sender)?
    .bind_blob(3, recipient)?
    .bind_blob(4, message)?
    .bind_integer(5, sequence as i64)?
    .execute()
}

pub fn inbox_dequeue(
    txn: &Transaction,
    sender: &[u8],
    recipient: &[u8],
    sequence: u64,
) -> Result<(), SelfError> {
    txn.prepare(
        "DELETE FROM inbox WHERE sender = (
            SELECT id FROM addresses WHERE address=?1
        ) AND recipient = (
            SELECT id FROM addresses WHERE address=?2
        ) AND sequence = ?3;",
    )?
    .bind_blob(1, sender)?
    .bind_blob(2, recipient)?
    .bind_integer(3, sequence as i64)?
    .execute()
}

pub fn inbox_next(txn: &Transaction) -> Result<Option<QueuedMessage>, SelfError> {
    let stmt = txn.prepare(
        "SELECT a1.address, a2.address, event, message, sequence FROM inbox
        JOIN addresses a1 ON
            a1.id = inbox.sender
        JOIN addresses a2 ON
            a2.id = inbox.recipient
        ORDER BY inbox.id ASC LIMIT 1;",
    )?;

    if !stmt.step()? {
        return Ok(None);
    }

    let sender = match stmt.column_blob(0)? {
        Some(sender) => sender,
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    let recipient = match stmt.column_blob(1)? {
        Some(recipient) => recipient,
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    let event = match stmt.column_integer(2)? {
        Some(event) => Event::from_u8(event as u8),
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    let message = match stmt.column_blob(3)? {
        Some(message) => message,
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    let sequence = match stmt.column_integer(4)? {
        Some(sequence) => sequence as u64,
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    Ok(Some(QueuedMessage {
        event,
        sender,
        recipient,
        message,
        sequence,
    }))
}

pub fn outbox_queue(
    txn: &Transaction,
    event: Event,
    sender: &[u8],
    recipient: &[u8],
    message: &[u8],
    sequence: u64,
) -> Result<(), SelfError> {
    txn.prepare(
        "INSERT INTO outbox (event, sender, recipient, message, sequence)
        VALUES (
            ?1,
            (SELECT id FROM addresses WHERE address=?2),
            (SELECT id FROM addresses WHERE address=?3),
            ?4,
            ?5
        );",
    )?
    .bind_integer(1, event.to_u8() as i64)?
    .bind_blob(2, sender)?
    .bind_blob(3, recipient)?
    .bind_blob(4, message)?
    .bind_integer(5, sequence as i64)?
    .execute()
}

pub fn outbox_dequeue(
    txn: &Transaction,
    sender: &[u8],
    recipient: &[u8],
    sequence: u64,
) -> Result<(), SelfError> {
    txn.prepare(
        "DELETE FROM outbox WHERE sender = (
            SELECT id FROM addresses WHERE address=?1
        ) AND recipient = (
            SELECT id FROM addresses WHERE address=?2
        ) AND sequence = ?3;",
    )?
    .bind_blob(1, sender)?
    .bind_blob(2, recipient)?
    .bind_integer(3, sequence as i64)?
    .execute()
}

pub fn outbox_next(txn: &Transaction) -> Result<Option<QueuedMessage>, SelfError> {
    let stmt = txn.prepare(
        "SELECT a1.address, a2.address, event, message, sequence FROM outbox
        JOIN addresses a1 ON
            a1.id = outbox.sender
        JOIN addresses a2 ON
            a2.id = outbox.recipient
        ORDER BY outbox.id ASC LIMIT 1;",
    )?;

    if !stmt.step()? {
        return Ok(None);
    }

    let sender = match stmt.column_blob(0)? {
        Some(sender) => sender,
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    let recipient = match stmt.column_blob(1)? {
        Some(recipient) => recipient,
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    let event = match stmt.column_integer(2)? {
        Some(event) => Event::from_u8(event as u8),
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    let message = match stmt.column_blob(3)? {
        Some(message) => message,
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    let sequence = match stmt.column_integer(4)? {
        Some(sequence) => sequence as u64,
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    Ok(Some(QueuedMessage {
        event,
        sender,
        recipient,
        message,
        sequence,
    }))
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::{self, random_id},
        keypair::signing,
        storage::{
            query::{self, Event},
            Connection,
        },
    };

    #[test]
    fn query_identity_create() {
        let connection = Connection::new(":memory:").expect("connection failed");
        let identifier = random_id();

        connection
            .transaction(|txn| query::identity_create(txn, &identifier, 1, 1714500792))
            .expect("transaction failed");
    }

    #[test]
    fn query_identity_synced_at() {
        let connection = Connection::new(":memory:").expect("connection failed");

        let identifier = random_id();

        connection
            .transaction(|txn| query::identity_create(txn, &identifier, 1, 1714500792))
            .expect("transaction failed");

        connection
            .transaction(|txn| {
                let synced_at =
                    query::identity_synced_at(txn, &identifier).expect("failed to get synced at");

                assert_eq!(1714500792, synced_at.expect("synced_at was none!"));

                Ok(())
            })
            .expect("transaction failed");

        connection
            .transaction(|txn| query::identity_sync(txn, &identifier, 1714509999))
            .expect("transaction failed");

        connection
            .transaction(|txn| {
                let synced_at =
                    query::identity_synced_at(txn, &identifier).expect("failed to get synced at");

                assert_eq!(1714509999, synced_at.expect("synced_at was none!"));

                Ok(())
            })
            .expect("transaction failed");
    }

    #[test]
    fn query_identity_operation() {
        let connection = Connection::new(":memory:").expect("connection failed");

        let identifier = random_id();
        let operation0: Vec<u8> = vec![0, 1, 2, 3];
        let operation1: Vec<u8> = vec![4, 5, 6, 7];

        connection
            .transaction(|txn| query::identity_create(txn, &identifier, 1, 1714500792))
            .expect("transaction failed");

        connection
            .transaction(|txn| query::identity_operation_create(txn, &identifier, 0, &operation0))
            .expect("transaction failed");

        connection
            .transaction(|txn| {
                let logs = query::identity_operation_log(txn, &identifier)
                    .expect("failed to get synced at");

                assert_eq!(1, logs.len());
                assert_eq!(operation0, logs[0]);

                Ok(())
            })
            .expect("transaction failed");

        connection
            .transaction(|txn| query::identity_operation_create(txn, &identifier, 1, &operation1))
            .expect("transaction failed");

        connection
            .transaction(|txn| {
                let logs = query::identity_operation_log(txn, &identifier)
                    .expect("failed to get synced at");

                assert_eq!(2, logs.len());
                assert_eq!(operation0, logs[0]);
                assert_eq!(operation1, logs[1]);

                Ok(())
            })
            .expect("transaction failed");
    }

    #[test]
    fn query_credential_store() {
        let connection = Connection::new(":memory:").expect("connection failed");

        let issuer_sk = signing::KeyPair::new();
        let bearer_sk = signing::KeyPair::new();
        let credential_type = b"[VerifiableCredential, PassportCredential]";
        let credential = b"credential";

        connection
            .transaction(|txn| {
                query::address_create(txn, issuer_sk.address())?;
                query::address_create(txn, bearer_sk.address())?;
                query::credential_store(
                    txn,
                    issuer_sk.address(),
                    bearer_sk.address(),
                    credential_type,
                    credential,
                )
            })
            .expect("transaction failed");

        connection
            .transaction(|txn| {
                let credentials = query::credential_lookup_by_bearer(txn, bearer_sk.address())?;
                assert_eq!(credentials.len(), 1);
                assert_eq!(credentials[0], credential);
                Ok(())
            })
            .expect("transaction failed");

        connection
            .transaction(|txn| {
                let credentials = query::credential_lookup_by_issuer(txn, issuer_sk.address())?;
                assert_eq!(credentials.len(), 1);
                assert_eq!(credentials[0], credential);
                Ok(())
            })
            .expect("transaction failed");

        connection
            .transaction(|txn| {
                let credentials =
                    query::credential_lookup_by_credential_type(txn, credential_type)?;
                assert_eq!(credentials.len(), 1);
                assert_eq!(credentials[0], credential);
                Ok(())
            })
            .expect("transaction failed");
    }

    #[test]
    fn query_keypair_association() {
        let connection = Connection::new(":memory:").expect("connection failed");

        let identifier_sk = signing::KeyPair::new();
        let invocation_sk = signing::KeyPair::new();

        connection
            .transaction(|txn| {
                query::identity_create(txn, identifier_sk.address(), 0, crate::time::unix())?;
                query::keypair_create(txn, identifier_sk.clone(), 0, crate::time::unix())?;
                query::keypair_create(txn, invocation_sk.clone(), 0, crate::time::unix())?;
                query::keypair_assign(txn, identifier_sk.address(), 256)?;
                query::keypair_assign(txn, invocation_sk.address(), 16)?;
                query::keypair_associate(txn, identifier_sk.address(), invocation_sk.address(), 0)
            })
            .expect("transaction failed");

        connection
            .transaction(|txn| {
                let keys: Vec<signing::KeyPair> =
                    query::keypair_associated_with(txn, identifier_sk.address(), 32)?;
                assert_eq!(keys.len(), 0);

                let keys: Vec<signing::KeyPair> =
                    query::keypair_associated_with(txn, identifier_sk.address(), 16)?;
                assert_eq!(keys.len(), 1);

                Ok(())
            })
            .expect("transaction failed");
    }

    #[test]
    fn query_inbox_queue() {
        let connection = Connection::new(":memory:").expect("connection failed");

        let sender = random_id();
        let recipient = random_id();

        // queue a message for an unknown sender
        connection
            .transaction(|txn| {
                query::inbox_queue(
                    txn,
                    Event::Message,
                    &sender,
                    &recipient,
                    &crypto::random::vec(256),
                    0,
                )
            })
            .expect_err("transaction succeeded");

        // create the senders address
        connection
            .transaction(|txn| query::address_create(txn, &sender))
            .expect("transaction failed");

        // queue a message for an unknown recipient
        connection
            .transaction(|txn| {
                query::inbox_queue(
                    txn,
                    Event::Message,
                    &sender,
                    &recipient,
                    &crypto::random::vec(256),
                    0,
                )
            })
            .expect_err("transaction succeeded");

        // create the recipients address
        connection
            .transaction(|txn| query::address_create(txn, &recipient))
            .expect("transaction failed");

        // queue a message for an unknown sender
        connection
            .transaction(|txn| {
                query::inbox_queue(
                    txn,
                    Event::Message,
                    &sender,
                    &recipient,
                    &crypto::random::vec(256),
                    0,
                )
            })
            .expect("transaction failed");

        // queue a message with the same sequence
        // which should succeed as we don't enforce
        // uniqueness constraints
        connection
            .transaction(|txn| {
                query::inbox_queue(
                    txn,
                    Event::Message,
                    &sender,
                    &recipient,
                    &crypto::random::vec(256),
                    0,
                )
            })
            .expect("transaction failed");

        // queue multiple in a transaction
        connection
            .transaction(|txn| {
                for i in 2..100 {
                    query::inbox_queue(
                        txn,
                        Event::Message,
                        &sender,
                        &recipient,
                        &crypto::random::vec(256),
                        i,
                    )?
                }

                Ok(())
            })
            .expect("transaction succeeded");
    }

    #[test]
    fn query_inbox_dequeue() {
        let connection = Connection::new(":memory:").expect("connection failed");

        let sender = random_id();
        let recipient = random_id();

        // dequeue a message that does not exist
        connection
            .transaction(|txn| query::inbox_dequeue(txn, &sender, &recipient, 0))
            .expect("transaction failed");

        // create the sender and recipients address and queue a message
        connection
            .transaction(|txn| {
                query::address_create(txn, &sender)?;
                query::address_create(txn, &recipient)?;

                query::inbox_queue(
                    txn,
                    Event::Message,
                    &sender,
                    &recipient,
                    &crypto::random::vec(256),
                    0,
                )
            })
            .expect("transaction failed");

        // dequeue a message that does exist
        connection
            .transaction(|txn| query::inbox_dequeue(txn, &sender, &recipient, 0))
            .expect("transaction failed");
    }

    #[test]
    fn query_inbox_next() {
        let connection = Connection::new(":memory:").expect("connection failed");

        let sender = random_id();
        let recipient = random_id();

        // get the next message on an empty inbox
        connection
            .transaction(|txn| {
                let result = query::inbox_next(txn)?;
                assert!(result.is_none());
                Ok(())
            })
            .expect("transaction failed");

        // create the sender and recipients address and queue a message
        connection
            .transaction(|txn| {
                query::address_create(txn, &sender)?;
                query::address_create(txn, &recipient)?;

                query::inbox_queue(
                    txn,
                    Event::Message,
                    &sender,
                    &recipient,
                    &crypto::random::vec(256),
                    0,
                )
            })
            .expect("transaction failed");

        // get a message that does exist
        connection
            .transaction(|txn| {
                let message = query::inbox_next(txn)?.expect("no message in queue");

                assert_eq!(message.sender, sender);
                assert_eq!(message.recipient, recipient);
                assert_eq!(message.sequence, 0);

                Ok(())
            })
            .expect("transaction failed");

        // get a message that does exist again and dequeue it
        connection
            .transaction(|txn| {
                let message = query::inbox_next(txn)?.expect("no message in queue");

                assert_eq!(message.sender, sender);
                assert_eq!(message.recipient, recipient);
                assert_eq!(message.sequence, 0);

                query::inbox_dequeue(txn, &sender, &recipient, 0)
            })
            .expect("transaction failed");

        // get the next message on an empty inbox
        connection
            .transaction(|txn| {
                let result = query::inbox_next(txn)?;
                assert!(result.is_none());
                Ok(())
            })
            .expect("transaction failed");

        // queue a bunch more messages and dequeue them
        for i in 1..100 {
            let content = crypto::random::vec(256);

            connection
                .transaction(|txn| {
                    query::inbox_queue(txn, Event::Message, &sender, &recipient, &content, i)
                })
                .expect("transaction failed");

            connection
                .transaction(|txn| {
                    let message = query::inbox_next(txn)?.expect("no message in queue");

                    assert_eq!(message.sender, sender);
                    assert_eq!(message.recipient, recipient);
                    assert_eq!(message.message, content);
                    assert_eq!(message.sequence, i);

                    query::inbox_dequeue(txn, &sender, &recipient, i)
                })
                .expect("transaction failed");
        }

        // batch queue a bunch more messages
        connection
            .transaction(|txn| {
                for i in 100..200 {
                    query::inbox_queue(
                        txn,
                        Event::Message,
                        &sender,
                        &recipient,
                        &crypto::random::vec(256),
                        i,
                    )?;
                }
                Ok(())
            })
            .expect("transaction failed");

        // batch dequeue all of the messages
        connection
            .transaction(|txn| {
                for i in 100..200 {
                    let message = query::inbox_next(txn)?.expect("no message in queue");

                    assert_eq!(message.sender, sender);
                    assert_eq!(message.recipient, recipient);
                    assert_eq!(message.sequence, i);

                    query::inbox_dequeue(txn, &sender, &recipient, i)?;
                }

                Ok(())
            })
            .expect("transaction failed");

        // get the next message on an empty inbox
        connection
            .transaction(|txn| {
                let result = query::inbox_next(txn)?;
                assert!(result.is_none());
                Ok(())
            })
            .expect("transaction failed");
    }

    #[test]
    fn query_outbox_queue() {
        let connection = Connection::new(":memory:").expect("connection failed");

        let sender = random_id();
        let recipient = random_id();

        // queue a message for an unknown sender
        connection
            .transaction(|txn| {
                query::outbox_queue(
                    txn,
                    Event::Message,
                    &sender,
                    &recipient,
                    &crypto::random::vec(256),
                    0,
                )
            })
            .expect_err("transaction succeeded");

        // create the senders address
        connection
            .transaction(|txn| query::address_create(txn, &sender))
            .expect("transaction failed");

        // queue a message for an unknown recipient
        connection
            .transaction(|txn| {
                query::outbox_queue(
                    txn,
                    Event::Message,
                    &sender,
                    &recipient,
                    &crypto::random::vec(256),
                    0,
                )
            })
            .expect_err("transaction succeeded");

        // create the recipients address
        connection
            .transaction(|txn| query::address_create(txn, &recipient))
            .expect("transaction failed");

        // queue a message for an unknown sender
        connection
            .transaction(|txn| {
                query::outbox_queue(
                    txn,
                    Event::Message,
                    &sender,
                    &recipient,
                    &crypto::random::vec(256),
                    0,
                )
            })
            .expect("transaction failed");

        // queue a message with the same sequence
        // which should succeed as we don't enforce
        // uniqueness constraints
        connection
            .transaction(|txn| {
                query::outbox_queue(
                    txn,
                    Event::Message,
                    &sender,
                    &recipient,
                    &crypto::random::vec(256),
                    0,
                )
            })
            .expect("transaction failed");

        // queue multiple in a transaction
        connection
            .transaction(|txn| {
                for i in 2..100 {
                    query::outbox_queue(
                        txn,
                        Event::Message,
                        &sender,
                        &recipient,
                        &crypto::random::vec(256),
                        i,
                    )?
                }

                Ok(())
            })
            .expect("transaction succeeded");
    }

    #[test]
    fn query_outbox_dequeue() {
        let connection = Connection::new(":memory:").expect("connection failed");

        let sender = random_id();
        let recipient = random_id();

        // dequeue a message that does not exist
        connection
            .transaction(|txn| query::outbox_dequeue(txn, &sender, &recipient, 0))
            .expect("transaction failed");

        // create the sender and recipients address and queue a message
        connection
            .transaction(|txn| {
                query::address_create(txn, &sender)?;
                query::address_create(txn, &recipient)?;

                query::outbox_queue(
                    txn,
                    Event::Message,
                    &sender,
                    &recipient,
                    &crypto::random::vec(256),
                    0,
                )
            })
            .expect("transaction failed");

        // dequeue a message that does exist
        connection
            .transaction(|txn| query::outbox_dequeue(txn, &sender, &recipient, 0))
            .expect("transaction failed");
    }

    #[test]
    fn query_outbox_next() {
        let connection = Connection::new(":memory:").expect("connection failed");

        let sender = random_id();
        let recipient = random_id();

        // get the next message on an empty outbox
        connection
            .transaction(|txn| {
                let result = query::outbox_next(txn)?;
                assert!(result.is_none());
                Ok(())
            })
            .expect("transaction failed");

        // create the sender and recipients address and queue a message
        connection
            .transaction(|txn| {
                query::address_create(txn, &sender)?;
                query::address_create(txn, &recipient)?;

                query::outbox_queue(
                    txn,
                    Event::Message,
                    &sender,
                    &recipient,
                    &crypto::random::vec(256),
                    0,
                )
            })
            .expect("transaction failed");

        // get a message that does exist
        connection
            .transaction(|txn| {
                let message = query::outbox_next(txn)?.expect("no message in queue");

                assert_eq!(message.sender, sender);
                assert_eq!(message.recipient, recipient);
                assert_eq!(message.sequence, 0);

                Ok(())
            })
            .expect("transaction failed");

        // get a message that does exist again and dequeue it
        connection
            .transaction(|txn| {
                let message = query::outbox_next(txn)?.expect("no message in queue");

                assert_eq!(message.sender, sender);
                assert_eq!(message.recipient, recipient);
                assert_eq!(message.sequence, 0);

                query::outbox_dequeue(txn, &sender, &recipient, 0)
            })
            .expect("transaction failed");

        // get the next message on an empty outbox
        connection
            .transaction(|txn| {
                let result = query::outbox_next(txn)?;
                assert!(result.is_none());
                Ok(())
            })
            .expect("transaction failed");

        // queue a bunch more messages and dequeue them
        for i in 1..100 {
            let content = crypto::random::vec(256);

            connection
                .transaction(|txn| {
                    query::outbox_queue(txn, Event::Message, &sender, &recipient, &content, i)
                })
                .expect("transaction failed");

            connection
                .transaction(|txn| {
                    let message = query::outbox_next(txn)?.expect("no message in queue");

                    assert_eq!(message.sender, sender);
                    assert_eq!(message.recipient, recipient);
                    assert_eq!(message.message, content);
                    assert_eq!(message.sequence, i);

                    query::outbox_dequeue(txn, &sender, &recipient, i)
                })
                .expect("transaction failed");
        }

        // batch queue a bunch more messages
        connection
            .transaction(|txn| {
                for i in 100..200 {
                    query::outbox_queue(
                        txn,
                        Event::Message,
                        &sender,
                        &recipient,
                        &crypto::random::vec(256),
                        i,
                    )?;
                }
                Ok(())
            })
            .expect("transaction failed");

        // batch dequeue all of the messages
        connection
            .transaction(|txn| {
                for i in 100..200 {
                    let message = query::outbox_next(txn)?.expect("no message in queue");

                    assert_eq!(message.sender, sender);
                    assert_eq!(message.recipient, recipient);
                    assert_eq!(message.sequence, i);

                    query::outbox_dequeue(txn, &sender, &recipient, i)?;
                }

                Ok(())
            })
            .expect("transaction failed");

        // get the next message on an empty outbox
        connection
            .transaction(|txn| {
                let result = query::outbox_next(txn)?;
                assert!(result.is_none());
                Ok(())
            })
            .expect("transaction failed");
    }

    #[test]
    fn query_object_store() {
        let connection = Connection::new(":memory:").expect("connection failed");

        let hash: &[u8] = &[0; 32];
        let key: &[u8] = &[1; 32];
        let data: &[u8] = &[2; 4096];

        // store an object
        connection
            .transaction(|txn| query::object_create(txn, hash, key, data))
            .expect("transaction failed");

        // retrieve an object
        connection
            .transaction(|txn| {
                let (stored_key, stored_data) = query::object_lookup(txn, hash)
                    .expect("failed to execute transaction")
                    .expect("object not found");

                assert_eq!(stored_key, key);
                assert_eq!(stored_data, data);

                Ok(())
            })
            .expect("transaction failed");
    }
}
