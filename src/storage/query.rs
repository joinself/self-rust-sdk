use crate::account::Message;
use crate::error::SelfError;
use crate::storage::Transaction;

pub trait KeyPair {
    fn address(&self) -> &[u8];
    fn encode(&self) -> Vec<u8>;
    fn decode(d: &[u8]) -> Self;
}
pub struct QueuedMessage {
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
    pub message: Vec<u8>,
    pub sequence: u64,
}

fn address_create(txn: &Transaction, address: &[u8]) -> Result<(), SelfError> {
    txn.prepare("INSERT OR IGNORE INTO addresses (address) VALUES (?1)")?
        .bind_blob(1, address)?
        .execute()
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

pub fn group_as(
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
    from_address: &[u8],
    to_address: &[u8],
    for_address: &[u8],
    kind: u64,
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
    stmt.bind_integer(4, kind as i64)?;
    stmt.bind_blob(5, token)?;

    Ok(())
}

pub fn inbox_queue(
    txn: &Transaction,
    sender: &[u8],
    recipient: &[u8],
    message: &[u8],
    sequence: u64,
) -> Result<(), SelfError> {
    txn.prepare(
        "INSERT INTO inbox (sender, recipient, message, sequence)
        VALUES (
            (SELECT id FROM addresses WHERE address=?1),
            (SELECT id FROM addresses WHERE address=?2),
            ?3,
            ?4
        );",
    )?
    .bind_blob(1, sender)?
    .bind_blob(2, recipient)?
    .bind_blob(3, message)?
    .bind_integer(4, sequence as i64)?
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
        "SELECT a1.address, a2.address, message, sequence FROM inbox
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

    let message = match stmt.column_blob(2)? {
        Some(message) => message,
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    let sequence = match stmt.column_integer(3)? {
        Some(sequence) => sequence as u64,
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    Ok(Some(QueuedMessage {
        sender,
        recipient,
        message,
        sequence,
    }))
}

pub fn outbox_queue(
    txn: &Transaction,
    sender: &[u8],
    recipient: &[u8],
    message: &[u8],
    sequence: u64,
) -> Result<(), SelfError> {
    txn.prepare(
        "INSERT INTO outbox (sender, recipient, message, sequence)
        VALUES (
            (SELECT id FROM addresses WHERE address=?1),
            (SELECT id FROM addresses WHERE address=?2),
            ?3,
            ?4
        );",
    )?
    .bind_blob(1, sender)?
    .bind_blob(2, recipient)?
    .bind_blob(3, message)?
    .bind_integer(4, sequence as i64)?
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
        "SELECT a1.address, a2.address, message, sequence FROM outbox
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

    let message = match stmt.column_blob(2)? {
        Some(message) => message,
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    let sequence = match stmt.column_integer(3)? {
        Some(sequence) => sequence as u64,
        None => return Err(SelfError::StorageColumnTypeMismatch),
    };

    Ok(Some(QueuedMessage {
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
        storage::query,
        storage::Connection,
    };

    #[test]
    fn query_inbox_queue() {
        let connection = Connection::new(":memory:").expect("connection failed");

        let sender = random_id();
        let recipient = random_id();

        // queue a message for an unknown sender
        connection
            .transaction(|txn| {
                query::inbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), 0)
            })
            .expect_err("transaction succeeded");

        // create the senders address
        connection
            .transaction(|txn| query::address_create(txn, &sender))
            .expect("transaction failed");

        // queue a message for an unknown recipient
        connection
            .transaction(|txn| {
                query::inbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), 0)
            })
            .expect_err("transaction succeeded");

        // create the recipients address
        connection
            .transaction(|txn| query::address_create(txn, &recipient))
            .expect("transaction failed");

        // queue a message for an unknown sender
        connection
            .transaction(|txn| {
                query::inbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), 0)
            })
            .expect("transaction failed");

        // queue a message with the same sequence
        // which should succeed as we don't enforce
        // uniqueness constraints
        connection
            .transaction(|txn| {
                query::inbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), 0)
            })
            .expect("transaction failed");

        // queue multiple in a transaction
        connection
            .transaction(|txn| {
                for i in 2..100 {
                    query::inbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), i)?
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

                query::inbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), 0)
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

                query::inbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), 0)
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
                .transaction(|txn| query::inbox_queue(txn, &sender, &recipient, &content, i))
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
                    query::inbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), i)?;
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
                query::outbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), 0)
            })
            .expect_err("transaction succeeded");

        // create the senders address
        connection
            .transaction(|txn| query::address_create(txn, &sender))
            .expect("transaction failed");

        // queue a message for an unknown recipient
        connection
            .transaction(|txn| {
                query::outbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), 0)
            })
            .expect_err("transaction succeeded");

        // create the recipients address
        connection
            .transaction(|txn| query::address_create(txn, &recipient))
            .expect("transaction failed");

        // queue a message for an unknown sender
        connection
            .transaction(|txn| {
                query::outbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), 0)
            })
            .expect("transaction failed");

        // queue a message with the same sequence
        // which should succeed as we don't enforce
        // uniqueness constraints
        connection
            .transaction(|txn| {
                query::outbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), 0)
            })
            .expect("transaction failed");

        // queue multiple in a transaction
        connection
            .transaction(|txn| {
                for i in 2..100 {
                    query::outbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), i)?
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

                query::outbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), 0)
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

                query::outbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), 0)
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
                .transaction(|txn| query::outbox_queue(txn, &sender, &recipient, &content, i))
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
                    query::outbox_queue(txn, &sender, &recipient, &crypto::random::vec(256), i)?;
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
}
