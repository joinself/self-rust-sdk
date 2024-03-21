use crate::error::SelfError;
use crate::storage::Transaction;

pub trait KeyPair {
    fn address(&self) -> &[u8];
    fn encode(&self) -> Vec<u8>;
    fn decode(d: &[u8]) -> Self;
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

/*
pub fn metrics_create(
    txn: &mut Transaction,
    as_address: &signing::PublicKey,
    with_address: &signing::PublicKey,
) -> Result<(), SelfError> {
    txn.execute(
        "INSERT INTO metrics (as_address, with_address, sequence)
            VALUES(
                (SELECT id FROM addresses WHERE address = ?1),
                (SELECT id FROM addresses WHERE address = ?2),
                0
            );",
        (as_address.address(), with_address.address()),
    )
    .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

    Ok(())
}

pub fn metrics_sequence_get(
    txn: &mut Transaction,
    as_address: &signing::PublicKey,
    with_address: &signing::PublicKey,
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

    let mut rows = match statement.query([as_address.address(), with_address.address()]) {
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

pub fn metrics_sequence_update(
    txn: &mut Transaction,
    as_address: &signing::PublicKey,
    with_address: &signing::PublicKey,
    sequence: u64,
) -> Result<(), SelfError> {
    txn.execute(
        "UPDATE metrics
        SET sequence = ?3
        WHERE as_address = (SELECT id FROM addresses WHERE address=?1)
        AND with_address = (SELECT id FROM addresses WHERE address=?2);",
        (as_address.address(), with_address.address(), sequence),
    )
    .map_err(|_| SelfError::StorageTransactionCommitFailed)?;

    Ok(())
}
 */
