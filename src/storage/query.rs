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
