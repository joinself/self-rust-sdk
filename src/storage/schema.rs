use crate::storage::Transaction;

fn schema_create_addresses(txn: &Transaction) {
    if table_exists(txn, "addresses") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL
            );
            CREATE UNIQUE INDEX idx_addresss_address
            ON addresses (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

fn schema_create_keypairs(txn: &Transaction) {
    if table_exists(txn, "keypairs") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE keypairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                roles INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                revoked_at INTEGER,
                keypair BLOB NOT NULL
            );
            CREATE UNIQUE INDEX idx_keypairs_for_address
            ON keypairs (for_address);",
        )
        .expect("failed to prepare statement");
}

pub fn schema_create_signature_key_pairs(txn: &Transaction) {
    if table_exists(txn, "signature_key_pairs") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE signature_key_pairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL,
                value BLOB NOT NULL
            );

            CREATE UNIQUE INDEX idx_signature_key_pairs_address
            ON signature_key_pairs (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_hpke_private_keys(txn: &Transaction) {
    if table_exists(txn, "hpke_private_keys") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE hpke_private_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL,
                value BLOB NOT NULL
            );

            CREATE UNIQUE INDEX idx_hpke_private_keys_address
            ON hpke_private_keys (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_key_packages(txn: &Transaction) {
    if table_exists(txn, "key_packages") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE key_packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL,
                value BLOB NOT NULL
            );

            CREATE UNIQUE INDEX idx_key_packages_address
            ON key_packages (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_psk_bundles(txn: &Transaction) {
    if table_exists(txn, "psk_bundles") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE psk_bundles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL,
                value BLOB NOT NULL
            );

            CREATE UNIQUE INDEX idx_psk_bundles_address
            ON psk_bundles (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_encryption_key_pairs(txn: &Transaction) {
    if table_exists(txn, "encryption_key_pairs") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE encryption_key_pairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL,
                value BLOB NOT NULL
            );

            CREATE UNIQUE INDEX idx_encryption_key_pairs_address
            ON encryption_key_pairs (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_group_states(txn: &Transaction) {
    if table_exists(txn, "group_states") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE group_states (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL,
                value BLOB NOT NULL
            );

            CREATE UNIQUE INDEX idx_group_states_address
            ON group_states (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

fn table_exists(txn: &Transaction, table: &str) -> bool {
    let stmt = txn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?1;")
        .expect("failed to prepare statement");

    stmt.bind_text(1, table).expect("failed to bind param");
    stmt.step().expect("failed to execute statement")
}
