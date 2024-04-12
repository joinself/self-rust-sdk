use crate::storage::Transaction;

pub fn schema_create_addresses(txn: &Transaction) {
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

pub fn schema_create_keypairs(txn: &Transaction) {
    if table_exists(txn, "keypairs") {
        print!("keypairs exists!");
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE keypairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address INTEGER NOT NULL,
                roles INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                revoked_at INTEGER,
                keypair BLOB NOT NULL
            );
            CREATE UNIQUE INDEX idx_keypairs_address
            ON keypairs (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_groups(txn: &Transaction) {
    if table_exists(txn, "groups") {
        print!("groups exists!");
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address INTEGER NOT NULL,
                purpose INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX idx_groups_address
            ON groups (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_members(txn: &Transaction) {
    if table_exists(txn, "members") {
        print!("members exists!");
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                member_address INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX idx_members_membership
            ON members (group_id, member_address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_tokens(txn: &Transaction) {
    if table_exists(txn, "tokens") {
        print!("tokens exists!");
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind INTEGER NOT NULL,
                to_address INTEGER NOT NULL,
                from_address INTEGER NOT NULL,
                for_address INTEGER NOT NULL,
                token BLOB NOT NULL
            );
            CREATE INDEX idx_tokens_address
            ON tokens (for_address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_inbox(txn: &Transaction) {
    if table_exists(txn, "inbox") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE inbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event INTEGER NOT NULL,
                sender INTEGER NOT NULL,
                recipient INTEGER NOT NULL,
                message INTEGER NOT NULL,
                sequence INTEGER NOT NULL
            );",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_outbox(txn: &Transaction) {
    if table_exists(txn, "outbox") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event INTEGER NOT NULL,
                sender INTEGER NOT NULL,
                recipient INTEGER NOT NULL,
                message INTEGER NOT NULL,
                sequence INTEGER NOT NULL
            );",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_mls_signature_key_pairs(txn: &Transaction) {
    if table_exists(txn, "mls_signature_key_pairs") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE mls_signature_key_pairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL,
                value BLOB NOT NULL
            );

            CREATE UNIQUE INDEX idx_mls_signature_key_pairs
            ON mls_signature_key_pairs (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_mls_hpke_private_keys(txn: &Transaction) {
    if table_exists(txn, "mls_hpke_private_keys") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE mls_hpke_private_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL,
                value BLOB NOT NULL
            );

            CREATE UNIQUE INDEX idx_mls_hpke_private_keys_address
            ON mls_hpke_private_keys (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_mls_key_packages(txn: &Transaction) {
    if table_exists(txn, "mls_key_packages") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE mls_key_packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL,
                value BLOB NOT NULL
            );

            CREATE UNIQUE INDEX idx_mls_key_packages_address
            ON mls_key_packages (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_mls_psk_bundles(txn: &Transaction) {
    if table_exists(txn, "mls_psk_bundles") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE mls_psk_bundles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL,
                value BLOB NOT NULL
            );

            CREATE UNIQUE INDEX idx_mls_psk_bundles_address
            ON mls_psk_bundles (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_mls_encryption_key_pairs(txn: &Transaction) {
    if table_exists(txn, "mls_encryption_key_pairs") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE mls_encryption_key_pairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL,
                value BLOB NOT NULL
            );

            CREATE UNIQUE INDEX idx_mls_encryption_key_pairs_address
            ON mls_encryption_key_pairs (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_mls_group_states(txn: &Transaction) {
    if table_exists(txn, "mls_group_states") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE mls_group_states (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address BLOB NOT NULL,
                value BLOB NOT NULL
            );

            CREATE UNIQUE INDEX idx_mls_group_states_address
            ON mls_group_states (address);",
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
