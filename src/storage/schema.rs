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

pub fn schema_create_credentials(txn: &Transaction) {
    if table_exists(txn, "credentials") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issuer_address INTEGER NOT NULL,
                bearer_address INTEGER NOT NULL,
                credential_type INTEGER NOT NULL,
                credential BLOB NOT NULL
            );
            CREATE INDEX idx_credentials_bearer_address
            ON credentials (bearer_address);
            CREATE INDEX idx_credentials_credential_type
            ON credentials (credential_type);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_credential_types(txn: &Transaction) {
    if table_exists(txn, "credential_types") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE credential_types (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type BLOB NOT NULL
            );
            CREATE INDEX idx_credential_types_type
            ON credential_types (type);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_keypairs(txn: &Transaction) {
    if table_exists(txn, "keypairs") {
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

pub fn schema_create_keypair_associations(txn: &Transaction) {
    if table_exists(txn, "keypair_associations") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE keypair_associations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identity_address INTEGER NOT NULL,
                keypair_address INTEGER NOT NULL,
                sequence INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX idx_keypair_associations_keypair
            ON keypair_associations (keypair);
            CREATE INDEX idx_keypair_associations_identity
            ON keypair_associations (identity);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_identities(txn: &Transaction) {
    if table_exists(txn, "identities") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE identities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address INTEGER NOT NULL,
                status INTEGER NOT NULL,
                discovered_at INTEGER NOT NULL,
                synced_at INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX idx_identities_address
            ON identities (address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_identity_operations(txn: &Transaction) {
    if table_exists(txn, "identity_operations") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE identity_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address INTEGER NOT NULL,
                sequence INTEGER NOT NULL,
                operation BLOB NOT NULL
            );
            CREATE UNIQUE INDEX idx_identity_operations_address
            ON identity_operations (address, sequence);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_groups(txn: &Transaction) {
    if table_exists(txn, "groups") {
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

pub fn schema_create_subscriptions(txn: &Transaction) {
    if table_exists(txn, "subscriptions") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                to_address INTEGER NOT NULL,
                as_address INTEGER NOT NULL,
                offset INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX idx_subscriptions_address
            ON subscriptions (to_address, as_address);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_metrics(txn: &Transaction) {
    if table_exists(txn, "metrics") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_address INTEGER NOT NULL,
                to_address INTEGER NOT NULL,
                sequence_tx INTEGER NOT NULL,
                sequence_rx INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX idx_metrics_address
            ON metrics (to_address, from_address);",
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
                from_address INTEGER NOT NULL,
                to_address INTEGER NOT NULL,
                message INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                sequence INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX idx_inbox_message
            ON inbox (to_address, from_address, sequence);",
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
                from_address INTEGER NOT NULL,
                to_address INTEGER NOT NULL,
                message INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                sequence INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX idx_outbox_message
            ON outbox (to_address, from_address, sequence);",
        )
        .expect("failed to prepare statement");

    stmt.execute().expect("failed to execute statement");
}

pub fn schema_create_objects(txn: &Transaction) {
    if table_exists(txn, "objects") {
        return;
    }

    let stmt = txn
        .prepare(
            "CREATE TABLE objects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash BLOB NOT NULL,
                key BLOB NOT NULL,
                data BLOB NOT NULL
            );
            CREATE UNIQUE INDEX idx_objects_hash
            ON objects (hash);",
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
