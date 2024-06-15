use crate::keypair::signing::PublicKey;

pub struct Commit {
    from_address: PublicKey,
    to_address: PublicKey,
    commit: Vec<u8>,
    sequence: u64,
    timestamp: i64,
}

impl Commit {
    pub fn new(
        from_address: PublicKey,
        to_address: PublicKey,
        commit: Vec<u8>,
        sequence: u64,
        timestamp: i64,
    ) -> Commit {
        Commit {
            from_address,
            to_address,
            commit,
            sequence,
            timestamp,
        }
    }

    pub fn from_address(&self) -> &PublicKey {
        &self.from_address
    }

    pub fn to_address(&self) -> &PublicKey {
        &self.to_address
    }

    pub fn commit(&self) -> &[u8] {
        &self.commit
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }
}

pub struct KeyPackage {
    from_address: PublicKey,
    to_address: PublicKey,
    package: Vec<u8>,
    sequence: u64,
    timestamp: i64,
    authorized: bool,
}

impl KeyPackage {
    pub fn new(
        from_address: PublicKey,
        to_address: PublicKey,
        package: Vec<u8>,
        sequence: u64,
        timestamp: i64,
        authorized: bool,
    ) -> KeyPackage {
        KeyPackage {
            from_address,
            to_address,
            package,
            sequence,
            timestamp,
            authorized,
        }
    }

    pub fn from_address(&self) -> &PublicKey {
        &self.from_address
    }

    pub fn to_address(&self) -> &PublicKey {
        &self.to_address
    }

    pub fn package(&self) -> &[u8] {
        &self.package
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }

    pub fn is_authorized(&self) -> bool {
        self.authorized
    }
}

pub struct Proposal {
    from_address: PublicKey,
    to_address: PublicKey,
    proposal: Vec<u8>,
    sequence: u64,
    timestamp: i64,
}

impl Proposal {
    pub fn new(
        from_address: PublicKey,
        to_address: PublicKey,
        proposal: Vec<u8>,
        sequence: u64,
        timestamp: i64,
    ) -> Proposal {
        Proposal {
            from_address,
            to_address,
            proposal,
            sequence,
            timestamp,
        }
    }

    pub fn from_address(&self) -> &PublicKey {
        &self.from_address
    }

    pub fn to_address(&self) -> &PublicKey {
        &self.to_address
    }

    pub fn proposal(&self) -> &[u8] {
        &self.proposal
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }
}

pub struct Welcome {
    from_address: PublicKey,
    to_address: PublicKey,
    welcome: Vec<u8>,
    subscription: Vec<u8>,
    sequence: u64,
    timestamp: i64,
    authorized: bool,
}

impl Welcome {
    pub fn new(
        from_address: PublicKey,
        to_address: PublicKey,
        welcome: Vec<u8>,
        subscription: Vec<u8>,
        sequence: u64,
        timestamp: i64,
        authorized: bool,
    ) -> Welcome {
        Welcome {
            from_address,
            to_address,
            welcome,
            sequence,
            timestamp,
            subscription,
            authorized,
        }
    }

    pub fn from_address(&self) -> &PublicKey {
        &self.from_address
    }

    pub fn to_address(&self) -> &PublicKey {
        &self.to_address
    }

    pub fn welcome(&self) -> &[u8] {
        &self.welcome
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }

    pub fn subscription_token(&self) -> &[u8] {
        &self.subscription
    }

    pub fn is_authorized(&self) -> bool {
        self.authorized
    }
}
