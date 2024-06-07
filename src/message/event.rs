use crate::keypair::signing::PublicKey;

pub struct Commit {
    sender: PublicKey,
    recipient: PublicKey,
    commit: Vec<u8>,
    sequence: u64,
}

impl Commit {
    pub fn new(sender: PublicKey, recipient: PublicKey, commit: Vec<u8>, sequence: u64) -> Commit {
        Commit {
            sender,
            recipient,
            commit,
            sequence,
        }
    }

    pub fn sender(&self) -> &PublicKey {
        &self.sender
    }

    pub fn recipient(&self) -> &PublicKey {
        &self.recipient
    }

    pub fn commit(&self) -> &[u8] {
        &self.commit
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

pub struct KeyPackage {
    sender: PublicKey,
    recipient: PublicKey,
    package: Vec<u8>,
    sequence: u64,
    authorized: bool,
}

impl KeyPackage {
    pub fn new(
        sender: PublicKey,
        recipient: PublicKey,
        package: Vec<u8>,
        sequence: u64,
        authorized: bool,
    ) -> KeyPackage {
        KeyPackage {
            sender,
            recipient,
            package,
            sequence,
            authorized,
        }
    }

    pub fn sender(&self) -> &PublicKey {
        &self.sender
    }

    pub fn recipient(&self) -> &PublicKey {
        &self.recipient
    }

    pub fn package(&self) -> &[u8] {
        &self.package
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn is_authorized(&self) -> bool {
        self.authorized
    }
}

pub struct Proposal {
    sender: PublicKey,
    recipient: PublicKey,
    proposal: Vec<u8>,
    sequence: u64,
}

impl Proposal {
    pub fn new(
        sender: PublicKey,
        recipient: PublicKey,
        proposal: Vec<u8>,
        sequence: u64,
    ) -> Proposal {
        Proposal {
            sender,
            recipient,
            proposal,
            sequence,
        }
    }

    pub fn sender(&self) -> &PublicKey {
        &self.sender
    }

    pub fn recipient(&self) -> &PublicKey {
        &self.recipient
    }

    pub fn proposal(&self) -> &[u8] {
        &self.proposal
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

pub struct Welcome {
    sender: PublicKey,
    recipient: PublicKey,
    welcome: Vec<u8>,
    sequence: u64,
    subscription: Vec<u8>,
    authorized: bool,
}

impl Welcome {
    pub fn new(
        sender: PublicKey,
        recipient: PublicKey,
        welcome: Vec<u8>,
        sequence: u64,
        subscription: Vec<u8>,
        authorized: bool,
    ) -> Welcome {
        Welcome {
            sender,
            recipient,
            welcome,
            sequence,
            subscription,
            authorized,
        }
    }

    pub fn sender(&self) -> &PublicKey {
        &self.sender
    }

    pub fn recipient(&self) -> &PublicKey {
        &self.recipient
    }

    pub fn welcome(&self) -> &[u8] {
        &self.welcome
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn subscription_token(&self) -> &[u8] {
        &self.subscription
    }

    pub fn is_authorized(&self) -> bool {
        self.authorized
    }
}
