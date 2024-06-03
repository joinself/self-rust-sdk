use crate::keypair::signing::PublicKey;

pub struct Message<'m> {
    sender: &'m PublicKey,
    recipient: &'m PublicKey,
    message: &'m [u8],
    sequence: u64,
}

impl<'m> Message<'m> {
    pub fn new(
        sender: &'m PublicKey,
        recipient: &'m PublicKey,
        message: &'m [u8],
        sequence: u64,
    ) -> Message<'m> {
        Message {
            sender,
            recipient,
            message,
            sequence,
        }
    }

    pub fn sender(&self) -> &'m PublicKey {
        self.sender
    }

    pub fn recipient(&self) -> &'m PublicKey {
        self.recipient
    }

    pub fn message(&self) -> &'m [u8] {
        self.message
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

pub struct Commit<'c> {
    sender: &'c PublicKey,
    recipient: &'c PublicKey,
    commit: &'c [u8],
    sequence: u64,
}

impl<'c> Commit<'c> {
    pub fn new(
        sender: &'c PublicKey,
        recipient: &'c PublicKey,
        commit: &'c [u8],
        sequence: u64,
    ) -> Commit<'c> {
        Commit {
            sender,
            recipient,
            commit,
            sequence,
        }
    }

    pub fn sender(&self) -> &'c PublicKey {
        self.sender
    }

    pub fn recipient(&self) -> &'c PublicKey {
        self.recipient
    }

    pub fn commit(&self) -> &'c [u8] {
        self.commit
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

pub struct KeyPackage<'k> {
    sender: &'k PublicKey,
    recipient: &'k PublicKey,
    package: &'k [u8],
    sequence: u64,
    authorized: bool,
}

impl<'k> KeyPackage<'k> {
    pub fn new(
        sender: &'k PublicKey,
        recipient: &'k PublicKey,
        package: &'k [u8],
        sequence: u64,
        authorized: bool,
    ) -> KeyPackage<'k> {
        KeyPackage {
            sender,
            recipient,
            package,
            sequence,
            authorized,
        }
    }

    pub fn sender(&self) -> &'k PublicKey {
        self.sender
    }

    pub fn recipient(&self) -> &'k PublicKey {
        self.recipient
    }

    pub fn package(&self) -> &'k [u8] {
        self.package
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn is_authorized(&self) -> bool {
        self.authorized
    }
}

pub struct Proposal<'p> {
    sender: &'p PublicKey,
    recipient: &'p PublicKey,
    proposal: &'p [u8],
    sequence: u64,
}

impl<'p> Proposal<'p> {
    pub fn new(
        sender: &'p PublicKey,
        recipient: &'p PublicKey,
        proposal: &'p [u8],
        sequence: u64,
    ) -> Proposal<'p> {
        Proposal {
            sender,
            recipient,
            proposal,
            sequence,
        }
    }

    pub fn sender(&self) -> &'p PublicKey {
        self.sender
    }

    pub fn recipient(&self) -> &'p PublicKey {
        self.recipient
    }

    pub fn proposal(&self) -> &'p [u8] {
        self.proposal
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

pub struct Welcome<'w> {
    sender: &'w PublicKey,
    recipient: &'w PublicKey,
    welcome: &'w [u8],
    sequence: u64,
    subscription: &'w [u8],
    authorized: bool,
}

impl<'w> Welcome<'w> {
    pub fn new(
        sender: &'w PublicKey,
        recipient: &'w PublicKey,
        welcome: &'w [u8],
        sequence: u64,
        subscription: &'w [u8],
        authorized: bool,
    ) -> Welcome<'w> {
        Welcome {
            sender,
            recipient,
            welcome,
            sequence,
            subscription,
            authorized,
        }
    }

    pub fn sender(&self) -> &'w PublicKey {
        self.sender
    }

    pub fn recipient(&self) -> &'w PublicKey {
        self.recipient
    }

    pub fn welcome(&self) -> &'w [u8] {
        self.welcome
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn subscription_token(&self) -> &'w [u8] {
        self.subscription
    }

    pub fn is_authorized(&self) -> bool {
        self.authorized
    }
}
