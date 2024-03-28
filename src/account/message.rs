use crate::keypair::signing::PublicKey;

pub struct Message<'m> {
    pub sender: &'m PublicKey,
    pub recipient: &'m PublicKey,
    pub message: &'m [u8],
}

pub struct Commit<'c> {
    pub sender: &'c PublicKey,
    pub recipient: &'c PublicKey,
    pub commit: &'c [u8],
}

pub struct Welcome<'w> {
    pub sender: &'w PublicKey,
    pub recipient: &'w PublicKey,
    pub welcome: &'w [u8],
}

pub struct KeyPackage<'k> {
    pub sender: &'k PublicKey,
    pub recipient: &'k PublicKey,
    pub package: &'k [u8],
}
