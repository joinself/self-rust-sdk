use crate::keypair::signing::PublicKey;

pub enum Message {
    Custom,
    ConnectionRequest,
    ConnectionResponse,
}

pub struct Commit<'w> {
    pub sender: &'w PublicKey,
    pub recipient: &'w PublicKey,
    pub commit: &'w [u8],
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
