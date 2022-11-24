use crate::keypair::{KeyPair};
use crate::transport::rest::{Rest};

struct Key {
    role: i32,
    keypair: KeyPair,
    created: i64,
    revoked: i64,
}

struct Device {
    
}

pub struct Account {
    keychain: Vec<KeyPair>,
}

impl Account {
    pub fn new() -> Account {
        return Account { 
            keychain: Vec::new(),
        };
    }

    

    /*
    pub fn register() -> Result<(), > {

    }
    */

    pub fn rest_client() -> Rest {
        
    }
}