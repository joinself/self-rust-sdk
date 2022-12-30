use crate::error::SelfError;
use crate::keypair::exchange::KeyPair as ExchangeKeyPair;
use crate::keypair::signing::KeyPair as SigningKeyPair;

use olm_sys::*;

pub struct Account {
    account: *mut OlmAccount,
}

impl Account {
    pub fn new(signing_keypair: SigningKeyPair, exchange_keypair: ExchangeKeyPair) -> Account {
        let mut ed25519_secret_key = signing_keypair.to_vec();
        let mut ed25519_public_key = signing_keypair.public().to_vec();
        let mut curve25519_secret_key = exchange_keypair.to_vec();
        let mut curve25519_public_key = exchange_keypair.public().to_vec();

        unsafe {
            let account_len = olm_account_size() as usize;
            let account_buf = vec![0; account_len].into_boxed_slice();

            let account = olm_account(Box::into_raw(account_buf) as *mut libc::c_void);

            olm_import_account(
                account,
                ed25519_secret_key.as_mut_ptr() as *mut libc::c_void,
                ed25519_public_key.as_mut_ptr() as *mut libc::c_void,
                curve25519_secret_key.as_mut_ptr() as *mut libc::c_void,
                curve25519_public_key.as_mut_ptr() as *mut libc::c_void,
            );

            return Account { account };
        }
    }

    pub fn generate_one_time_keys(&mut self, count: usize) -> Result<(), SelfError> {
        unsafe {
            if (olm_account_max_number_of_one_time_keys(self.account) as usize) < count {
                // TODO return error
            }
        }

        return Ok(());
    }

    /*
        olm_account_size()
        olm_account(),
        olm_create_account_random_length()
        olm_create_account()
        olm_unpickle_account()
        olm_pickle_account_length()
        olm_pickle_account()
        olm_account_signature_length()
        olm_account_sign()
        olm_account_max_number_of_one_time_keys()
        olm_account_mark_keys_as_published()
        olm_account_generate_one_time_keys_random_length()
        olm_account_generate_one_time_keys()
        olm_account_one_time_keys_length()
        olm_account_one_time_keys()
        olm_remove_one_time_keys()
        olm_account_identity_keys_length()
        olm_account_identity_keys()
        olm_account_last_error()
    */
}

impl Drop for Account {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(self.account));
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn import_acocunt() {
        let skp = crate::keypair::signing::KeyPair::new();
        let ekp = crate::keypair::exchange::KeyPair::new();

        Account::new(skp, ekp);
    }
}
