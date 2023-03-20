use crate::crypto::session::Session;
use crate::error::SelfError;
use crate::keypair::exchange::{self, KeyPair as ExchangeKeyPair};
use crate::keypair::signing::KeyPair as SigningKeyPair;

use olm_sys::*;

pub struct Account {
    account: *mut OlmAccount,
}

impl Account {
    pub fn new(signing_keypair: SigningKeyPair, exchange_keypair: ExchangeKeyPair) -> Account {
        let mut ed25519_secret_key = signing_keypair.to_vec();
        let mut ed25519_public_key = signing_keypair.public().id();
        let mut curve25519_secret_key = exchange_keypair.to_vec();
        let mut curve25519_public_key = exchange_keypair.public().id();

        unsafe {
            let account_len = olm_account_size() as usize;
            let account_buf = vec![0 as u8; account_len].into_boxed_slice();
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

    pub fn from_pickle(pickle: &mut [u8], password: Option<&[u8]>) -> Result<Account, SelfError> {
        unsafe {
            let account_len = olm_account_size() as usize;
            let account_buf = vec![0 as u8; account_len].into_boxed_slice();
            let account = olm_account(Box::into_raw(account_buf) as *mut libc::c_void);

            let password_len = password
                .and_then(|pwd| Some(pwd.len()))
                .or_else(|| Some(0))
                .unwrap();

            let password_buf = password
                .and_then(|pwd| Some(pwd as *const [u8] as *const libc::c_void))
                .or_else(|| Some(std::ptr::null()))
                .unwrap();

            olm_unpickle_account(
                account,
                password_buf,
                password_len as u64,
                pickle as *mut [u8] as *mut libc::c_void,
                pickle.len() as u64,
            );

            let account = Account { account: account };

            account.last_error()?;

            return Ok(account);
        }
    }

    pub fn one_time_keys(&self) -> Vec<u8> {
        unsafe {
            let mut one_time_keys_len = olm_account_one_time_keys_length(self.account);
            let mut one_time_keys_buf =
                vec![0 as u8; one_time_keys_len as usize].into_boxed_slice();

            one_time_keys_len = olm_account_one_time_keys(
                self.account,
                one_time_keys_buf.as_mut_ptr() as *mut libc::c_void,
                one_time_keys_len,
            );

            return one_time_keys_buf[0..one_time_keys_len as usize].to_vec();
        }
    }

    pub fn generate_one_time_keys(&mut self, count: usize) -> Result<(), SelfError> {
        unsafe {
            if (olm_account_max_number_of_one_time_keys(self.account) as usize) < count {
                return self.last_error();
            }

            let random_len =
                olm_account_generate_one_time_keys_random_length(self.account, count as u64);
            let mut random_buf = vec![0 as u8; random_len as usize].into_boxed_slice();
            sodium_sys::randombytes_buf(random_buf.as_mut_ptr() as *mut libc::c_void, random_len);

            olm_account_generate_one_time_keys(
                self.account,
                count as u64,
                random_buf.as_mut_ptr() as *mut libc::c_void,
                random_len,
            );
        }

        return self.last_error();
    }

    pub fn remove_one_time_keys(&mut self, session: &Session) -> Result<(), SelfError> {
        unsafe {
            olm_remove_one_time_keys(self.account, session.as_mut_ptr());
        }

        return self.last_error();
    }

    pub fn mark_keys_as_published(&mut self) -> Result<(), SelfError> {
        unsafe {
            olm_account_mark_keys_as_published(self.account);
        }
        return self.last_error();
    }

    pub fn identity_keys(&self) -> Vec<u8> {
        unsafe {
            let mut identity_keys_len = olm_account_identity_keys_length(self.account);
            let mut identity_keys_buf =
                vec![0 as u8; identity_keys_len as usize].into_boxed_slice();

            identity_keys_len = olm_account_identity_keys(
                self.account,
                identity_keys_buf.as_mut_ptr() as *mut libc::c_void,
                identity_keys_len,
            );

            return identity_keys_buf[0..identity_keys_len as usize].to_vec();
        }
    }

    pub fn pickle(&self, password: Option<&[u8]>) -> Result<Vec<u8>, SelfError> {
        unsafe {
            let mut account_pickle_len = olm_pickle_account_length(self.account);
            let mut account_pickle_buf =
                vec![0 as u8; account_pickle_len as usize].into_boxed_slice();

            let password_len = password
                .and_then(|pwd| Some(pwd.len()))
                .or_else(|| Some(0))
                .unwrap();

            let password_buf = password
                .and_then(|pwd| Some(pwd as *const [u8] as *const libc::c_void))
                .or_else(|| Some(std::ptr::null()))
                .unwrap();

            account_pickle_len = olm_pickle_account(
                self.account,
                password_buf,
                password_len as u64,
                account_pickle_buf.as_mut_ptr() as *mut libc::c_void,
                account_pickle_len,
            );

            self.last_error()?;

            return Ok(account_pickle_buf[0..account_pickle_len as usize].to_vec());
        }
    }

    pub fn create_inbound_session(
        &mut self,
        identity_key: &exchange::PublicKey,
        one_time_message: &[u8],
    ) -> Result<Session, SelfError> {
        let session = Session::new();

        let identity_key_buf = base64::encode_config(identity_key.id(), base64::STANDARD_NO_PAD);

        unsafe {
            let mut one_time_message_buf = one_time_message.to_owned();

            olm_create_inbound_session_from(
                session.as_mut_ptr(),
                self.account,
                identity_key_buf.as_ptr() as *const libc::c_void,
                identity_key_buf.len() as u64,
                one_time_message_buf.as_mut_ptr() as *mut libc::c_void,
                one_time_message_buf.len() as u64,
            );

            session.last_error()?;

            return Ok(session);
        }
    }

    pub fn create_outbound_session(
        &mut self,
        identity_key: &exchange::PublicKey,
        one_time_key: &[u8],
    ) -> Result<Session, SelfError> {
        let session = Session::new();

        let identity_key_buf = base64::encode_config(identity_key.id(), base64::STANDARD_NO_PAD);

        unsafe {
            let random_len = olm_create_outbound_session_random_length(session.as_mut_ptr());
            let mut random_buf = vec![0 as u8; random_len as usize].into_boxed_slice();
            sodium_sys::randombytes_buf(random_buf.as_mut_ptr() as *mut libc::c_void, random_len);

            olm_create_outbound_session(
                session.as_mut_ptr(),
                self.account,
                identity_key_buf.as_ptr() as *const libc::c_void,
                identity_key_buf.len() as u64,
                one_time_key.as_ptr() as *const libc::c_void,
                one_time_key.len() as u64,
                random_buf.as_ptr() as *mut libc::c_void,
                random_len,
            );

            session.last_error()?;

            return Ok(session);
        }
    }

    fn last_error(&self) -> Result<(), SelfError> {
        unsafe {
            #[allow(non_upper_case_globals)]
            return match olm_account_last_error_code(self.account) {
                OlmErrorCode_OLM_SUCCESS => Ok(()),
                OlmErrorCode_OLM_NOT_ENOUGH_RANDOM => Err(SelfError::CryptoNotEnoughRandom),
                OlmErrorCode_OLM_OUTPUT_BUFFER_TOO_SMALL => {
                    Err(SelfError::CryptoOutputBufferTooSmall)
                }
                OlmErrorCode_OLM_BAD_MESSAGE_VERSION => Err(SelfError::CryptoBadMessageVersion),
                OlmErrorCode_OLM_BAD_MESSAGE_FORMAT => Err(SelfError::CryptoBadMessageFormat),
                OlmErrorCode_OLM_BAD_MESSAGE_MAC => Err(SelfError::CryptoBadMessageMac),
                OlmErrorCode_OLM_BAD_MESSAGE_KEY_ID => Err(SelfError::CryptoBadMessageKeyID),
                OlmErrorCode_OLM_INVALID_BASE64 => Err(SelfError::CryptoInvalidBase64),
                OlmErrorCode_OLM_BAD_ACCOUNT_KEY => Err(SelfError::CrytpoBadAccountKey),
                OlmErrorCode_OLM_UNKNOWN_PICKLE_VERSION => {
                    Err(SelfError::CryptoUnknownPickleVersion)
                }
                OlmErrorCode_OLM_CORRUPTED_PICKLE => Err(SelfError::CryptoCorruptedPickle),
                OlmErrorCode_OLM_BAD_SESSION_KEY => Err(SelfError::CryptoBadSessionKey),
                OlmErrorCode_OLM_UNKNOWN_MESSAGE_INDEX => Err(SelfError::CryptoUnknownMessageIndex),
                OlmErrorCode_OLM_BAD_LEGACY_ACCOUNT_PICKLE => {
                    Err(SelfError::CryptoBadLegacyAccountPickle)
                }
                OlmErrorCode_OLM_BAD_SIGNATURE => Err(SelfError::CryptoBadSignature),
                OlmErrorCode_OLM_INPUT_BUFFER_TOO_SMALL => {
                    Err(SelfError::CryptoInputBufferTooSmall)
                }
                OlmErrorCode_OLM_SAS_THEIR_KEY_NOT_SET => Err(SelfError::CryptoSasTheirKeyNotSet),
                OlmErrorCode_OLM_PICKLE_EXTRA_DATA => Err(SelfError::CryptoPickleExtraData),
                _ => Err(SelfError::CryptoUnknown),
            };
        }
    }
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

    #[test]
    fn one_time_keys() {
        let skp = crate::keypair::signing::KeyPair::new();
        let ekp = crate::keypair::exchange::KeyPair::new();
        let mut acc = Account::new(skp, ekp);

        acc.generate_one_time_keys(100)
            .expect("failed to generate one time keys");

        let one_time_keys_json = acc.one_time_keys();
        let json: std::collections::HashMap<String, serde_json::Value> =
            serde_json::from_slice(&one_time_keys_json)
                .expect("failed to decode one time keys json");

        let one_time_keys = json
            .get("curve25519")
            .unwrap()
            .as_object()
            .expect("could not coerce value to map");
        assert!(one_time_keys.get("AAAAAQ").is_some());
        assert_eq!(one_time_keys.len(), 100);
    }

    #[test]
    fn identity_keys() {
        let skp = crate::keypair::signing::KeyPair::new();
        let ekp = crate::keypair::exchange::KeyPair::new();
        let spk = skp.public().id();
        let epk = ekp.public().id();
        let acc = Account::new(skp, ekp);

        let identity_keys_json = acc.identity_keys();
        let json: std::collections::HashMap<String, serde_json::Value> =
            serde_json::from_slice(&identity_keys_json)
                .expect("failed to decode one time keys json");

        assert_eq!(
            base64::decode(json.get("ed25519").unwrap().as_str().unwrap()).unwrap(),
            spk,
        );

        assert_eq!(
            base64::decode(json.get("curve25519").unwrap().as_str().unwrap()).unwrap(),
            epk,
        );
    }

    #[test]
    fn serialize_deserialize() {
        let skp = crate::keypair::signing::KeyPair::new();
        let ekp = crate::keypair::exchange::KeyPair::new();
        let spk = skp.public().id();
        let epk = ekp.public().id();
        let acc = Account::new(skp, ekp);

        // try pickle with both password and no password
        acc.pickle(None).expect("failed to pickle account");
        let mut pickle = acc
            .pickle(Some("my-password".as_bytes()))
            .expect("failed to pickle account");

        let acc = Account::from_pickle(&mut pickle, Some("my-password".as_bytes()))
            .expect("failed to unpickle account");

        let identity_keys_json = acc.identity_keys();
        let json: std::collections::HashMap<String, serde_json::Value> =
            serde_json::from_slice(&identity_keys_json)
                .expect("failed to decode one time keys json");

        assert_eq!(
            base64::decode(json.get("ed25519").unwrap().as_str().unwrap()).unwrap(),
            spk,
        );

        assert_eq!(
            base64::decode(json.get("curve25519").unwrap().as_str().unwrap()).unwrap(),
            epk,
        );
    }
}
