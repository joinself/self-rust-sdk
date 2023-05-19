use crate::error::SelfError;
use crate::identifier::Identifier;
use olm_sys::*;

pub struct Session {
    session: *mut OlmSession,
    as_identifier: Identifier,
    with_identifier: Identifier,
    sequence_tx: u64,
    sequence_rx: u64,
}

unsafe impl Send for Session {}

impl Session {
    pub fn new(as_identifier: Identifier, with_identifier: Identifier) -> Session {
        unsafe {
            let session_len = olm_session_size() as usize;
            let session_buf = vec![0_u8; session_len].into_boxed_slice();
            let session = olm_session(Box::into_raw(session_buf) as *mut libc::c_void);

            Session {
                session,
                as_identifier,
                with_identifier,
                sequence_tx: 0,
                sequence_rx: 0,
            }
        }
    }

    pub fn from_pickle(
        as_identifier: Identifier,
        with_identifier: Identifier,
        sequence_tx: u64,
        sequence_rx: u64,
        pickle: &mut [u8],
        password: Option<&[u8]>,
    ) -> Result<Session, SelfError> {
        unsafe {
            let session_len = olm_session_size() as usize;
            let session_buf = vec![0_u8; session_len].into_boxed_slice();
            let session = olm_session(Box::into_raw(session_buf) as *mut libc::c_void);

            let password_len = password.map(|pwd| pwd.len()).unwrap_or(0);

            let password_buf = password
                .map(|pwd| pwd as *const [u8] as *const libc::c_void)
                .unwrap_or(std::ptr::null());

            olm_unpickle_session(
                session,
                password_buf,
                password_len as u64,
                pickle as *mut [u8] as *mut libc::c_void,
                pickle.len() as u64,
            );

            let session = Session {
                session,
                as_identifier,
                with_identifier,
                sequence_tx,
                sequence_rx,
            };

            session.last_error()?;

            Ok(session)
        }
    }

    /// # Safety
    ///
    /// This function should only be called internally by olm messages.
    pub unsafe fn as_mut_ptr(&self) -> *mut OlmSession {
        self.session
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(u64, Vec<u8>), SelfError> {
        unsafe {
            let mtype = olm_encrypt_message_type(self.session);

            let random_len = olm_encrypt_random_length(self.session);
            let mut random_buf = vec![0_u8; random_len as usize].into_boxed_slice();
            sodium_sys::randombytes_buf(random_buf.as_mut_ptr() as *mut libc::c_void, random_len);

            let mut message_len = olm_encrypt_message_length(self.session, plaintext.len() as u64);
            let mut message_buf = vec![0_u8; message_len as usize].into_boxed_slice();

            message_len = olm_encrypt(
                self.session,
                plaintext.as_ptr() as *const libc::c_void,
                plaintext.len() as u64,
                random_buf.as_mut_ptr() as *mut libc::c_void,
                random_len,
                message_buf.as_mut_ptr() as *mut libc::c_void,
                message_len,
            );

            self.last_error()?;
            self.sequence_tx += 1;

            Ok((mtype, message_buf[0..message_len as usize].to_vec()))
        }
    }

    pub fn decrypt(&mut self, mtype: u64, ciphertext: &mut [u8]) -> Result<Vec<u8>, SelfError> {
        unsafe {
            let mut plaintext_len = olm_decrypt_max_plaintext_length(
                self.session,
                mtype,
                ciphertext.to_owned().as_mut_ptr() as *mut libc::c_void, // clone the ciphertext, as the input is destroyed
                ciphertext.len() as u64,
            );

            self.last_error()?;

            let mut plaintext_buf = vec![0_u8; plaintext_len as usize].into_boxed_slice();

            plaintext_len = olm_decrypt(
                self.session,
                mtype,
                ciphertext.as_mut_ptr() as *mut libc::c_void,
                ciphertext.len() as u64,
                plaintext_buf.as_mut_ptr() as *mut libc::c_void,
                plaintext_len,
            );

            self.last_error()?;
            self.sequence_rx += 1;

            Ok(plaintext_buf[0..plaintext_len as usize].to_vec())
        }
    }

    pub fn matches_inbound_session(&self, one_time_message: &[u8]) -> Result<bool, SelfError> {
        let identity_key = match &self.with_identifier {
            Identifier::Owned(kp) => kp.public().to_exchange_key()?,
            Identifier::Referenced(pk) => pk.to_exchange_key()?,
        };

        let identity_key_buf = base64::encode_config(identity_key.id(), base64::STANDARD_NO_PAD);

        unsafe {
            let result = olm_matches_inbound_session_from(
                self.session,
                identity_key_buf.as_ptr() as *const libc::c_void,
                identity_key_buf.len() as u64,
                one_time_message.to_owned().as_mut_ptr() as *mut libc::c_void,
                one_time_message.len() as u64,
            );

            self.last_error()?;

            Ok(result == 1)
        }
    }

    pub fn pickle(&self, password: Option<&[u8]>) -> Result<Vec<u8>, SelfError> {
        unsafe {
            let mut session_pickle_len = olm_pickle_session_length(self.session);
            let mut session_pickle_buf = vec![0_u8; session_pickle_len as usize].into_boxed_slice();

            let password_len = password.map(|pwd| pwd.len()).unwrap_or(0);

            let password_buf = password
                .map(|pwd| pwd as *const [u8] as *const libc::c_void)
                .unwrap_or(std::ptr::null());

            session_pickle_len = olm_pickle_session(
                self.session,
                password_buf,
                password_len as u64,
                session_pickle_buf.as_mut_ptr() as *mut libc::c_void,
                session_pickle_len,
            );

            self.last_error()?;

            Ok(session_pickle_buf[0..session_pickle_len as usize].to_vec())
        }
    }

    pub fn last_error(&self) -> Result<(), SelfError> {
        unsafe {
            #[allow(non_upper_case_globals)]
            return match olm_session_last_error_code(self.session) {
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
                OlmErrorCode_OLM_BAD_ACCOUNT_KEY => Err(SelfError::CryptoBadAccountKey),
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

    pub fn as_identifier(&self) -> &Identifier {
        &self.as_identifier
    }

    pub fn with_identifier(&self) -> &Identifier {
        &self.with_identifier
    }

    pub fn sequence_tx(&self) -> u64 {
        self.sequence_tx
    }

    pub fn sequence_rx(&self) -> u64 {
        self.sequence_rx
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(self.session));
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::crypto::account::Account;

    #[test]
    fn encrypt_and_decrypt() {
        let alice_skp = crate::keypair::signing::KeyPair::new();
        let alice_ekp = crate::keypair::exchange::KeyPair::new();
        let alice_id = Identifier::Referenced(alice_skp.public());
        let mut alice_acc = Account::new(alice_skp, alice_ekp);

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ekp = crate::keypair::exchange::KeyPair::new();
        let bob_id = Identifier::Referenced(bob_skp.public());
        let mut bob_acc = Account::new(bob_skp, bob_ekp);

        alice_acc
            .generate_one_time_keys(10)
            .expect("failed to generate one time keys");

        let alices_one_time_keys = alice_acc.one_time_keys();

        // encrypt a message from bob with a new session to alice
        let mut bobs_session_with_alice = bob_acc
            .create_outbound_session(alice_id, &alices_one_time_keys[0])
            .expect("failed to create outbound session");

        let (mtype, mut bobs_message_to_alice_1) = bobs_session_with_alice
            .encrypt("hello alice, pt1".as_bytes())
            .expect("failed to encrypt message to alice");

        assert_eq!(mtype, 0);

        // create alices session with bob from bobs first message
        let mut alices_session_with_bob = alice_acc
            .create_inbound_session(bob_id, &bobs_message_to_alice_1)
            .expect("failed to create inbound session");

        // remove the one time key from alices account
        alice_acc
            .remove_one_time_keys(&alices_session_with_bob)
            .expect("failed to remove session");

        // decrypt the message from bob
        let plaintext = alices_session_with_bob
            .decrypt(mtype, &mut bobs_message_to_alice_1)
            .expect("failed to decrypt bobs message");

        assert_eq!(&plaintext, "hello alice, pt1".as_bytes());

        // send another message from bob
        let (mtype, mut bobs_message_to_alice_2) = bobs_session_with_alice
            .encrypt("hello alice, pt2".as_bytes())
            .expect("failed to encrypt message to alice");

        // expect it to be a one time message as alice has not sent a response message
        // to fully set up the session
        assert_eq!(mtype, 0);

        // check it's intended for the session alice currently has with bob
        let matches = alices_session_with_bob
            .matches_inbound_session(&bobs_message_to_alice_2)
            .expect("failed to check if one time key message matches session");

        assert!(matches);

        // decrypt the message from bob
        let plaintext = alices_session_with_bob
            .decrypt(mtype, &mut bobs_message_to_alice_2)
            .expect("failed to decrypt bobs message");

        assert_eq!(&plaintext, "hello alice, pt2".as_bytes());

        // send a response message to bob
        let (mtype, mut alices_message_to_bob_1) = alices_session_with_bob
            .encrypt("hey bob".as_bytes())
            .expect("failed to encrypt message to bob");

        assert_eq!(mtype, 1);

        let plaintext = bobs_session_with_alice
            .decrypt(mtype, &mut alices_message_to_bob_1)
            .expect("failed to decrypt message from alice");

        assert_eq!(&plaintext, "hey bob".as_bytes());

        // send another message from bob
        let (mtype, _) = bobs_session_with_alice
            .encrypt("hello alice, pt2".as_bytes())
            .expect("failed to encrypt message to alice");

        assert_eq!(mtype, 1);
    }

    #[test]
    fn serialize_and_deserialize() {
        let alice_skp = crate::keypair::signing::KeyPair::new();
        let alice_ekp = crate::keypair::exchange::KeyPair::new();
        let alice_id = Identifier::Owned(alice_skp.clone());
        let mut alice_acc = Account::new(alice_skp, alice_ekp);

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ekp = crate::keypair::exchange::KeyPair::new();
        let bob_id = Identifier::Owned(bob_skp.clone());
        let mut bob_acc = Account::new(bob_skp, bob_ekp);

        alice_acc
            .generate_one_time_keys(10)
            .expect("failed to generate one time keys");

        let alices_one_time_keys = alice_acc.one_time_keys();

        // encrypt a message from bob with a new session to alice
        let mut bobs_session_with_alice = bob_acc
            .create_outbound_session(alice_id.clone(), &alices_one_time_keys[0])
            .expect("failed to create outbound session");

        let (mtype, mut bobs_message_to_alice_1) = bobs_session_with_alice
            .encrypt("hello alice, pt1".as_bytes())
            .expect("failed to encrypt message to alice");

        assert_eq!(mtype, 0);

        // create alices session with bob from bobs first message
        let alices_session_with_bob = alice_acc
            .create_inbound_session(bob_id.clone(), &bobs_message_to_alice_1)
            .expect("failed to create inbound session");

        let mut alices_session_with_bob_pickle = alices_session_with_bob
            .pickle(Some("password".as_bytes()))
            .expect("failed to pickle session");

        let mut alices_session_with_bob = Session::from_pickle(
            alice_id,
            bob_id,
            0,
            0,
            &mut alices_session_with_bob_pickle,
            Some("password".as_bytes()),
        )
        .expect("failed to unpickle session");

        // remove the one time key from alices account
        alice_acc
            .remove_one_time_keys(&alices_session_with_bob)
            .expect("failed to remove session");

        // decrypt the message from bob
        let plaintext = alices_session_with_bob
            .decrypt(mtype, &mut bobs_message_to_alice_1)
            .expect("failed to decrypt bobs message");

        assert_eq!(&plaintext, "hello alice, pt1".as_bytes());
    }
}
