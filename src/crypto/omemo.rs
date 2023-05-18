use crate::crypto::session::Session;
use crate::error::SelfError;
use crate::identifier::Identifier;

use serde::{Deserialize, Serialize};

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub struct Group {
    as_identifier: Identifier,
    participants: Vec<Rc<RefCell<Session>>>,
    sequence_tx: u64,
}

#[derive(Serialize, Deserialize)]
pub struct GroupMessage {
    recipients: HashMap<Vec<u8>, Message>,
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Message {
    mtype: u64,
    ciphertext: Vec<u8>,
}

impl GroupMessage {
    fn new(ciphertext: &[u8]) -> GroupMessage {
        GroupMessage {
            recipients: HashMap::new(),
            ciphertext: ciphertext.to_vec(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<GroupMessage, SelfError> {
        match ciborium::de::from_reader(bytes) {
            Ok(keypair) => Ok(keypair),
            Err(_) => Err(SelfError::CryptoGroupMessageInvalid),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(self, &mut encoded).unwrap();
        encoded
    }

    pub fn one_time_key_message(&self, recipient: &[u8]) -> Option<Vec<u8>> {
        match self.recipients.get(recipient) {
            Some(message) => {
                if message.mtype != 0 {
                    return None;
                }
                Some(message.ciphertext.clone())
            }
            None => None,
        }
    }

    pub fn recipients(&self) -> Vec<Vec<u8>> {
        self.recipients.keys().cloned().collect()
    }

    fn set_recipient_ciphertext(&mut self, id: &[u8], mtype: u64, ciphertext: &[u8]) {
        self.recipients.insert(
            id.to_vec(),
            Message {
                mtype,
                ciphertext: ciphertext.to_vec(),
            },
        );
    }
}

impl Group {
    pub fn new(as_identifier: Identifier, sequence_tx: u64) -> Group {
        Group {
            as_identifier,
            participants: Vec::new(),
            sequence_tx,
        }
    }

    pub fn as_identifier(&self) -> Identifier {
        self.as_identifier.clone()
    }

    pub fn sequence(&self) -> u64 {
        self.sequence_tx
    }

    pub fn participants(&self) -> &Vec<Rc<RefCell<Session>>> {
        &self.participants
    }

    pub fn add_participant(&mut self, session: Rc<RefCell<Session>>) {
        self.participants.push(session);
    }

    pub fn remove_participant(&mut self, id: &Identifier) {
        self.participants
            .retain(|session| !session.borrow().with_identifier().eq(id));
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SelfError> {
        Ok(self.encrypt_group_message(plaintext)?.encode())
    }

    pub fn encrypt_group_message(&mut self, plaintext: &[u8]) -> Result<GroupMessage, SelfError> {
        let mut key_buf =
            vec![0u8; sodium_sys::crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize]
                .into_boxed_slice();
        let mut nonce_buf =
            vec![0u8; sodium_sys::crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize]
                .into_boxed_slice();
        let mut ciphertext_buf =
            vec![
                0u8;
                plaintext.len() + sodium_sys::crypto_aead_xchacha20poly1305_ietf_ABYTES as usize
            ];
        let mut ciphertext_len = ciphertext_buf.len() as u64;

        unsafe {
            sodium_sys::crypto_aead_xchacha20poly1305_ietf_keygen(key_buf.as_mut_ptr());

            sodium_sys::randombytes_buf(
                nonce_buf.as_mut_ptr() as *mut libc::c_void,
                nonce_buf.len() as u64,
            );

            sodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext_buf.as_mut_ptr(),
                &mut ciphertext_len,
                plaintext.as_ptr(),
                plaintext.len() as u64,
                std::ptr::null(),
                0_u64,
                std::ptr::null_mut(),
                nonce_buf.as_mut_ptr(),
                key_buf.as_mut_ptr(),
            );

            ciphertext_buf.to_vec().set_len(ciphertext_len as usize);
        }

        let mut group_message = GroupMessage::new(&ciphertext_buf);

        let key_and_nonce = [key_buf, nonce_buf].concat();

        for s in &mut self.participants {
            let (mtype, ciphertext) = s.get_mut().encrypt(&key_and_nonce)?;
            group_message.set_recipient_ciphertext(
                &s.borrow().with_identifier().id(),
                mtype,
                &ciphertext,
            );
        }

        self.sequence_tx += 1;

        Ok(group_message)
    }

    pub fn decrypt(&mut self, from: &Identifier, ciphertext: &[u8]) -> Result<Vec<u8>, SelfError> {
        let mut group_message = GroupMessage::decode(ciphertext)?;
        self.decrypt_group_message(from, &mut group_message)
    }

    pub fn decrypt_group_message(
        &mut self,
        from: &Identifier,
        group_message: &mut GroupMessage,
    ) -> Result<Vec<u8>, SelfError> {
        // TODO error handling
        let sender = match self
            .participants
            .iter()
            .position(|s| s.borrow().with_identifier().eq(from))
        {
            Some(p) => &mut self.participants[p],
            None => return Err(SelfError::CryptoUnknownGroupParticipant),
        };

        // TODO error handling
        let message = group_message
            .recipients
            .get_mut(&self.as_identifier.id())
            .unwrap();
        let mut plaintext_len = (group_message.ciphertext.len() as u32
            - sodium_sys::crypto_aead_xchacha20poly1305_ietf_ABYTES)
            as u64;
        let mut plaintext_buf = vec![0u8; plaintext_len as usize].into_boxed_slice();

        unsafe {
            let key_and_nonce = sender
                .get_mut()
                .decrypt(message.mtype, &mut message.ciphertext)?;

            let status = sodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt(
                plaintext_buf.as_mut_ptr(),
                &mut plaintext_len,
                std::ptr::null_mut(),
                group_message.ciphertext.as_mut_ptr(),
                group_message.ciphertext.len() as u64,
                std::ptr::null_mut(),
                0_u64,
                key_and_nonce[32..56].as_ptr(),
                key_and_nonce[0..32].as_ptr(),
            );

            if status != 0 {
                // TOOD error handling
            }

            let mut plaintext = plaintext_buf.to_vec();
            plaintext.set_len(plaintext_len as usize);

            Ok(plaintext)
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{crypto::account::Account, identifier::Identifier};

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

        let carol_skp = crate::keypair::signing::KeyPair::new();
        let carol_ekp = crate::keypair::exchange::KeyPair::new();
        let carol_id = Identifier::Referenced(carol_skp.public());
        let mut carol_acc = Account::new(carol_skp, carol_ekp);

        // generate one time keys or alice and get one for bob to use
        alice_acc
            .generate_one_time_keys(10)
            .expect("failed to generate one time keys");

        let alices_one_time_keys = alice_acc.one_time_keys();

        // generate one time keys or carol and get one for bob to use
        carol_acc
            .generate_one_time_keys(10)
            .expect("failed to generate one time keys");

        let carols_one_time_keys = carol_acc.one_time_keys();

        // create bob a new session with alice and carol
        let bobs_session_with_alice = bob_acc
            .create_outbound_session(alice_id.clone(), &alices_one_time_keys[0])
            .expect("failed to create outbound session");

        let bobs_session_with_carol = bob_acc
            .create_outbound_session(carol_id.clone(), &carols_one_time_keys[0])
            .expect("failed to create outbound session");

        // create a group with alice and carol
        let mut group = Group::new(bob_id.clone(), 0);
        group.add_participant(Rc::new(RefCell::new(bobs_session_with_alice)));
        group.add_participant(Rc::new(RefCell::new(bobs_session_with_carol)));

        let group_message = group
            .encrypt(b"hello alice and carol")
            .expect("failed to encrypt group message");
        let mut alices_message_from_bob = GroupMessage::decode(&group_message).unwrap();
        let mut carols_message_from_bob = GroupMessage::decode(&group_message).unwrap();

        // create alices session with bob
        let alices_one_time_message = alices_message_from_bob
            .one_time_key_message(b"alice")
            .expect("failed to find alice in the recipients");
        let alices_session_with_bob = alice_acc
            .create_inbound_session(bob_id.clone(), &alices_one_time_message)
            .expect("failed to create alices session with bob");

        // create carols session with bob
        let carols_one_time_message = carols_message_from_bob
            .one_time_key_message(b"carol")
            .expect("failed to find carol in the recipients");
        let carols_session_with_bob = carol_acc
            .create_inbound_session(bob_id.clone(), &carols_one_time_message)
            .expect("failed to create carols session with bob");

        // attempt to decrypt the group message intended for alice
        let mut alices_group = Group::new(alice_id.clone(), 0);
        alices_group.add_participant(Rc::new(RefCell::new(alices_session_with_bob)));
        let plaintext = alices_group
            .decrypt_group_message(&bob_id, &mut alices_message_from_bob)
            .expect("failed to decrypt message from bob");

        assert_eq!(plaintext, b"hello alice and carol");

        // attempt to decrypt the group message intended for alice
        let mut carols_group = Group::new(carol_id.clone(), 0);
        carols_group.add_participant(Rc::new(RefCell::new(carols_session_with_bob)));
        let plaintext = carols_group
            .decrypt_group_message(&bob_id, &mut carols_message_from_bob)
            .expect("failed to decrypt message from bob");

        assert_eq!(plaintext, b"hello alice and carol");
    }
}
