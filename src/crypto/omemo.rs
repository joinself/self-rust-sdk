use crate::crypto::session::Session;
use crate::error::SelfError;

use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct Group {
    id: Vec<u8>,
    participants: Vec<Participant>,
}

struct Participant {
    id: Vec<u8>,
    session: Arc<Mutex<Session>>,
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
        return GroupMessage {
            recipients: HashMap::new(),
            ciphertext: ciphertext.to_vec(),
        };
    }

    pub fn decode(bytes: &[u8]) -> Result<GroupMessage, SelfError> {
        return match ciborium::de::from_reader(bytes) {
            Ok(keypair) => Ok(keypair),
            Err(_) => Err(SelfError::CryptoGroupMessageInvalid),
        };
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(self, &mut encoded).unwrap();
        return encoded;
    }

    pub fn one_time_key_message(&self, recipient: &[u8]) -> Option<Vec<u8>> {
        match self.recipients.get(recipient) {
            Some(message) => {
                if message.mtype != 0 {
                    return None;
                }
                return Some(message.ciphertext.clone());
            }
            None => None,
        }
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
    pub fn new(id: &[u8]) -> Group {
        return Group {
            id: id.to_vec(),
            participants: Vec::new(),
        };
    }

    pub fn add_participant(&mut self, id: &[u8], session: Arc<Mutex<Session>>) {
        self.participants.push(Participant {
            id: id.to_vec(),
            session,
        });
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SelfError> {
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
                0 as u64,
                std::ptr::null_mut(),
                nonce_buf.as_mut_ptr(),
                key_buf.as_mut_ptr(),
            );

            ciphertext_buf.to_vec().set_len(ciphertext_len as usize);
        }

        let mut group_message = GroupMessage::new(&ciphertext_buf);

        let key_and_nonce = [key_buf, nonce_buf].concat();

        for p in &mut self.participants {
            let session = p.session.lock().map_err(|_| SelfError::CryptoUnknown)?;
            let (mtype, ciphertext) = session.encrypt(&key_and_nonce)?;
            drop(session);
            group_message.set_recipient_ciphertext(&p.id, mtype, &ciphertext);
        }

        return Ok(group_message.encode());
    }

    pub fn decrypt(&mut self, from: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SelfError> {
        let mut group_message = GroupMessage::decode(ciphertext)?;
        return self.decrypt_group_message(from, &mut group_message);
    }

    pub fn decrypt_group_message(
        &mut self,
        from: &[u8],
        group_message: &mut GroupMessage,
    ) -> Result<Vec<u8>, SelfError> {
        // TODO error handling
        let sender = match self.participants.iter().position(|p| p.id.eq(from)) {
            Some(p) => &mut self.participants[p],
            None => return Err(SelfError::CryptoUnknownGroupParticipant),
        };

        // TODO error handling
        let message = group_message.recipients.get_mut(&self.id).unwrap();
        let mut plaintext_len = (group_message.ciphertext.len() as u32
            - sodium_sys::crypto_aead_xchacha20poly1305_ietf_ABYTES)
            as u64;
        let mut plaintext_buf = vec![0u8; plaintext_len as usize].into_boxed_slice();

        unsafe {
            let session = sender.session.lock().map_err(|_| SelfError::CryptoUnknown)?;
            let key_and_nonce = session.decrypt(
                message.mtype, 
                &mut message.ciphertext
            )?;
            drop(session);

            let status = sodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt(
                plaintext_buf.as_mut_ptr(),
                &mut plaintext_len,
                std::ptr::null_mut(),
                group_message.ciphertext.as_mut_ptr(),
                group_message.ciphertext.len() as u64,
                std::ptr::null_mut(),
                0 as u64,
                key_and_nonce[32..56].as_ptr(),
                key_and_nonce[0..32].as_ptr(),
            );

            if status != 0 {
                // TOOD error handling
            }

            let mut plaintext = plaintext_buf.to_vec();
            plaintext.set_len(plaintext_len as usize);

            return Ok(plaintext);
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::crypto::account::Account;
    use serde_json::Value;
    use std::collections::HashMap;

    #[test]
    fn encrypt_and_decrypt() {
        let alice_skp = crate::keypair::signing::KeyPair::new();
        let alice_ekp = crate::keypair::exchange::KeyPair::new();
        let alice_curve25519_pk = alice_ekp.public().clone();
        let mut alice_acc = Account::new(alice_skp, alice_ekp);

        let bob_skp = crate::keypair::signing::KeyPair::new();
        let bob_ekp = crate::keypair::exchange::KeyPair::new();
        let bob_curve25519_pk = bob_ekp.public().clone();
        let mut bob_acc = Account::new(bob_skp, bob_ekp);

        let carol_skp = crate::keypair::signing::KeyPair::new();
        let carol_ekp = crate::keypair::exchange::KeyPair::new();
        let carol_curve25519_pk = carol_ekp.public().clone();
        let mut carol_acc = Account::new(carol_skp, carol_ekp);

        // generate one time keys or alice and get one for bob to use
        alice_acc
            .generate_one_time_keys(10)
            .expect("failed to generate one time keys");

        let alices_one_time_keys: HashMap<String, Value> =
            serde_json::from_slice(&alice_acc.one_time_keys())
                .expect("failed to load alices one time keys");

        let alices_one_time_key = alices_one_time_keys
            .get("curve25519")
            .and_then(|keys| keys.as_object()?.get("AAAAAQ"))
            .unwrap()
            .as_str()
            .unwrap();

        // generate one time keys or carol and get one for bob to use
        carol_acc
            .generate_one_time_keys(10)
            .expect("failed to generate one time keys");

        let carols_one_time_keys: HashMap<String, Value> =
            serde_json::from_slice(&carol_acc.one_time_keys())
                .expect("failed to load alices one time keys");

        let carols_one_time_key = carols_one_time_keys
            .get("curve25519")
            .and_then(|keys| keys.as_object()?.get("AAAAAQ"))
            .unwrap()
            .as_str()
            .unwrap();

        // create bob a new session with alice and carol
        let bobs_session_with_alice = bob_acc
            .create_outbound_session(&alice_curve25519_pk, alices_one_time_key.as_bytes())
            .expect("failed to create outbound session");

        let bobs_session_with_carol = bob_acc
            .create_outbound_session(&carol_curve25519_pk, carols_one_time_key.as_bytes())
            .expect("failed to create outbound session");

        // create a group with alice and carol
        let mut group = Group::new(b"bob");
        group.add_participant(b"alice", Arc::new(Mutex::new(bobs_session_with_alice)));
        group.add_participant(b"carol", Arc::new(Mutex::new(bobs_session_with_carol)));

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
            .create_inbound_session(&bob_curve25519_pk, &alices_one_time_message)
            .expect("failed to create alices session with bob");

        // create carols session with bob
        let carols_one_time_message = carols_message_from_bob
            .one_time_key_message(b"carol")
            .expect("failed to find carol in the recipients");
        let carols_session_with_bob = carol_acc
            .create_inbound_session(&bob_curve25519_pk, &carols_one_time_message)
            .expect("failed to create carols session with bob");

        // attempt to decrypt the group message intended for alice
        let mut alices_group = Group::new(b"alice");
        alices_group.add_participant(b"bob", Arc::new(Mutex::new(alices_session_with_bob)));
        let plaintext = alices_group
            .decrypt_group_message(b"bob", &mut alices_message_from_bob)
            .expect("failed to decrypt message from bob");

        assert_eq!(plaintext, b"hello alice and carol");

        // attempt to decrypt the group message intended for alice
        let mut carols_group = Group::new(b"carol");
        carols_group.add_participant(b"bob", Arc::new(Mutex::new(carols_session_with_bob)));
        let plaintext = carols_group
            .decrypt_group_message(b"bob", &mut carols_message_from_bob)
            .expect("failed to decrypt message from bob");

        assert_eq!(plaintext, b"hello alice and carol");
    }
}
