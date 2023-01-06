use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use crate::crypto::session::Session;
use crate::error::SelfError;

pub struct Group {
    id: String,
    participants: Vec<Participant>,
}

struct Participant {
    id: String,
    session: Session,
}

#[derive(Serialize, Deserialize)]
struct GroupMessage {
    pub recipients: HashMap<String, Message>,
    pub ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct Message {
    pub mtype: u64,
    pub ciphertext: String,
}

impl GroupMessage {
    fn new(ciphertext: &[u8]) -> GroupMessage {
        return GroupMessage {
            recipients: HashMap::new(),
            ciphertext: base64::encode_config(ciphertext, base64::STANDARD_NO_PAD),
        };
    }

    fn from_bytes(bytes: &[u8]) -> GroupMessage {
        // TODO add error handling
        serde_json::from_slice(bytes).unwrap()
    }

    fn set_recipient_ciphertext(&mut self, id: &str, mtype: u64, ciphertext: &[u8]) {
        self.recipients.insert(
            String::from(id),
            Message {
                mtype,
                ciphertext: base64::encode_config(ciphertext, base64::STANDARD_NO_PAD),
            },
        );
    }

    fn encode(&self) -> Vec<u8> {
        // TODO error handle this
        return serde_json::to_vec(self).unwrap();
    }
}

impl Group {
    pub fn new(id: &str) -> Group {
        return Group {
            id: String::from(id),
            participants: Vec::new(),
        };
    }

    pub fn add_participant(&mut self, id: String, session: Session) {
        self.participants.push(Participant { id, session });
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
            let (mtype, ciphertext) = p.session.encrypt(&key_and_nonce)?;

            group_message.set_recipient_ciphertext(&p.id, mtype, &ciphertext);
        }

        return Ok(group_message.encode());
    }

    pub fn decrypt(&mut self, from: &str, ciphertext: &[u8]) -> Result<Vec<u8>, SelfError> {
        let sender = match self.participants.iter().position(|p| p.id == from) {
            Some(p) => &mut self.participants[p],
            None => return Err(SelfError::CryptoUnknownGroupParticipant),
        };

        // TODO error handling
        let group_message = GroupMessage::from_bytes(ciphertext);
        let message = group_message.recipients.get(&self.id).unwrap();
        let mut decoded_ciphertext =
            base64::decode_config(&message.ciphertext, base64::STANDARD_NO_PAD).unwrap();

        sender
            .session
            .decrypt(message.mtype, &mut decoded_ciphertext)?;

        return Ok(Vec::new());
    }
}
