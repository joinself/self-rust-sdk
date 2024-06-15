use crate::crypto::e2e;
use crate::error::SelfError;
use crate::protocol::messaging;
use crate::storage::{query, query::QueuedMessage, Connection};
use crate::transport::websocket::Event;

pub fn inbox_queue(storage: &Connection, event: &mut Event) -> Result<(), SelfError> {
    storage.transaction(|txn| {
        // load the metrics for this to_address and from_address
        // determine if this message is in order or a duplicate
        let sequence_rx = match query::metrics_load_sequence_rx(
            txn,
            event.from_address.address(),
            event.to_address.address(),
        )? {
            Some(sequence_rx) => {
                if event.sequence <= sequence_rx {
                    // we've seen this event before, skip it
                    return Ok(());
                }
                sequence_rx
            }
            None => {
                query::address_create(txn, event.from_address.address())?;
                query::metrics_create(
                    txn,
                    event.from_address.address(),
                    event.to_address.address(),
                    0,
                    0,
                )?;

                0
            }
        };

        let event_type = to_event_type(event.content_type, event.sequence, sequence_rx + 1);
        if event_type == query::Event::DecryptedMessage {
            let content = match flatbuffers::root::<messaging::MlsMessage>(&event.content) {
                Ok(content) => content,
                Err(err) => {
                    println!("messaging event error: {}", err);
                    return Err(SelfError::WebsocketProtocolEncodingInvalid);
                }
            };

            let message = match content.message() {
                Some(message) => Vec::from(message.bytes()),
                None => return Err(SelfError::WebsocketProtocolEncodingInvalid),
            };

            // if this an in sequence message, we can already
            // decrypt it
            event.content = e2e::mls_group_decrypt(txn, event.to_address.address(), &message)?;
        }

        // store the event to our inbox
        query::address_create(txn, event.from_address.address())?;
        query::inbox_queue(
            txn,
            event_type,
            event.from_address.address(),
            event.to_address.address(),
            &event.content,
            event.timestamp,
            event.sequence,
        )
    })
}

pub struct InboxIterator {
    storage: *mut Connection,
    current: Option<QueuedMessage>,
}

impl InboxIterator {
    pub fn new(storage: *mut Connection) -> InboxIterator {
        InboxIterator {
            storage,
            current: None,
        }
    }

    pub fn next(&mut self) -> Option<&QueuedMessage> {
        unsafe {
            let result = (*self.storage).transaction(|txn| {
                // if there's an existing message, dequeue it
                if let Some(current) = &self.current {
                    query::inbox_dequeue(
                        txn,
                        &current.from_address,
                        &current.to_address,
                        current.sequence,
                    )?;
                }

                // queue up the next message
                self.current = query::inbox_next(txn)?;

                // if the message is encrypted, then encrypt it
                if let Some(next) = &mut self.current {
                    if next.event.eq(&query::Event::EncryptedMessage) {
                        let content =
                            match flatbuffers::root::<messaging::MlsMessage>(&next.message) {
                                Ok(content) => content,
                                Err(err) => {
                                    println!("messaging event error: {}", err);
                                    return Err(SelfError::WebsocketProtocolEncodingInvalid);
                                }
                            };

                        let message = match content.message() {
                            Some(message) => Vec::from(message.bytes()),
                            None => return Err(SelfError::WebsocketProtocolEncodingInvalid),
                        };

                        next.event = query::Event::DecryptedMessage;

                        // if this is an encrypted message, decrypt it
                        next.message = e2e::mls_group_decrypt(txn, &next.to_address, &message)?;

                        // update the inbox message with the decrypted message
                        query::inbox_update(
                            txn,
                            next.event,
                            &next.from_address,
                            &next.to_address,
                            &next.message,
                            next.sequence,
                        )?;
                    }
                }

                Ok(())
            });

            if let Err(err) = result {
                println!("inbox next message error: {}", err);
                return None;
            }
        }

        self.current.as_ref()
    }
}

fn to_event_type(
    content_type: messaging::ContentType,
    recevied_sequence: u64,
    next_sequence: u64,
) -> query::Event {
    match content_type {
        messaging::ContentType::MLS_COMMIT => query::Event::Commit,
        messaging::ContentType::MLS_KEY_PACKAGE => query::Event::KeyPackage,
        messaging::ContentType::MLS_MESSAGE => {
            if recevied_sequence == next_sequence {
                query::Event::DecryptedMessage
            } else {
                query::Event::EncryptedMessage
            }
        }
        messaging::ContentType::MLS_PROPOSAL => query::Event::Proposal,
        messaging::ContentType::MLS_WELCOME => query::Event::Welcome,
        _ => query::Event::Invalid,
    }
}

/*
            unsafe {
                let result = (*storage).transaction(|txn| {
                    query::inbox_dequeue(txn, &next.from_address, &next.to_address, next.sequence)?;
                    next_message = query::inbox_next(txn)?;

                    if let Some(next) = &mut next_message{
                        if next.event.eq(&query::Event::Message) {
                            // if this is a message, decrypt it
                            next.message =
                                e2e::mls_group_decrypt(txn, &next.to_address, &next.message)?;
                        }
                    }

                    Ok(())
                });

                if let Err(err) = result {
                    println!("transaction failed: {}", err);
                }
            }

*/
