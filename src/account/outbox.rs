use crate::error::SelfError;
use crate::keypair::signing::KeyPair;
use crate::storage::{query, query::QueuedMessage, Connection};

pub struct OutboxIterator<'c> {
    storage: &'c Connection,
    current: Option<(KeyPair, QueuedMessage)>,
}

impl<'c> OutboxIterator<'c> {
    pub fn new(storage: &'c Connection) -> OutboxIterator<'c> {
        OutboxIterator {
            storage,
            current: None,
        }
    }

    pub fn next(&mut self) -> Option<&(KeyPair, QueuedMessage)> {
        let result = (*self.storage).transaction(|txn| {
            // if there's an existing message, dequeue it
            if let Some((_, current)) = &self.current {
                query::outbox_dequeue(
                    txn,
                    &current.from_address,
                    &current.to_address,
                    current.sequence,
                )?;
            }

            // TODO decide if we need to re-encrypt message
            // queue up the next message
            let next = match query::outbox_next(txn)? {
                Some(next) => next,
                None => {
                    self.current = None;
                    return Ok(());
                }
            };

            let as_address = match query::keypair_lookup::<KeyPair>(txn, &next.from_address)? {
                Some(as_address) => as_address,
                None => return Err(SelfError::KeyPairNotFound),
            };

            self.current = Some((as_address, next));

            Ok(())
        });

        if let Err(err) = result {
            println!("inbox next message error: {}", err);
            return None;
        }

        self.current.as_ref()
    }
}
