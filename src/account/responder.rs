use crate::account::token::token_create_authorization;
use crate::crypto::random_id;
use crate::error::SelfError;
use crate::identifier::Identifier;
use crate::message::{
    self, ChatDelivered, ChatRead, ConnectionResponse, Content, Envelope, ResponseStatus,
};
use crate::storage::Storage;
use crate::token::Token;

use std::sync::MutexGuard;

/// build a response to accept the connection request
pub fn connection_request_accept(
    message: &Envelope,
    storage: &mut MutexGuard<Storage>,
) -> Result<(Identifier, Vec<u8>), SelfError> {
    if let Some(payload) = message.content.content_get() {
        let connection_req = message::ConnectionRequest::decode(&payload)?;

        // save the tokens from the sender
        if let Some(authorization_token) = connection_req.ath {
            storage.token_create(
                &message.from,
                Some(&message.to),
                i64::MAX,
                &Token::decode(&authorization_token)?,
            )?;
        }

        if let Some(notification_token) = connection_req.ntf {
            storage.token_create(
                &message.from,
                Some(&message.to),
                i64::MAX,
                &Token::decode(&notification_token)?,
            )?;
        }

        // generate tokens for the sender of the request
        let token = token_create_authorization(storage, Some(&message.from), &message.to, None)?;

        // respond to sender
        let content = ConnectionResponse {
            ath: Some(token.encode()?),
            ntf: None, // TODO handle notification tokens,
            sts: ResponseStatus::Accepted,
        }
        .encode()?;

        // send a response accepting the request to the sender
        let mut msg = Content::new();

        if let Some(cti) = message.content.cti_get() {
            msg.cti_set(&cti);
        }
        msg.type_set(message::MESSAGE_TYPE_CONNECTION_RES);
        msg.issued_at_set(crate::time::now().timestamp());
        msg.content_set(&content);

        return Ok((message.from.clone(), msg.encode()?));
    }

    Err(SelfError::MessageContentMissing)
}

pub fn connection_request_reject(
    message: &Envelope,
    storage: &mut MutexGuard<Storage>,
) -> Result<(Identifier, Vec<u8>), SelfError> {
    if let Some(payload) = message.content.content_get() {
        let connection_req = message::ConnectionRequest::decode(&payload)?;

        // save the tokens from the sender, even though we are rejecting the request
        // so we can avoid doing POW over the message to send the response
        if let Some(authorization_token) = connection_req.ath {
            storage.token_create(
                &message.from,
                Some(&message.to),
                i64::MAX,
                &Token::decode(&authorization_token)?,
            )?;
        }

        if let Some(notification_token) = connection_req.ntf {
            storage.token_create(
                &message.from,
                Some(&message.to),
                i64::MAX,
                &Token::decode(&notification_token)?,
            )?;
        }

        // respond to sender
        let content = ConnectionResponse {
            ath: None,
            ntf: None,
            sts: ResponseStatus::Rejected,
        }
        .encode()?;

        // send a response accepting the request to the sender
        let mut msg = Content::new();

        if let Some(cti) = message.content.cti_get() {
            msg.cti_set(&cti);
        }
        msg.type_set(message::MESSAGE_TYPE_CONNECTION_RES);
        msg.issued_at_set(crate::time::now().timestamp());
        msg.content_set(&content);

        return Ok((message.from.clone(), msg.encode()?));
    }

    Err(SelfError::MessageContentMissing)
}

/// build a response to indicate a message has been del;ivered
pub fn chat_message_delivered(message: &Envelope) -> Result<(Identifier, Vec<u8>), SelfError> {
    if let Some(message_id) = message.content.cti_get() {
        let mut msg = Content::new();
        msg.cti_set(&random_id());
        msg.type_set(message::MESSAGE_TYPE_CHAT_DELIVERED);
        msg.issued_at_set(crate::time::now().timestamp());
        msg.content_set(
            &ChatDelivered {
                dlm: vec![message_id],
            }
            .encode()?,
        );

        return Ok((message.from.clone(), msg.encode()?));
    }

    Err(SelfError::MessageCTIMissing)
}

/// build a response to indicate a message has been read
pub fn chat_message_read(message: &Envelope) -> Result<(Identifier, Vec<u8>), SelfError> {
    if let Some(message_id) = message.content.cti_get() {
        // respond to sender
        let content = ChatRead {
            rdm: vec![message_id],
        }
        .encode()?;

        // send a response accepting the request to the sender
        let mut msg = Content::new();

        msg.cti_set(&random_id());
        msg.type_set(message::MESSAGE_TYPE_CHAT_READ);
        msg.issued_at_set(crate::time::now().timestamp());
        msg.content_set(&content);

        return Ok((message.from.clone(), msg.encode()?));
    }

    Err(SelfError::MessageCTIMissing)
}
