use prost::Message;

use crate::account::{self, inbox, outbox, KeyPurpose};
use crate::credential::{
    Address, Credential, Presentation, VerifiableCredential, VerifiablePresentation,
};
use crate::crypto::{self, e2e};
use crate::error::SelfError;
use crate::hashgraph::{Hashgraph, Method, Operation, Role};
use crate::keypair::signing::{self, KeyPair, PublicKey};
use crate::message;
use crate::object;
use crate::protocol::p2p;
use crate::storage::{query, Connection};
use crate::time;
use crate::token;
use crate::transport::object::ObjectStore;
use crate::transport::rpc::Rpc;
use crate::transport::websocket::{self, Subscription, Websocket};

use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub fn identity_list(storage: &Connection) -> Result<Vec<signing::PublicKey>, SelfError> {
    let mut identifiers = Vec::new();

    storage.transaction(|txn| {
        identifiers = query::keypair_identifiers(txn)?;

        Ok(())
    })?;

    Ok(identifiers
        .iter()
        .map(|i| PublicKey::from_bytes(i).expect("failed to load public key"))
        .collect())
}

pub fn identity_resolve(
    storage: &Connection,
    rpc: &Rpc,
    address: &[u8],
) -> Result<Hashgraph, SelfError> {
    let mut operations = Vec::new();
    let mut synced_at = None;

    storage.transaction(|txn| {
        synced_at = query::identity_synced_at(txn, address)?;
        operations = query::identity_operation_log(txn, address)?;

        Ok(())
    })?;

    let mut hashgraph = Hashgraph::load(&operations, false)?;

    if let Some(synced_at) = synced_at {
        // this has been synced within the last 5 minutes, return the cached results
        if (time::now() - Duration::from_secs(300)).timestamp() < synced_at {
            return Ok(hashgraph);
        }
    }

    let sequence = operations.len();
    operations = rpc.resolve(address, sequence as u32)?;

    for operation in &operations {
        hashgraph.execute(operation.clone())?;
    }

    storage.transaction(|txn| {
        for (seq, op) in operations.iter().enumerate() {
            query::identity_operation_create(txn, address, (sequence + seq) as u32, op)?;
        }

        Ok(())
    })?;

    Ok(hashgraph)
}

pub fn identity_execute(
    storage: &Connection,
    rpc: &Rpc,
    operation: &mut Operation,
) -> Result<(), SelfError> {
    storage.transaction(|txn| {
        if operation.sequence() == 0 {
            let identifier_kp =
                match query::keypair_lookup::<signing::KeyPair>(txn, operation.identifier())? {
                    Some(identifier_kp) => identifier_kp,
                    None => return Err(SelfError::KeyPairNotFound),
                };

            // if this is the first operation, create the identity
            query::identity_create(txn, identifier_kp.address(), 0, crate::time::unix())?;

            // TODO check that key has no existing roles...
            query::keypair_assign(txn, identifier_kp.address(), KeyPurpose::Identifier as u64)?;

            // this is the first operation, so sign it with the identifier key
            operation.sign(&identifier_kp);
        }

        let signers = operation.signers().to_owned();

        // iterate through signers and sign the operation
        for key in signers {
            if key.matches(operation.identifier()) {
                continue;
            }

            let signing_kp = match query::keypair_lookup::<signing::KeyPair>(txn, key.address())? {
                Some(signing_kp) => signing_kp,
                None => return Err(SelfError::KeyPairNotFound),
            };

            operation.sign(&signing_kp);
        }

        // assign roles for new keys and link them with the identifier
        for (roles, key) in operation.created() {
            query::keypair_assign(txn, key, *roles)?;
            query::keypair_associate(txn, operation.identifier(), key, operation.sequence())?;
        }

        // assign roles for existing keys
        for (roles, key) in operation.created() {
            query::keypair_assign(txn, key, *roles)?;
        }

        Ok(())
    })?;

    // TODO consider recovering from failed RPC call...
    let signed_operation = operation.build()?;
    rpc.execute(operation.identifier(), &signed_operation)?;

    storage.transaction(|txn| {
        query::identity_operation_create(
            txn,
            operation.identifier(),
            operation.sequence(),
            &signed_operation,
        )
    })
}

pub fn credential_issue(
    storage: &Connection,
    credential: &Credential,
) -> Result<VerifiableCredential, SelfError> {
    let mut issuer_kp: Option<KeyPair> = None;

    let (signer, created) = match credential.signer() {
        Some(signer) => signer,
        None => return Err(SelfError::CredentialSignerMissing),
    };

    storage.transaction(|txn| {
        // TODO check keypair has role if assigned to identifier...
        issuer_kp = query::keypair_lookup(txn, signer.address())?;
        Ok(())
    })?;

    let issuer_kp = match issuer_kp {
        Some(issuer_kp) => issuer_kp,
        None => return Err(SelfError::KeyPairNotFound),
    };

    credential.sign(&issuer_kp, *created)
}

pub fn credential_store(
    storage: &Connection,
    credential: &VerifiableCredential,
) -> Result<(), SelfError> {
    credential.validate()?;

    let issuer = credential.issuer()?;
    let bearer = credential.credential_subject()?;
    let credential_type = serde_json::to_vec(credential.credential_type())
        .expect("failed to serialize credential type");
    let credential_encoded = credential.into_bytes()?;

    storage.transaction(|txn| {
        query::address_create(txn, issuer.address().address())?;

        query::credential_store(
            txn,
            issuer.address().address(),
            bearer.address().address(),
            &credential_type,
            &credential_encoded,
        )
    })
}

pub fn credential_lookup_by_issuer(
    storage: &Connection,
    issuer: &PublicKey,
) -> Result<Vec<VerifiableCredential>, SelfError> {
    let mut credentials = Vec::new();
    let mut encoded_credentials = Vec::new();

    storage.transaction(|txn| {
        encoded_credentials = query::credential_lookup_by_issuer(txn, issuer.address())?;
        Ok(())
    })?;

    for credential in encoded_credentials {
        credentials.push(VerifiableCredential::from_bytes(&credential)?)
    }

    Ok(credentials)
}

pub fn credential_lookup_by_bearer(
    storage: &Connection,
    bearer: &PublicKey,
) -> Result<Vec<VerifiableCredential>, SelfError> {
    let mut credentials = Vec::new();
    let mut encoded_credentials = Vec::new();

    storage.transaction(|txn| {
        encoded_credentials = query::credential_lookup_by_bearer(txn, bearer.address())?;
        Ok(())
    })?;

    for credential in encoded_credentials {
        credentials.push(VerifiableCredential::from_bytes(&credential)?)
    }

    Ok(credentials)
}

pub fn credential_lookup_by_credential_type(
    storage: &Connection,
    credential_type: &[&str],
) -> Result<Vec<VerifiableCredential>, SelfError> {
    let mut credentials = Vec::new();
    let mut encoded_credentials = Vec::new();
    let credential_type =
        serde_json::to_vec(credential_type).expect("failed to encode credential type");

    storage.transaction(|txn| {
        encoded_credentials = query::credential_lookup_by_credential_type(txn, &credential_type)?;
        Ok(())
    })?;

    for credential in encoded_credentials {
        credentials.push(VerifiableCredential::from_bytes(&credential)?)
    }

    Ok(credentials)
}

pub fn presentation_issue(
    storage: &Connection,
    presentation: &Presentation,
) -> Result<VerifiablePresentation, SelfError> {
    let mut signers = Vec::new();

    storage.transaction(|txn| {
        // TODO check keypair has role if assigned to identifier...
        for signer in presentation.required_signers() {
            match signer.method() {
                Method::Key => {
                    match query::keypair_lookup::<KeyPair>(txn, signer.address().address())? {
                        Some(signer_kp) => {
                            signers.push((signer.to_owned(), signer_kp));
                        }
                        None => return Err(SelfError::KeyPairNotFound),
                    }
                }
                Method::Aure => {
                    let signing_key = match signer.signing_key() {
                        Some(signing_key) => signing_key,
                        None => continue,
                    };

                    match query::keypair_lookup_with::<signing::KeyPair>(
                        txn,
                        signing_key.address(),
                        Role::Assertion as u64,
                    )? {
                        Some(signer_kp) => signers.push((signer.to_owned(), signer_kp)),
                        None => return Err(SelfError::KeyPairNotFound),
                    };
                }
            }
        }

        Ok(())
    })?;

    let signer_refs = signers
        .iter()
        .map(|(address, signing_kp)| (address, signing_kp))
        .collect::<Vec<(&Address, &KeyPair)>>();

    presentation.sign(&signer_refs, crate::time::now())
}

pub fn object_upload(
    storage: &Connection,
    object_store: &ObjectStore,
    as_address: &PublicKey,
    object: &object::Object,
    persist_local: bool,
) -> Result<(), SelfError> {
    let mut signing_kp: Option<KeyPair> = None;

    if object.key().is_none() {
        return Err(SelfError::ObjectKeyMissing);
    }

    if object.data().is_none() {
        return Err(SelfError::ObjectDataInvalid);
    }

    storage.transaction(|txn| {
        signing_kp = query::keypair_lookup(txn, as_address.address())?;

        if persist_local {
            query::object_create(
                txn,
                object.id(),
                object.key().expect("object key missing"),
                object.data().expect("object data missing"),
            )?;
        }

        Ok(())
    })?;

    let signing_kp = match signing_kp {
        Some(signing_kp) => signing_kp,
        None => return Err(SelfError::KeyPairNotFound),
    };

    object_store.upload(object, &signing_kp)
}

pub fn object_download(
    storage: &Connection,
    object_store: &ObjectStore,
    as_address: &PublicKey,
    object: &mut object::Object,
) -> Result<(), SelfError> {
    let mut signing_kp: Option<KeyPair> = None;
    let mut stored_object: Option<(Vec<u8>, Vec<u8>)> = None;

    storage.transaction(|txn| {
        stored_object = query::object_lookup(txn, object.id())?;

        if stored_object.is_some() {
            return Ok(());
        }

        signing_kp = query::keypair_lookup(txn, as_address.address())?;

        Ok(())
    })?;

    match stored_object {
        Some((key, data)) => object.decrypt_with_key(data, key),
        None => object_store.download(object),
    }
}

pub fn inbox_open(storage: &Connection, websocket: &Websocket) -> Result<PublicKey, SelfError> {
    let signing_kp = KeyPair::new();
    let mut key_packages: Vec<Vec<u8>> = Vec::new();
    let timestamp = time::unix();

    let subscription_token =
        token::Subscription::new(&signing_kp, signing_kp.public(), timestamp, i64::MAX);

    storage.transaction(|txn| {
        query::keypair_create(txn, signing_kp.clone(), 0, timestamp)?;

        query::subscription_create(txn, signing_kp.address(), signing_kp.address(), timestamp)?;

        query::token_create(
            txn,
            query::Token::Subscription,
            signing_kp.address(),
            signing_kp.address(),
            signing_kp.address(),
            subscription_token.as_bytes(),
        )?;

        // setup the mls credentials and generate some key packages
        key_packages = e2e::mls_inbox_setup(txn, &signing_kp, 4)?;

        // TODO mark this keypair as used as a messaging inbox

        Ok(())
    })?;

    // open & subscribe...
    websocket.open(&signing_kp)?;
    websocket.subscribe(&[Subscription {
        to_address: signing_kp.public().to_owned(),
        as_address: signing_kp.to_owned(),
        token: Some(token::Token::Subscription(subscription_token)),
        last_active: timestamp,
        last_message: timestamp,
    }])?;

    Ok(signing_kp.public().to_owned())
}

pub fn subscription_load(storage: &Connection, websocket: &Websocket) -> Result<(), SelfError> {
    let mut subscription_list = Vec::new();

    storage.transaction(|txn| {
        subscription_list = query::subscription_list(txn)?;
        Ok(())
    })?;

    if subscription_list.is_empty() {
        return Ok(());
    }

    let mut subscriptions = Vec::new();
    let timestamp = crate::time::unix();

    for (to_address, as_address, token, from) in subscription_list {
        subscriptions.push(Subscription {
            to_address: PublicKey::from_bytes(&to_address)?,
            as_address: KeyPair::decode(&as_address)?,
            token: token.map(|t| token::Token::decode(&t).expect("invalid token")),
            last_message: from,
            last_active: timestamp,
        });
    }

    websocket.subscribe(&subscriptions)
}

pub fn outbox_process(storage: &Connection, websocket: &Websocket) -> Result<(), SelfError> {
    let mut iterator = outbox::OutboxIterator::new(storage);

    while let Some((as_address, next)) = iterator.next() {
        let payload = websocket::assemble_payload_message(
            as_address,
            &PublicKey::from_bytes(&next.to_address)?,
            next.sequence,
            &next.message,
        )?;

        let (resp_tx, resp_rx) = crossbeam::channel::bounded(1);

        websocket.send(
            as_address,
            &payload,
            None,
            Arc::new(move |resp| {
                resp_tx.send(resp).unwrap();
            }),
        );

        resp_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| SelfError::HTTPRequestConnectionTimeout)??;
    }

    Ok(())
}

pub fn inbox_process(
    storage: &Connection,
    on_message: account::OnMessageCB,
) -> Result<(), SelfError> {
    let mut iterator = inbox::InboxIterator::new(storage);

    while let Some(next) = iterator.next() {
        let decoded_message = match p2p::Message::decode(next.message.as_ref()) {
            Ok(decoded_message) => decoded_message,
            Err(err) => {
                println!("received invalid protobuf message: {}", err);
                return Err(SelfError::MessageEncodingInvalid);
            }
        };

        let from_address = PublicKey::from_bytes(&next.from_address)?;
        let to_address = PublicKey::from_bytes(&next.to_address)?;
        let content_type = message::ContentType::from(decoded_message.content_type());
        let content = message::Content::decode(content_type, &decoded_message.content)?;

        on_message(message::Message::new(
            decoded_message.id,
            from_address,
            to_address,
            content,
            next.sequence,
            next.timestamp,
        ));
    }

    Ok(())
}

pub fn group_create(
    storage: &Connection,
    websocket: &Websocket,
    as_address: &PublicKey,
) -> Result<PublicKey, SelfError> {
    let group_kp = KeyPair::new();
    let group_pk = group_kp.public().to_owned();
    let mut as_keypair: Option<KeyPair> = None;
    let now = time::unix();

    let subscription_token =
        token::Subscription::new(&group_kp, as_address, time::unix(), i64::MAX);

    storage.transaction(|txn| {
        // TODO think about how what roles actually means here...
        as_keypair = match query::keypair_lookup(txn, as_address.address())? {
            Some(as_keypair) => Some(as_keypair),
            None => return Err(SelfError::KeyPairNotFound),
        };

        query::keypair_create(
            txn,
            group_kp.clone(),
            KeyPurpose::Inbox as u64,
            crate::time::unix(),
        )?;
        query::group_create(txn, group_kp.address(), 2)?;
        query::group_member_add(txn, group_kp.address(), as_address.address())?;
        e2e::mls_group_create(txn, group_kp.address(), as_keypair.as_ref().unwrap())?;
        query::token_create(
            txn,
            query::Token::Subscription,
            group_kp.address(),
            as_address.address(),
            group_kp.address(),
            subscription_token.as_bytes(),
        )
    })?;

    let as_keypair = match as_keypair {
        Some(as_keypair) => as_keypair,
        None => return Err(SelfError::KeyPairNotFound),
    };

    websocket.open(&group_kp)?;
    websocket.subscribe(&[Subscription {
        to_address: group_kp.public().to_owned(),
        as_address: as_keypair,
        token: Some(token::Token::Subscription(subscription_token)),
        last_message: now,
        last_active: now,
    }])?;

    Ok(group_pk)
}

pub fn group_member_as(
    storage: &Connection,
    group_address: &PublicKey,
) -> Result<Option<PublicKey>, SelfError> {
    let mut as_keypair: Option<PublicKey> = None;

    storage.transaction(|txn| {
        // TODO think about how what roles actually means here...
        as_keypair = match query::group_as(txn, group_address.address())? {
            Some(as_keypair) => Some(PublicKey::from_bytes(&as_keypair)?),
            None => return Err(SelfError::KeyPairNotFound),
        };

        Ok(())
    })?;

    Ok(as_keypair)
}

pub fn connection_negotiate(
    storage: &Connection,
    websocket: &Websocket,
    as_address: &PublicKey,
    with_address: &PublicKey,
) -> Result<(), SelfError> {
    let mut key_package_payload: Option<Vec<u8>> = None;
    let mut as_keypair: Option<KeyPair> = None;
    let mut sequence_tx = 0;
    let timestamp = time::unix();

    storage.transaction(|txn| {
        as_keypair = query::keypair_lookup(txn, as_address.address())?;

        let as_address = match &as_keypair {
            Some(as_address) => as_address,
            None => return Err(SelfError::KeyPairNotFound),
        };

        query::address_create(txn, with_address.address())?;
        sequence_tx = match query::metrics_load(txn, as_address.address(), with_address.address())?
        {
            Some((sequence_tx, _)) => {
                query::metrics_update_sequence_tx(
                    txn,
                    as_address.address(),
                    with_address.address(),
                    sequence_tx + 1,
                )?;
                sequence_tx + 1
            }
            None => {
                query::metrics_create(txn, as_address.address(), with_address.address(), 1, 0)?;
                1
            }
        };

        // generate a key package
        let key_package = e2e::mls_key_package_create(txn, as_address)?;

        // generate a temporary send token

        // generate a temporary push token

        // load metrics to get sequence...

        // assemble key package message
        let key_package_encoded = websocket::assemble_payload_key_package(
            as_address,
            with_address,
            sequence_tx,
            &key_package,
            None,
            None,
        )?;

        // queue message in inbox
        query::outbox_queue(
            txn,
            query::Event::KeyPackage,
            as_address.address(),
            with_address.address(),
            &key_package_encoded,
            timestamp,
            sequence_tx,
        )?;

        key_package_payload = Some(key_package_encoded);

        Ok(())
    })?;

    // TODO send with any tokens we may have...

    let (resp_tx, resp_rx) = crossbeam::channel::bounded(1);

    let as_keypair = match &as_keypair {
        Some(as_keypair) => as_keypair,
        None => return Err(SelfError::KeyPairNotFound),
    };

    let key_package_payload = match &key_package_payload {
        Some(key_package_payload) => key_package_payload,
        None => return Err(SelfError::MessagePayloadInvalid),
    };

    // websocket send
    websocket.send(
        as_keypair,
        key_package_payload,
        None,
        Arc::new(move |resp| {
            resp_tx.send(resp).unwrap();
        }),
    );

    resp_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| SelfError::HTTPRequestConnectionTimeout)??;

    // notify...

    storage.transaction(|txn| {
        query::outbox_dequeue(
            txn,
            as_address.address(),
            with_address.address(),
            sequence_tx,
        )
    })
}

pub fn connection_establish(
    storage: &Connection,
    websocket: &Websocket,
    as_address: &PublicKey,
    with_address: &PublicKey,
    key_package: &[u8],
) -> Result<(), SelfError> {
    let group_kp = KeyPair::new();

    let mut welcome_payload: Option<Vec<u8>> = None;
    let mut commit_payload: Option<Vec<u8>> = None;
    let mut as_keypair: Option<KeyPair> = None;
    let mut sequence_tx = 0;
    let timestamp = time::unix();

    // generate tokens for ourself and our counterparty
    let as_send_token = token::Send::new(&group_kp, Some(as_address), time::unix(), i64::MAX);
    let with_send_token = token::Send::new(&group_kp, Some(with_address), time::unix(), i64::MAX);

    let as_subscription_token =
        token::Subscription::new(&group_kp, as_address, time::unix(), i64::MAX);

    let with_subscription_token =
        token::Subscription::new(&group_kp, with_address, time::unix(), i64::MAX);

    // TODO generate push token

    storage.transaction(|txn| {
        as_keypair = query::keypair_lookup(txn, as_address.address())?;

        let as_address = match &as_keypair {
            Some(as_address) => as_address,
            None => return Err(SelfError::KeyPairNotFound),
        };

        // TODO think about how what roles actually means here...
        query::keypair_create(
            txn,
            group_kp.clone(),
            KeyPurpose::Inbox | KeyPurpose::Messaging,
            crate::time::unix(),
        )?;
        query::group_create(txn, group_kp.address(), 1)?;
        query::group_member_add(txn, group_kp.address(), as_address.address())?;
        query::group_member_add(txn, group_kp.address(), with_address.address())?;
        query::metrics_create(txn, as_address.address(), group_kp.address(), 1, 0)?;

        let (commit_message, welcome_message) = e2e::mls_group_create_with_members(
            txn,
            group_kp.address(),
            as_address,
            &[key_package],
        )?;

        // store our send and subscription tokens that we will use to connect
        query::token_create(
            txn,
            query::Token::Send,
            group_kp.address(),
            as_address.address(),
            group_kp.address(),
            as_send_token.as_bytes(),
        )?;
        query::token_create(
            txn,
            query::Token::Subscription,
            group_kp.address(),
            as_address.address(),
            group_kp.address(),
            as_subscription_token.as_bytes(),
        )?;

        sequence_tx = match query::metrics_load(txn, as_address.address(), with_address.address())?
        {
            Some((sequence_tx, _)) => {
                query::metrics_update_sequence_tx(
                    txn,
                    as_address.address(),
                    with_address.address(),
                    sequence_tx + 1,
                )?;
                sequence_tx + 1
            }
            None => {
                query::metrics_create(txn, as_address.address(), with_address.address(), 1, 0)?;
                1
            }
        };

        commit_payload = Some(websocket::assemble_payload_commit(
            as_address,
            group_kp.public(),
            1,
            &commit_message,
        )?);

        welcome_payload = Some(websocket::assemble_payload_welcome(
            as_address,
            with_address,
            sequence_tx,
            &welcome_message,
            Some(with_send_token.as_bytes()),
            Some(with_subscription_token.as_bytes()),
        )?);

        // queue commit and welcome message
        query::outbox_queue(
            txn,
            query::Event::Commit,
            as_address.address(),
            group_kp.address(),
            commit_payload.as_ref().unwrap(),
            timestamp,
            1,
        )?;

        query::outbox_queue(
            txn,
            query::Event::Welcome,
            as_address.address(),
            with_address.address(),
            welcome_payload.as_ref().unwrap(),
            timestamp,
            sequence_tx,
        )
    })?;

    let as_keypair = match &as_keypair {
        Some(as_keypair) => as_keypair,
        None => return Err(SelfError::KeyPairNotFound),
    };

    let commit_payload = match &commit_payload {
        Some(commit_payload) => commit_payload,
        None => return Err(SelfError::MessagePayloadInvalid),
    };

    let welcome_payload = match &welcome_payload {
        Some(welcome_payload) => welcome_payload,
        None => return Err(SelfError::MessagePayloadInvalid),
    };

    // open the group inbox and subscribe
    websocket.open(&group_kp)?;
    websocket.subscribe(&[Subscription {
        to_address: group_kp.public().to_owned(),
        as_address: as_keypair.to_owned(),
        token: Some(token::Token::Subscription(as_subscription_token)),
        last_message: timestamp,
        last_active: timestamp,
    }])?;

    let (resp_tx, resp_rx) = crossbeam::channel::bounded(1);

    // send the commit message to the group inbox
    websocket.send(
        as_keypair,
        commit_payload,
        None,
        Arc::new(move |resp| {
            resp_tx.send(resp).unwrap();
        }),
    );

    resp_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| SelfError::HTTPRequestConnectionTimeout)??;

    storage.transaction(|txn| {
        query::outbox_dequeue(txn, as_address.address(), group_kp.address(), 1)
    })?;

    // TODO send with any tokens we may have...

    let (resp_tx, resp_rx) = crossbeam::channel::bounded(1);

    // websocket send
    websocket.send(
        as_keypair,
        welcome_payload,
        None,
        Arc::new(move |resp| {
            resp_tx.send(resp).unwrap();
        }),
    );

    resp_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| SelfError::HTTPRequestConnectionTimeout)??;

    // TODO notify...

    storage.transaction(|txn| {
        query::outbox_dequeue(
            txn,
            as_address.address(),
            with_address.address(),
            sequence_tx,
        )
    })
}

pub fn connection_accept(
    storage: &Connection,
    websocket: &Websocket,
    as_address: &PublicKey,
    welcome: &[u8],
    subscription_token: &[u8],
) -> Result<(), SelfError> {
    let mut group_address: Option<PublicKey> = None;
    let mut as_keypair: Option<KeyPair> = None;
    let timestamp = time::unix();

    let subscription_token = match token::Token::decode(subscription_token)? {
        token::Token::Subscription(subscription) => subscription,
        _ => return Err(SelfError::TokenTypeInvalid),
    };

    storage.transaction(|txn| {
        as_keypair = query::keypair_lookup(txn, as_address.address())?;
        if as_keypair.is_none() {
            return Err(SelfError::KeyPairNotFound);
        }

        let (group, members) = e2e::mls_group_create_from_welcome(txn, welcome)?;
        query::group_create(txn, group.address(), 1)?;

        for member in members {
            query::group_member_add(txn, group.address(), member.address())?;
        }

        query::token_create(
            txn,
            query::Token::Subscription,
            group.address(),
            as_address.address(),
            group.address(),
            subscription_token.as_bytes(),
        )?;

        query::subscription_create(txn, group.address(), as_address.address(), time::unix())?;

        group_address = Some(group);

        Ok(())
    })?;

    let as_keypair = match &as_keypair {
        Some(as_keypair) => as_keypair,
        None => return Err(SelfError::KeyPairNotFound),
    };

    let group_address = match &group_address {
        Some(group_address) => group_address,
        None => return Err(SelfError::KeyPairNotFound),
    };

    // subscribe
    websocket.subscribe(&[Subscription {
        to_address: group_address.to_owned(),
        as_address: as_keypair.to_owned(),
        token: Some(token::Token::Subscription(subscription_token)),
        last_message: timestamp,
        last_active: timestamp,
    }])?;

    // TODO notify...

    // TODO deqeue sent...

    Ok(())
}

pub fn message_send(
    storage: Arc<AtomicPtr<Connection>>,
    websocket: &Websocket,
    to_address: &PublicKey,
    content: &message::Content,
    callback: Arc<dyn Fn(Result<(), SelfError>) + Sync + Send>,
) {
    let mut as_address: Option<KeyPair> = None;
    let mut from_address: Option<PublicKey> = None;
    let mut group_address: Option<PublicKey> = None;
    let mut ciphertext = Vec::new();
    let mut sequence_tx = 0;
    let timestamp = time::unix();

    let loaded_storage = storage.load(Ordering::SeqCst);
    if loaded_storage.is_null() {
        callback(Err(SelfError::AccountNotConfigured));
        return;
    };

    let loaded_storage = unsafe { &(*loaded_storage) };

    if let Err(err) = loaded_storage.transaction(|txn| {
        // TODO determine is this is a group, did or inbox address?
        group_address = query::group_with(txn, to_address.address(), 1)?
            .map(|address| PublicKey::from_bytes(&address).expect("failed to load key"));

        let group_address = match &group_address {
            Some(group_address) => group_address,
            None => return Err(SelfError::KeyPairNotFound),
        };

        from_address = query::group_as_with_purpose(txn, group_address.address(), 1)?
            .map(|address| PublicKey::from_bytes(&address).expect("failed to load key"));

        let from_address = match &from_address {
            Some(from_address) => from_address,
            None => return Err(SelfError::KeyPairNotFound),
        };

        let message = p2p::Message {
            version: p2p::Version::V1.into(),
            content_type: content.content_type().into(),
            id: crypto::random_id(),
            content: content.encode()?,
        };

        as_address = query::keypair_lookup(txn, from_address.address())?;
        let as_address = match &as_address {
            Some(as_address) => as_address,
            None => return Err(SelfError::KeyPairNotFound),
        };

        ciphertext = e2e::mls_group_encrypt(
            txn,
            group_address.address(),
            as_address,
            &message.encode_to_vec(),
        )?;

        sequence_tx = match query::metrics_load(txn, as_address.address(), group_address.address())?
        {
            Some((sequence_tx, _)) => {
                query::metrics_update_sequence_tx(
                    txn,
                    as_address.address(),
                    group_address.address(),
                    sequence_tx + 1,
                )?;
                sequence_tx + 1
            }
            None => {
                query::metrics_create(txn, as_address.address(), group_address.address(), 1, 0)?;
                1
            }
        };

        query::outbox_queue(
            txn,
            query::Event::EncryptedMessage,
            as_address.address(),
            group_address.address(),
            &ciphertext,
            timestamp,
            sequence_tx,
        )
    }) {
        callback(Err(err));
        return;
    }

    let as_address = match &as_address {
        Some(as_address) => as_address,
        None => {
            callback(Err(SelfError::KeyPairNotFound));
            return;
        }
    };

    let group_address = match &group_address {
        Some(group_address) => group_address,
        None => {
            callback(Err(SelfError::KeyPairNotFound));
            return;
        }
    };

    let payload = match websocket::assemble_payload_message(
        as_address,
        group_address,
        sequence_tx,
        &ciphertext,
    ) {
        Ok(payload) => payload,
        Err(err) => {
            callback(Err(err));
            return;
        }
    };

    let cb_as_address = as_address.clone();
    let cb_group_address = group_address.clone();

    websocket.send(
        as_address,
        &payload,
        None,
        Arc::new(move |response| {
            if let Err(err) = response {
                callback(Err(err));
                return;
            }

            let loaded_storage = storage.load(Ordering::SeqCst);
            if loaded_storage.is_null() {
                callback(Err(SelfError::AccountNotConfigured));
                return;
            };

            let loaded_storage = unsafe { &(*loaded_storage) };

            if let Err(err) = loaded_storage.transaction(|txn| {
                query::outbox_dequeue(
                    txn,
                    cb_as_address.address(),
                    cb_group_address.address(),
                    sequence_tx,
                )
            }) {
                callback(Err(err));
                return;
            }

            callback(Ok(()));
        }),
    );
}
