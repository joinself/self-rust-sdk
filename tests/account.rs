use std::{
    sync::{Arc, Once},
    time::Duration,
};

use self_sdk::account::{Account, MessagingCallbacks};
use self_test_mock::Server;

static INIT: Once = Once::new();
static mut SERVER: Option<Server> = None;
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(100);

pub fn test_server() {
    unsafe {
        INIT.call_once(|| {
            SERVER = Some(Server::new(3000, 3001));
        });
    }
}

#[test]
fn encrypted_messaging() {
    test_server();

    let ws_url = "ws://127.0.0.1:3001/";
    let rpc_url = "http://127.0.0.1:3000/";

    let (alice_welcome_tx, alice_welcome_rx) = crossbeam::channel::bounded::<bool>(1);

    // setup alices account
    let mut alice = Account::new();
    let alice_kpc = alice.clone();

    let alice_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|_| {}),
        on_disconnect: Arc::new(|_, _| {}),
        on_message: Arc::new(|_, _| None),
        on_commit: Arc::new(|_, _| {}),
        on_key_package: Arc::new(move |_, key_package| {
            alice_kpc
                .connection_connect(
                    key_package.recipient,
                    key_package.sender,
                    Some(key_package.package),
                )
                .expect("failed to connect using key package");
        }),
        on_welcome: Arc::new(move |_, _| {
            println!("alice received welcome");
            alice_welcome_tx
                .send(true)
                .expect("failed to channel send welcome");
        }),
    };

    alice
        .configure(
            rpc_url,
            ws_url,
            ":memory:",
            b"",
            alice_callbacks,
            Arc::new(1),
        )
        .expect("failed to configure account");

    // setup bob's account
    let mut bobby = Account::new();
    let bobby_kpc = bobby.clone();

    let bobby_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|_| {}),
        on_disconnect: Arc::new(|_, _| {}),
        on_message: Arc::new(|_, _| None),
        on_commit: Arc::new(|_, _| {}),
        on_key_package: Arc::new(move |_, key_package| {
            bobby_kpc
                .connection_connect(
                    key_package.recipient,
                    key_package.sender,
                    Some(key_package.package),
                )
                .expect("failed to connect using key package");
        }),
        on_welcome: Arc::new(|_, _| {
            println!("bobby received welcome");
        }),
    };

    bobby
        .configure(
            rpc_url,
            ws_url,
            ":memory:",
            b"",
            bobby_callbacks,
            Arc::new(1),
        )
        .expect("failed to configure account");

    // create an inbox for alice and bob
    let alice_inbox = alice.inbox_open(None).expect("failed to open inbox");
    let bobby_inbox = bobby.inbox_open(None).expect("failed to open inbox");

    // initiate a connection from alice to bob
    alice
        .connection_connect(&alice_inbox, &bobby_inbox, None)
        .expect("failed to send connection request");

    // accept the connection from alice
    alice_welcome_rx
        .recv_timeout(Duration::from_millis(100))
        .expect("welcome message timeout");
}

/*
use crossbeam::channel::Sender;
use openmls::prelude::{config::CryptoConfig, *};
use openmls::treesync::RatchetTree;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsCryptoProvider;


pub struct OpenMlsBackend<'t> {
    crypto: RustCrypto,
    key_store: &'t Transaction,
}

impl OpenMlsBackend<'_> {
    pub fn new(txn: &Transaction) -> OpenMlsBackend {
        OpenMlsBackend {
            crypto: RustCrypto::default(),
            key_store: txn,
        }
    }
}

impl OpenMlsCryptoProvider for OpenMlsBackend<'_> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = Transaction;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        self.key_store
    }
}

fn mls_generate_credential_with_key(
    signature_key: &KeyPair,
    backend: &impl OpenMlsCryptoProvider,
) -> CredentialWithKey {
    let credential =
        Credential::new(signature_key.address().to_owned(), CredentialType::Basic).unwrap();

    // Store the signature key into the key store so OpenMLS has access
    // to it.
    backend
        .key_store()
        .store(&signature_key.id(), signature_key)
        .expect("failed to store signature key");

    CredentialWithKey {
        credential,
        signature_key: signature_key.public().public_key_bytes().into(),
    }
}

// A helper to create key package bundles.
fn mls_generate_key_package(
    backend: &impl OpenMlsCryptoProvider,
    signer: &KeyPair,
    credential_with_key: CredentialWithKey,
) -> KeyPackage {
    // Create the key package
    KeyPackage::builder()
        .build(
            CryptoConfig {
                ciphersuite: crate::crypto::e2e::DEFAULT_CIPHER_SUITE,
                version: ProtocolVersion::default(),
            },
            backend,
            signer,
            credential_with_key,
        )
        .unwrap()
}

#[test]
fn encrypted_message_exchange() {
    test_server();

    let (alice_msg_tx, alice_msg_rx) = crossbeam::channel::bounded::<TestMsg>(64);
    let (bobby_msg_tx, bobby_msg_rx) = crossbeam::channel::bounded::<TestMsg>(64);
    let (carol_msg_tx, carol_msg_rx) = crossbeam::channel::bounded::<TestMsg>(64);

    let alice_callbacks = Callbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |message| -> Option<Response> {
            alice_msg_tx
                .send((
                    message.sender.to_owned(),
                    message.recipient.to_owned(),
                    message.content.to_owned(),
                ))
                .expect("failed to channel send msg");
            None
        }),
    };

    let bobby_callbacks = Callbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |message| -> Option<Response> {
            bobby_msg_tx
                .send((
                    message.sender.to_owned(),
                    message.recipient.to_owned(),
                    message.content.to_owned(),
                ))
                .expect("failed to channel send msg");
            None
        }),
    };

    let carol_callbacks = Callbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |message| -> Option<Response> {
            carol_msg_tx
                .send((
                    message.sender.to_owned(),
                    message.recipient.to_owned(),
                    message.content.to_owned(),
                ))
                .expect("failed to channel send msg");
            None
        }),
    };

    let ws_url = "ws://127.0.0.1:3001/";
    let rpc_url = "http://127.0.0.1:3000/";

    let alice_storage = Connection::new(":memory:").expect("alice storage failed");
    let bobby_storage = Connection::new(":memory:").expect("bobby storage failed");
    let carol_storage = Connection::new(":memory:").expect("carol storage failed");

    let alice_websocket = Websocket::new(ws_url, alice_callbacks).expect("alice websocket failed");
    let bobby_websocket = Websocket::new(ws_url, bobby_callbacks).expect("bobby websocket failed");
    let carol_websocket = Websocket::new(ws_url, carol_callbacks).expect("carol websocket failed");

    let alice_rpc = Rpc::new(rpc_url).expect("alice rpc failed");
    let bobby_rpc = Rpc::new(rpc_url).expect("bobby rpc failed");
    let carol_rpc = Rpc::new(rpc_url).expect("carol rpc failed");

    let alice_kp = KeyPair::new();
    let bobby_kp = KeyPair::new();
    let carol_kp = KeyPair::new();

    let now = time::unix();

    alice_storage
        .transaction(|txn| {
            query::keypair_create(txn, alice_kp.clone(), Role::Authentication.bits(), now)
                .expect("failed to create keypair");
            txn.commit()
        })
        .expect("alice txn failed");

    bobby_storage
        .transaction(|txn| {
            query::keypair_create(txn, bobby_kp.clone(), Role::Authentication.bits(), now)
                .expect("failed to create keypair");
            txn.commit()
        })
        .expect("alice txn failed");

    carol_storage
        .transaction(|txn| {
            query::keypair_create(txn, carol_kp.clone(), Role::Authentication.bits(), now)
                .expect("failed to create keypair");
            txn.commit()
        })
        .expect("alice txn failed");

    // mls credential setup setup
    alice_storage
        .transaction(|txn| {
            let alice_mls_backend = &OpenMlsBackend::new(txn);

            mls_generate_credential_with_key(&alice_kp, alice_mls_backend);

            txn.commit()
        })
        .expect("alice transaction failed");

    bobby_storage
        .transaction(|txn| {
            let bobby_backend = &OpenMlsBackend::new(txn);

            let bobby_credential_with_key =
                mls_generate_credential_with_key(&bobby_kp, bobby_backend);

            // generate a key package for asynchronous handshake
            let bobby_key_package =
                mls_generate_key_package(bobby_backend, &bobby_kp, bobby_credential_with_key);

            // publish key to server
            let mut bobby_encoded_key_package = Vec::new();
            ciborium::ser::into_writer(&bobby_key_package, &mut bobby_encoded_key_package)
                .expect("failed to encode key package");

            bobby_rpc.publish(bobby_kp.address(), &[bobby_encoded_key_package])?;

            txn.commit()
        })
        .expect("bobby transaction failed");

    carol_storage
        .transaction(|txn| {
            let carol_backend = &OpenMlsBackend::new(txn);

            let carol_credential_with_key =
                mls_generate_credential_with_key(&carol_kp, carol_backend);

            // generate a key package for asynchronous handshake
            let carol_key_package =
                mls_generate_key_package(carol_backend, &carol_kp, carol_credential_with_key);

            // publish key to server
            let mut carol_encoded_key_package = Vec::new();
            ciborium::ser::into_writer(&carol_key_package, &mut carol_encoded_key_package)
                .expect("failed to encode key package");

            carol_rpc.publish(carol_kp.address(), &[carol_encoded_key_package])?;

            txn.commit()
        })
        .expect("carol transaction failed");

    // get the key bundles for bobby and carol
    let bobby_key_package = alice_rpc
        .acquire(bobby_kp.address(), alice_kp.address())
        .expect("failed to acquire key package");
    let bobby_key_package: KeyPackage = ciborium::de::from_reader(bobby_key_package.as_slice())
        .expect("failed to decode key package");

    let carol_key_package = alice_rpc
        .acquire(carol_kp.address(), alice_kp.address())
        .expect("failed to acquire key package");
    let carol_key_package: KeyPackage = ciborium::de::from_reader(carol_key_package.as_slice())
        .expect("failed to decode key package");

    let mut serialized_welcome = Vec::new();

    // create a group
    alice_storage
        .transaction(|txn| {
            let alice_mls_backend = &OpenMlsBackend::new(txn);

            let alice_credential =
                Credential::new(alice_kp.address().to_owned(), CredentialType::Basic).unwrap();

            let alice_group_cfg = &MlsGroupConfig::builder()
                .use_ratchet_tree_extension(true)
                .build();

            // Now Sasha starts a new group ...
            let mut alice_group = MlsGroup::new(
                alice_mls_backend,
                &alice_kp,
                alice_group_cfg,
                CredentialWithKey {
                    credential: alice_credential,
                    signature_key: alice_kp.public().public_key_bytes().into(),
                },
            )
            .expect("An unexpected error occurred.");

            // ... and invites Maxim.
            // The key package has to be retrieved from Maxim in some way. Most likely
            // via a server storing key packages for users.
            let (mls_message_out, welcome_out, group_info) = alice_group
                .add_members(
                    alice_mls_backend,
                    &alice_kp,
                    &[bobby_key_package, carol_key_package],
                )
                .expect("Could not add members.");

            // Sasha merges the pending commit that adds Maxim.
            alice_group
                .merge_pending_commit(alice_mls_backend)
                .expect("error merging pending commit");

            // Sascha serializes the [`MlsMessageOut`] containing the [`Welcome`].
            serialized_welcome = welcome_out
                .tls_serialize_detached()
                .expect("Error serializing welcome");

            txn.commit()
        })
        .expect("alice transaction failed");

    // bobby and carol join the group
    bobby_storage
        .transaction(|txn| {
            let bobby_backend = &OpenMlsBackend::new(txn);

            let mls_message_in = MlsMessageIn::tls_deserialize(&mut serialized_welcome.as_slice())
                .expect("An unexpected error occurred.");

            let welcome = match mls_message_in.extract() {
                MlsMessageInBody::Welcome(welcome) => Some(welcome),
                // We know it's a welcome message, so we ignore all other cases.
                _ => unreachable!("Unexpected message type."),
            };

            MlsGroup::new_from_welcome(
                bobby_backend,
                &MlsGroupConfig::default(),
                welcome.unwrap(),
                // The public tree is need and transferred out of band.
                // It is also possible to use the [`RatchetTreeExtension`]
                None,
            )
            .expect("Error joining group from Welcome");

            txn.commit()
        })
        .expect("bobby transaction failed");

    carol_storage
        .transaction(|txn| {
            let carol_backend = &OpenMlsBackend::new(txn);

            let mls_message_in = MlsMessageIn::tls_deserialize(&mut serialized_welcome.as_slice())
                .expect("An unexpected error occurred.");

            let welcome = match mls_message_in.extract() {
                MlsMessageInBody::Welcome(welcome) => Some(welcome),
                // We know it's a welcome message, so we ignore all other cases.
                _ => unreachable!("Unexpected message type."),
            };

            MlsGroup::new_from_welcome(
                carol_backend,
                &MlsGroupConfig::default(),
                welcome.unwrap(),
                // The public tree is need and transferred out of band.
                // It is also possible to use the [`RatchetTreeExtension`]
                None,
            )
            .expect("Error joining group from Welcome");

            txn.commit()
        })
        .expect("carol transaction failed");
}

// account_create
// account_list
// account_remove
// backup_create
// connection_create
// connection_list
// connection_remove
// credential_assert
// credential_create
// credential_list
// credential_verify
// credential_revoke
// group_create
// group_invite
// group_leave
// group_remove
// inbox_close
// inbox_list
// inbox_open
// keypair_list
// keypair_sign
// keypair_verify
// message_accept
// message_reject
// message_send
// object_upload
// object_download
// token_create

/*
#[test]
fn account_configure() {
    test_server();

    let mut account = Account::new();
    account
        .configure(
            "http://127.0.0.1:3000/",
            "ws://127.0.0.1:3001/",
            "/tmp/test_account_configure/",
            b"123456789",
            Arc::new(Box::new(0)),
            MessagingCallbacks {
                on_connect: None,
                on_disconnect: None,
                on_message: Arc::new(|_, _| {}),
                on_request: Arc::new(|_, _| ResponseStatus::Ignored),
                on_response: Arc::new(|_, _| {}),
            },
        )
        .expect("failed to configure account");
}

#[test]
fn account_register() {
    test_server();

    let mut account = Account::new();
    account
        .configure(
            "http://127.0.0.1:3000/",
            "ws://127.0.0.1:3001/",
            "/tmp/test_account_register/",
            b"123456789",
            Arc::new(Box::new(0)),
            MessagingCallbacks {
                on_connect: None,
                on_disconnect: None,
                on_message: Arc::new(|_, _| {}),
                on_request: Arc::new(|_, _| ResponseStatus::Ignored),
                on_response: Arc::new(|_, _| {}),
            },
        )
        .expect("failed to configure account");

    account.register().expect("failed to register account");

    assert!(account.messaging_identifer().is_some());
}

#[test]
fn account_connect_without_token_accept() {
    test_server();

    let (alices_on_response_tx, alices_on_response_rx) =
        crossbeam::channel::bounded::<Envelope>(64);

    let (bobs_on_request_tx, bobs_on_request_rx) = crossbeam::channel::bounded::<Envelope>(64);

    let mut alices_account = register_test_account(
        "test_account_connect_without_token_accept_alice",
        Some(MessagingChannels {
            on_request: None,
            on_response: Some(alices_on_response_tx),
            on_message: None,
        }),
    );

    let mut bobs_account = register_test_account(
        "test_account_connect_without_token_accept_bob",
        Some(MessagingChannels {
            on_request: Some(bobs_on_request_tx),
            on_response: None,
            on_message: None,
        }),
    );

    let alices_identifier = alices_account
        .messaging_identifer()
        .expect("must have an identifier");

    let bobs_identifier = bobs_account
        .messaging_identifer()
        .expect("must have an identifier");

    alices_account
        .connect(&bobs_identifier, None, None)
        .expect("failed to send connection to bob");

    // receive alices request
    let request = bobs_on_request_rx
        .recv_deadline(default_timeout())
        .expect("request wait timeout");

    // emulate mobile client storing this request and accepting it later on...
    let encoded_request = request.encode().expect("encoding message envelope failed");
    let request = Envelope::decode(&encoded_request).expect("decoding message envelope failed");

    assert_eq!(request.to, bobs_identifier);
    assert_eq!(request.from, alices_identifier);

    let msg_type = request.content.type_get().expect("message type empty");
    assert_eq!(msg_type, message::MESSAGE_TYPE_CONNECTION_REQ);

    let content = request.content.content_get().expect("content is empty");
    let connection_req =
        ConnectionRequest::decode(&content).expect("failed to encode connection request");
    assert!(connection_req.ath.is_some());

    let request_id = request.content.cti_get().expect("request cti is missing");

    // accept the request
    bobs_account
        .accept(&request)
        .expect("failed to accept alices request");

    // receive bobs response
    let response = alices_on_response_rx
        .recv_deadline(default_timeout())
        .expect("response wait timeout");

    // emulate mobile client storing this request and accepting it later on...
    let encoded_response = response.encode().expect("encoding message envelope failed");
    let response = Envelope::decode(&encoded_response).expect("decoding message envelope failed");

    assert_eq!(response.to, alices_identifier);
    assert_eq!(response.from, bobs_identifier);

    let msg_type = response.content.type_get().expect("message type empty");
    assert_eq!(msg_type, message::MESSAGE_TYPE_CONNECTION_RES);

    let content = response.content.content_get().expect("content is empty");
    let connection_res =
        ConnectionResponse::decode(&content).expect("failed to encode connection response");
    assert!(connection_res.ath.is_some());
    assert_eq!(connection_res.sts, ResponseStatus::Accepted);

    let response_id = response.content.cti_get().expect("response cti is missing");
    assert_eq!(request_id, response_id);
}

#[test]
fn account_connect_without_token_reject() {
    test_server();

    let (alices_on_response_tx, alices_on_response_rx) =
        crossbeam::channel::bounded::<Envelope>(64);

    let (bobs_on_request_tx, bobs_on_request_rx) = crossbeam::channel::bounded::<Envelope>(64);

    let mut alices_account = register_test_account(
        "test_account_connect_without_token_reject_alice",
        Some(MessagingChannels {
            on_request: None,
            on_response: Some(alices_on_response_tx),
            on_message: None,
        }),
    );

    let mut bobs_account = register_test_account(
        "test_account_connect_without_token_reject_bob",
        Some(MessagingChannels {
            on_request: Some(bobs_on_request_tx),
            on_response: None,
            on_message: None,
        }),
    );

    let alices_identifier = alices_account
        .messaging_identifer()
        .expect("must have an identifier");

    let bobs_identifier = bobs_account
        .messaging_identifer()
        .expect("must have an identifier");

    alices_account
        .connect(&bobs_identifier, None, None)
        .expect("failed to send connection to bob");

    // receive alices request
    let request = bobs_on_request_rx
        .recv_deadline(default_timeout())
        .expect("request wait timeout");

    // emulate mobile client storing this request and accepting it later on...
    let encoded_request = request.encode().expect("encoding message envelope failed");
    let request = Envelope::decode(&encoded_request).expect("decoding message envelope failed");

    assert_eq!(request.to, bobs_identifier);
    assert_eq!(request.from, alices_identifier);

    let msg_type = request.content.type_get().expect("message type empty");
    assert_eq!(msg_type, message::MESSAGE_TYPE_CONNECTION_REQ);

    let content = request.content.content_get().expect("content is empty");
    let connection_req =
        ConnectionRequest::decode(&content).expect("failed to encode connection request");
    assert!(connection_req.ath.is_some());

    let request_id = request.content.cti_get().expect("request cti is missing");

    // reject the request
    bobs_account
        .reject(&request)
        .expect("failed to reject alices request");

    // receive bobs response
    let response = alices_on_response_rx
        .recv_deadline(default_timeout())
        .expect("response wait timeout");

    // emulate mobile client storing this request and accepting it later on...
    let encoded_response = response.encode().expect("encoding message envelope failed");
    let response = Envelope::decode(&encoded_response).expect("decoding message envelope failed");

    assert_eq!(response.to, alices_identifier);
    assert_eq!(response.from, bobs_identifier);

    let msg_type = response.content.type_get().expect("message type empty");
    assert_eq!(msg_type, message::MESSAGE_TYPE_CONNECTION_RES);

    let content = response.content.content_get().expect("content is empty");
    let connection_res =
        ConnectionResponse::decode(&content).expect("failed to encode connection response");
    assert!(connection_res.ath.is_none());
    assert_eq!(connection_res.sts, ResponseStatus::Rejected);

    let response_id = response.content.cti_get().expect("response cti is missing");
    assert_eq!(request_id, response_id);
}

#[test]
fn account_connect_with_auth_token_accept() {
    test_server();

    let (alices_on_response_tx, alices_on_response_rx) =
        crossbeam::channel::bounded::<Envelope>(64);

    let (bobs_on_request_tx, bobs_on_request_rx) = crossbeam::channel::bounded::<Envelope>(64);

    let mut alices_account = register_test_account(
        "test_account_connect_with_auth_token_accept_alice",
        Some(MessagingChannels {
            on_request: None,
            on_response: Some(alices_on_response_tx),
            on_message: None,
        }),
    );

    let mut bobs_account = register_test_account(
        "test_account_connect_with_auth_token_accept_bob",
        Some(MessagingChannels {
            on_request: Some(bobs_on_request_tx),
            on_response: None,
            on_message: None,
        }),
    );

    let alices_identifier = alices_account
        .messaging_identifer()
        .expect("must have an identifier");

    let bobs_identifier = bobs_account
        .messaging_identifer()
        .expect("must have an identifier");

    let (auth_token, _) = bobs_account
        .token_generate(Some(&alices_identifier), None)
        .expect("failed to create token");

    alices_account
        .connect(&bobs_identifier, Some(&auth_token), None)
        .expect("failed to send connection to bob");

    // receive alices request
    let request = bobs_on_request_rx
        .recv_deadline(default_timeout())
        .expect("request wait timeout");

    // emulate mobile client storing this request and accepting it later on...
    let encoded_request = request.encode().expect("encoding message envelope failed");
    let request = Envelope::decode(&encoded_request).expect("decoding message envelope failed");

    assert_eq!(request.to, bobs_identifier);
    assert_eq!(request.from, alices_identifier);

    let msg_type = request.content.type_get().expect("message type empty");
    assert_eq!(msg_type, message::MESSAGE_TYPE_CONNECTION_REQ);

    let content = request.content.content_get().expect("content is empty");
    let connection_req =
        ConnectionRequest::decode(&content).expect("failed to encode connection request");
    assert!(connection_req.ath.is_some());

    let request_id = request.content.cti_get().expect("request cti is missing");

    // accept the request
    bobs_account
        .accept(&request)
        .expect("failed to accept alices request");

    // receive bobs response
    let response = alices_on_response_rx
        .recv_deadline(default_timeout())
        .expect("response wait timeout");

    // emulate mobile client storing this request and accepting it later on...
    let encoded_response = response.encode().expect("encoding message envelope failed");
    let response = Envelope::decode(&encoded_response).expect("decoding message envelope failed");

    assert_eq!(response.to, alices_identifier);
    assert_eq!(response.from, bobs_identifier);

    let msg_type = response.content.type_get().expect("message type empty");
    assert_eq!(msg_type, message::MESSAGE_TYPE_CONNECTION_RES);

    let content = response.content.content_get().expect("content is empty");
    let connection_res =
        ConnectionResponse::decode(&content).expect("failed to encode connection response");
    assert!(connection_res.ath.is_some());
    assert_eq!(connection_res.sts, ResponseStatus::Accepted);

    let response_id = response.content.cti_get().expect("response cti is missing");
    assert_eq!(request_id, response_id);
}

#[test]
fn account_connect_with_auth_token_reject() {
    test_server();

    let (alices_on_response_tx, alices_on_response_rx) =
        crossbeam::channel::bounded::<Envelope>(64);

    let (bobs_on_request_tx, bobs_on_request_rx) = crossbeam::channel::bounded::<Envelope>(64);

    let mut alices_account = register_test_account(
        "test_account_connect_with_auth_token_reject_alice",
        Some(MessagingChannels {
            on_request: None,
            on_response: Some(alices_on_response_tx),
            on_message: None,
        }),
    );

    let mut bobs_account = register_test_account(
        "test_account_connect_with_auth_token_reject_bob",
        Some(MessagingChannels {
            on_request: Some(bobs_on_request_tx),
            on_response: None,
            on_message: None,
        }),
    );

    let alices_identifier = alices_account
        .messaging_identifer()
        .expect("must have an identifier");

    let bobs_identifier = bobs_account
        .messaging_identifer()
        .expect("must have an identifier");

    let (auth_token, _) = bobs_account
        .token_generate(Some(&alices_identifier), None)
        .expect("failed to create token");

    alices_account
        .connect(&bobs_identifier, Some(&auth_token), None)
        .expect("failed to send connection to bob");

    // receive alices request
    let request = bobs_on_request_rx
        .recv_deadline(default_timeout())
        .expect("request wait timeout");

    // emulate mobile client storing this request and accepting it later on...
    let encoded_request = request.encode().expect("encoding message envelope failed");
    let request = Envelope::decode(&encoded_request).expect("decoding message envelope failed");

    assert_eq!(request.to, bobs_identifier);
    assert_eq!(request.from, alices_identifier);

    let msg_type = request.content.type_get().expect("message type empty");
    assert_eq!(msg_type, message::MESSAGE_TYPE_CONNECTION_REQ);

    let content = request.content.content_get().expect("content is empty");
    let connection_req =
        ConnectionRequest::decode(&content).expect("failed to encode connection request");
    assert!(connection_req.ath.is_some());

    let request_id = request.content.cti_get().expect("request cti is missing");

    // reject the request
    bobs_account
        .reject(&request)
        .expect("failed to reject alices request");

    // receive bobs response
    let response = alices_on_response_rx
        .recv_deadline(default_timeout())
        .expect("response wait timeout");

    // emulate mobile client storing this request and accepting it later on...
    let encoded_response = response.encode().expect("encoding message envelope failed");
    let response = Envelope::decode(&encoded_response).expect("decoding message envelope failed");

    assert_eq!(response.to, alices_identifier);
    assert_eq!(response.from, bobs_identifier);

    let msg_type = response.content.type_get().expect("message type empty");
    assert_eq!(msg_type, message::MESSAGE_TYPE_CONNECTION_RES);

    let content = response.content.content_get().expect("content is empty");
    let connection_res =
        ConnectionResponse::decode(&content).expect("failed to encode connection response");
    assert!(connection_res.ath.is_none());
    assert_eq!(connection_res.sts, ResponseStatus::Rejected);

    let response_id = response.content.cti_get().expect("response cti is missing");
    assert_eq!(request_id, response_id);
}

#[test]
fn account_send_chat_message() {
    test_server();

    let (alices_on_message_tx, alices_on_message_rx) = crossbeam::channel::bounded::<Envelope>(64);
    let (alices_on_request_tx, alices_on_request_rx) = crossbeam::channel::bounded::<Envelope>(64);
    let (bobs_on_message_tx, bobs_on_message_rx) = crossbeam::channel::bounded::<Envelope>(64);
    let (bobs_on_response_tx, bobs_on_response_rx) = crossbeam::channel::bounded::<Envelope>(64);

    let mut alices_account = register_test_account(
        "test_account_send_chat_message_alice",
        Some(MessagingChannels {
            on_request: Some(alices_on_request_tx),
            on_response: None,
            on_message: Some(alices_on_message_tx),
        }),
    );

    let mut bobs_account = register_test_account(
        "test_account_send_chat_message_bob",
        Some(MessagingChannels {
            on_request: None,
            on_response: Some(bobs_on_response_tx),
            on_message: Some(bobs_on_message_tx),
        }),
    );

    let alices_identifier = alices_account
        .messaging_identifer()
        .expect("must have an identifier");

    let bobs_identifier = bobs_account
        .messaging_identifer()
        .expect("must have an identifier");

    let (auth_token, _) = alices_account
        .token_generate(Some(&bobs_identifier), None)
        .expect("failed to create token");

    bobs_account
        .connect(&alices_identifier, Some(&auth_token), None)
        .expect("failed to send connection to alice");

    // receive bobs request
    let request = alices_on_request_rx
        .recv_deadline(default_timeout())
        .expect("request wait timeout");

    // accept the request
    alices_account
        .accept(&request)
        .expect("failed to accept bobs request");

    // receive bobs response
    let _ = bobs_on_response_rx
        .recv_deadline(default_timeout())
        .expect("response wait timeout");

    // create a new chat message
    let mut content = Content::new();
    content.cti_set(&random_id());
    content.type_set(message::MESSAGE_TYPE_CHAT_MSG);
    content.issued_at_set(unix());

    let message = ChatMessage {
        mrf: None,
        msg: String::from("hello alice"),
    }
    .encode()
    .expect("failed to encode message");

    content.content_set(&message);

    // send a chat message to alice
    bobs_account
        .send(&alices_identifier, &content)
        .expect("failed to send message to alice?");

    // wait to receive message from bob
    let message = alices_on_message_rx
        .recv_deadline(default_timeout())
        .expect("timeout waiting for bobs message");
    assert_eq!(message.to, alices_identifier);
    assert_eq!(message.from, bobs_identifier);

    let message_id = message.content.cti_get().expect("message cti empty");
    let content = message
        .content
        .content_get()
        .expect("message content empty");
    let chat_message = ChatMessage::decode(&content).expect("failed to decode message");
    assert_eq!(chat_message.msg, "hello alice");

    // wait to receive delivered receipt from alice
    let delivery_response = bobs_on_message_rx
        .recv_deadline(default_timeout())
        .expect("timeout waiting for delivery receipt");
    assert_eq!(delivery_response.to, bobs_identifier);
    assert_eq!(delivery_response.from, alices_identifier);

    // check the delivery receipt has acknowledged the message from bob
    let content = delivery_response
        .content
        .content_get()
        .expect("message content missing");
    let delivered = ChatDelivered::decode(&content).expect("failed to decode encoded receipt");
    assert_eq!(&message_id, delivered.dlm.first().expect("no message id"));

    // emulate mobile client storing this request and accepting it later on...
    let encoded_message = message.encode().expect("encoding message envelope failed");
    let message = Envelope::decode(&encoded_message).expect("decoding message envelope failed");

    // accept the message to send a read receipt to bob
    alices_account
        .accept(&message)
        .expect("failed to send read receipt to bob");

    // wait to receive read receipt from alice
    let read_response = bobs_on_message_rx
        .recv_deadline(default_timeout())
        .expect("timeout waiting for delivery receipt");
    assert_eq!(read_response.to, bobs_identifier);
    assert_eq!(read_response.from, alices_identifier);

    // get the read receipt from alice
    let content = read_response
        .content
        .content_get()
        .expect("message content missing");

    let read = ChatRead::decode(&content).expect("failed to decode encoded receipt");
    assert_eq!(&message_id, read.rdm.first().expect("no message id"));
}

#[test]
fn account_create_group() {
    test_server();

    let mut alices_account = register_test_account(
        "test_account_connect_alice",
        Some(MessagingChannels {
            on_request: None,
            on_response: None,
            on_message: None,
        }),
    );

    let using_identifier = alices_account
        .messaging_identifer()
        .expect("messaging identifier should be set");
    alices_account
        .group_create(&using_identifier)
        .expect("group creation failed");
}

fn register_test_account(test_name: &str, channels: Option<MessagingChannels>) -> Account {
    let mut account = Account::new();

    let channels = match channels {
        Some(channels) => channels,
        None => MessagingChannels {
            on_request: None,
            on_response: None,
            on_message: None,
        },
    };

    let on_message = match channels.on_message {
        Some(on_message_ch) => Arc::new(move |_, envelope: &Envelope| {
            on_message_ch.send(envelope.clone()).expect("send failed");
        }),
        None => default_on_message(),
    };

    let on_request = match channels.on_request {
        Some(on_request_ch) => Arc::new(move |_, envelope: &Envelope| {
            on_request_ch.send(envelope.clone()).expect("send failed");
            ResponseStatus::Ignored
        }),
        None => default_on_request(),
    };

    let on_response = match channels.on_response {
        Some(on_response_ch) => Arc::new(move |_, envelope: &Envelope| {
            on_response_ch.send(envelope.clone()).expect("send failed");
        }),
        None => default_on_response(),
    };

    account
        .configure(
            "http://127.0.0.1:3000/",
            "ws://127.0.0.1:3001/",
            &format!("/tmp/{}/", test_name),
            b"123456789",
            Arc::new(Box::new(0)),
            MessagingCallbacks {
                on_connect: None,
                on_disconnect: None,
                on_message,
                on_request,
                on_response,
            },
        )
        .expect("failed to configure account");

    account.register().expect("failed to register account");

    account
}

fn default_timeout() -> Instant {
    Instant::now() + DEFAULT_TIMEOUT
}

fn default_on_message() -> OnMessageCB {
    Arc::new(|_, envelope| {
        println!(
            "got message from: {} typ: {:?}",
            hex::encode(envelope.from.id()),
            envelope.content.type_get()
        );
    })
}

fn default_on_request() -> OnRequestCB {
    Arc::new(|_, envelope| {
        println!(
            "got request from: {} typ: {:?}",
            hex::encode(envelope.from.id()),
            envelope.content.type_get()
        );

        ResponseStatus::Ignored
    })
}

fn default_on_response() -> OnResponseCB {
    Arc::new(|_, envelope| {
        println!(
            "got response from: {} typ: {:?}",
            hex::encode(envelope.from.id()),
            envelope.content.type_get()
        );
    })
}
*/
*/
