use std::{
    sync::{Arc, Once},
    time::Duration,
};

use self_sdk::{
    account::{Account, MessagingCallbacks},
    credential::{default, Address, CredentialBuilder, CONTEXT_DEFAULT, CREDENTIAL_DEFAULT},
    hashgraph::{Hashgraph, Role},
    time::now,
};
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
fn register_identity() {
    test_server();

    let ws_url = "ws://127.0.0.1:3001/";
    let rpc_url = "http://127.0.0.1:3000/";

    let mut alice = Account::new();
    let alice_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |_| {}),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |_| {}),
        on_welcome: Arc::new(move |_| {}),
    };

    alice
        .configure(rpc_url, ws_url, ":memory:", b"", alice_callbacks)
        .expect("failed to configure account");

    // create a new document for alice and register a new identity
    let alice_identifier_key = alice
        .keychain_signing_create()
        .expect("failed to create keypair");
    let alice_invocation_key = alice
        .keychain_signing_create()
        .expect("failed to create keypair");
    let alice_multirole_key = alice
        .keychain_signing_create()
        .expect("failed to create keypair");

    let document = Hashgraph::new();

    let mut operation = document
        .create()
        .id(alice_identifier_key.address())
        .grant_embedded(alice_invocation_key.address(), Role::Invocation)
        .grant_embedded(
            alice_multirole_key.address(),
            Role::Verification | Role::Authentication | Role::Assertion | Role::Messaging,
        )
        .sign_with(&alice_identifier_key)
        .sign_with(&alice_invocation_key)
        .sign_with(&alice_multirole_key)
        .finish();

    // execute the operation creating the identity
    alice
        .identity_execute(&mut operation)
        .expect("failed to execute identity operation");

    // resolve the identity's hashgraph
    let document = alice
        .identity_resolve(&alice_identifier_key)
        .expect("failed to resolve identity");

    // check that it has the right roles
    assert!(document.key_has_roles(alice_invocation_key.address(), Role::Invocation as u64));
    assert!(document.key_has_roles(alice_multirole_key.address(), Role::Verification as u64));
    assert!(document.key_has_roles(
        alice_multirole_key.address(),
        Role::Authentication | Role::Assertion | Role::Messaging
    ));

    let mut bobby = Account::new();
    let bobby_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |_| {}),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |_| {}),
        on_welcome: Arc::new(move |_| {}),
    };

    bobby
        .configure(rpc_url, ws_url, ":memory:", b"", bobby_callbacks)
        .expect("failed to configure account");

    // register a new account with bobby
    let bobby_identifier_key = bobby
        .keychain_signing_create()
        .expect("failed to create keypair");
    let bobby_invocation_key = bobby
        .keychain_signing_create()
        .expect("failed to create keypair");
    let bobby_multirole_key = bobby
        .keychain_signing_create()
        .expect("failed to create keypair");

    let document = Hashgraph::new();

    let mut operation = document
        .create()
        .id(bobby_identifier_key.address())
        .grant_embedded(bobby_invocation_key.address(), Role::Invocation)
        .grant_embedded(
            bobby_multirole_key.address(),
            Role::Verification | Role::Authentication | Role::Assertion | Role::Messaging,
        )
        .sign_with(&bobby_identifier_key)
        .sign_with(&bobby_invocation_key)
        .sign_with(&bobby_multirole_key)
        .finish();

    bobby
        .identity_execute(&mut operation)
        .expect("failed to execute identity operation");

    // resolve his keys with alice's account
    let document = alice
        .identity_resolve(&bobby_identifier_key)
        .expect("failed to resolve identity");

    // check that it has the right roles
    assert!(document.key_has_roles(bobby_invocation_key.address(), Role::Invocation as u64));
    assert!(document.key_has_roles(bobby_multirole_key.address(), Role::Verification as u64));
    assert!(document.key_has_roles(
        bobby_multirole_key.address(),
        Role::Authentication | Role::Assertion | Role::Messaging
    ));

    // update bobbys document to change his key's roles
    let document = bobby
        .identity_resolve(&bobby_identifier_key)
        .expect("failed to resolve identity");
    let bobby_invocation_keys = bobby
        .keychain_signing_associated_with(&bobby_identifier_key, Role::Invocation)
        .expect("failed to find keys");

    let mut operation = document
        .create()
        .timestamp((self_sdk::time::now() + std::time::Duration::from_secs(1)).timestamp())
        .modify(
            bobby_multirole_key.address(),
            Role::Verification | Role::Authentication | Role::Messaging,
        )
        .sign_with(&bobby_invocation_keys[0])
        .finish();

    bobby
        .identity_execute(&mut operation)
        .expect("failed to execute operation");

    // try to resolve the changes from alices account
    let document = alice
        .identity_resolve(&bobby_identifier_key)
        .expect("failed to resolve identity");

    // as we have already have a valid cache entry for bobby, we don't pull down his latest changes
    // as we are inside the cache validity window of 5 minutes. as such, his key's roles won't have changed
    assert!(document.key_has_roles(
        bobby_multirole_key.address(),
        Role::Authentication | Role::Assertion | Role::Messaging
    ));
}

#[test]
fn encrypted_messaging() {
    test_server();

    let ws_url = "ws://127.0.0.1:3001/";
    let rpc_url = "http://127.0.0.1:3000/";

    let (alice_welcome_tx, alice_welcome_rx) = crossbeam::channel::bounded::<bool>(1);
    let (alice_message_tx, alice_message_rx) = crossbeam::channel::bounded::<Vec<u8>>(1);
    let (bobby_message_tx, bobby_message_rx) = crossbeam::channel::bounded::<Vec<u8>>(1);

    // setup alices account
    let mut alice = Account::new();
    let alice_wm_cb = alice.clone();

    let alice_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |message| {
            alice_message_tx
                .send(message.message().to_vec())
                .expect("failed to send received message for alice");
        }),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |_| {}),
        on_welcome: Arc::new(move |welcome| {
            alice_wm_cb
                .connection_accept(
                    welcome.recipient(),
                    welcome.welcome(),
                    welcome.subscription_token(),
                )
                .expect("failed to connect using welcome mesage");

            alice_welcome_tx
                .send(true)
                .expect("failed to channel send welcome");
        }),
    };

    alice
        .configure(rpc_url, ws_url, ":memory:", b"", alice_callbacks)
        .expect("failed to configure account");

    // setup bob's account
    let mut bobby = Account::new();
    let bobby_kp_cb = bobby.clone();
    let bobby_ms_cb = bobby.clone();

    let bobby_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |message| {
            bobby_ms_cb
                .message_send(message.sender(), b"hey alice")
                .expect("failed to send response message from bobby");
            bobby_message_tx
                .send(message.message().to_vec())
                .expect("failed to send received message for bobby");
        }),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |key_package| {
            bobby_kp_cb
                .connection_establish(
                    key_package.recipient(),
                    key_package.sender(),
                    key_package.package(),
                )
                .expect("failed to connect using key package");
        }),
        on_welcome: Arc::new(|_| {}),
    };

    bobby
        .configure(rpc_url, ws_url, ":memory:", b"", bobby_callbacks)
        .expect("failed to configure account");

    // create an inbox for alice and bob
    let alice_inbox = alice.inbox_open().expect("failed to open inbox");
    let bobby_inbox = bobby.inbox_open().expect("failed to open inbox");

    // initiate a connection from alice to bob
    alice
        .connection_negotiate(&alice_inbox, &bobby_inbox)
        .expect("failed to send connection request");

    // accept the connection from alice
    alice_welcome_rx
        .recv_timeout(DEFAULT_TIMEOUT)
        .expect("welcome message timeout");

    // alice send an encrypted message to the group
    alice
        .message_send(&bobby_inbox, b"hey bobby")
        .expect("failed to send message");

    let message_from_alice = bobby_message_rx
        .recv_timeout(DEFAULT_TIMEOUT)
        .expect("failed to receive message");
    assert_eq!(message_from_alice, b"hey bobby");

    let message_from_bobby = alice_message_rx
        .recv_timeout(DEFAULT_TIMEOUT)
        .expect("failed to receive message");
    assert_eq!(message_from_bobby, b"hey alice");
}

#[test]
fn credentials() {
    test_server();

    let ws_url = "ws://127.0.0.1:3001/";
    let rpc_url = "http://127.0.0.1:3000/";

    let mut alice = Account::new();
    let alice_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |_| {}),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |_| {}),
        on_welcome: Arc::new(move |_| {}),
    };

    alice
        .configure(rpc_url, ws_url, ":memory:", b"", alice_callbacks)
        .expect("failed to configure account");

    // create a new document for alice and register a new identity
    let alice_identifier_key = alice
        .keychain_signing_create()
        .expect("failed to create keypair");
    let alice_invocation_key = alice
        .keychain_signing_create()
        .expect("failed to create keypair");
    let alice_multirole_key = alice
        .keychain_signing_create()
        .expect("failed to create keypair");

    let document = Hashgraph::new();

    let mut operation = document
        .create()
        .id(alice_identifier_key.address())
        .grant_embedded(alice_invocation_key.address(), Role::Invocation)
        .grant_embedded(
            alice_multirole_key.address(),
            Role::Verification | Role::Authentication | Role::Assertion | Role::Messaging,
        )
        .sign_with(&alice_identifier_key)
        .sign_with(&alice_invocation_key)
        .sign_with(&alice_multirole_key)
        .finish();

    // execute the operation creating the identity
    alice
        .identity_execute(&mut operation)
        .expect("failed to execute identity operation");

    let mut bobby = Account::new();
    let bobby_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |_| {}),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |_| {}),
        on_welcome: Arc::new(move |_| {}),
    };

    bobby
        .configure(rpc_url, ws_url, ":memory:", b"", bobby_callbacks)
        .expect("failed to configure account");

    // create a new link key for bobby
    let bobby_link_key = bobby
        .keychain_signing_create()
        .expect("failed to create keypair");

    // issue a credential from alice about bobby
    let mut credential = CredentialBuilder::new()
        .context(default(CONTEXT_DEFAULT))
        .credential_type(default(CREDENTIAL_DEFAULT))
        .credential_subject(&Address::key(&bobby_link_key))
        .credential_subject_claim("friendOf", "alice")
        .issuer(&Address::aure(&alice_identifier_key))
        .valid_from(now())
        .sign_with(&alice_multirole_key, now())
        .finish()
        .expect("failed to build credential");

    let verified_credential = alice
        .credential_issue(&mut credential)
        .expect("failed to issue credential");

    // store the credential from alice
    bobby
        .credential_store(&verified_credential)
        .expect("failed to store credential");

    // query the credential and check it's details
    let credentials = bobby
        .credential_lookup_by_issuer(&alice_identifier_key)
        .expect("failed to lookup credentials");
    assert_eq!(credentials.len(), 1);

    let credentials = bobby
        .credential_lookup_by_bearer(&bobby_link_key)
        .expect("failed to lookup credentials");
    assert_eq!(credentials.len(), 1);

    let credentials = bobby
        .credential_lookup_by_credential_type(CREDENTIAL_DEFAULT)
        .expect("failed to lookup credentials");
    assert_eq!(credentials.len(), 1);

    credentials[0]
        .validate()
        .expect("failed to validate credential");
    assert_eq!(
        credentials[0]
            .credential_subject()
            .expect("credential subject failed")
            .address(),
        &bobby_link_key
    );
    assert_eq!(
        credentials[0]
            .credential_subject_claim("friendOf")
            .expect("credential claim failed"),
        "alice"
    );
    assert_eq!(
        credentials[0]
            .issuer()
            .expect("credential issuer failed")
            .address(),
        &alice_identifier_key
    );
    assert_eq!(
        credentials[0]
            .signing_key()
            .expect("credential signing key failed"),
        alice_multirole_key
    );

    // verify that the alices issuing key is valid
    let issuer = credentials[0].issuer().expect("issuer failed");
    let signing_key = credentials[0].signing_key().expect("signing key failed");
    let created = credentials[0].created().expect("created timestamp failed");

    let issuer_document = bobby
        .identity_resolve(issuer.address())
        .expect("failed to resolve issuer identity");
    assert!(issuer_document.key_has_roles_at(
        signing_key.address(),
        Role::Assertion as u64,
        created.timestamp()
    ));
}

/*
#[test]
fn encrypted_messaging_benchmark() {
    test_server();

    let ws_url = "ws://127.0.0.1:3001/";
    let rpc_url = "http://127.0.0.1:3000/";

    let (alice_welcome_tx, alice_welcome_rx) = crossbeam::channel::bounded::<bool>(1);

    // setup alices account
    let mut alice = Account::new();
    let alice_wm_cb = alice.clone();

    let alice_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|_| {}),
        on_disconnect: Arc::new(|_, _| {}),
        on_message: Arc::new(move |_, _| {

        }),
        on_commit: Arc::new(|_, _| {}),
        on_key_package: Arc::new(move |_, _| {}),
        on_welcome: Arc::new(move |_, welcome| {
            alice_wm_cb
                .connection_accept(welcome.recipient, welcome.welcome)
                .expect("failed to connect using welcome mesage");

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
    let bobby_kp_cb = bobby.clone();

    let bobby_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|_| {}),
        on_disconnect: Arc::new(|_, _| {}),
        on_message: Arc::new(move |_, _| {
        }),
        on_commit: Arc::new(|_, _| {}),
        on_key_package: Arc::new(move |_, key_package| {
            bobby_kp_cb
                .connection_connect(
                    key_package.recipient,
                    key_package.sender,
                    Some(key_package.package),
                )
                .expect("failed to connect using key package");
        }),
        on_welcome: Arc::new(|_, _| {}),
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

    println!("bobby inbox: {}", hex::encode(bobby_inbox.address()));

    // initiate a connection from alice to bob
    alice
        .connection_connect(&alice_inbox, &bobby_inbox, None)
        .expect("failed to send connection request");

    // accept the connection from alice
    alice_welcome_rx
        .recv_timeout(DEFAULT_TIMEOUT)
        .expect("welcome message timeout");

    let start = std::time::Instant::now();

    for _ in 0..1000 {
        alice
            .message_send(&bobby_inbox, b"hey bobby")
            .expect("failed to send message");
    }

    println!("sent 1000 in {} ms", std::time::Instant::now().duration_since(start).as_millis());
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
