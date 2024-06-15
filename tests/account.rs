use std::{
    collections::HashMap,
    sync::{Arc, Once},
    time::Duration,
};

use hex::ToHex;
use self_sdk::{
    account::{Account, MessagingCallbacks},
    credential::{
        default, Address, CredentialBuilder, PresentationBuilder, CONTEXT_DEFAULT,
        CREDENTIAL_DEFAULT, PRESENTATION_DEFAULT,
    },
    crypto::random_id,
    hashgraph::{Hashgraph, Role},
    message::{self, CredentialPresentationDetail, ResponseStatus},
    object::{self, Object},
    time::now,
};
use self_test_mock::Server;

static INIT: Once = Once::new();
static mut SERVER: Option<Server> = None;
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(100);

pub fn test_server() {
    unsafe {
        INIT.call_once(|| {
            SERVER = Some(Server::new(3000, 3001, 3002));
        });
    }
}

#[test]
fn register_identity() {
    test_server();

    let rpc_url = "http://127.0.0.1:3000/";
    let obj_url = "http://127.0.0.1:3001/";
    let ws_url = "ws://127.0.0.1:3002/";

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
        .configure(rpc_url, obj_url, ws_url, ":memory:", b"", alice_callbacks)
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
        .configure(rpc_url, obj_url, ws_url, ":memory:", b"", bobby_callbacks)
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
fn messaging_subscriptions() {
    test_server();

    let rpc_url = "http://127.0.0.1:3000/";
    let obj_url = "http://127.0.0.1:3001/";
    let ws_url = "ws://127.0.0.1:3002/";

    let (alice_welcome_tx, alice_welcome_rx) = crossbeam::channel::bounded::<bool>(1);
    let (alice_message_tx, alice_message_rx) = crossbeam::channel::bounded::<message::Content>(1);
    let (bobby_message_tx, _) = crossbeam::channel::bounded::<message::Content>(1);

    // setup alices account
    let mut alice = Account::new();
    let alice_wm_cb = alice.clone();
    let alice_db_path = format!("/tmp/{}.db", &random_id().encode_hex::<String>());

    //println!(">>> db path: {}", &alice_db_path);

    let alice_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |_| {}),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |_| {}),
        on_welcome: Arc::new(move |welcome| {
            alice_wm_cb
                .connection_accept(
                    welcome.to_address(),
                    welcome.welcome(),
                    welcome.subscription_token(),
                )
                .expect("failed to connect using welcome mesage");

            alice_welcome_tx
                .send(true)
                .expect("failed to channel send welcome");
        }),
    };

    // configure alice's account storage path to be persistent
    alice
        .configure(
            rpc_url,
            obj_url,
            ws_url,
            &alice_db_path,
            b"",
            alice_callbacks,
        )
        .expect("failed to configure account");

    // setup bob's account
    let mut bobby = Account::new();
    let bobby_kp_cb = bobby.clone();
    let bobby_ms_cb = bobby.clone();

    let bobby_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |message| {
            let chat_message = message::ChatBuilder::new()
                .message("hey alice")
                .finish()
                .expect("failed to build chat message");

            bobby_ms_cb
                .message_send(message.from_address(), &chat_message)
                .expect("failed to send response message from bobby");
            bobby_message_tx
                .send(message.content().clone())
                .expect("failed to send received message for bobby");
        }),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |key_package| {
            bobby_kp_cb
                .connection_establish(
                    key_package.to_address(),
                    key_package.from_address(),
                    key_package.package(),
                )
                .expect("failed to connect using key package");
        }),
        on_welcome: Arc::new(|_| {}),
    };

    bobby
        .configure(rpc_url, obj_url, ws_url, ":memory:", b"", bobby_callbacks)
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

    // shutdown alice's account
    alice
        .shutdown()
        .expect("failed to shutdown alice's account");

    // reload alice's account
    let mut alice = Account::new();

    let alice_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |message| {
            alice_message_tx
                .send(message.content().clone())
                .expect("failed to send received message for alice");
        }),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |_| {}),
        on_welcome: Arc::new(move |_| {}),
    };

    // configure alice's account storage path to be persistent
    alice
        .configure(
            rpc_url,
            obj_url,
            ws_url,
            &alice_db_path,
            b"",
            alice_callbacks,
        )
        .expect("failed to configure account");

    // implement metrics tracking to remove processing of duplicate messages
    // track last received message time for subscriptions
    // schedule task to update time offset for subscriptions (update based on inactivity vs timestamp of messages received)

    let chat_message = message::ChatBuilder::new()
        .message("hey alice")
        .finish()
        .expect("failed to build chat message");

    // alice send an encrypted message to the group
    bobby
        .message_send(&bobby_inbox, &chat_message)
        .expect("failed to send message");

    let message_from_bobby = alice_message_rx
        .recv_timeout(DEFAULT_TIMEOUT)
        .expect("failed to receive message");

    match message_from_bobby {
        message::Content::Chat(chat) => {
            assert_eq!(chat.message(), "hey alice");
        }
        _ => unreachable!(),
    }
}

#[test]
fn object_upload_and_download() {
    test_server();

    let rpc_url = "http://127.0.0.1:3000/";
    let obj_url = "http://127.0.0.1:3001/";
    let ws_url = "ws://127.0.0.1:3002/";

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
        .configure(rpc_url, obj_url, ws_url, ":memory:", b"", alice_callbacks)
        .expect("failed to configure account");

    let alice_kp = alice
        .keychain_signing_create()
        .expect("failed to create keypair");

    let data_a: Vec<u8> = vec![8; 1 << 16];
    let data_b: Vec<u8> = vec![16; 1 << 16];
    let object_upload_a = Object::from_bytes("binary/octet-stream".to_string(), data_a.clone());
    let object_upload_b = Object::from_bytes("binary/octet-stream".to_string(), data_b.clone());

    // upload a file and cache it locally
    alice
        .object_upload(&alice_kp, &object_upload_a, true)
        .expect("failed to upload object");

    // retrieve the locally cached file
    let mut object_download_a = Object::new(
        object_upload_a.id().to_vec(),
        object_upload_a.key().expect("key missing").to_vec(),
        "binary/octet-stream".to_string(),
    );

    alice
        .object_download(&alice_kp, &mut object_download_a)
        .expect("failed to download object");
    assert_eq!(object_download_a.data().expect("data missing"), data_a);

    // upload a file, but don't cache it locally
    alice
        .object_upload(&alice_kp, &object_upload_b, false)
        .expect("failed to upload object");

    // retrieve the remotely stored file
    let mut object_download_b = Object::new(
        object_upload_b.id().to_vec(),
        object_upload_b.key().expect("key missing").to_vec(),
        "binary/octet-stream".to_string(),
    );

    alice
        .object_download(&alice_kp, &mut object_download_b)
        .expect("failed to download object");
    assert_eq!(object_download_b.data().expect("data missing"), data_b);
}

#[test]
fn credentials_and_presentations() {
    test_server();

    let rpc_url = "http://127.0.0.1:3000/";
    let obj_url = "http://127.0.0.1:3001/";
    let ws_url = "ws://127.0.0.1:3002/";

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
        .configure(rpc_url, obj_url, ws_url, ":memory:", b"", alice_callbacks)
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
        .configure(rpc_url, obj_url, ws_url, ":memory:", b"", bobby_callbacks)
        .expect("failed to configure account");

    // create a new link key for bobby
    let bobby_link_key = bobby
        .keychain_signing_create()
        .expect("failed to create keypair");

    // create a new holder key for bobby to use as a holder of the credentials
    let bobby_holder_key = bobby
        .keychain_signing_create()
        .expect("failed to create keypair");

    // issue a credential from alice about bobby
    let credential = CredentialBuilder::new()
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
        .credential_issue(&credential)
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

    // present the credentials back to alice
    let presentation = PresentationBuilder::new()
        .context(default(CONTEXT_DEFAULT))
        .presentation_type(default(PRESENTATION_DEFAULT))
        .holder(&Address::key(&bobby_holder_key))
        .credential_add(credentials[0].clone())
        .finish()
        .expect("failed to create presentation");

    bobby
        .presentation_issue(&presentation)
        .expect("failed to generate verifiable presentation");
}

#[test]
fn message_chat() {
    test_server();

    let rpc_url = "http://127.0.0.1:3000/";
    let obj_url = "http://127.0.0.1:3001/";
    let ws_url = "ws://127.0.0.1:3002/";

    let (alice_welcome_tx, alice_welcome_rx) = crossbeam::channel::bounded::<bool>(1);
    let (alice_message_tx, alice_message_rx) = crossbeam::channel::bounded::<message::Content>(1);
    let (bobby_message_tx, bobby_message_rx) = crossbeam::channel::bounded::<message::Content>(1);

    // setup alices account
    let mut alice = Account::new();
    let alice_wm_cb = alice.clone();

    let alice_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |message| {
            alice_message_tx
                .send(message.content().clone())
                .expect("failed to send received message for alice");
        }),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |_| {}),
        on_welcome: Arc::new(move |welcome| {
            alice_wm_cb
                .connection_accept(
                    welcome.to_address(),
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
        .configure(rpc_url, obj_url, ws_url, ":memory:", b"", alice_callbacks)
        .expect("failed to configure account");

    // setup bob's account
    let mut bobby = Account::new();
    let bobby_kp_cb = bobby.clone();
    let bobby_ms_cb = bobby.clone();

    let bobby_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |message| {
            let chat_message = message::ChatBuilder::new()
                .message("hey alice")
                .finish()
                .expect("failed to build chat message");

            bobby_ms_cb
                .message_send(message.from_address(), &chat_message)
                .expect("failed to send response message from bobby");
            bobby_message_tx
                .send(message.content().clone())
                .expect("failed to send received message for bobby");
        }),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |key_package| {
            bobby_kp_cb
                .connection_establish(
                    key_package.to_address(),
                    key_package.from_address(),
                    key_package.package(),
                )
                .expect("failed to connect using key package");
        }),
        on_welcome: Arc::new(|_| {}),
    };

    bobby
        .configure(rpc_url, obj_url, ws_url, ":memory:", b"", bobby_callbacks)
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

    let chat_message = message::ChatBuilder::new()
        .message("hey bobby")
        .finish()
        .expect("failed to build chat message");

    // alice send an encrypted message to the group
    alice
        .message_send(&bobby_inbox, &chat_message)
        .expect("failed to send message");

    let message_from_alice = bobby_message_rx
        .recv_timeout(DEFAULT_TIMEOUT)
        .expect("failed to receive message");

    match message_from_alice {
        message::Content::Chat(chat) => {
            assert_eq!(chat.message(), "hey bobby");
        }
        _ => unreachable!(),
    }

    let message_from_bobby = alice_message_rx
        .recv_timeout(DEFAULT_TIMEOUT)
        .expect("failed to receive message");

    match message_from_bobby {
        message::Content::Chat(chat) => {
            assert_eq!(chat.message(), "hey alice");
        }
        _ => unreachable!(),
    }
}

#[test]
fn message_credential_verification() {
    test_server();

    let rpc_url = "http://127.0.0.1:3000/";
    let obj_url = "http://127.0.0.1:3001/";
    let ws_url = "ws://127.0.0.1:3002/";

    let (alice_welcome_tx, alice_welcome_rx) = crossbeam::channel::bounded::<bool>(1);
    let (alice_message_tx, alice_message_rx) = crossbeam::channel::bounded::<message::Content>(1);
    let (bobby_message_tx, bobby_message_rx) = crossbeam::channel::bounded::<message::Content>(1);

    // setup alices account
    let mut alice = Account::new();
    let alice_wm_cb = alice.clone();

    let alice_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |message| {
            alice_message_tx
                .send(message.content().clone())
                .expect("failed to send received message for alice");
        }),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |_| {}),
        on_welcome: Arc::new(move |welcome| {
            alice_wm_cb
                .connection_accept(
                    welcome.to_address(),
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
        .configure(rpc_url, obj_url, ws_url, ":memory:", b"", alice_callbacks)
        .expect("failed to configure account");

    // setup bob's account
    let mut bobby = Account::new();
    let bobby_kp_cb = bobby.clone();
    let bobby_ms_cb = bobby.clone();

    let bobby_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |message| {
            let credential = CredentialBuilder::new()
                .context(default(CONTEXT_DEFAULT))
                .credential_type(default(CREDENTIAL_DEFAULT))
                .credential_subject(&Address::key(message.from_address()))
                .credential_subject_claim("friendOf", "bobby")
                .issuer(&Address::aure(message.to_address()))
                .valid_from(now())
                .sign_with(message.to_address(), now())
                .finish()
                .expect("failed to build credential");

            let alice_verified_credential = bobby_ms_cb
                .credential_issue(&credential)
                .expect("failed to issue credential");

            // request credential verification from bobby
            let content = message::CredentialVerificationResponseBuilder::new()
                .status(message::ResponseStatus::Created)
                .credential(alice_verified_credential)
                .finish()
                .expect("failed to build verification request");

            bobby_ms_cb
                .message_send(message.from_address(), &content)
                .expect("failed to send response message from bobby");

            bobby_message_tx
                .send(message.content().clone())
                .expect("failed to send received message for bobby");
        }),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |key_package| {
            bobby_kp_cb
                .connection_establish(
                    key_package.to_address(),
                    key_package.from_address(),
                    key_package.package(),
                )
                .expect("failed to connect using key package");
        }),
        on_welcome: Arc::new(|_| {}),
    };

    bobby
        .configure(rpc_url, obj_url, ws_url, ":memory:", b"", bobby_callbacks)
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

    // upload evidence for verification request
    let alice_evidence_data = vec![1; 4096];
    let alice_evidence_object = object::Object::from_bytes(
        "binary/octet-stream".to_string(),
        alice_evidence_data.clone(),
    );

    alice
        .object_upload(&alice_inbox, &alice_evidence_object, true)
        .expect("failed to store evidence object");

    // generate a credential to be used as supporting proof for the verification
    let alice_link_key = alice
        .keychain_signing_create()
        .expect("failed to create keypair");

    let credential = CredentialBuilder::new()
        .context(default(CONTEXT_DEFAULT))
        .credential_type(default(CREDENTIAL_DEFAULT))
        .credential_subject(&Address::key(&alice_link_key))
        .credential_subject_claim("firstName", "alice")
        .issuer(&Address::aure(&alice_inbox))
        .valid_from(now())
        .sign_with(&alice_inbox, now())
        .finish()
        .expect("failed to build credential");

    let alice_verified_credential = alice
        .credential_issue(&credential)
        .expect("failed to issue credential");

    alice
        .credential_store(&alice_verified_credential)
        .expect("failed to store credential");

    // request credential verification from bobby
    let content = message::CredentialVerificationRequestBuilder::new()
        .credential_type(default(CREDENTIAL_DEFAULT))
        .proof(alice_verified_credential)
        .evidence("passport.image".to_string(), alice_evidence_object)
        .finish()
        .expect("failed to build verification request");

    alice
        .message_send(&bobby_inbox, &content)
        .expect("failed to send message");

    let request_from_alice = bobby_message_rx
        .recv_timeout(DEFAULT_TIMEOUT)
        .expect("failed to receive message");

    match request_from_alice {
        message::Content::CredentialVerificationRequest(request) => {
            assert_eq!(request.credential_type(), CREDENTIAL_DEFAULT);

            let mut evidence = request.evidence().expect("failed to decode evidence");
            assert_eq!(evidence.len(), 1);

            let evidence = &mut evidence[0];
            assert_eq!(evidence.evidence_type, "passport.image");

            // check bobby can download the image
            bobby
                .object_download(&bobby_inbox, &mut evidence.object)
                .expect("failed to download evidence object");

            // check the proof
            let proof = request.proof().expect("failed to decode proof");
            assert_eq!(proof.len(), 1);

            let proof = &proof[0];

            assert_eq!(proof.credential_type(), CREDENTIAL_DEFAULT);

            let subject = proof
                .credential_subject()
                .expect("failed to get credential subject");
            assert_eq!(&alice_link_key, subject.address());

            let subject_claim = proof
                .credential_subject_claim("firstName")
                .expect("missing credential claim");
            assert_eq!(subject_claim, "alice");
        }
        _ => unreachable!(),
    }

    let response_from_bobby = alice_message_rx
        .recv_timeout(DEFAULT_TIMEOUT)
        .expect("failed to receive message");

    match response_from_bobby {
        message::Content::CredentialVerificationResponse(response) => {
            assert_eq!(response.status(), ResponseStatus::Created);

            let credentials = response
                .credentials()
                .expect("failed to decode credentials");
            assert_eq!(credentials.len(), 1);

            let credential = &credentials[0];

            let subject = credential
                .credential_subject()
                .expect("credential subject invalid");
            assert_eq!(subject.address(), &alice_inbox);

            let subject_claim = credential
                .credential_subject_claim("friendOf")
                .expect("credential subject claim invalid");
            assert_eq!(subject_claim, "bobby");
        }
        _ => unreachable!(),
    }
}

#[test]
fn message_credential_presentation() {
    test_server();

    let rpc_url = "http://127.0.0.1:3000/";
    let obj_url = "http://127.0.0.1:3001/";
    let ws_url = "ws://127.0.0.1:3002/";

    let (alice_welcome_tx, alice_welcome_rx) = crossbeam::channel::bounded::<bool>(1);
    let (alice_message_tx, alice_message_rx) = crossbeam::channel::bounded::<message::Content>(1);
    let (bobby_message_tx, bobby_message_rx) = crossbeam::channel::bounded::<message::Content>(1);

    // setup alices account
    let mut alice = Account::new();
    let alice_wm_cb = alice.clone();

    let alice_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |message| {
            alice_message_tx
                .send(message.content().clone())
                .expect("failed to send received message for alice");
        }),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |_| {}),
        on_welcome: Arc::new(move |welcome| {
            alice_wm_cb
                .connection_accept(
                    welcome.to_address(),
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
        .configure(rpc_url, obj_url, ws_url, ":memory:", b"", alice_callbacks)
        .expect("failed to configure account");

    // setup bob's account
    let mut bobby = Account::new();
    let bobby_kp_cb = bobby.clone();
    let bobby_ms_cb = bobby.clone();

    let bobby_callbacks = MessagingCallbacks {
        on_connect: Arc::new(|| {}),
        on_disconnect: Arc::new(|_| {}),
        on_message: Arc::new(move |msg| {
            match msg.content() {
                message::Content::CredentialPresentationRequest(request) => {
                    // present the credentials back to alice
                    let mut presentation_builder = PresentationBuilder::new();

                    let as_address = match bobby_ms_cb.group_member_as(msg.to_address()) {
                        Ok(as_address) => match as_address {
                            Some(as_address) => as_address,
                            None => return,
                        },
                        Err(_) => return,
                    };

                    presentation_builder
                        .context(default(CONTEXT_DEFAULT))
                        .presentation_type(default(PRESENTATION_DEFAULT))
                        .holder(&Address::key(&as_address));

                    for detail in request.details().expect("failed to decode details") {
                        let credential_type: Vec<&str> =
                            detail.credential_type.iter().map(|t| t.as_ref()).collect();

                        let credentials = bobby_ms_cb
                            .credential_lookup_by_credential_type(&credential_type)
                            .expect("failed to find credentials");

                        for credential in credentials {
                            presentation_builder.credential_add(credential);
                        }
                    }

                    let presentation = presentation_builder
                        .finish()
                        .expect("failed to create presentation");

                    let verifiable_presentation = bobby_ms_cb
                        .presentation_issue(&presentation)
                        .expect("failed to generate verifiable presentation");

                    // request credential verification from bobby
                    let content = message::CredentialPresentationResponseBuilder::new()
                        .status(message::ResponseStatus::Accepted)
                        .presentation(verifiable_presentation)
                        .finish()
                        .expect("failed to build verification request");

                    bobby_ms_cb
                        .message_send(msg.from_address(), &content)
                        .expect("failed to send response message from bobby");

                    bobby_message_tx
                        .send(msg.content().clone())
                        .expect("failed to send received message for bobby");
                }
                _ => unreachable!("not an option"),
            }
        }),
        on_commit: Arc::new(|_| {}),
        on_key_package: Arc::new(move |key_package| {
            bobby_kp_cb
                .connection_establish(
                    key_package.to_address(),
                    key_package.from_address(),
                    key_package.package(),
                )
                .expect("failed to connect using key package");
        }),
        on_welcome: Arc::new(|_| {}),
    };

    bobby
        .configure(rpc_url, obj_url, ws_url, ":memory:", b"", bobby_callbacks)
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

    // generate a credential to be used by bobby in the presentation
    let bobby_link_key = bobby
        .keychain_signing_create()
        .expect("failed to create keypair");

    let credential = CredentialBuilder::new()
        .context(default(CONTEXT_DEFAULT))
        .credential_type(default(CREDENTIAL_DEFAULT))
        .credential_subject(&Address::key(&bobby_link_key))
        .credential_subject_claim("firstName", "bobby")
        .issuer(&Address::aure(&bobby_inbox))
        .valid_from(now())
        .sign_with(&bobby_inbox, now())
        .finish()
        .expect("failed to build credential");

    let bobby_verified_credential = bobby
        .credential_issue(&credential)
        .expect("failed to issue credential");

    bobby
        .credential_store(&bobby_verified_credential)
        .expect("failed to store credential");

    // request credential presentation from bobby
    let content = message::CredentialPresentationRequestBuilder::new()
        .details(CredentialPresentationDetail {
            credential_type: default(CREDENTIAL_DEFAULT),
            subject: HashMap::new(),
        })
        .finish()
        .expect("failed to build verification request");

    alice
        .message_send(&bobby_inbox, &content)
        .expect("failed to send message");

    let request_from_alice = bobby_message_rx
        .recv_timeout(DEFAULT_TIMEOUT)
        .expect("failed to receive message");

    match request_from_alice {
        message::Content::CredentialPresentationRequest(request) => {
            assert_eq!(request.details().expect("fail").len(), 1);
        }
        _ => unreachable!(),
    }

    let response_from_bobby = alice_message_rx
        .recv_timeout(DEFAULT_TIMEOUT)
        .expect("failed to receive message");

    match response_from_bobby {
        message::Content::CredentialPresentationResponse(response) => {
            assert_eq!(response.status(), ResponseStatus::Accepted);

            let presentations = response
                .presentations()
                .expect("failed to decode credentials");
            assert_eq!(presentations.len(), 1);

            let presentation = &presentations[0];

            let holder = presentation.holder().expect("credential holder invalid");

            assert_eq!(holder.address(), &bobby_inbox);
            assert_eq!(presentation.credentials().len(), 1);
            assert_eq!(presentation.presentation_type(), PRESENTATION_DEFAULT);

            let credential = presentation
                .credentials()
                .first()
                .expect("empty credentials");

            let subject = credential.credential_subject().expect("invalid subject");
            assert_eq!(subject.address(), &bobby_link_key);

            let subject_claim = credential
                .credential_subject_claim("firstName")
                .expect("invalid subject claim");
            assert_eq!(subject_claim, "bobby");

            let mut signed_by_holder = false;
            let mut signed_by_link = false;

            for signer in presentation.signers().expect("invalid signers") {
                if signer.address().eq(&bobby_inbox) {
                    signed_by_holder = true;
                } else if signer.address().eq(&bobby_link_key) {
                    signed_by_link = true;
                }
            }

            assert!(signed_by_holder);
            assert!(signed_by_link);
        }
        _ => unreachable!(),
    }
}
