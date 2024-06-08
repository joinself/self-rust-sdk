use std::{
    sync::{Arc, Once},
    time::Duration,
};

use self_sdk::{
    account::{Account, MessagingCallbacks},
    credential::{
        default, Address, CredentialBuilder, PresentationBuilder, CONTEXT_DEFAULT,
        CREDENTIAL_DEFAULT, PRESENTATION_DEFAULT,
    },
    hashgraph::{Hashgraph, Role},
    message::{self, ResponseStatus},
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
                .message_send(message.sender(), &chat_message)
                .expect("failed to send response message from bobby");
            bobby_message_tx
                .send(message.content().clone())
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
                .credential_subject(&Address::key(message.sender()))
                .credential_subject_claim("friendOf", "bobby")
                .issuer(&Address::aure(message.recipient()))
                .valid_from(now())
                .sign_with(message.recipient(), now())
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
                .message_send(message.sender(), &content)
                .expect("failed to send response message from bobby");

            bobby_message_tx
                .send(message.content().clone())
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
fn message_credential_presentation() {}
