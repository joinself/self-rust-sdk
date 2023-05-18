use self_sdk::account::{Account, MessagingCallbacks};
use self_test_mock::Server;

use std::sync::{Arc, Once};

static mut SERVER: Option<Server> = None;
static INIT: Once = Once::new();

pub fn test_server() {
    unsafe {
        INIT.call_once(|| {
            SERVER = Some(Server::new(3000, 3001));
        });
    }
}

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
                on_message: None,
                on_request: None,
                on_response: None,
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
                on_message: None,
                on_request: None,
                on_response: None,
            },
        )
        .expect("failed to configure account");

    let recovery_key = self_sdk::keypair::signing::KeyPair::new();
    account
        .register(&recovery_key)
        .expect("failed to register account");

    assert!(account.messaging_identifer().is_some());
}

#[test]
fn account_connect_without_token() {
    test_server();

    let mut alices_account = register_test_account("test_account_connect_alice");
    let bobs_account = register_test_account("test_account_connect_bob");

    let bobs_identifier = bobs_account
        .messaging_identifer()
        .expect("must have an identifier");

    alices_account
        .connect(&bobs_identifier, None, None)
        .expect("failed to send connection to bob");

    std::thread::sleep(std::time::Duration::from_secs(1));
}

fn register_test_account(test_name: &str) -> Account {
    let mut account = Account::new();
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
                on_message: Some(Arc::new(|_, envelope| {
                    println!(
                        "got message from: {} typ: {:?}",
                        hex::encode(envelope.from.id()),
                        envelope.content.type_get()
                    )
                })),
                on_request: None,
                on_response: None,
            },
        )
        .expect("failed to configure account");

    let recovery_key = self_sdk::keypair::signing::KeyPair::new();
    account
        .register(&recovery_key)
        .expect("failed to register account");

    account
}
