use self_sdk::account::{Account, MessagingCallbacks};
use self_test_mock::Server;

#[test]
fn account_configure() {
    let server = Server::new(3000, 3001);

    let mut account = Account::new();
    account
        .configure(
            "http://127.0.0.1:3000/",
            "ws://127.0.0.1:3001/",
            "/tmp/test_account_configure/",
            b"123456789",
            MessagingCallbacks {
                on_connect: None,
                on_disconnect: None,
                on_message: None,
                on_request: None,
                on_response: None,
            },
        )
        .expect("failed to configure account");

    drop(server);
}

#[test]
fn account_register() {
    let server = Server::new(3002, 3003);

    let mut account = Account::new();
    account
        .configure(
            "http://127.0.0.1:3002/",
            "ws://127.0.0.1:3003/",
            "/tmp/test_account_configure/",
            b"123456789",
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

    drop(server);
}
