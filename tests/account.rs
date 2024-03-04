/*
use crossbeam::channel::Sender;
use self_sdk::{
    account::{Account, MessagingCallbacks},
    crypto::random_id,
    message::{
        self, ChatDelivered, ChatMessage, ChatRead, ConnectionRequest, ConnectionResponse, Content,
        Envelope, ResponseStatus,
    },
    time::unix,
};
use self_test_mock::Server;

use std::{
    any::Any,
    sync::{Arc, Once},
    time::{Duration, Instant},
};

static mut SERVER: Option<Server> = None;
static INIT: Once = Once::new();
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(100);

struct MessagingChannels {
    on_request: Option<Sender<Envelope>>,
    on_response: Option<Sender<Envelope>>,
    on_message: Option<Sender<Envelope>>,
}

pub type OnRequestCB = Arc<dyn Fn(Arc<dyn Any + Send>, &Envelope) -> ResponseStatus + Sync + Send>;
pub type OnResponseCB = Arc<dyn Fn(Arc<dyn Any + Send>, &Envelope) + Sync + Send>;
pub type OnMessageCB = Arc<dyn Fn(Arc<dyn Any + Send>, &Envelope) + Sync + Send>;

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
