use std::sync::Arc;

use crossbeam::channel;
use prost::Message;
use tokio::runtime::Runtime;
use tonic::transport::Channel;
use tonic::IntoRequest;

use crate::error::SelfError;
use crate::protocol::api::{
    ApiClient, ExecuteRequest, PublishRequest, Request, RequestHeader, ResponseStatus, Version,
};

pub struct Rpc {
    client: ApiClient<Channel>,
    runtime: Arc<Runtime>,
}

impl Rpc {
    pub fn new(endpoint: &str) -> Result<Rpc, SelfError> {
        let endpoint = String::from(endpoint);
        let runtime = Runtime::new().unwrap();
        let (tx, rx) = channel::bounded(1);

        runtime.spawn(async move {
            let result = ApiClient::connect(endpoint).await;
            tx.send(result).unwrap();
        });

        let result = match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(result) => result,
            Err(_) => {
                println!("rpc: client timeout");
                return Err(SelfError::RpcConnectionTimeout);
            }
        };

        let client = match result {
            Ok(client) => client,
            Err(err) => {
                println!("rpc: {}", err);
                return Err(SelfError::RpcConnectionFailed);
            }
        };

        let runtime = Arc::new(runtime);

        Ok(Rpc { client, runtime })
    }

    pub fn execute(&mut self, id: &[u8], operation: &[u8]) -> Result<(), SelfError> {
        let (tx, rx) = channel::bounded(1);

        let id = id.to_vec();
        let operation = operation.to_vec();

        let mut client = self.client.clone();
        let runtime = self.runtime.clone();

        runtime.spawn(async move {
            let execute = ExecuteRequest { id, operation }.encode_to_vec();

            let request = Request {
                header: Some(RequestHeader {
                    version: Version::V1 as i32,
                }),
                content: execute,
                authorization: None,
                proof_of_work: None,
            };

            tx.send(client.execute(request).await).unwrap();
        });

        let response = match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(response) => match response {
                Ok(response) => response.into_inner(),
                Err(_) => return Err(SelfError::RpcRequestFailed),
            },
            Err(err) => {
                println!("rpc: {}", err);
                return Err(SelfError::RpcRequestTimeout);
            }
        };

        if let Some(header) = response.header {
            if header.status > 204 {
                println!("rpc: request failed with '{}'", header.message);
                return Err(rpc_error_status(header.status));
            }
        }

        Ok(())
    }

    pub fn publish(&mut self, id: &[u8], keys: &[Vec<u8>]) -> Result<(), SelfError> {
        let (tx, rx) = channel::bounded(1);

        let id = id.to_vec();
        let keys = keys.to_vec();

        let mut client = self.client.clone();
        let runtime = self.runtime.clone();

        runtime.spawn(async move {
            let publish = PublishRequest { id, keys }.encode_to_vec();

            let request = Request {
                header: Some(RequestHeader {
                    version: Version::V1 as i32,
                }),
                content: publish,
                authorization: None,
                proof_of_work: None,
            };

            tx.send(client.publish(request).await).unwrap();
        });

        let response = match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(response) => match response {
                Ok(response) => response.into_inner(),
                Err(_) => return Err(SelfError::RpcRequestFailed),
            },
            Err(err) => {
                println!("rpc: {}", err);
                return Err(SelfError::RpcRequestTimeout);
            }
        };

        if let Some(header) = response.header {
            if header.status > 204 {
                println!("rpc: request failed with '{}'", header.message);
                return Err(rpc_error_status(header.status));
            }
        }

        Ok(())
    }
}

fn rpc_error_status(status: i32) -> SelfError {
    match ResponseStatus::try_from(status).expect("failed to decode response status") {
        ResponseStatus::StatusBadRequest => SelfError::RpcBadRequest,
        ResponseStatus::StatusUnauthorized => SelfError::RpcUnauthorized,
        ResponseStatus::StatusPaymentRequired => SelfError::RpcPaymentRequired,
        ResponseStatus::StatusForbidden => SelfError::RpcForbidden,
        ResponseStatus::StatusNotFound => SelfError::RpcNotFound,
        ResponseStatus::StatusMethodNotAllowed => SelfError::RpcMethodNotAllowed,
        ResponseStatus::StatusNotAcceptable => SelfError::RpcNotAcceptable,
        ResponseStatus::StatusRequestTimeout => SelfError::RpcRequestTimeout,
        ResponseStatus::StatusConflict => SelfError::RpcConflict,
        ResponseStatus::StatusGone => SelfError::RpcGone,
        ResponseStatus::StatusLengthRequired => SelfError::RpcLengthRequired,
        ResponseStatus::StatusPreconditionFailed => SelfError::RpcPreconditionFailed,
        ResponseStatus::StatusRequestEntityTooLarge => SelfError::RpcRequestEntityTooLarge,
        ResponseStatus::StatusExpectationFailed => SelfError::RpcExpectationFailed,
        ResponseStatus::StatusInternalServerError => SelfError::RpcInternalServerError,
        ResponseStatus::StatusNotImplemented => SelfError::RpcNotImplemented,
        ResponseStatus::StatusBadGateway => SelfError::RpcBadGateway,
        ResponseStatus::StatusServiceUnavailable => SelfError::RpcServiceUnavailable,
        ResponseStatus::StatusGatewayTimeout => SelfError::RpcGatewayTimeout,
        _ => SelfError::RpcUnknown,
    }
}
