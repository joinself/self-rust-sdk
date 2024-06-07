use std::ops::Add;

use hex::ToHex;
use reqwest::blocking::{Client, Request, Response};
use reqwest::{Method, StatusCode, Url};

use crate::crypto::pow;
use crate::error::SelfError;
use crate::keypair::signing;
use crate::{object, token};

pub struct ObjectStore {
    client: reqwest::blocking::Client,
    endpoint: Url,
}

impl ObjectStore {
    pub fn new(object_endpoint: &str) -> Result<ObjectStore, SelfError> {
        let endpoint = match Url::parse(object_endpoint) {
            Ok(endpoint) => endpoint,
            Err(_) => return Err(SelfError::HTTPRequestURLInvalid),
        };

        Ok(ObjectStore {
            client: Client::new(),
            endpoint,
        })
    }

    pub fn upload(
        &self,
        object: &object::Object,
        issued_by: &signing::KeyPair,
    ) -> Result<(), SelfError> {
        let endpoint = self
            .endpoint
            .join("/objects/")
            .expect("failed to build object url");

        let mut request = Request::new(Method::POST, endpoint);

        let data = match object.data() {
            Some(data) => data,
            None => return Err(SelfError::ObjectDataInvalid),
        };

        self.proof_of_work(request.headers_mut(), object.id());
        self.authenticate(request.headers_mut(), issued_by, data);
        *request.body_mut() = Some(reqwest::blocking::Body::from(data.to_vec()));

        match self.client.execute(request) {
            Ok(response) => handle_response_status(&response),
            Err(err) => Err(handle_error(err)),
        }
    }

    pub fn download(&self, object: &mut object::Object) -> Result<(), SelfError> {
        // TODO proof of work over request path...
        let stub = format!("/objects/{}", object.id().encode_hex::<String>());
        let endpoint = self
            .endpoint
            .join(&stub)
            .expect("failed to build object url");
        let request = Request::new(Method::GET, endpoint);

        let response = match self.client.execute(request) {
            Ok(response) => response,
            Err(err) => return Err(handle_error(err)),
        };

        handle_response_status(&response)?;

        let data = match response.bytes() {
            Ok(data) => data,
            Err(_) => return Err(SelfError::HTTPResposeBodyInvalid),
        };

        object.decrypt(data.to_vec())
    }

    fn proof_of_work(&self, headers: &mut reqwest::header::HeaderMap, id: &[u8]) {
        // calculate proof of work over the object id (which is actually just the object data's hash)
        let (pow_hash, pow_nonce) = pow::ProofOfWork::new(8).calculate(id);
        let pow_hash = base64::encode_config(pow_hash, base64::URL_SAFE_NO_PAD);

        let pow_hash = reqwest::header::HeaderValue::from_str(&pow_hash);
        let pow_nonce = reqwest::header::HeaderValue::from_str(&pow_nonce.to_string());
        headers.insert("X-Self-POW-Hash", pow_hash.unwrap());
        headers.insert("X-Self-POW-Nonce", pow_nonce.unwrap());
    }

    fn authenticate(
        &self,
        headers: &mut reqwest::header::HeaderMap,
        issued_by: &signing::KeyPair,
        content: &[u8],
    ) {
        let token = token::Authentication::new(
            issued_by,
            crate::time::unix(),
            crate::time::now()
                .add(std::time::Duration::from_secs(10))
                .timestamp(),
            content,
        );

        let token = base64::encode_config(token.as_bytes(), base64::URL_SAFE_NO_PAD);
        let token = reqwest::header::HeaderValue::from_str(&token);
        headers.insert("Authorization", token.unwrap());
    }
}

fn handle_error(e: reqwest::Error) -> SelfError {
    println!("reqwest err: {}", e);
    if e.is_redirect() {
        return SelfError::HTTPRequestRedirected;
    }

    if e.is_connect() {
        return SelfError::HTTPRequestConnectionFailed;
    }

    if e.is_timeout() {
        return SelfError::HTTPRequestConnectionTimeout;
    }

    SelfError::HTTPRequestUnknown
}

fn handle_response_status(response: &Response) -> Result<(), SelfError> {
    if response.status().is_success() {
        return Ok(());
    }

    match response.status() {
        StatusCode::BAD_REQUEST => Err(SelfError::HTTPResponseBadRequest),
        StatusCode::NOT_FOUND => Err(SelfError::HTTPResponseNotFound),
        StatusCode::UNAUTHORIZED => Err(SelfError::HTTPResponseUnauthorized),
        StatusCode::FORBIDDEN => Err(SelfError::HTTPResponseForbidden),
        StatusCode::NOT_ACCEPTABLE => Err(SelfError::HTTPResponseNotAcceptable),
        StatusCode::CONFLICT => Err(SelfError::HTTPResponseConflict),
        StatusCode::PAYLOAD_TOO_LARGE => Err(SelfError::HTTPResponsePayloadTooLarge),
        StatusCode::SERVICE_UNAVAILABLE => Err(SelfError::HTTPResponseServiceUnavailable),
        StatusCode::INTERNAL_SERVER_ERROR => Err(SelfError::HTTPResponseInternalServerError),
        _ => Err(SelfError::HTTPResponseUnexpected),
    }
}
