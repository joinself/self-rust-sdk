use chrono::Duration;
use reqwest::blocking::{Client, Request};
use reqwest::Url;

use crate::crypto::pow::ProofOfWork;
use crate::error::SelfError;
use crate::keypair::signing::KeyPair;

pub struct Rest {
    client: reqwest::blocking::Client,
}

pub struct Response {
    pub code: u16,
    pub data: Vec<u8>,
}

impl Rest {
    pub fn new() -> Rest {
        Rest {
            client: Client::new(),
        }
    }

    pub fn get(
        &self,
        url: &str,
        signing_key: Option<&KeyPair>,
        pow: bool,
    ) -> Result<Response, SelfError> {
        self.request(reqwest::Method::GET, url, None, signing_key, pow)
    }

    pub fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        signing_key: Option<&KeyPair>,
        pow: bool,
    ) -> Result<Response, SelfError> {
        self.request(reqwest::Method::POST, url, Some(body), signing_key, pow)
    }

    pub fn put(
        &self,
        url: &str,
        body: Vec<u8>,
        signing_key: Option<&KeyPair>,
        pow: bool,
    ) -> Result<Response, SelfError> {
        self.request(reqwest::Method::PUT, url, Some(body), signing_key, pow)
    }

    pub fn delete(
        &self,
        url: &str,
        signing_key: Option<&KeyPair>,
        pow: bool,
    ) -> Result<Response, SelfError> {
        self.request(reqwest::Method::DELETE, url, None, signing_key, pow)
    }

    fn authorization(&self, signing_key: &KeyPair, headers: &mut reqwest::header::HeaderMap) {
        let mut token = crate::message::Message::new();

        token.subject_set(&signing_key.id());
        token.type_set("authorization");
        token.cti_set(&crate::crypto::random_id());

        token
            .sign(
                signing_key,
                Some((crate::time::now() + Duration::seconds(10)).timestamp()),
            )
            .expect("signing token failed unexpectedly");

        let cws = token.encode().expect("encoding tokne failed unexpectedly");
        let cws_encoded = base64::encode_config(cws, base64::URL_SAFE_NO_PAD);

        let authorization = reqwest::header::HeaderValue::from_str(&cws_encoded);
        headers.insert("Authorization", authorization.unwrap());
    }

    fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<Vec<u8>>,
        signing_key: Option<&KeyPair>,
        pow: bool,
    ) -> Result<Response, SelfError> {
        let target = match Url::parse(url) {
            Ok(target) => target,
            Err(err) => {
                println!("{:?}", err);
                return Err(SelfError::RestRequestURLInvalid);
            }
        };

        let mut request = Request::new(method, target);

        if let Some(sk) = signing_key {
            self.authorization(sk, request.headers_mut());
        }

        if let Some(bd) = body {
            if pow {
                self.proof_of_work(&bd, request.headers_mut());
            }

            *request.body_mut() = Some(reqwest::blocking::Body::from(bd));
        }

        let response = self.client.execute(request);
        if response.is_err() {
            return Err(handle_error(response.err().unwrap()));
        }

        let successful_response = response.unwrap();
        let status = successful_response.status().as_u16();

        return match successful_response.bytes() {
            Ok(bytes) => Ok(Response {
                code: status,
                data: bytes.to_vec(),
            }),
            Err(err) => {
                println!("{}", err);
                return Err(SelfError::RestRequestInvalid);
            }
        };
    }

    fn proof_of_work(&self, body: &[u8], headers: &mut reqwest::header::HeaderMap) {
        // compute proof of work hash over operation
        // TODO load pow difficulty from some other sourcee
        let (hash, nonce) = ProofOfWork::new(20).calculate(body);

        let hash_encoded = base64::encode_config(hash, base64::URL_SAFE_NO_PAD);

        let pow_hash = reqwest::header::HeaderValue::from_str(&hash_encoded);
        let pow_nonce = reqwest::header::HeaderValue::from_str(&nonce.to_string());
        headers.insert("X-Self-POW-Hash", pow_hash.unwrap());
        headers.insert("X-Self-POW-Nonce", pow_nonce.unwrap());
    }
}

fn handle_error(e: reqwest::Error) -> SelfError {
    println!("reqwest err: {}", e);
    if e.is_redirect() {
        return SelfError::RestRequestRedirected;
    }

    if e.is_connect() {
        return SelfError::RestRequestConnectionFailed;
    }

    if e.is_timeout() {
        return SelfError::RestRequestConnectionTimeout;
    }

    SelfError::RestRequestUnknown
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::keypair::signing::KeyPair;
    use httptest::{matchers::*, responders::*, Expectation, Server};

    #[test]
    fn get() {
        let server = Server::run();

        let m = all_of![
            request::method_path("GET", "/v1/identities"),
            request::headers(contains(key("authorization"))),
        ];

        server.expect(
            Expectation::matching(m)
                .respond_with(status_code(200).body("{\"status\":\"success\"}")),
        );

        // create a new client and siging keypair
        let kp = KeyPair::new();
        let client = Rest::new();

        let url = server.url_str("/v1/identities");

        let response = client.get(&url, Some(&kp), false);
        assert!(response.is_ok());

        let successful_response = response.unwrap();
        assert_eq!(successful_response.code, 200);
        assert_eq!(
            successful_response.data,
            "{\"status\":\"success\"}".as_bytes()
        );
    }

    #[test]
    fn post() {
        let server = Server::run();

        let m = all_of![
            request::method_path("POST", "/v1/identities"),
            request::headers(contains(key("authorization"))),
            request::body("{\"history\":[]\"}"),
        ];

        server.expect(
            Expectation::matching(m)
                .respond_with(status_code(201).body("{\"status\":\"success\"}")),
        );

        // create a new client and siging keypair
        let kp = KeyPair::new();
        let client = Rest::new();

        let url = server.url_str("/v1/identities");

        let response = client.post(
            &url,
            "{\"history\":[]\"}".as_bytes().to_vec(),
            Some(&kp),
            false,
        );
        assert!(response.is_ok());

        let successful_response = response.unwrap();
        assert_eq!(successful_response.code, 201);
        assert_eq!(
            successful_response.data,
            "{\"status\":\"success\"}".as_bytes()
        );
    }

    #[test]
    fn put() {
        let server = Server::run();

        let m = all_of![
            request::method_path("PUT", "/v1/identities"),
            request::headers(contains(key("authorization"))),
            request::body("{\"history\":[]\"}"),
        ];

        server.expect(
            Expectation::matching(m)
                .respond_with(status_code(202).body("{\"status\":\"success\"}")),
        );

        // create a new client and siging keypair
        let kp = KeyPair::new();
        let client = Rest::new();

        let url = server.url_str("/v1/identities");

        let response = client.put(
            &url,
            "{\"history\":[]\"}".as_bytes().to_vec(),
            Some(&kp),
            false,
        );
        assert!(response.is_ok());

        let successful_response = response.unwrap();
        assert_eq!(successful_response.code, 202);
        assert_eq!(
            successful_response.data,
            "{\"status\":\"success\"}".as_bytes()
        );
    }

    #[test]
    fn delete() {
        let server = Server::run();

        let m = all_of![
            request::method_path("DELETE", "/v1/identities"),
            request::headers(contains(key("authorization"))),
        ];

        server.expect(
            Expectation::matching(m)
                .respond_with(status_code(202).body("{\"status\":\"success\"}")),
        );

        // create a new client and siging keypair
        let kp = KeyPair::new();
        let client = Rest::new();

        let url = server.url_str("/v1/identities");

        let response = client.delete(&url, Some(&kp), false);
        assert!(response.is_ok());

        let successful_response = response.unwrap();
        assert_eq!(successful_response.code, 202);
        assert_eq!(
            successful_response.data,
            "{\"status\":\"success\"}".as_bytes()
        );
    }
}
