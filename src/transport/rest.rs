use chrono::Duration;
use reqwest::blocking::{Client, Request};
use reqwest::Url;

use crate::error::SelfError;
use crate::keypair::signing::KeyPair;

pub struct Rest {
    client: reqwest::blocking::Client,
    signing_key: KeyPair,
}

pub struct Response {
    pub code: u16,
    pub data: Vec<u8>,
}

impl Rest {
    pub fn new(signing_key: KeyPair) -> Rest {
        return Rest {
            client: Client::new(),
            signing_key: signing_key,
        };
    }

    pub fn get(&self, url: &str) -> Result<Response, SelfError> {
        return self.request(reqwest::Method::GET, url, None);
    }

    pub fn post(&self, url: &str, body: Vec<u8>) -> Result<Response, SelfError> {
        return self.request(reqwest::Method::POST, url, Some(body));
    }

    pub fn put(&self, url: &str, body: Vec<u8>) -> Result<Response, SelfError> {
        return self.request(reqwest::Method::PUT, url, Some(body));
    }

    pub fn delete(&self, url: &str) -> Result<Response, SelfError> {
        return self.request(reqwest::Method::DELETE, url, None);
    }

    fn authorization(&self, headers: &mut reqwest::header::HeaderMap) {
        let mut token = crate::message::Message::new();

        token.subject_set(&self.signing_key.id());
        token.type_set("authorization");
        token.cti_set(&crate::crypto::random_id());

        token
            .sign(
                &self.signing_key,
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
    ) -> Result<Response, SelfError> {
        let target = match Url::parse(url) {
            Ok(target) => target,
            Err(err) => {
                println!("{:?}", err);
                return Err(SelfError::RestRequestURLInvalid);
            }
        };

        let mut request = Request::new(method, target);
        self.authorization(request.headers_mut());

        if body.is_some() {
            *request.body_mut() = Some(reqwest::blocking::Body::from(body.unwrap()));
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

    return SelfError::RestRequestUnknown;
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
        let client = Rest::new(kp);

        let url = server.url_str("/v1/identities");

        let response = client.get(&url);
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
        let client = Rest::new(kp);

        let url = server.url_str("/v1/identities");

        let response = client.post(&url, "{\"history\":[]\"}".as_bytes().to_vec());
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
        let client = Rest::new(kp);

        let url = server.url_str("/v1/identities");

        let response = client.put(&url, "{\"history\":[]\"}".as_bytes().to_vec());
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
        let client = Rest::new(kp);

        let url = server.url_str("/v1/identities");

        let response = client.delete(&url);
        assert!(response.is_ok());

        let successful_response = response.unwrap();
        assert_eq!(successful_response.code, 202);
        assert_eq!(
            successful_response.data,
            "{\"status\":\"success\"}".as_bytes()
        );
    }
}
