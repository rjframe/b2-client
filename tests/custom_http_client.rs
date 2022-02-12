//! Ensures that the b2-client API can fully support any arbitrary HTTP client
//! as its backend.

use std::fmt;

use b2_client::{
    account::authorize_account,
    client::{HeaderMap, HttpClient},
    error::{ValidationError, Error},
};

#[derive(Debug, Default, Clone)]
struct FakeClient;

#[derive(Debug, Eq, PartialEq)]
struct FakeError;

impl fmt::Display for FakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oh no!")
    }
}

impl std::error::Error for FakeError {}

macro_rules! gen_send_func {
    ($name:ident) => {
        fn $name(&mut self, _url: impl AsRef<str>)
        -> Result<&mut Self, ValidationError> {
            Ok(self)
        }
    }
}

#[async_trait::async_trait]
impl HttpClient for FakeClient {
    type Error = Error<FakeError>;

    gen_send_func!(get);
    gen_send_func!(head);
    gen_send_func!(post);

    fn with_header<S: AsRef<str>>(&mut self, _name: S, _value: S)
    -> Result<&mut Self, ValidationError> {
        Ok(self)
    }

    fn with_body(&mut self, _body: impl Into<Vec<u8>>) -> &mut Self { self }
    fn with_body_json(&mut self, _body: serde_json::Value) -> &mut Self { self }

    fn read_body_from_file(&mut self, _path: impl Into<std::path::PathBuf>)
    -> &mut Self {
        self
    }

    fn user_agent(&mut self, _user_agent_string: impl Into<String>)
    -> Result<&mut Self, ValidationError>
    {
        Ok(self)
    }

    async fn send(&mut self) -> Result<Vec<u8>, Self::Error> {
        Err(Error::Client(FakeError))
    }

    async fn send_keep_headers(&mut self)
    -> Result<(Vec<u8>, HeaderMap), Self::Error> {
        Err(Error::Client(FakeError))
    }
}

#[async_std::test]
async fn can_use_custom_client() {
    let client = FakeClient;

    let auth = authorize_account(client, "SOME KEY ID", "SOME KEY").await;
    match auth.unwrap_err() {
        Error::Client(e) => assert_eq!(e, FakeError),
        _ => panic!("Unknown error type"),
    }
}
