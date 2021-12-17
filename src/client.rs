/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

//! HTTP client wrappers.
//!
//! Errors from the backend HTTP client are passed to user code, so dealing with
//! errors is inconsistent between implementations; if you switch from one
//! backend to another, your code that inspects errors will need to be updated.
//!
//! To use a custom HTTP client backend, implement [HttpClient] over an object
//! that wraps your client.

use std::path::PathBuf;

use crate::error::{ValidationError, Error};

#[cfg(feature = "with_surf")]
pub use surf_client::SurfClient;

#[cfg(feature = "with_hyper")]
pub use hyper_client::HyperClient;

/// A trait that wraps an HTTP client to send HTTP requests.
#[async_trait::async_trait]
pub trait HttpClient
    where Self: Sized,
{
    /// The response type of the request.
    type Response;
    /// The HTTP client's Error type.
    type Error;

    /// Create a new `HttpClient`.
    fn new() -> Self;

    /// Create an HTTP `CONNECT` request to the specified URL.
    fn connect(&mut self, url: impl AsRef<str>)
    -> Result<&mut Self, ValidationError>;
    /// Create an HTTP `DELETE` request to the specified URL.
    fn delete(&mut self, url: impl AsRef<str>)
    -> Result<&mut Self, ValidationError>;
    /// Create an HTTP `GET` request to the specified URL.
    fn get(&mut self, url: impl AsRef<str>)
    -> Result<&mut Self, ValidationError>;
    /// Create an HTTP `HEAD` request to the specified URL.
    fn head(&mut self, url: impl AsRef<str>)
    -> Result<&mut Self, ValidationError>;
    /// Create an HTTP `PATCH` request to the specified URL.
    fn patch(&mut self, url: impl AsRef<str>)
    -> Result<&mut Self, ValidationError>;
    /// Create an HTTP `POST` request to the specified URL.
    fn post(&mut self, url: impl AsRef<str>)
    -> Result<&mut Self, ValidationError>;
    /// Create an HTTP `PUT` request to the specified URL.
    fn put(&mut self, url: impl AsRef<str>)
    -> Result<&mut Self, ValidationError>;
    /// Create an HTTP `TRACE` request to the specified URL.
    fn trace(&mut self, url: impl AsRef<str>)
    -> Result<&mut Self, ValidationError>;

    /// Add a header to the request.
    fn with_header<S: AsRef<str>>(&mut self, name: S, value: S) -> &mut Self;
    /// Use the provided bytes as the request body.
    fn with_body(&mut self, data: impl Into<Vec<u8>>) -> &mut Self;
    /// Use the given [serde_json::Value] as the request's body.
    fn with_body_json(&mut self, body: serde_json::Value) -> &mut Self;
    /// Read the provided path as the request's body.
    fn read_body_from_file(&mut self, path: impl Into<PathBuf>) -> &mut Self;

    /// Send the previously-constructed request and return a response.
    async fn send(&mut self) -> Result<Self::Response, Self::Error>;
}

#[cfg(feature = "with_surf")]
mod surf_client {
    use std::path::PathBuf;
    use super::{HttpClient, ValidationError, Error};
    use surf::{
        http::Method,
        Request,
        Url,
    };

    #[derive(Debug)]
    pub struct SurfClient {
        client: surf::Client,
        req: Option<Request>,
        body: Option<Body>,
    }

    #[derive(Debug)]
    enum Body {
        Json(serde_json::Value),
        // TODO: I'd rather store a reference, but doing so spams lifetimes all
        // over everything (if we can avoid adding an explicit lifetime to
        // HttpClient we should be OK).
        //
        // The best solution is likely going to be to refcount it.
        Bytes(Vec<u8>),
        File(PathBuf),
    }

    impl SurfClient {
        /// Use the provided [surf::Client] instead of a new one.
        pub fn with_client(mut self, client: surf::Client) -> Self {
            self.client = client;
            self
        }
    }

    macro_rules! gen_method_func {
        ($func:ident, $method:ident) => {
            fn $func(&mut self, url: impl AsRef<str>)
            -> Result<&mut Self, ValidationError> {
                let url = Url::parse(url.as_ref())?;
                self.req = Some(Request::new(Method::$method, url));

                Ok(self)
            }
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for SurfClient {
        /// The JSON response received from a server.
        type Response = serde_json::Value;
        /// Errors that can be returned by a `SurfClient`.
        type Error = Error<surf::Error>;

        /// Create a new `SurfClient`.
        fn new() -> Self {
            Self {
                client: surf::Client::new(),
                req: None,
                body: None,
            }
        }

        gen_method_func!(connect, Connect);
        gen_method_func!(delete, Delete);
        gen_method_func!(get, Get);
        gen_method_func!(head, Head);
        gen_method_func!(patch, Patch);
        gen_method_func!(post, Post);
        gen_method_func!(put, Put);
        gen_method_func!(trace, Trace);

        fn with_header<S: AsRef<str>>(&mut self, name: S, value: S)
        -> &mut Self {
            if let Some(req) = &mut self.req {
                req.insert_header(name.as_ref(), value.as_ref());
            }
            self
        }

        fn with_body(&mut self, data: impl Into<Vec<u8>>) -> &mut Self
        {
            self.body = Some(Body::Bytes(data.into()));
            self
        }

        fn with_body_json(&mut self, body: serde_json::Value) -> &mut Self {
            // Nothing I've tried will actually save the body in the req.
            // We store it and set it in send().
            self.body = Some(Body::Json(body));
            self
        }

        fn read_body_from_file(&mut self, path: impl Into<PathBuf>)
        -> &mut Self {
            self.body = Some(Body::File(path.into()));
            self
        }

        /// Send the previously-constructed request and return a response.
        ///
        /// # Errors
        ///
        /// * If a request has not been created, returns [Error::NoRequest].
        /// * Returns any underlying HTTP client errors in [Error::Client].
        async fn send(&mut self) -> Result<Self::Response, Self::Error> {
            if let Some(mut req) = self.req.to_owned() {
                if let Some(body) = &self.body {
                    match body {
                        Body::Json(val) => req.body_json(val)?,
                        Body::Bytes(data) => req.body_bytes(data),
                        Body::File(path) =>
                            req.set_body(surf::Body::from_file(path).await?),
                    }
                }

                let res = self.client.send(req).await?
                    .body_json().await?;

                self.req = None;

                Ok(res)
            } else {
                Err(Error::NoRequest)
            }
        }
    }
}

#[cfg(feature = "with_hyper")]
mod hyper_client {
    use std::path::PathBuf;
    use super::{HttpClient, ValidationError, Error};
    use hyper::{
        client::connect::HttpConnector,
        header::{HeaderName, HeaderValue},
        Method
    };
    use hyper_tls::HttpsConnector;
    use url::Url;


    #[derive(Debug)]
    pub struct HyperClient {
        client: hyper::Client<HttpsConnector<HttpConnector>>,
        method: Option<Method>,
        url: String,
        headers: Vec<(HeaderName, HeaderValue)>,
        body: Option<Body>,
    }

    #[derive(Debug)]
    enum Body {
        Json(serde_json::Value),
        Bytes(hyper::body::Bytes),
        File(PathBuf),
    }

    macro_rules! gen_method_func {
        ($func:ident, $method: ident) => {
            fn $func(&mut self, url: impl AsRef<str>)
            -> Result<&mut Self, ValidationError> {
                let _url = Url::parse(url.as_ref())?;

                self.method = Some(Method::$method);
                self.url = String::from(url.as_ref());
                Ok(self)
            }
        }
    }

    impl HyperClient {
        pub fn with_client(
            mut self,
            client: hyper::Client<HttpsConnector<HttpConnector>>
        ) -> Self {
            self.client = client;
            self
        }

        /// Use the provided [Bytes](hyper::body::Bytes) as the request's body.
        ///
        /// The `Bytes` type is cheaply cloneable, so this method should be
        /// preferred over [with_bytes] when you wish to retain ownership of the
        /// byte buffer (e.g., to reuse it when uploading multiple file parts).
        pub fn with_body_bytes(&mut self, bytes: hyper::body::Bytes)
        -> &mut Self {
            self.body = Some(Body::Bytes(bytes));
            self
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for HyperClient {
        /// The JSON response received from the server.
        type Response = serde_json::Value;
        type Error = Error<hyper::Error>;

        /// Create a new `HttpClient`.
        fn new() -> Self {
            let https = HttpsConnector::new();
            let client = hyper::Client::builder()
                .build::<_, hyper::Body>(https);

            Self {
                client,
                method: None,
                url: String::default(),
                headers: vec![],
                body: None,
            }
        }

        gen_method_func!(connect, CONNECT);
        gen_method_func!(delete, DELETE);
        gen_method_func!(get, GET);
        gen_method_func!(head, HEAD);
        gen_method_func!(patch, PATCH);
        gen_method_func!(post, POST);
        gen_method_func!(put, PUT);
        gen_method_func!(trace, TRACE);

        /// Add a header to the request.
        fn with_header<S: AsRef<str>>(&mut self, name: S, value: S)
        -> &mut Self {
            use std::str::FromStr as _;
            use hyper::header::{HeaderName, HeaderValue};

            // TODO: These errors need to be reported.
            let name = HeaderName::from_str(name.as_ref()).unwrap();
            let value = HeaderValue::from_str(value.as_ref()).unwrap();

            self.headers.push((name, value));
            self
        }

        fn with_body<'a>(&mut self, data: impl Into<Vec<u8>>) -> &mut Self {
            self.body = Some(
                Body::Bytes(hyper::body::Bytes::from(data.into()))
            );

            self
        }

        fn with_body_json(&mut self, body: serde_json::Value) -> &mut Self {
            self.body = Some(Body::Json(body));
            self
        }

        fn read_body_from_file(&mut self, path: impl Into<PathBuf>)
        -> &mut Self {
            self.body = Some(Body::File(path.into()));
            self
        }

        /// Send the previously-constructed request and return a response.
        ///
        /// # Errors
        ///
        /// * If a request has not been created, returns [Error::NoRequest].
        /// * Returns any underlying HTTP client errors in [Error::Client].
        async fn send(&mut self) -> Result<Self::Response, Self::Error> {
            if self.method.is_none() {
                return Err(Error::NoRequest);
            }

            let mut req = hyper::Request::builder()
                .method(self.method.as_ref().unwrap())
                .uri(&self.url);

            for (name, value) in &self.headers {
                req = req.header(name, value);
            }

            let body = match &self.body {
                Some(body) => match body {
                    Body::Json(val) => hyper::Body::from(val.to_string()),
                    Body::Bytes(data) => hyper::Body::from(data.clone()),
                    Body::File(path) => {
                        use tokio::{
                            fs::File,
                            io::AsyncReadExt as _,
                        };

                        // TODO: We might do better to create a stream over the
                        // file and pass it to the hyper::Body.
                        let mut file = File::open(path).await?;
                        let mut buf = vec![];
                        file.read_to_end(&mut buf).await?;

                        hyper::Body::from(buf)
                    },
                },
                None => hyper::Body::empty(),
            };

            let req = req.body(body).expect(concat!(
                "Invalid request. Please file an issue on b2-client for ",
                "improper validation"
            ));

            let res = self.client.request(req).await?
                .into_body();
            let res = hyper::body::to_bytes(res).await?;

            self.method = None;
            self.url = String::default();
            self.headers.clear();
            self.body = None;

            Ok(serde_json::from_slice(&res)?)
        }
    }
}

// TODO: Implement for isahc
#[cfg(feature = "with_isahc")]
mod isahc_client {
}

//#[cfg(feature = "with_isahc")]
//pub use isahc_client::IsahcRequest;
