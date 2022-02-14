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

use std::{
    collections::HashMap,
    path::PathBuf,
};

use crate::error::{ValidationError, Error};

#[cfg(feature = "with_surf")]
pub use surf_client::SurfClient;

#[cfg(feature = "with_hyper")]
pub use hyper_client::HyperClient;

#[cfg(feature = "with_isahc")]
pub use isahc_client::IsahcClient;

/// A trait that wraps an HTTP client to send HTTP requests.
#[async_trait::async_trait]
pub trait HttpClient
    where Self: Default + Clone + Sized,
{
    /// The HTTP client's Error type.
    type Error;

    /// Create an HTTP `GET` request to the specified URL.
    fn get(&mut self, url: impl AsRef<str>)
    -> Result<&mut Self, ValidationError>;
    /// Create an HTTP `HEAD` request to the specified URL.
    fn head(&mut self, url: impl AsRef<str>)
    -> Result<&mut Self, ValidationError>;
    /// Create an HTTP `POST` request to the specified URL.
    fn post(&mut self, url: impl AsRef<str>)
    -> Result<&mut Self, ValidationError>;

    /// Add a header to the request.
    ///
    /// To add a `User-Agent` header, call [user_agent](Self::user_agent).
    fn with_header<S: AsRef<str>>(&mut self, name: S, value: S)
    -> Result<&mut Self, ValidationError>;
    /// Use the provided bytes as the request body.
    fn with_body(&mut self, data: impl Into<Vec<u8>>) -> &mut Self;
    /// Use the given [serde_json::Value] as the request's body.
    fn with_body_json(&mut self, body: serde_json::Value) -> &mut Self;
    /// Read the provided path as the request's body.
    fn read_body_from_file(&mut self, path: impl Into<PathBuf>) -> &mut Self;

    /// Set the User-Agent header value to send with requests.
    fn user_agent(&mut self, user_agent_string: impl Into<String>)
    -> Result<&mut Self, ValidationError>;

    /// Send the previously-constructed request and return a response.
    async fn send(&mut self) -> Result<Vec<u8>, Self::Error>;

    /// Send the previously-constructed request and return a response with the
    /// returned HTTP headers.
    async fn send_keep_headers(&mut self)
    -> Result<(Vec<u8>, HeaderMap), Self::Error>;
}

// TODO: Use http_types::{HeaderName, HeaderValue} instead of Strings?
pub type HeaderMap = HashMap<String, String>;

/// Generate a standard User-Agent string for HTTP client backends.
///
/// This is only useful if creating your own implementation of [HttpClient] and
/// you want to maintain b2-client's standard User-Agent format.
///
/// # Examples
///
/// ```
/// # use b2_client::client::default_user_agent;
/// struct CurlClient { user_agent: String };
///
/// impl Default for CurlClient {
///     fn default() -> Self {
///         Self {
///             user_agent: default_user_agent!("curl"),
///         }
///     }
/// }
/// ```
#[macro_export]
macro_rules! default_user_agent {
    ($client:literal) => {
        format!("rust-b2-client/{}; {}",
            option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"),
            $client
        )
    };
}
pub use default_user_agent;

#[cfg(feature = "with_surf")]
mod surf_client {
    use std::path::PathBuf;
    use super::*;
    use surf::{
        http::Method,
        Request,
        Url,
    };

    #[derive(Debug, Clone)]
    pub struct SurfClient {
        client: surf::Client,
        req: Option<Request>,
        body: Option<Body>,
        user_agent: String,
    }

    impl Default for SurfClient {
        /// Create a new `SurfClient`.
        fn default() -> Self {
            Self {
                client: surf::Client::new(),
                req: None,
                body: None,
                user_agent: default_user_agent!("surf"),
            }
        }
    }

    // Body type for sending; TODO rename to avoid ambiguity?
    #[derive(Debug, Clone)]
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

        async fn send_impl(&mut self, keep_headers: bool)
        -> Result<(Vec<u8>, Option<HeaderMap>), <Self as HttpClient>::Error> {
            if let Some(mut req) = self.req.to_owned() {
                if let Some(body) = &self.body {
                    match body {
                        Body::Json(val) => req.body_json(val)?,
                        Body::Bytes(data) => req.body_bytes(data),
                        Body::File(path) =>
                            req.set_body(surf::Body::from_file(path).await?),
                    }
                }

                req.insert_header("User-Agent", &self.user_agent);

                let mut res = self.client.send(req).await?;
                let body = res.body_bytes().await?;

                let headers = if keep_headers {
                    let headers: &surf::http::Headers = res.as_ref();
                    let mut ret = HeaderMap::new();

                    for (k, v) in headers.iter() {
                        ret.insert(k.to_string(), v.to_string());
                    }

                    Some(ret)
                } else {
                    None
                };

                self.req = None;

                Ok((body, headers))
            } else {
                Err(Error::NoRequest)
            }
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
        /// Errors that can be returned by a `SurfClient`.
        type Error = Error<surf::Error>;

        gen_method_func!(get, Get);
        gen_method_func!(head, Head);
        gen_method_func!(post, Post);

        fn with_header<S: AsRef<str>>(&mut self, name: S, value: S)
        -> Result<&mut Self, ValidationError> {
            use std::str::FromStr as _;
            use http_types::headers::{HeaderName, HeaderValue};

            if let Some(req) = &mut self.req {
                let name = HeaderName::from_str(name.as_ref())?;
                let value = HeaderValue::from_str(value.as_ref())?;

                req.insert_header(name, value);
            }

            Ok(self)
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

        /// Set the User-Agent header value to send with requests.
        ///
        /// The default User-Agent string is "rust-b2-client/<version>; surf".
        ///
        /// # Errors
        ///
        /// Returns [ValidationError] if the `user_agent_string` is empty.
        fn user_agent(&mut self, user_agent_string: impl Into<String>)
        -> Result<&mut Self, ValidationError> {
            let user_agent = user_agent_string.into();

            if user_agent.is_empty() {
                Err(ValidationError::MissingData(
                    "User-Agent is required".into()
                ))
            } else {
                self.user_agent = user_agent;
                Ok(self)
            }
        }

        /// Send the previously-constructed request and return a response.
        ///
        /// # Errors
        ///
        /// * If a request has not been created, returns [Error::NoRequest].
        /// * Returns any underlying HTTP client errors in [Error::Client].
        async fn send(&mut self) -> Result<Vec<u8>, Self::Error> {
            self.send_impl(false).await.map(|v| v.0)
        }

        /// Send the previously-constructed request and return a response with
        /// the returned HTTP headers.
        ///
        /// # Errors
        ///
        /// * If a request has not been created, returns [Error::NoRequest].
        /// * Returns any underlying HTTP client errors in [Error::Client].
        async fn send_keep_headers(&mut self)
        -> Result<(Vec<u8>, HeaderMap), Self::Error> {
            self.send_impl(true).await.map(|(r, m)| (r, m.unwrap()))
        }
    }
}

#[cfg(feature = "with_hyper")]
mod hyper_client {
    use std::path::PathBuf;
    use super::*;
    use hyper::{
        client::connect::HttpConnector,
        header::{HeaderName, HeaderValue},
        Method
    };
    use hyper_tls::HttpsConnector;
    use url::Url;


    #[derive(Debug, Clone)]
    pub struct HyperClient {
        client: hyper::Client<HttpsConnector<HttpConnector>>,
        method: Option<Method>,
        url: String,
        headers: Vec<(HeaderName, HeaderValue)>,
        body: Option<Body>,
        user_agent: String,
    }

    impl Default for HyperClient {
        /// Create a new `HttpClient`.
        fn default() -> Self {
            let https = HttpsConnector::new();
            let client = hyper::Client::builder()
                .build::<_, hyper::Body>(https);

            Self {
                client,
                method: None,
                url: String::default(),
                headers: vec![],
                body: None,
                user_agent: default_user_agent!("hyper"),
            }
        }
    }

    #[derive(Debug, Clone)]
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

        async fn send_impl(&mut self, keep_headers: bool)
        -> Result<(Vec<u8>, Option<HeaderMap>), <Self as HttpClient>::Error> {
            if self.method.is_none() {
                return Err(Error::NoRequest);
            }

            let mut req = hyper::Request::builder()
                .method(self.method.as_ref().unwrap())
                .uri(&self.url);

            for (name, value) in &self.headers {
                req = req.header(name, value);
            }

            req = req.header("User-Agent", &self.user_agent);

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

            let (mut parts, body) = self.client.request(req).await?
                .into_parts();

            let body = hyper::body::to_bytes(body).await?.to_vec();

            let headers = if keep_headers {
                let mut headers = HeaderMap::new();

                headers.extend(
                    parts.headers.drain()
                        .filter(|(k, _)| k.is_some())
                        .map(|(k, v)|
                            // TODO: Ensure that all possible header values from
                            // B2 are required to be valid strings on their
                            // side.
                            (
                                k.unwrap().to_string(),
                                v.to_str().unwrap().to_owned()
                            )
                        )
                );

                Some(headers)
            } else {
                None
            };

            self.method = None;
            self.url = String::default();
            self.headers.clear();
            self.body = None;

            Ok((body, headers))
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for HyperClient {
        type Error = Error<hyper::Error>;

        gen_method_func!(get, GET);
        gen_method_func!(head, HEAD);
        gen_method_func!(post, POST);

        /// Add a header to the request.
        fn with_header<S: AsRef<str>>(&mut self, name: S, value: S)
        -> Result<&mut Self, ValidationError> {
            use std::str::FromStr as _;
            use hyper::header::{HeaderName, HeaderValue};

            let name = HeaderName::from_str(name.as_ref())?;
            let value = HeaderValue::from_str(value.as_ref())?;

            self.headers.push((name, value));
            Ok(self)
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

        fn user_agent(&mut self, user_agent_string: impl Into<String>)
        -> Result<&mut Self, ValidationError> {
            let user_agent = user_agent_string.into();

            if user_agent.is_empty() {
                Err(ValidationError::MissingData(
                    "User-Agent is required".into()
                ))
            } else {
                self.user_agent = user_agent;
                Ok(self)
            }
        }

        /// Send the previously-constructed request and return a response.
        ///
        /// # Errors
        ///
        /// * If a request has not been created, returns [Error::NoRequest].
        /// * Returns any underlying HTTP client errors in [Error::Client].
        async fn send(&mut self) -> Result<Vec<u8>, Self::Error> {
            self.send_impl(false).await.map(|v| v.0)
        }

        async fn send_keep_headers(&mut self)
        -> Result<(Vec<u8>, HeaderMap), Self::Error> {
            self.send_impl(true).await.map(|(r, m)| (r, m.unwrap()))
        }
    }
}

#[cfg(feature = "with_isahc")]
mod isahc_client {
    use super::*;
    use isahc::http::{
        header::{HeaderName, HeaderValue},
        method::Method,
        request::Builder as RequestBuilder,
    };

    #[derive(Debug)]
    enum Body {
        Bytes(Vec<u8>),
        Json(serde_json::Value),
        File(PathBuf),
    }

    #[derive(Debug)]
    pub struct IsahcClient {
        client: isahc::HttpClient,
        req: Option<RequestBuilder>,
        user_agent: String,
        body: Option<Body>,
        headers: Vec<(HeaderName, HeaderValue)>,
    }

    impl Default for IsahcClient {
        /// Create a new `HttpClient`.
        fn default() -> Self {
            Self {
                client: isahc::HttpClient::new().unwrap(),
                req: None,
                user_agent: default_user_agent!("isahc"),
                body: None,
                headers: Vec::new(),
            }
        }
    }

    impl Clone for IsahcClient {
        /// Clone an `IsahcClient` object.
        ///
        /// The client itself and the user-agent string are cloned. The current
        /// request is not.
        fn clone(&self) -> Self {
            Self {
                client: self.client.clone(),
                req: None,
                user_agent: self.user_agent.clone(),
                body: None,
                headers: Vec::new(),
            }
        }
    }

    impl IsahcClient {
        async fn send_impl(&mut self, keep_headers: bool)
        -> Result<(
            Vec<u8>, Option<HeaderMap>),
            <Self as super::HttpClient>::Error
        > {
            use futures_lite::AsyncReadExt as _;

            if let Some(mut req) = self.req.take() {
                for (name, value) in &self.headers {
                    req = req.header(name, value);
                }

                req = req.header("User-Agent", &self.user_agent);

                let body = if let Some(body) = self.body.take() {
                    match body {
                        Body::Bytes(bytes) => Some(bytes),
                        Body::Json(json) => Some(serde_json::to_vec(&json)?),
                        Body::File(path) => {
                            // TODO: Use async_std?
                            use std::{fs::File, io::Read as _};

                            let mut file = File::open(path)?;
                            let mut buf: Vec<u8> = vec![];
                            file.read_to_end(&mut buf)?;

                            Some(buf)
                        },
                    }
                } else {
                    None
                };

                let (mut parts, body) = match body {
                    Some(body) => self.client.send_async(req.body(body)?)
                        .await?.into_parts(),
                    None => self.client.send_async(
                        req.body(isahc::AsyncBody::empty())?
                    ).await?.into_parts(),
                };

                let headers = if keep_headers {
                    let mut headers = HeaderMap::new();

                    headers.extend(
                        parts.headers.drain()
                        .filter(|(k, _)| k.is_some())
                        .map(|(k, v)|
                            // TODO: Ensure that all possible header values from
                            // B2 are required to be valid strings on their
                            // side.
                            (
                                k.unwrap().to_string(),
                                v.to_str().unwrap().to_owned()
                            )
                        )
                    );

                    Some(headers)
                } else {
                    None
                };

                let mut buf = Vec::new();
                body.bytes().read_to_end(&mut buf).await?;

                // self.req and self.body had their values reset already; we
                // only need to clear the list of headers and we're ready for
                // the next request.
                self.headers.clear();

                Ok((buf, headers))
            } else {
                Err(Error::NoRequest)
            }
        }
    }

    macro_rules! gen_method_func {
        ($func:ident, $method:ident) => {
            fn $func(&mut self, url: impl AsRef<str>)
            -> Result<&mut Self, ValidationError> {
                self.req = Some(
                    RequestBuilder::new()
                        .method(Method::$method)
                        .uri(url.as_ref())
                );

                Ok(self)
            }
        };
    }

    #[async_trait::async_trait]
    impl HttpClient for IsahcClient
        where Self: Clone + Sized,
    {
        type Error = Error<isahc::Error>;

        gen_method_func!(get, GET);
        gen_method_func!(head, HEAD);
        gen_method_func!(post, POST);

        fn with_header<S: AsRef<str>>(&mut self, name: S, value: S)
        -> Result<&mut Self, ValidationError> {
            use std::str::FromStr as _;

            let name = HeaderName::from_str(name.as_ref())?;
            let value = HeaderValue::from_str(value.as_ref())?;

            self.headers.push((name, value));
            Ok(self)
        }

        fn with_body(&mut self, data: impl Into<Vec<u8>>) -> &mut Self {
            self.body = Some(Body::Bytes(data.into()));
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

        fn user_agent(&mut self, user_agent_string: impl Into<String>)
        -> Result<&mut Self, ValidationError> {
            let user_agent = user_agent_string.into();

            if ! user_agent.is_empty() {
                self.user_agent = user_agent;
                Ok(self)
            } else {
                Err(ValidationError::MissingData(
                    "User-Agent is required".into()
                ))
            }
        }

        async fn send(&mut self) -> Result<Vec<u8>, Self::Error> {
            self.send_impl(false).await.map(|v| v.0)
        }

        async fn send_keep_headers(&mut self)
        -> Result<(Vec<u8>, HeaderMap), Self::Error> {
            self.send_impl(true).await.map(|v| (v.0, v.1.unwrap()))
        }
    }
}
