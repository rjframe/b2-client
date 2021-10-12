//! HTTP client wrappers.
//!
//! All implementations of [HttpRequest] here create a new HTTP client per
//! request.
//!
//! If you wish to reuse a client for multiple requests (or alter
//! configurations, add middlewares, etc.), implement [HttpRequest] on your own
//! type. For example, with [Surf](https://crates.io/crates/surf):
//!
//! ```no_run
//! # use b2_client::client::*;
//! enum Method {
//!     Connect,
//!     Delete,
//!     Get,
//!     // ...
//! }
//!
//! struct SurfClient {
//!     client: surf::Client,
//!     req: Option<surf::RequestBuilder>,
//! }
//!
//! #[async_trait::async_trait]
//! impl HttpRequest for SurfClient {
//!     // Sending a request takes ownership of Self, so we need to return it
//!     // with our response.
//!     type Response = (Self, surf::Response);
//!     type Error = surf::Error;
//!
//!     fn connect(url: impl AsRef<str>) -> Self {
//!         let client = surf::Client::new();
//!         let req = client.connect(url.as_ref());
//!
//!         Self {
//!             client,
//!             req: Some(req),
//!         }
//!     }
//!
//!     // ...
//!     # fn delete(url: impl AsRef<str>) -> Self { panic!() }
//!     # fn get(url: impl AsRef<str>) -> Self { panic!() }
//!     # fn head(url: impl AsRef<str>) -> Self { panic!() }
//!     # fn patch(url: impl AsRef<str>) -> Self { panic!() }
//!     # fn post(url: impl AsRef<str>) -> Self { panic!() }
//!     # fn put(url: impl AsRef<str>) -> Self { panic!() }
//!     # fn trace(url: impl AsRef<str>) -> Self { panic!() }
//!     # fn with_header<S: AsRef<str>>(self, name: S, value: S) -> Self {
//!     #   panic!()
//!     # }
//!     # fn with_body(self, body: &serde_json::Value) -> Self { panic!() }
//!
//!     async fn send(mut self) -> Result<Self::Response, Self::Error> {
//!         if let Some(req) = self.req {
//!             let req = self.client.send(req.build()).await?;
//!             self.req = None;
//!
//!             Ok((self, req))
//!         } else {
//!             // You'll likely want to provide a custom error type that wraps
//!             // your client's error and return it here rather than panicking.
//!             panic!("No request to send.");
//!         }
//!     }
//! }
//! ```

use crate::error::Error;


/// A trait that wraps an HTTP client to send an HTTP request.
#[async_trait::async_trait]
pub trait HttpRequest {
    /// The response type of the request.
    type Response;
    /// The HTTP client's Error type.
    type Error;

    /// Create an HTTP `CONNECT` request to the specified URL.
    fn connect(url: impl AsRef<str>) -> Self;
    /// Create an HTTP `DELETE` request to the specified URL.
    fn delete(url: impl AsRef<str>) -> Self;
    /// Create an HTTP `GET` request to the specified URL.
    fn get(url: impl AsRef<str>) -> Self;
    /// Create an HTTP `HEAD` request to the specified URL.
    fn head(url: impl AsRef<str>) -> Self;
    /// Create an HTTP `PATCH` request to the specified URL.
    fn patch(url: impl AsRef<str>) -> Self;
    /// Create an HTTP `POST` request to the specified URL.
    fn post(url: impl AsRef<str>) -> Self;
    /// Create an HTTP `PUT` request to the specified URL.
    fn put(url: impl AsRef<str>) -> Self;
    /// Create an HTTP `TRACE` request to the specified URL.
    fn trace(url: impl AsRef<str>) -> Self;

    /// Add a header to the request.
    fn with_header<S: AsRef<str>>(self, name: S, value: S) -> Self;
    /// Use the given [serde_json::Value] as the request's body.
    // TODO: Take ownership of body?
    fn with_body(self, body: &serde_json::Value) -> Self;

    /// Send the request and return the HTTP client's Response.
    async fn send(self) -> Result<Self::Response, Self::Error>;
}

#[cfg(feature = "with_surf")]
mod surf_client {
    use super::{HttpRequest, Error};

    /// A wrapper to make HTTP requests via the
    /// [Surf](https://crates.io/crates/surf) HTTP client library.
    pub struct SurfRequest {
        req: surf::RequestBuilder,
    }

    #[async_trait::async_trait]
    impl HttpRequest for SurfRequest {
        type Response = serde_json::Value;
        type Error = Error<surf::Error>;

        fn connect(url: impl AsRef<str>) -> Self {
            Self { req: surf::connect(url) }
        }

        fn delete(url: impl AsRef<str>) -> Self {
            Self { req: surf::delete(url) }
        }

        fn get(url: impl AsRef<str>) -> Self {
            Self { req: surf::get(url) }
        }

        fn head(url: impl AsRef<str>) -> Self {
            Self { req: surf::head(url) }
        }

        fn patch(url: impl AsRef<str>) -> Self {
            Self { req: surf::patch(url) }
        }

        fn post(url: impl AsRef<str>) -> Self {
            Self { req: surf::post(url) }
        }

        fn put(url: impl AsRef<str>) -> Self {
            Self { req: surf::put(url) }
        }

        fn trace(url: impl AsRef<str>) -> Self {
            Self { req: surf::trace(url) }
        }

        fn with_header<S: AsRef<str>>(mut self, name: S, value: S) -> Self {
            self.req = self.req.header(name.as_ref(), value.as_ref());
            self
        }

        fn with_body(mut self, body: &serde_json::Value) -> Self {
            // Unwrap: serde_json is used internally, so isn't going to fail
            // except for bugs within serde_json.
            self.req = self.req.body_json(body).unwrap();
            self
        }

        async fn send(self) -> Result<Self::Response, Self::Error> {
            let mut res = self.req.send().await?;
            Ok(res.body_json().await?)
        }
    }
}

#[cfg(feature = "with_surf")]
pub use surf_client::SurfRequest;

#[cfg(feature = "with_hyper")]
mod hyper_client {
    use super::{HttpRequest, Error};
    use hyper::{Body, Method};

    enum InnerRequest {
        Builder(http::request::Builder),
        Request(http::Request<Body>),
    }

    /// A wrapper to make HTTP requests via the
    /// [Hyper](https://crates.io/crates/hyper) library.
    pub struct HyperRequest {
        req: InnerRequest,
    }

    #[async_trait::async_trait]
    impl HttpRequest for HyperRequest {
        type Response = serde_json::Value;
        type Error = Error<hyper::Error>;

        fn connect(url: impl AsRef<str>) -> Self {
            let req = hyper::Request::builder()
                .method(Method::CONNECT)
                .uri(url.as_ref());

            Self { req: InnerRequest::Builder(req) }
        }

        fn delete(url: impl AsRef<str>) -> Self {
            let req = hyper::Request::builder()
                .method(Method::DELETE)
                .uri(url.as_ref());

            Self { req: InnerRequest::Builder(req) }
        }

        fn get(url: impl AsRef<str>) -> Self {
            let req = hyper::Request::builder()
                .method(Method::GET)
                .uri(url.as_ref());

            Self { req: InnerRequest::Builder(req) }
        }

        fn head(url: impl AsRef<str>) -> Self {
            let req = hyper::Request::builder()
                .method(Method::HEAD)
                .uri(url.as_ref());

            Self { req: InnerRequest::Builder(req) }
        }

        fn patch(url: impl AsRef<str>) -> Self {
            let req = hyper::Request::builder()
                .method(Method::PATCH)
                .uri(url.as_ref());

            Self { req: InnerRequest::Builder(req) }
        }

        fn post(url: impl AsRef<str>) -> Self {
            let req = hyper::Request::builder()
                .method(Method::POST)
                .uri(url.as_ref());

            Self { req: InnerRequest::Builder(req) }
        }

        fn put(url: impl AsRef<str>) -> Self {
            let req = hyper::Request::builder()
                .method(Method::PUT)
                .uri(url.as_ref());

            Self { req: InnerRequest::Builder(req) }
        }

        fn trace(url: impl AsRef<str>) -> Self {
            let req = hyper::Request::builder()
                .method(Method::TRACE)
                .uri(url.as_ref());

            Self { req: InnerRequest::Builder(req) }
        }

        fn with_header<S: AsRef<str>>(mut self, name: S, value: S) -> Self {
            use std::str::FromStr as _;
            use hyper::header::{HeaderName, HeaderValue};

            // TODO: Return Result - errors on invalid name/values.
            let name = HeaderName::from_str(name.as_ref()).unwrap();
            let value = HeaderValue::from_str(value.as_ref()).unwrap();

            match self.req {
                InnerRequest::Builder(r) => {
                    let req = r.header(name, value);
                    self.req = InnerRequest::Builder(req);
                },
                InnerRequest::Request(ref mut r) => {
                    let headers = r.headers_mut();
                    headers.insert(name, value);
                },
            }

            self
        }

        fn with_body(mut self, body: &serde_json::Value) -> Self {
            match self.req {
                InnerRequest::Builder(r) => {
                    // Unwrap: Serializing from string won't fail.
                    let req = r.body(Body::from(body.to_string())).unwrap();
                    self.req = InnerRequest::Request(req);
                },
                InnerRequest::Request(ref mut r) => {
                    let b = r.body_mut();
                    *b = Body::from(body.to_string());
                },
            }

            self
        }

        async fn send(self) -> Result<Self::Response, Self::Error> {
            use hyper::client::Client;

            let client = Client::new();

            let req = match self.req {
                InnerRequest::Builder(r) => {
                    // Unwrap: The empty body will never fail to serialize.
                    r.body(Body::empty()).unwrap()
                },
                InnerRequest::Request(r) => r,
            };

            let res = client.request(req).await?
                .into_body();
            let res = hyper::body::to_bytes(res).await?;

            serde_json::from_slice(&res)
                .map_err(Error::from_json)
        }
    }
}

#[cfg(feature = "with_hyper")]
pub use hyper_client::HyperRequest;

// TODO: Implement for isahc
#[cfg(feature = "with_isahc")]
mod isahc_client {
}

//#[cfg(feature = "with_isahc")]
//pub use isahc_client::IsahcRequest;
