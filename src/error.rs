/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

//! Error types for b2-client
//!
//! Errors are divided into two types:
//!
//! * [ValidationError] for data validation errors prior to sending a request to
//!   the B2 API.
//! * [Error] for errors returned by the Backblaze B2 API or the HTTP client.

use std::fmt;

use serde::{Serialize, Deserialize};


/// Errors from validating B2 requests prior to making the request.
#[derive(Debug)]
pub enum ValidationError {
    /// Failure to parse a URL.
    ///
    /// The string is a short description of the failure.
    BadUrl(String),
    /// Data failed validation.
    ///
    /// The string is a short description of the failure.
    // TODO: Separate this into useful variants.
    Invalid(String),
}

impl std::error::Error for ValidationError {}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadUrl(s) => write!(f, "Error parsing URL: {}", s),
            Self::Invalid(s) => write!(f, "{}", s),
        }
    }
}

#[cfg(feature = "url")]
impl From<url::ParseError> for ValidationError {
    fn from(e: url::ParseError) -> Self {
        Self::BadUrl(format!("{}", e))
    }
}

// TODO: Rename?
/// Errors related to making B2 API calls.
#[derive(Debug)]
pub enum Error<E>
    // Surf's Error doesn't implement StdError.
    where E: fmt::Debug + fmt::Display,
{
    /// An error from the underlying HTTP client.
    Client(E),
    /// An error from the Backblaze B2 API.
    B2(B2Error),
    /// An error deserializing the HTTP client's response.
    Format(serde_json::Error),
    /// Attempted to send a non-existent request.
    NoRequest,
}

impl<E> std::error::Error for Error<E>
    where E: fmt::Debug + fmt::Display,
{}

impl<E> fmt::Display for Error<E>
    where E: fmt::Debug + fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Display;

        match self {
            Self::Client(e) => Display::fmt(&e, f),
            Self::B2(e) => Display::fmt(&e, f),
            Self::Format(e) => e.fmt(f),
            Self::NoRequest => write!(f, "No request was created"),
        }
    }
}

impl<E> From<B2Error> for Error<E>
    where E: fmt::Debug + fmt::Display,
{
    fn from(e: B2Error) -> Self {
        Self::B2(e)
    }
}

impl<E> From<serde_json::Error> for Error<E>
    where E: fmt::Debug + fmt::Display,
{
    fn from(e: serde_json::Error) -> Self {
        Self::Format(e)
    }
}

#[cfg(feature = "with_surf")]
impl From<surf::Error> for Error<surf::Error> {
    fn from(e: surf::Error) -> Self {
        Self::Client(e)
    }
}

#[cfg(feature = "with_hyper")]
impl From<hyper::Error> for Error<hyper::Error> {
    fn from(e: hyper::Error) -> Self {
        Self::Client(e)
    }
}

/// An error code from the B2 API.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ErrorCode {
    BadRequest,
    BadAuthToken,
    ExpiredAuthToken,
    Unauthorized,
    Unsupported,
    TransactionCapExceeded,
    InternalError,
    ServiceUnavailable,
}

impl ErrorCode {
    // TODO: Error type
    /// Convert the error code received from the B2 service to an [ErrorCode].
    fn from_api_code<S: AsRef<str>>(code: S) -> Result<Self, String> {
        match code.as_ref() {
            "bad_request" => Ok(Self::BadRequest),
            "bad_auth_token" => Ok(Self::BadAuthToken),
            "expired_auth_token" => Ok(Self::ExpiredAuthToken),
            "unauthorized" => Ok(Self::Unauthorized),
            "unsupported" => Ok(Self::Unsupported),
            "transaction_cap_exceeded" => Ok(Self::TransactionCapExceeded),
            "internal_error" => Ok(Self::InternalError),
            "service_unavailable" => Ok(Self::ServiceUnavailable),
            // TODO: Use an Unknown(code) variant instead.
            _ => Err(String::from(code.as_ref())),
        }
    }

    /// Get the HTTP status code of this error.
    fn status(&self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::BadAuthToken => 401,
            Self::ExpiredAuthToken => 401,
            Self::Unauthorized => 401,
            Self::Unsupported => 401,
            Self::TransactionCapExceeded => 403,
            Self::InternalError => 500,
            Self::ServiceUnavailable => 503,
        }
    }
}

/// An error response from the Backblaze B2 API.
///
/// See <https://www.backblaze.com/b2/docs/calling.html#error_handling> for
/// information on B2 error handling.
#[derive(Debug, Deserialize)]
// TODO: Manually impl Serialize to JSON. Include HTTP status code.
pub struct B2Error {
    /// A code that identifies the error.
    // TODO: Store an `ErrorCode` instead?
    #[serde(rename = "code")]
    code_str: String,
    /// A description of what went wrong.
    message: String,
}

impl B2Error {
    /// Get the HTTP status code for the error.
    pub fn http_status(&self) -> u16 {
        self.code().status()
    }

    pub fn code(&self) -> ErrorCode {
        match ErrorCode::from_api_code(&self.code_str) {
            Ok(code) => code,
            Err(code) => panic!(
                "Unknown API code '{}'. Please file an issue on b2-client.",
                code
            ),
        }
    }
}

impl std::error::Error for B2Error {}

impl fmt::Display for B2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code_str, self.message)
    }
}
