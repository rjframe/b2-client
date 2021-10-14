/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

//! Error types for b2-client

use std::fmt;

use serde::{Serialize, Deserialize};


#[cfg(feature = "with_surf")]
type E = surf::Error;

#[cfg(feature = "with_hyper")]
type E = hyper::Error;

/// Errors that can be returned by `b2-client` function calls.
#[derive(Debug)]
pub enum Error
{
    /// An error from the underlying HTTP client.
    Client(E),
    /// An error from the Backblaze B2 API.
    B2(B2Error),
    /// An error de/serializing data that's expected to be a valid JSON string.
    Format(serde_json::Error),
    /// Failure to parse a URL.
    ///
    /// The string is a short description of the failure.
    BadUrl(String),
    /// Data failed validation. The string is a short description of the
    /// failure.
    Invalid(String),
    NoRequest,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", *self)
    }
}

impl Error {
    /// Create an [Error] from a [B2Error].
    pub fn from_b2(e: B2Error) -> Self { Self::B2(e) }

    /// Create an [Error] from a [serde_json::Error].
    // TODO: I don't like this name; we're not converting from JSON.
    pub fn from_json(e: serde_json::Error) -> Self {
        Self::Format(e)
    }
}

impl From<E> for Error {
    fn from(e: E) -> Self {
        Self::Client(e)
    }
}

#[cfg(feature = "url")]
impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Self {
        Self::BadUrl(format!("{}", e))
    }
}

/// An error code from the B2 API.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ErrorCode {
    BadRequest,
    BadAuthToken,
    Unauthorized,
    Unsupported,
    TransactionCapExceeded,
}

impl ErrorCode {
    // TODO: Error type
    /// Convert the error code received from the B2 service to an [ErrorCode].
    fn from_api_code<S: AsRef<str>>(code: S) -> Result<Self, String> {
        match code.as_ref() {
            "bad_request" => Ok(Self::BadRequest),
            "bad_auth_token" => Ok(Self::BadAuthToken),
            "unauthorized" => Ok(Self::Unauthorized),
            "unsupported" => Ok(Self::Unsupported),
            "transaction_cap_exceeded" => Ok(Self::TransactionCapExceeded),
            _ => Err(String::from(code.as_ref())),
        }
    }

    /// Get the HTTP status code of this error.
    fn status(&self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::BadAuthToken => 401,
            Self::Unauthorized => 401,
            Self::Unsupported => 401,
            Self::TransactionCapExceeded => 403,
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
