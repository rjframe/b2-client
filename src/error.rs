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

use std::{
    collections::HashMap,
    fmt,
};

use serde::{Serialize, Deserialize};


// TODO: Splitting these up will provide nicer error handling when the user
// actually wants to handle them, rather than merely print them. It also means
// many error types, so may make learning/using the library more difficult.
// TODO: Some of these would be good for code to be able to inspect; we need
// data-oriented errors rather than string-oriented errors.
/// Errors from validating B2 requests prior to making the request.
#[derive(Debug)]
pub enum ValidationError {
    /// Failure to parse a URL.
    ///
    /// The string the problematic URL.
    BadUrl(String),
    /// The data is an invalid format or contains invalid information.
    ///
    /// The string is a short description of the failure.
    BadFormat(String),
    /// Required information was not provided.
    ///
    /// The string is a short description of the failure.
    MissingData(String),
    /// The data is outside its valid range.
    ///
    /// The string is a short description of the failure.
    OutOfBounds(String), // TODO: I need a better name.
    /// Two pieces of data are incompatible together.
    ///
    /// The string is a short description of the failure.
    Incompatible(String),
    /// Multiple [LifecycleRule](crate::bucket::LifecycleRule)s exist for the
    /// same file.
    ///
    /// Returns a map of conflicting filename prefixes; the most broad prefix
    /// (the base path) for each group of conflicts is the key.
    ConflictingRules(HashMap<String, Vec<String>>),
}

impl std::error::Error for ValidationError {}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadUrl(s) => write!(f, "Error parsing URL: {}", s),
            Self::BadFormat(s) => write!(f, "{}", s),
            Self::MissingData(s) => write!(f, "{}", s),
            Self::OutOfBounds(s) => write!(f, "{}", s),
            Self::Incompatible(s) => write!(f, "{}", s),
            Self::ConflictingRules(_) => write!(f,
                "Only one lifecycle rule can apply to any given set of files"),
        }
    }
}

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
    /// The [Authorization] lacks a required capability to perform a task.
    ///
    /// This error is typically used when the B2 API returns `null` rather than
    /// returning an error.
    Unauthorized(crate::account::Capability),
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
            Self::Unauthorized(c) => write!(f, "Missing capability: {:?}", c),
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
    // 400
    BadBucketId,
    BadRequest,
    DuplicateBucketName,
    TooManyBuckets,

    // 401
    BadAuthToken,
    ExpiredAuthToken,
    Unauthorized,
    Unsupported,

    // 403
    TransactionCapExceeded,

    // 409
    Conflict,

    // 500
    InternalError,

    // 503
    ServiceUnavailable,
}

impl ErrorCode {
    // TODO: Error type
    /// Convert the error code received from the B2 service to an [ErrorCode].
    fn from_api_code<S: AsRef<str>>(code: S) -> Result<Self, String> {
        match code.as_ref() {
            "bad_bucket_id" => Ok(Self::BadBucketId),
            "bad_request" => Ok(Self::BadRequest),
            "duplicate_bucket_name" => Ok(Self::DuplicateBucketName),
            "too_many_buckets" => Ok(Self::TooManyBuckets),

            "bad_auth_token" => Ok(Self::BadAuthToken),
            "expired_auth_token" => Ok(Self::ExpiredAuthToken),
            "unauthorized" => Ok(Self::Unauthorized),
            "unsupported" => Ok(Self::Unsupported),

            "transaction_cap_exceeded" => Ok(Self::TransactionCapExceeded),

            "conflict" => Ok(Self::Conflict),

            "internal_error" => Ok(Self::InternalError),

            "service_unavailable" => Ok(Self::ServiceUnavailable),
            // TODO: Use an Unknown(code) variant instead.
            _ => Err(String::from(code.as_ref())),
        }
    }

    /// Get the HTTP status code of this error.
    fn status(&self) -> u16 {
        match self {
            Self::BadBucketId => 400,
            Self::BadRequest => 400,
            Self::DuplicateBucketName => 400,
            Self::TooManyBuckets => 400,
            Self::BadAuthToken => 401,
            Self::ExpiredAuthToken => 401,
            Self::Unauthorized => 401,
            Self::Unsupported => 401,
            Self::TransactionCapExceeded => 403,
            Self::Conflict => 409,
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
