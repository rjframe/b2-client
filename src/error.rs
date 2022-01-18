/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

//! Error types for b2-client
//!
//! Errors are divided into two types:
//!
//! * [ValidationError] for data validation errors prior to sending a request to
//!   the B2 API. This is currently being split into multiple errors as
//!   appropriate:
//!     * [LifecycleRuleValidationError]
//! * [Error] for errors returned by the Backblaze B2 API or the HTTP client.

use std::{
    collections::HashMap,
    fmt,
};

use crate::bucket::LifecycleRule;

use serde::{Serialize, Deserialize};


// TODO: Splitting these up will provide nicer error handling when the user
// actually wants to handle them, rather than merely print them. As part of
// this, we need data-oriented errors rather than string-oriented errors.
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
        }
    }
}

impl From<url::ParseError> for ValidationError {
    fn from(e: url::ParseError) -> Self {
        Self::BadUrl(format!("{}", e))
    }
}

/// Error type from failure to validate a set of [LifecycleRule]s.
#[derive(Debug)]
pub enum LifecycleRuleValidationError {
    /// The maximum number of rules (100) was exceeded for the bucket.
    TooManyRules(usize),
    /// Multiple [LifecycleRule]s exist for the same file.
    ///
    /// Returns a map of conflicting filename prefixes; the most broad prefix
    /// (the base path) for each group of conflicts is the key and the
    /// conflicting rules are in the value.
    ConflictingRules(HashMap<String, Vec<LifecycleRule>>),
}

impl std::error::Error for LifecycleRuleValidationError {}

impl fmt::Display for LifecycleRuleValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyRules(i) => write!(f, concat!(
                "A bucket can have no more than 100 rules;",
                "you have provided {}"), i
            ),
            Self::ConflictingRules(_) => (write!(f,
                "Only one lifecycle rule can apply to any given set of files"
            )),
        }
    }
}

/// Errors related to making B2 API calls.
#[derive(Debug)]
pub enum Error<E>
    // Surf's Error doesn't implement StdError.
    where E: fmt::Debug + fmt::Display,
{
    /// An error from the underlying HTTP client.
    Client(E),
    /// An I/O error from the local filesystem.
    IO(std::io::Error),
    /// An error from the Backblaze B2 API.
    B2(B2Error),
    /// An error deserializing the HTTP client's response.
    Format(serde_json::Error),
    /// The [Authorization](crate::account::Authorization) lacks a required
    /// capability to perform a task. The provided capability is required.
    ///
    /// This error is typically used when the B2 API returns `null` rather than
    /// returning an error or to return what we know will be an authorization
    /// error prior to sending a request to the API.
    Unauthorized(crate::account::Capability),
    /// An error validating data prior to making a Backblaze B2 API call.
    Validation(ValidationError),
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
            Self::IO(e) => e.fmt(f),
            Self::B2(e) => Display::fmt(&e, f),
            Self::Format(e) => e.fmt(f),
            Self::Unauthorized(c) => write!(f, "Missing capability: {:?}", c),
            Self::Validation(e) => e.fmt(f),
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

impl<E> From<std::io::Error> for Error<E>
    where E: fmt::Debug + fmt::Display,
{
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
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

impl<E> From<ValidationError> for Error<E>
    where E: fmt::Debug + fmt::Display,
{
    fn from(e: ValidationError) -> Self {
        Self::Validation(e)
    }
}

/// An error code from the B2 API.
///
/// The HTTP status code is not necessarily constant for any given error code.
/// See the B2 documentation for the relevant API call to match HTTP status
/// codes and B2 error codes.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ErrorCode {
    // 400
    BadBucketId,
    BadRequest,
    DuplicateBucketName,
    FileNotPresent,
    TooManyBuckets,

    // 401
    AccessDenied, // Also 403
    BadAuthToken,
    ExpiredAuthToken,
    Unauthorized,
    Unsupported,

    // 403
    CapExceeded,
    StorageCapExceeded,
    TransactionCapExceeded,

    // 404
    NotFound,

    // 405
    MethodNotAllowed,

    // 408
    RequestTimeout,

    // 409
    Conflict,

    // 416
    RangeNotSatisfiable,

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
            "file_not_present" => Ok(Self::FileNotPresent),
            "too_many_buckets" => Ok(Self::TooManyBuckets),

            "bad_auth_token" => Ok(Self::BadAuthToken),
            "expired_auth_token" => Ok(Self::ExpiredAuthToken),
            "unauthorized" => Ok(Self::Unauthorized),
            "unsupported" => Ok(Self::Unsupported),

            "access_denied" => Ok(Self::AccessDenied),
            "cap_exceeded" => Ok(Self::CapExceeded),
            "storage_cap_exceeded" => Ok(Self::StorageCapExceeded),
            "transaction_cap_exceeded" => Ok(Self::TransactionCapExceeded),

            "not_found" => Ok(Self::NotFound),

            "method_not_allowed" => Ok(Self::MethodNotAllowed),

            "request_timeout" => Ok(Self::RequestTimeout),

            "range_not_satisfiable" => Ok(Self::RangeNotSatisfiable),

            "conflict" => Ok(Self::Conflict),

            "internal_error" => Ok(Self::InternalError),

            "service_unavailable" => Ok(Self::ServiceUnavailable),
            // TODO: Use an Unknown(code) variant instead.
            _ => Err(String::from(code.as_ref())),
        }
    }
}

/// An error response from the Backblaze B2 API.
///
/// See <https://www.backblaze.com/b2/docs/calling.html#error_handling> for
/// information on B2 error handling.
#[derive(Debug, Deserialize)]
pub struct B2Error {
    /// The HTTP status code accompanying the error.
    status: u16,
    /// A code that identifies the error.
    // TODO: Store an `ErrorCode` instead?
    #[serde(rename = "code")]
    code_str: String,
    /// A description of what went wrong.
    message: String,
}

impl B2Error {
    /// Get the HTTP status code for the error.
    pub fn http_status(&self) -> u16 { self.status }

    pub fn code(&self) -> ErrorCode {
        match ErrorCode::from_api_code(&self.code_str) {
            Ok(code) => code,
            // TODO: I need to avoid the panic. We don't need to halt someone
            // else's code for this.
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
