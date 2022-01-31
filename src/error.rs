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
//!     * [BadHeaderName]
//!     * [BucketValidationError]
//!     * [CorsRuleValidationError]
//!     * [FileNameValidationError]
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
    OutOfBounds(String),
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

/// Error type with information on invalid HTTP header name.
#[derive(Debug)]
pub struct BadHeaderName {
    /// The name of the bad header.
    pub header: String,
    /// The illegal character in the header name.
    pub invalid_char: char,
}

impl std::error::Error for BadHeaderName {}

impl fmt::Display for BadHeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid character in header {}: {}",
            self.header,
            self.invalid_char
        )
    }
}

/// Error type for invalid bucket names.
#[derive(Debug)]
pub enum BucketValidationError {
    /// The name of the bucket must be between 8 and 50 characters, inclusive.
    // TODO: find full B2 requirement - bytes? ASCII-only characters? I think it
    // will be the latter since only ASCII control characters were explicitly
    // prohibited.
    BadNameLength(usize),
    /// Illegal character in filename.
    InvalidChar(char),
}

impl std::error::Error for BucketValidationError {}

impl fmt::Display for BucketValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadNameLength(sz) => write!(f,
                "Name must be between 6 and 50 characters, inclusive. Was {}",
                sz
            ),
            Self::InvalidChar(ch) => write!(f, "Unexpected character: {}", ch),
        }
    }
}

// TODO: Likely need to copy-paste this since the compiler won't reliably use
// the new name (same for `use as`).
/// Error type for invalid CORS rule names.
///
/// The requirements for CORS rules are the same as for bucket names.
pub type CorsRuleValidationError = BucketValidationError;

/// Error type for bad filenames.
#[derive(Debug)]
pub enum FileNameValidationError {
    /// A filename length cannot exceed 1024 bytes.
    BadLength(usize),
    /// An invalid character was in the filename string.
    InvalidChar(char),
}

impl std::error::Error for FileNameValidationError {}

impl fmt::Display for FileNameValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength(sz) => write!(f,
                "Name must be no more than 1024 bytes. Was {}", sz
            ),
            Self::InvalidChar(ch) => write!(f, "Illegal character: {}", ch),
        }
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
    ///
    /// There can be duplicate entries in the map when rules involving
    /// subfolders exist.
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

    /// The B2 service returned an unknown error code.
    ///
    /// If you receive this in practice, please file an issue or submit a patch
    /// to support the error code.
    Unknown(String),
}

impl ErrorCode {
    /// Convert the error code received from the B2 service to an [ErrorCode].
    fn from_api_code<S: AsRef<str>>(code: S) -> Self {
        match code.as_ref() {
            "bad_bucket_id" => Self::BadBucketId,
            "bad_request" => Self::BadRequest,
            "duplicate_bucket_name" => Self::DuplicateBucketName,
            "file_not_present" => Self::FileNotPresent,
            "too_many_buckets" => Self::TooManyBuckets,

            "bad_auth_token" => Self::BadAuthToken,
            "expired_auth_token" => Self::ExpiredAuthToken,
            "unauthorized" => Self::Unauthorized,
            "unsupported" => Self::Unsupported,

            "access_denied" => Self::AccessDenied,
            "cap_exceeded" => Self::CapExceeded,
            "storage_cap_exceeded" => Self::StorageCapExceeded,
            "transaction_cap_exceeded" => Self::TransactionCapExceeded,

            "not_found" => Self::NotFound,

            "method_not_allowed" => Self::MethodNotAllowed,

            "request_timeout" => Self::RequestTimeout,

            "range_not_satisfiable" => Self::RangeNotSatisfiable,

            "conflict" => Self::Conflict,

            "internal_error" => Self::InternalError,

            "service_unavailable" => Self::ServiceUnavailable,

            s => Self::Unknown(s.to_owned()),
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
    #[serde(rename = "code")]
    code_str: String,
    /// A description of what went wrong.
    message: String,
}

impl B2Error {
    /// Get the HTTP status code for the error.
    pub fn http_status(&self) -> u16 { self.status }

    pub fn code(&self) -> ErrorCode {
        ErrorCode::from_api_code(&self.code_str)
    }
}

impl std::error::Error for B2Error {}

impl fmt::Display for B2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code_str, self.message)
    }
}
