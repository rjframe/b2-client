use std::fmt;

use serde::{Serialize, Deserialize};


/// Errors that can be returned by `b2-client` function calls.
#[derive(Debug)]
pub enum Error<E>
    // Surf's Error doesn't impl StdError.
    where E: fmt::Debug + fmt::Display,
{
    /// An error from the underlying HTTP client.
    Client(E),
    /// An error from the Backblaze B2 API.
    B2(B2Error),
    /// An error de/serializing data that's expected to be a valid JSON string.
    Format(serde_json::Error),
}

impl<E> std::error::Error for Error<E>
    where E: fmt::Debug + fmt::Display,
{}

impl<E> fmt::Display for Error<E>
    where E: fmt::Debug + fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", *self)
    }
}

impl<E> Error<E>
    where E: fmt::Debug + fmt::Display,
{
    /// Create an [Error] from a [B2Error].
    pub fn from_b2(e: B2Error) -> Self { Self::B2(e) }

    /// Create an [Error] from a [serde_json::Error].
    // TODO: I don't like this name; we're not converting from JSON.
    pub fn from_json(e: serde_json::Error) -> Self {
        Self::Format(e)
    }
}

impl<E> From<E> for Error<E>
    where E: fmt::Debug + fmt::Display,
{
    /// Convert an error from an HTTP client to an [Error].
    fn from(e: E) -> Self { Self::Client(e) }
}

/// An error code from the B2 API.
#[derive(Debug, Serialize, Deserialize)]
pub enum ErrorCode {
    BadRequest,
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
