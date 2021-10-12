//! Account-related B2 API calls.

use crate::{
    client::HttpRequest,
    error::B2Error,
    Error,
};

use serde::{Serialize, Deserialize};


const B2_AUTH_URL: &'static str = "https://api.backblazeb2.com/b2api/v2/";

/// Authorization information obtained from [authorize_account].
// TODO: Make the fields private if feasible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    /// The ID for the account.
    pub account_id: String,
    /// The authorization token to use for all future calls.
    ///
    /// The token is valid for no more than 24 hours.
    pub authorization_token: String,
    /// The capabilities of this auth token.
    pub allowed: Capabilities,
    /// The base URL for all API calls except uploading or downloading files.
    pub api_url: String,
    /// The base URL to use for downloading files.
    pub download_url: String,
    /// The recommended size for each part of a large file.
    ///
    /// TODO: confirm this is in bytes.
    pub recommended_part_size: u64,
    /// The smallest possible size of a part of a large file, except the final
    /// part.
    pub absolute_minimum_part_size: u64,
    /// The base URL to use for all API calls using the AWS S3-compatible API.
    pub s3_api_url: String,
}

/// The set of capabilities and associated information granted by an
/// authorization token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    /// The list of capabilities granted.
    pub capabilities: Vec<Capability>,
    /// If the capabilities are limited to a single bucket, this is the bucket's
    /// ID.
    pub bucket_id: Option<String>,
    /// If the bucket is valid and hasn't been deleted, the name of the bucket
    /// corresponding to `bucket_id`. If the bucket referred to by `bucket_id`
    /// no longer exists, this will be `None`.
    pub bucket_name: Option<String>,
    /// If set, access is limited to files whose names begin with this prefix.
    pub name_prefix: Option<String>,
}

/// A capability potentially granted by an authorization token.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
// TODO: If this list is extended, add validation to CreateKeyBuilder.
pub enum Capability {
    ListKeys,
    WriteKeys,
    DeleteKeys,
    ListAllBucketNames,
    ListBuckets,
    ReadBuckets,
    WriteBuckets,
    DeleteBuckets,
    ReadBucketRetentions,
    WriteBucketRetentions,
    ReadBucketEncryption,
    WriteBucketEncryption,
    ListFiles,
    ReadFiles,
    ShareFiles,
    WriteFiles,
    DeleteFiles,
    ReadFileLegalHolds,
    WriteFileLegalHolds,
    ReadFileRetentions,
    WriteFileRetentions,
    BypassGovernance,
}

/// Log onto the B2 API.
///
/// The returned [Authorization] object must be passed to subsequent API calls.
///
/// You can obtain the `key_id` and `key` from the B2 administration pages or
/// from [create_key].
///
/// See <https://www.backblaze.com/b2/docs/b2_authorize_account.html> for
/// further information.
pub async fn authorize_account(key_id: &str, key: &str)
-> Result<Authorization, Error> {
    let id_and_key = format!("{}:{}", key_id, key);
    let id_and_key = base64::encode(id_and_key.as_bytes());

    let mut auth = String::from("Basic ");
    auth.push_str(&id_and_key);

    // TODO: We want to allow user code to bring their own backend.
    let res = crate::Requestor::post(
        format!("{}b2_authorize_account", B2_AUTH_URL)
    ).with_header("Authorization", &auth)
        .send().await?;

    // TODO: Can I avoid the clone? from_slice doesn't take ownership.
    // If I have an enum of Authorization|B2Error I should be able to
    // deserialize it in one step then match on it. The code would be much
    // clearer too.
    let json: Result<Authorization, _> = serde_json::from_value(res.clone());

    match json {
        Ok(r) => Ok(r),
        Err(_) => {
            let err: Result<B2Error, _> = serde_json::from_value(res);

            match err {
                Ok(e) => Err(Error::B2(e)),
                Err(e) => Err(Error::Format(e)),
            }
        }
    }
}

/// An opaque type with the ability to create a B2 API key with certain
/// capabilities.
///
/// Use [CreateKeyBuilder] to create a `CreateKey` object.
pub struct CreateKey {
    capabilities: Vec<Capability>,
    name: String,
    valid_duration: Option<chrono::Duration>,
    bucket_id: Option<String>,
    name_prefix: Option<String>,
}

/// A builder to create a [CreateKey] object.
///
/// See <https://www.backblaze.com/b2/docs/b2_create_key.html> for more
/// information.
pub struct CreateKeyBuilder {
    capabilities: Option<Vec<Capability>>,
    name: String,
    valid_duration: Option<chrono::Duration>,
    bucket_id: Option<String>,
    name_prefix: Option<String>,
}

// TODO: Error types.
impl CreateKeyBuilder {
    pub fn new<S: Into<String>>(name: S) -> Result<Self, String> {
        let name = name.into();

        if name.len() > 100 {
            // TODO: Name must be ASCII?
            return Err("Name must be no more than 100 characters.".into());
        }

        let invalid_char = |c: &char| !(c.is_alphanumeric() || *c == '-');

        if let Some(ch) = name.chars().find(invalid_char) {
            return Err(format!("Invalid character: {}", ch));
        }

        Ok(Self {
            capabilities: None,
            name,
            valid_duration: None,
            bucket_id: None,
            name_prefix: None,
        })
    }

    pub fn with_capabilities<V: Into<Vec<Capability>>>(mut self, caps: V)
    -> Result<Self, &'static str> {
        let caps = caps.into();

        if caps.len() == 0 {
            return Err("Key must have at least one capability.");
        }

        self.capabilities = Some(caps);
        Ok(self)
    }

    pub fn expires_after(mut self, dur: chrono::Duration)
    -> Result<Self, &'static str> {
        if dur >= chrono::Duration::days(1000) {
            return Err("Expiration must be less than 1000 days");
        } else if dur < chrono::Duration::seconds(1) {
            return Err("Expiration must be a positive number of seconds");
        }

        self.valid_duration = Some(dur);
        Ok(self)
    }

    pub fn limit_to_bucket<S: Into<String>>(mut self, id: S)
    -> Result<Self, &'static str> {
        let id = id.into();
        // TODO: Validate bucket id.

        self.bucket_id = Some(id);
        Ok(self)
    }

    pub fn with_name_prefix<S: Into<String>>(mut self, prefix: S)
    -> Result<Self, &'static str> {
        let prefix = prefix.into();
        // TODO: Validate prefix

        self.name_prefix = Some(prefix);
        Ok(self)
    }

    pub fn build(self) -> Result<CreateKey, String> {
        if self.capabilities.is_none() {
            return Err(
                "A list of capabilities for the key is required.".into()
            );
        }
        let capabilities = self.capabilities.unwrap();

        if self.bucket_id.is_some() {
            for cap in &capabilities {
                match cap {
                    Capability::ListAllBucketNames
                    | Capability::ListBuckets
                    | Capability::ReadBuckets
                    | Capability::ReadBucketEncryption
                    | Capability::WriteBucketEncryption
                    | Capability::ReadBucketRetentions
                    | Capability::WriteBucketRetentions
                    | Capability::ListFiles
                    | Capability::ReadFiles
                    | Capability::ShareFiles
                    | Capability::WriteFiles
                    | Capability::DeleteFiles
                    | Capability::ReadFileLegalHolds
                    | Capability::WriteFileLegalHolds
                    | Capability::ReadFileRetentions
                    | Capability::WriteFileRetentions
                    | Capability::BypassGovernance => {},
                    cap @ _ =>
                        return Err(format!("Invalid capability: {:?}", cap)),
                }
            }
        } else {
            if self.name_prefix.is_some() {
                return Err(
                    "bucket_id must be set when name_prefix is given".into()
                );
            }
        }

        Ok(CreateKey {
            capabilities,
            name: self.name,
            valid_duration: self.valid_duration,
            bucket_id: self.bucket_id,
            name_prefix: self.name_prefix,
        })
    }
}

// TODO: Return/Error type
pub async fn create_key(auth: &Authorization) -> Result<(), ()> {
    todo!()
}
