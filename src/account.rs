/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

//! Account-related B2 API calls.
// TODO: Timestamps are likely UTC. Is that documented anywhere?

use std::fmt;

use crate::{
    client::HttpClient,
    error::B2Error,
    Error,
};

use chrono::{DateTime, Local};
use serde::{Serialize, Deserialize};


const B2_AUTH_URL: &str = "https://api.backblazeb2.com/b2api/v2/";

/// Authorization token and related information obtained from
/// [authorize_account].
// TODO: Make the fields private if feasible. Most (all?) fields will likely
// need to be readable, but should not be writable.
// TODO: We probably do need to make this serializable.
#[derive(Debug)]
pub struct Authorization<C>
    where C: HttpClient,
{
    pub(crate) client: C,
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
    /// The recommended size in bytes for each part of a large file.
    pub recommended_part_size: u64,
    /// The smallest possible size in bytes of a part of a large file, except
    /// the final part.
    pub absolute_minimum_part_size: u64,
    /// The base URL to use for all API calls using the AWS S3-compatible API.
    pub s3_api_url: String,
}

impl<C> Authorization<C>
    where C: HttpClient,
{
    /// Return the API url to the specified service endpoint.
    pub(crate) fn api_url<S: AsRef<str>>(&self, endpoint: S) -> String {
        format!("{}/b2api/v2/{}", self.api_url, endpoint.as_ref())
    }

    /// Return the API url to the specified service download endpoint.
    pub(crate) fn download_url<S: AsRef<str>>(&self, endpoint: S) -> String {
        format!("{}/b2api/v2/{}", self.download_url, endpoint.as_ref())
    }
}

/// The authorization information received from B2
///
/// The public [Authorization] object contains everything here, plus private
/// data used by this API implementation, such as the HTTP client.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProtoAuthorization {
    account_id: String,
    authorization_token: String,
    allowed: Capabilities,
    api_url: String,
    download_url: String,
    recommended_part_size: u64,
    absolute_minimum_part_size: u64,
    s3_api_url: String,
}

impl ProtoAuthorization {
    fn create_authorization<C: HttpClient>(self, c: C) -> Authorization<C> {
        Authorization {
            client: c,
            account_id: self.account_id,
            authorization_token: self.authorization_token,
            allowed: self.allowed,
            api_url: self.api_url,
            download_url: self.download_url,
            recommended_part_size: self.recommended_part_size,
            absolute_minimum_part_size: self.absolute_minimum_part_size,
            s3_api_url: self.s3_api_url,
        }
    }
}

/// The set of capabilities and associated information granted by an
/// authorization token.
// TODO: Make the fields private if feasible. Most (all?) fields will likely
// need to be readable, but should not be writable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
pub async fn authorize_account<C>(mut client: C, key_id: &str, key: &str)
-> Result<Authorization<C>, Error>
    // TODO: The use of this error type precludes using arbitrary HTTP clients.
    where C: HttpClient<Response=serde_json::Value, Error=Error>,
{
    let id_and_key = format!("{}:{}", key_id, key);
    let id_and_key = base64::encode(id_and_key.as_bytes());

    let mut auth = String::from("Basic ");
    auth.push_str(&id_and_key);

    let req = client.get(
        format!("{}b2_authorize_account", B2_AUTH_URL)
    ).with_header("Authorization", &auth);

    let res = req.send().await?;

    // TODO: Avoid the clone. `from_slice` doesn't take ownership.
    // If I have an enum of `Authorization`|`B2Error` I should be able to
    // deserialize it in one step then match on it. The code would be much
    // clearer too.
    let auth: Result<ProtoAuthorization, _>
        = serde_json::from_value(res.clone());

    // TODO: Map instead of match.
    match auth {
        Ok(r) => {
            Ok(r.create_authorization(client))
        },
        Err(_) => {
            let err: Result<B2Error, _> = serde_json::from_value(res);

            match err {
                Ok(e) => Err(Error::B2(e)),
                Err(e) => Err(Error::Format(e)),
            }
        }
    }
}

struct Duration(chrono::Duration);

impl std::ops::Deref for Duration {
    type Target = chrono::Duration;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl From<chrono::Duration> for Duration {
    fn from(d: chrono::Duration) -> Self {
        Self(d)
    }
}

impl From<Duration> for chrono::Duration {
    fn from(d: Duration) -> Self { d.0 }
}

impl Serialize for Duration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer,
    {
        serializer.serialize_i64(self.num_milliseconds())
    }
}

struct DurationVisitor;

impl<'de> serde::de::Visitor<'de> for DurationVisitor {
    type Value = i64;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "the number of milliseconds representing the duration"
        )
    }

    fn visit_i64<E>(self, s: i64) -> Result<Self::Value, E>
        where E: serde::de::Error,
    {
        Ok(s)
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D>(deserializer: D) -> Result<Duration, D::Error>
        where D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_i64(DurationVisitor)
            .map(|i| Duration(chrono::Duration::milliseconds(i)))
    }
}


/// An opaque type with the ability to create a B2 API key with certain
/// capabilities.
///
/// Use [CreateKeyBuilder] to create a `CreateKey` object.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateKey {
    // account_id is provided by the Authorization object.
    account_id: Option<String>,
    capabilities: Vec<Capability>,
    key_name: String,
    valid_duration_in_seconds: Option<Duration>,
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
    valid_duration: Option<Duration>,
    bucket_id: Option<String>,
    name_prefix: Option<String>,
}

impl CreateKeyBuilder {
    pub fn new<S: Into<String>>(name: S) -> Result<Self, Error> {
        // TODO: Name must be ASCII?
        let name = name.into();

        if name.len() > 100 {
            return Err(Error::Invalid(
                "Name must be no more than 100 characters.".into()
            ));
        }

        let invalid_char = |c: &char| !(c.is_alphanumeric() || *c == '-');

        if let Some(ch) = name.chars().find(invalid_char) {
            return Err(Error::Invalid(format!("Invalid character: {}", ch)));
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
    -> Result<Self, Error> {
        let caps = caps.into();

        if caps.is_empty() {
            return Err(
                Error::Invalid("Key must have at least one capability.".into())
            );
        }

        self.capabilities = Some(caps);
        Ok(self)
    }

    pub fn expires_after(mut self, dur: chrono::Duration)
    -> Result<Self, Error> {
        if dur >= chrono::Duration::days(1000) {
            return Err(
                Error::Invalid("Expiration must be less than 1000 days".into())
            );
        } else if dur < chrono::Duration::seconds(1) {
            return Err(Error::Invalid(
                "Expiration must be a positive number of seconds".into()
            ));
        }

        self.valid_duration = Some(Duration(dur));
        Ok(self)
    }

    pub fn limit_to_bucket<S: Into<String>>(mut self, id: S)
    -> Result<Self, Error> {
        let id = id.into();
        // TODO: Validate bucket id.

        self.bucket_id = Some(id);
        Ok(self)
    }

    pub fn with_name_prefix<S: Into<String>>(mut self, prefix: S)
    -> Result<Self, Error> {
        let prefix = prefix.into();
        // TODO: Validate prefix

        self.name_prefix = Some(prefix);
        Ok(self)
    }

    pub fn build(self) -> Result<CreateKey, Error> {
        let capabilities = self.capabilities.ok_or(
            Error::Invalid(
                "A list of capabilities for the key is required.".into()
            )
        )?;

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
                    cap => return Err(Error::Invalid(format!(
                        "Invalid capability when bucket_id is set: {:?}",
                        cap
                    ))),
                }
            }
        } else if self.name_prefix.is_some() {
            return Err(Error::Invalid(
                "bucket_id must be set when name_prefix is given".into()
            ));
        }

        Ok(CreateKey {
            account_id: None,
            capabilities,
            key_name: self.name,
            valid_duration_in_seconds: self.valid_duration,
            bucket_id: self.bucket_id,
            name_prefix: self.name_prefix,
        })
    }
}

// TODO: Make the fields private if feasible. Most (all?) fields will likely
// need to be readable, but should not be writable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Key {
    pub key_name: String,
    pub application_key_id: String,
    pub capabilities: Vec<Capability>,
    pub account_id: String,
    pub expiration_timestamp: Option<DateTime<Local>>,
    pub bucket_id: Option<String>,
    pub name_prefix: Option<String>,
    pub options: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewlyCreatedKey {
    // The private part of the key. This is only returned upon key creation, so
    // must be stored in a safe place.
    application_key: String,

    // The rest of these are part of (and moved to) the Key.
    key_name: String,
    application_key_id: String,
    capabilities: Vec<Capability>,
    account_id: String,
    expiration_timestamp: Option<DateTime<Local>>,
    bucket_id: Option<String>,
    name_prefix: Option<String>,
    options: Option<Vec<String>>,
}

impl NewlyCreatedKey {
    fn create_public_key(self) -> (String, Key) {
        let secret = self.application_key;

        let key = Key {
            key_name: self.key_name,
            application_key_id: self.application_key_id,
            capabilities: self.capabilities,
            account_id: self.account_id,
            expiration_timestamp: self.expiration_timestamp,
            bucket_id: self.bucket_id,
            name_prefix: self.name_prefix,
            options: self.options,
        };

        (secret, key)
    }
}

/// Create a new API application key
///
/// Returns a tuple of the key secret and the key capability information. The
/// secret is never obtainable except by this function, so must be stored in a
/// secure location.
///
/// See <https://www.backblaze.com/b2/docs/b2_create_key.html> for further
/// information.
pub async fn create_key<C>(auth: &mut Authorization<C>, new_key_info: CreateKey)
-> Result<(String, Key), Error>
    // TODO: The use of this error type precludes using arbitrary HTTP clients.
    where C: HttpClient<Response=serde_json::Value, Error=Error>,
{
    let mut new_key_info = new_key_info;
    new_key_info.account_id = Some(auth.account_id.to_owned());

    let res = auth.client.post(
        auth.api_url("b2_create_key")
    ).with_header("Authorization", &auth.authorization_token)
        .with_body(&serde_json::to_value(new_key_info)
            .map_err(Error::from_json)?
        )
        .send().await?;

    // TODO: Remove the clone. See comment in authorize_account.
    let json: Result<NewlyCreatedKey, _> = serde_json::from_value(res.clone());

    match json {
        Ok(r) => {
            Ok(r.create_public_key())
        },
        Err(_) => {
            let err: Result<B2Error, _> = serde_json::from_value(res);

            match err {
                Ok(e) => Err(Error::B2(e)),
                Err(e) => Err(Error::Format(e)),
            }
        }
    }
}

// TODO: Find a good way to mock responses for any/all backends.
#[cfg(feature = "with_surf")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        client::SurfClient,
        error::ErrorCode,
    };
    use surf_vcr::{VcrMiddleware, VcrMode, VcrError};


    const AUTH_KEY_ID: &str = "B2_KEY_ID";
    const AUTH_KEY: &str = "B2_AUTH_KEY";

    /// Create a SurfClient with the surf-vcr middleware.
    async fn create_test_client(mode: VcrMode, cassette: &'static str)
    -> std::result::Result<SurfClient, VcrError> {
        let surf = surf::Client::new()
            .with(VcrMiddleware::new(mode, cassette).await?);

        let client = SurfClient::new()
            .with_client(surf);

        Ok(client)
    }

    /// Create a fake authorization to allow us to run tests without calling the
    /// authorize_account function.
    fn get_test_key(client: SurfClient, capabilities: Vec<Capability>)
    -> Authorization<SurfClient> {
        Authorization {
            client,
            account_id: "abcdefg".into(),
            authorization_token: "4_002d2e6b27577ea0000000002_019f9ac2_4af224_acct_BzTNBWOKUVQvIMyHK3tXHG7YqDQ=".into(),
            allowed: Capabilities {
                capabilities,
                bucket_id: None,
                bucket_name: None,
                name_prefix: None,
            },
            api_url: "https://api002.backblazeb2.com".into(),
            download_url: "https://f002.backblazeb2.com".into(),
            recommended_part_size: 100000000,
            absolute_minimum_part_size: 5000000,
            s3_api_url: "https://s3.us-west-002.backblazeb2.com".into(),
        }
    }

    #[async_std::test]
    async fn test_authorize_account() -> Result<(), anyhow::Error> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/auth_account.yaml"
        ).await?;

        let auth = authorize_account(client, AUTH_KEY_ID, AUTH_KEY).await?;
        assert!(auth.allowed.capabilities.contains(&Capability::ListBuckets));

        Ok(())
    }

    #[async_std::test]
    async fn authorize_account_bad_key() -> Result<(), anyhow::Error> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/auth_account.yaml"
        ).await?;

        let auth = authorize_account(client, AUTH_KEY_ID, "wrong-key").await;

        match auth.unwrap_err() {
            // The B2 documentation says we'll receive `unauthorized`, but this
            // is what we get.
            Error::B2(e) => assert_eq!(e.code(), ErrorCode::BadAuthToken),
            _ => panic!("Unexpected error type"),
        }

        Ok(())
    }

    #[async_std::test]
    async fn authorize_account_bad_key_id() -> Result<(), anyhow::Error> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/auth_account.yaml"
        ).await?;

        let auth = authorize_account(client, "wrong-id", AUTH_KEY).await;

        match auth.unwrap_err() {
            // The B2 documentation says we'll receive `unauthorized`, but this
            // is what we get.
            Error::B2(e) => assert_eq!(e.code(), ErrorCode::BadAuthToken),
            e => panic!("Unexpected error type: {:?}", e),
        }

        Ok(())
    }

    #[async_std::test]
    async fn test_create_key() -> Result<(), anyhow::Error> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/auth_account.yaml"
        ).await?;

        let mut auth = get_test_key(client, vec![Capability::WriteKeys]);

        let new_key_info = CreateKeyBuilder::new("my-special-key").unwrap()
            .with_capabilities(vec![Capability::ListFiles]).unwrap()
            .build().unwrap();

        let (secret, key) = create_key(&mut auth, new_key_info).await?;
        assert!(! secret.is_empty());
        assert_eq!(key.capabilities.len(), 1);
        assert_eq!(key.capabilities[0], Capability::ListFiles);

        Ok(())
    }
}
