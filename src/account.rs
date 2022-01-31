/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

//! Account-related B2 API calls.

use std::fmt;

use crate::{
    prelude::*,
    client::HttpClient,
    error::{ValidationError, Error},
    types::*,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};


const B2_AUTH_URL: &str = "https://api.backblazeb2.com/b2api/v2/";

/// Authorization token and related information obtained from
/// [authorize_account].
///
/// The token is valid for no more than 24 hours.
#[derive(Debug)]
pub struct Authorization<C>
    where C: HttpClient,
{
    pub(crate) client: C,
    pub(crate) account_id: String,
    // The authorization token to use for all future API calls.
    //
    // The token is valid for no more than 24 hours.
    pub(crate) authorization_token: String,
    allowed: Capabilities,
    // The base URL for all API calls except uploading or downloading files.
    api_url: String,
    // The base URL to use for downloading files.
    download_url: String,
    recommended_part_size: u64,
    absolute_minimum_part_size: u64,
    // The base URL to use for all API calls using the AWS S3-compatible API.j
    _s3_api_url: String,
}

impl<C> Authorization<C>
    where C: HttpClient,
{
    // Allow tests to create fake Authorizations.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        client: C,
        account_id: String,
        authorization_token: String,
        allowed: Capabilities,
        api_url: String,
        download_url: String,
        recommended_part_size: u64,
        absolute_minimum_part_size: u64,
        _s3_api_url: String,
    ) -> Self {
        Self {
            client,
            account_id,
            authorization_token,
            allowed,
            api_url,
            download_url,
            recommended_part_size,
            absolute_minimum_part_size,
            _s3_api_url,
        }
    }

    /// The ID for the account.
    pub fn account_id(&self) -> &str { &self.account_id }
    /// The capabilities granted to this auth token.
    pub fn capabilities(&self) -> &Capabilities { &self.allowed }
    /// The recommended size in bytes for each part of a large file.
    pub fn recommended_part_size(&self) -> u64 { self.recommended_part_size }
    /// The smallest possible size in bytes of a part of a large file, except
    /// the final part.
    pub fn minimum_part_size(&self) -> u64 { self.absolute_minimum_part_size }

    pub fn has_capability(&self, cap: Capability) -> bool {
        self.allowed.has_capability(cap)
    }

    /// Return the API url to the specified service endpoint.
    ///
    /// This URL is used for all API calls except downloading files.
    pub(crate) fn api_url<S: AsRef<str>>(&self, endpoint: S) -> String {
        format!("{}/b2api/v2/{}", self.api_url, endpoint.as_ref())
    }

    /// Return the API url for GET requests to the specified service download
    /// endpoint.
    pub(crate) fn download_get_url(&self) -> &str {
        &self.download_url
    }

    /// Return the API url for POST requests to the specified service download
    /// endpoint.
    pub(crate) fn download_url<S: AsRef<str>>(&self, endpoint: S) -> String {
        format!("{}/b2api/v2/{}", self.download_url, endpoint.as_ref())
    }
}

/// The authorization information received from B2
///
/// The public [Authorization] object contains everything here, plus private
/// data used by this API implementation, such as the HTTP client.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProtoAuthorization {
    account_id: String,
    authorization_token: String,
    allowed: Capabilities,
    api_url: String,
    download_url: String,
    recommended_part_size: u64,
    absolute_minimum_part_size: u64,
    _s3_api_url: String,
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
            _s3_api_url: self._s3_api_url,
        }
    }
}

/// The set of capabilities and associated information granted by an
/// authorization token.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    capabilities: Vec<Capability>,
    bucket_id: Option<String>,
    bucket_name: Option<String>,
    name_prefix: Option<String>,
}

impl Capabilities {
    // Allow tests to create Capabilities.
    #[cfg(test)]
    pub(crate) fn new(
        capabilities: Vec<Capability>,
        bucket_id: Option<String>,
        bucket_name: Option<String>,
        name_prefix: Option<String>,
    ) -> Self {
        Self {
            capabilities,
            bucket_id,
            bucket_name,
            name_prefix,
        }
    }

    /// The list of capabilities granted.
    pub fn capabilities(&self) -> &[Capability] { &self.capabilities }
    /// If the capabilities are limited to a single bucket, this is the bucket's
    /// ID.
    pub fn bucket_id(&self) -> Option<&String> { self.bucket_id.as_ref() }
    /// If the bucket is valid and hasn't been deleted, the name of the bucket
    /// corresponding to `bucket_id`. If the bucket referred to by `bucket_id`
    /// no longer exists, this will be `None`.
    pub fn bucket_name(&self) -> Option<&String> { self.bucket_name.as_ref() }
    /// If set, access is limited to files whose names begin with this prefix.
    pub fn name_prefix(&self) -> Option<&String> { self.name_prefix.as_ref() }

    /// Check if the provided capability is granted to the object containing
    /// this [Capabilities] object.
    pub fn has_capability(&self, cap: Capability) -> bool {
        self.capabilities.iter().any(|&c| c == cap)
    }
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
///
/// # Examples
///
/// ```no_run
/// # #[cfg(feature = "with_surf")]
/// # use b2_client::{
/// #     client::{HttpClient, SurfClient},
/// #     account::{authorize_account, delete_key_by_id},
/// # };
/// # #[cfg(feature = "with_surf")]
/// # async fn f() -> anyhow::Result<()> {
/// let mut auth = authorize_account(SurfClient::new(), "MY KEY ID", "MY KEY")
///     .await?;
///
/// let removed_key = delete_key_by_id(&mut auth, "OTHER KEY ID").await?;
/// # Ok(()) }
/// ```
pub async fn authorize_account<C, E>(mut client: C, key_id: &str, key: &str)
-> Result<Authorization<C>, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    let id_and_key = format!("{}:{}", key_id, key);
    let id_and_key = base64::encode(id_and_key.as_bytes());

    let mut auth = String::from("Basic ");
    auth.push_str(&id_and_key);

    let req = client.get(
        format!("{}b2_authorize_account", B2_AUTH_URL)
    ).expect("Invalid URL")
        .with_header("Authorization", &auth);

    let res = req.send().await?;

    let auth: B2Result<ProtoAuthorization> = serde_json::from_slice(&res)?;
    auth.map(|v| v.create_authorization(client)).into()
}

/// A request to create a B2 API key with certain capabilities.
///
/// Use [CreateKeyBuilder] to create a `CreateKey` object, then pass it to
/// [create_key] to create a new application [Key] from the request.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateKey<'a> {
    // account_id is provided by the Authorization object.
    account_id: Option<&'a str>,
    capabilities: Vec<Capability>,
    key_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid_duration_in_seconds: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name_prefix: Option<String>,
}

impl<'a> CreateKey<'a> {
    pub fn builder() -> CreateKeyBuilder {
        CreateKeyBuilder::default()
    }
}

/// A builder to create a [CreateKey] object.
///
/// After creating the `CreateKey`, pass it to [create_key] to obtain a new
/// application key.
///
/// See <https://www.backblaze.com/b2/docs/b2_create_key.html> for more
/// information.
#[derive(Default)]
pub struct CreateKeyBuilder {
    capabilities: Option<Vec<Capability>>,
    name: Option<String>,
    valid_duration: Option<Duration>,
    bucket_id: Option<String>,
    name_prefix: Option<String>,
}

impl CreateKeyBuilder {
    /// Create a new builder, with the key's name provided.
    pub fn name<S: Into<String>>(mut self, name: S)
    -> Result<Self, ValidationError> {
        // TODO: Validation: name must be ASCII (not explicitly documented).
        let name = name.into();

        if name.is_empty() {
            // I don't know the minimum name size, whether all characters can be
            // '-', etc. They're not documented but I wouldn't be surprised if
            // there are such restrictions.
            return Err(ValidationError::MissingData(
                "A key name must be present".into()
            ));
        } else if name.len() > 100 {
            return Err(ValidationError::BadFormat(
                "Name must be no more than 100 characters.".into()
            ));
        }

        let invalid_char = |c: &char| !(c.is_alphanumeric() || *c == '-');

        if let Some(ch) = name.chars().find(invalid_char) {
            return Err(
                ValidationError::BadFormat(format!("Invalid character: {}", ch))
            );
        }

        self.name = Some(name);
        Ok(self)
    }

    /// Create the key with the specified capabilities.
    ///
    /// At least one capability must be provided.
    pub fn capabilities<V: Into<Vec<Capability>>>(mut self, caps: V)
    -> Result<Self, ValidationError> {
        let caps = caps.into();

        if caps.is_empty() {
            return Err(ValidationError::MissingData(
                "A key must have at least one capability.".into()
            ));
        }

        self.capabilities = Some(caps);
        Ok(self)
    }

    /// Set an expiration duration for the key.
    ///
    /// If provided, the key must be positive and no more than 1,000 days.
    pub fn expires_after(mut self, dur: chrono::Duration)
    -> Result<Self, ValidationError> {
        if dur >= chrono::Duration::days(1000) {
            return Err(ValidationError::OutOfBounds(
                "Expiration must be less than 1000 days".into()
            ));
        } else if dur < chrono::Duration::seconds(1) {
            return Err(ValidationError::OutOfBounds(
                "Expiration must be a positive number of seconds".into()
            ));
        }

        self.valid_duration = Some(Duration(dur));
        Ok(self)
    }

    /// Limit the key's access to the specified bucket.
    pub fn limit_to_bucket<S: Into<String>>(mut self, id: S)
    -> Result<Self, ValidationError> {
        self.bucket_id = Some(id.into());
        Ok(self)
    }

    /// Limit access to files to those that begin with the specified prefix.
    pub fn name_prefix<S: Into<String>>(mut self, prefix: S)
    -> Result<Self, ValidationError> {
        let prefix = prefix.into();
        // TODO: Validate prefix

        self.name_prefix = Some(prefix);
        Ok(self)
    }

    /// Create a new [CreateKey].
    pub fn build<'a>(self) -> Result<CreateKey<'a>, ValidationError> {
        let name = self.name.ok_or_else(||
            ValidationError::MissingData(
                "A name for the key must be provided".into()
            )
        )?;

        let capabilities = self.capabilities.ok_or_else(||
            ValidationError::MissingData(
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
                    cap => return Err(ValidationError::Incompatible(format!(
                        "Invalid capability when bucket_id is set: {:?}",
                        cap
                    ))),
                }
            }
        } else if self.name_prefix.is_some() {
            return Err(ValidationError::MissingData(
                "bucket_id must be set when name_prefix is given".into()
            ));
        }

        Ok(CreateKey {
            account_id: None,
            capabilities,
            key_name: name,
            valid_duration_in_seconds: self.valid_duration,
            bucket_id: self.bucket_id,
            name_prefix: self.name_prefix,
        })
    }
}

/// An application key and associated information.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Key {
    key_name: String,
    application_key_id: String,
    capabilities: Vec<Capability>,
    account_id: String,
    expiration_timestamp: Option<DateTime<Utc>>,
    bucket_id: Option<String>,
    name_prefix: Option<String>,
    // options: Option<Vec<String>>, // Currently unused by B2.
}

impl Key {
    /// The name assigned to this key.
    pub fn key_name(&self) -> &str { &self.key_name }
    /// The list of capabilities granted by this key.
    pub fn capabilities(&self) -> &[Capability] { &self.capabilities }
    /// The account this key is for.
    pub fn account_id(&self) -> &str { &self.account_id }
    /// If present, this key's capabilities are restricted to the returned
    /// bucket.
    pub fn bucket_id(&self) -> Option<&String> { self.bucket_id.as_ref() }
    /// If set, access is limited to files whose names begin with this prefix.
    pub fn name_prefix(&self) -> Option<&String> { self.name_prefix.as_ref() }

    /// If present, the expiration date and time of this key.
    pub fn expiration(&self) -> Option<DateTime<Utc>> {
        self.expiration_timestamp
    }

    /// Check if the provided capability is granted by this key.
    pub fn has_capability(&self, cap: Capability) -> bool {
        self.capabilities.iter().any(|&c| c == cap)
    }
}

#[derive(Debug, Deserialize)]
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
    expiration_timestamp: Option<DateTime<Utc>>,
    bucket_id: Option<String>,
    name_prefix: Option<String>,
    // options: Option<Vec<String>>, Currently unused by B2.
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
        };

        (secret, key)
    }
}

/// Create a new API application key.
///
/// Returns a tuple of the key secret and the key capability information. The
/// secret is never obtainable except by this function, so must be stored in a
/// secure location.
///
/// See <https://www.backblaze.com/b2/docs/b2_create_key.html> for further
/// information.
///
/// # Examples
///
/// ```no_run
/// # #[cfg(feature = "with_surf")]
/// # use b2_client::{
/// #     client::{HttpClient, SurfClient},
/// #     account::{authorize_account, create_key, Capability, CreateKey},
/// # };
/// # #[cfg(feature = "with_surf")]
/// # async fn f() -> anyhow::Result<()> {
/// let mut auth = authorize_account(SurfClient::new(), "MY KEY ID", "MY KEY")
///     .await?;
///
/// let create_key_request = CreateKey::builder()
///     .name("my-key")?
///     .capabilities([Capability::ListFiles])?
///     .build()?;
///
/// let (secret, new_key) = create_key(&mut auth, create_key_request).await?;
/// # Ok(()) }
/// ```
pub async fn create_key<C, E>(
    auth: &mut Authorization<C>,
    new_key_info: CreateKey<'_>
) -> Result<(String, Key), Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::WriteKeys);

    let mut new_key_info = new_key_info;
    new_key_info.account_id = Some(&auth.account_id);

    let res = auth.client.post(auth.api_url("b2_create_key"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token)
        .with_body_json(serde_json::to_value(new_key_info)?)
        .send().await?;

    let new_key: B2Result<NewlyCreatedKey> = serde_json::from_slice(&res)?;
    new_key.map(|key| key.create_public_key()).into()
}

/// Delete the given [Key].
///
/// Returns a `Key` describing the just-deleted key.
///
/// See <https://www.backblaze.com/b2/docs/b2_delete_key.html> for further
/// information.
///
/// ```no_run
/// # #[cfg(feature = "with_surf")]
/// # use b2_client::{
/// #     client::{HttpClient, SurfClient},
/// #     account::{
/// #         authorize_account, create_key, delete_key, Capability, CreateKey,
/// #     },
/// # };
/// # #[cfg(feature = "with_surf")]
/// # async fn f() -> anyhow::Result<()> {
/// let mut auth = authorize_account(SurfClient::new(), "MY KEY ID", "MY KEY")
///     .await?;
///
/// let create_key_request = CreateKey::builder()
///     .name("my-key")?
///     .capabilities([Capability::ListFiles])?
///     .build()?;
///
/// let (_secret, new_key) = create_key(&mut auth, create_key_request).await?;
///
/// let deleted_key = delete_key(&mut auth, new_key).await?;
/// # Ok(()) }
/// ```
pub async fn delete_key<C, E>(auth: &mut Authorization<C>, key: Key)
-> Result<Key, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    delete_key_by_id(auth, key.application_key_id).await
}

/// Delete the key with the specified key ID.
///
/// Returns a [Key] describing the just-deleted key.
///
/// See <https://www.backblaze.com/b2/docs/b2_delete_key.html> for further
/// information.
///
/// # Examples
///
/// ```no_run
/// # #[cfg(feature = "with_surf")]
/// # use b2_client::{
/// #     client::{HttpClient, SurfClient},
/// #     account::{authorize_account, delete_key_by_id},
/// # };
/// # #[cfg(feature = "with_surf")]
/// # async fn f() -> anyhow::Result<()> {
/// let mut auth = authorize_account(SurfClient::new(), "MY KEY ID", "MY KEY")
///     .await?;
///
/// let removed_key = delete_key_by_id(&mut auth, "OTHER KEY ID").await?;
/// # Ok(()) }
/// ```
pub async fn delete_key_by_id<C, E, S: AsRef<str>>(
    auth: &mut Authorization<C>,
    key_id: S
) -> Result<Key, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::DeleteKeys);

    let res = auth.client.post(auth.api_url("b2_delete_key"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token)
        .with_body_json(serde_json::json!({"applicationKeyId": key_id.as_ref()}))
        .send().await?;

    let key: B2Result<Key> = serde_json::from_slice(&res)?;
    key.into()
}

/// A request to obtain a list of keys associated with an account.
///
/// Use [KeyListRequestBuilder] to create a `KeyListRequest`, then pass it to
/// [list_keys] to obtain the list of keys.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyListRequest<'a> {
    // account_id is provided by an Authorization.
    account_id: Option<&'a str>,
    max_key_count: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_application_key_id: Option<String>,
}

impl<'a> KeyListRequest<'a> {
    pub fn builder() -> KeyListRequestBuilder {
        KeyListRequestBuilder::default()
    }
}

impl<'a> Default for KeyListRequest<'a> {
    fn default() -> Self {
        KeyListRequestBuilder::default().build()
    }
}

/// A builder to create a [KeyListRequest] object.
///
/// After creating the `KeyListRequest`, pass it to [list_keys] to obtain the
/// list.
///
/// See <https://www.backblaze.com/b2/docs/b2_list_keys.html> for further
/// information.
#[derive(Debug)]
pub struct KeyListRequestBuilder {
    max_keys: u16,
    start_key_id: Option<String>,
}

impl Default for KeyListRequestBuilder {
    fn default() -> Self {
        Self {
            max_keys: 100,
            start_key_id: None,
        }
    }
}

impl KeyListRequestBuilder {
    /// Set the maximum number of keys to return in a single call to
    /// [list_keys].
    ///
    /// The default is 100 and maximum is 10,000.
    pub fn max_keys(mut self, limit: u16) -> Result<Self, ValidationError> {
        if limit > 10000 {
            return Err(ValidationError::OutOfBounds(
                "Key listing limit is 10,000".into()
            ));
        }

        self.max_keys = limit;
        Ok(self)
    }

    /// Set the key ID at which to begin listing.
    pub fn start_at_key(mut self, id: impl Into<String>)
    -> Result<Self, ValidationError> {
        self.start_key_id = Some(id.into());
        Ok(self)
    }

    /// Create a [KeyListRequest].
    pub fn build<'a>(self) -> KeyListRequest<'a> {
        KeyListRequest {
            account_id: None,
            max_key_count: self.max_keys,
            start_application_key_id: self.start_key_id,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyList {
    keys: Vec<Key>,
    next_application_key_id: Option<String>,
}

/// List application keys associated with the account of the given
/// [Authorization].
///
/// The `Authorization` must have [Capability::ListKeys].
///
/// Returns a tuple of the list of keys and the next [KeyListRequest] to obtain
/// the next set of keys, if there are keys that have not yet been returned. The
/// new key list request will have the same maximum key limit as the previous
/// request.
///
/// A single function call can generate multiple Class C transactions, which may
/// result in charges to your account. See
/// <https://www.backblaze.com/b2/docs/b2_list_keys.html> for further
/// information.
///
/// # Examples
///
/// ```no_run
/// # #[cfg(feature = "with_surf")]
/// # use b2_client::{
/// #     client::{HttpClient, SurfClient},
/// #     account::{
/// #         authorize_account, list_keys,
/// #         Capability, KeyListRequest,
/// #     },
/// # };
/// # #[cfg(feature = "with_surf")]
/// # async fn f() -> anyhow::Result<()> {
/// let mut auth = authorize_account(SurfClient::new(), "MY KEY ID", "MY KEY")
///     .await?;
///
/// let req = KeyListRequest::builder()
///     .max_keys(500)?
///     .build();
///
/// let (keys, _next_req) = list_keys(&mut auth, req).await?;
///
/// for key in keys.iter() {
///     // ...
/// }
/// # Ok(()) }
/// ```
pub async fn list_keys<'a, C, E>(
    auth: &'a mut Authorization<C>,
    list_req: KeyListRequest<'a>
) -> Result<(Vec<Key>, Option<KeyListRequest<'a>>), Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::ListKeys);

    let mut list_req = list_req;
    list_req.account_id = Some(&auth.account_id);

    let res = auth.client.post(auth.api_url("b2_list_keys"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token)
        .with_body_json(serde_json::to_value(list_req.clone())?)
        .send().await?;

    let keys: B2Result<KeyList> = serde_json::from_slice(&res)?;

    match keys {
        B2Result::Ok(keys) => {
            if let Some(id) = keys.next_application_key_id {
                Ok((
                    keys.keys,
                    Some(KeyListRequest {
                        account_id: Some(&auth.account_id),
                        max_key_count: list_req.max_key_count,
                        start_application_key_id: Some(id),
                    })
                ))
            } else {
                Ok((keys.keys, None))
            }
        },
        B2Result::Err(e) => Err(e.into())
    }
}


// TODO: Find a good way to mock responses for any/all backends.
#[cfg(feature = "with_surf")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::ErrorCode,
        test_utils::{create_test_auth, create_test_client},
    };
    use surf_vcr::VcrMode;


    /// Get the (key, id) pair from the environment for authorization tests.
    ///
    /// To make a call against the B2 API, the `B2_CLIENT_TEST_KEY` and
    /// `B2_CLIENT_TEST_KEY_ID` environment variables must be set. Otherwise,
    /// non-functional strings will be used that are adequate for replaying
    /// pre-recorded tests.
    fn get_key() -> (String, String) {
        let id = std::env::var("B2_CLIENT_TEST_KEY_ID")
            .unwrap_or_else(|_| "B2_KEY_ID".to_owned());
        let key = std::env::var("B2_CLIENT_TEST_KEY")
            .unwrap_or_else(|_| "B2_AUTH_KEY".to_owned());

        (id, key)
    }

    #[async_std::test]
    async fn test_authorize_account() -> Result<(), anyhow::Error> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/auth_account.yaml",
            None, None
        ).await?;

        let (id, key) = get_key();

        let auth = authorize_account(client, &id, &key).await?;
        assert!(auth.allowed.capabilities.contains(&Capability::ListBuckets));

        Ok(())
    }

    #[async_std::test]
    async fn authorize_account_bad_key() -> Result<(), anyhow::Error> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/bad_auth_account.yaml",
            None, None
        ).await?;

        let (id, _) = get_key();
        let auth = authorize_account(client, &id, "wrong-key").await;

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
            "test_sessions/bad_auth_account.yaml",
            None, None
        ).await?;

        let (_, key) = get_key();
        let auth = authorize_account(client, "wrong-id", &key).await;

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
            "test_sessions/auth_account.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteKeys])
            .await;

        let new_key_info = CreateKey::builder()
            .name("my-special-key")
            .unwrap()
            .capabilities(vec![Capability::ListFiles]).unwrap()
            .build().unwrap();

        let (secret, key) = create_key(&mut auth, new_key_info).await?;
        assert!(! secret.is_empty());
        assert_eq!(key.capabilities.len(), 1);
        assert_eq!(key.capabilities[0], Capability::ListFiles);

        Ok(())
    }

    #[async_std::test]
    async fn test_delete_key() -> Result<(), anyhow::Error> {
        // To run a real test against the B2 API, a valid key ID needs to be
        // provided below.

        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/auth_account.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::DeleteKeys])
            .await;

        let removed_key = delete_key_by_id(
            &mut auth, "002d2e6b27577ea0000000008"
        ).await?;

        assert_eq!(removed_key.key_name, "my-special-key");

        Ok(())
    }

    #[async_std::test]
    async fn test_list_keys() -> Result<(), anyhow::Error> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/auth_account.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::ListKeys])
            .await;

        let req = KeyListRequest::default();

        let (keys, next) = list_keys(&mut auth, req).await?;
        assert_eq!(keys.len(), 1);
        assert!(next.is_none());

        Ok(())
    }
}
