/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

//! B2 API calls for managing buckets.

use crate::{
    prelude::*,
    client::HttpClient,
    error::{ValidationError, Error},
    validate::{
        validated_bucket_name,
        validated_cors_rule_name,
        validated_lifecycle_rules,
    },
};

use serde::{Serialize, Deserialize};


/// A bucket classification for B2 buckets.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BucketType {
    /// A bucket where downloads are publicly-accessible.
    #[serde(rename = "allPublic")]
    Public,
    /// A bucket that restricts access to files.
    #[serde(rename = "allPrivate")]
    Private,
    /// A bucket containing B2 snapshots of other buckets.
    #[serde(rename = "snapshot")]
    Snapshot,
}

/// A valid CORS operation for B2 buckets.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub enum CorsOperation {
    #[serde(rename = "b2_download_file_by_name")]
    DownloadFileByName,
    #[serde(rename = "b2_download_file_by_id")]
    DownloadFileById,
    #[serde(rename = "b2_upload_file")]
    UploadFile,
    #[serde(rename = "b2_upload_part")]
    UploadPart,
    // S3-compatible API operations.
    #[serde(rename = "s3_delete")]
    S3Delete,
    #[serde(rename = "s3_get")]
    S3Get,
    #[serde(rename = "s3_head")]
    S3Head,
    #[serde(rename = "s3_post")]
    S3Post,
    #[serde(rename = "s3_put")]
    S3Put,
}

/// A rule to determine CORS behavior of B2 buckets.
///
/// See <https://www.backblaze.com/b2/docs/cors_rules.html> for further
/// information on CORS and file access via the B2 service.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CorsRule {
    cors_rule_name: String,
    allowed_origins: Vec<String>,
    allowed_operations: Vec<CorsOperation>,
    allowed_headers: Option<Vec<String>>,
    expose_headers: Option<Vec<String>>,
    max_age_seconds: u16,
}

impl CorsRule {
    /// Get a builder for a [CorsRule].
    pub fn builder() -> CorsRuleBuilder {
        CorsRuleBuilder::default()
    }
}

/// Create a [CorsRule].
///
/// See <https://www.backblaze.com/b2/docs/cors_rules.html> for further
/// information on CORS and file access via the B2 service.
#[derive(Debug, Default)]
pub struct CorsRuleBuilder {
    name: Option<String>,
    allowed_origins: Vec<String>,
    allowed_operations: Vec<CorsOperation>,
    allowed_headers: Option<Vec<String>>,
    expose_headers: Option<Vec<String>>,
    max_age: Option<u16>,
}

impl CorsRuleBuilder {
    /// A human-recognizeable name for the CORS rule.
    ///
    /// Names can contains any ASCII letters, numbers, and '-'. It must be
    /// between 6 and 50 characters, inclusive. Names beginning with "b2-" are
    /// reserved.
    pub fn with_name(mut self, name: impl Into<String>)
    -> Result<Self, ValidationError> {
        let name = validated_cors_rule_name(name)?;
        self.name = Some(name);
        Ok(self)
    }

    /// A list of origins covered by this rule.
    ///
    /// Examples of valid origins:
    ///
    /// * `http://www.example.com:8000`
    /// * `https://*.example.com`
    /// * `https://*:8765`
    /// * `https://*`
    /// * `*`
    ///
    /// If an entry is `*`, there can be no other entries. There can be no more
    /// than one `https` entry.
    // TODO: will I like this origins type?
    pub fn with_allowed_origins(mut self, origins: impl Into<Vec<String>>)
    -> Result<Self, ValidationError> {
        let origins = origins.into();

        if origins.is_empty() {
            return Err(ValidationError::MissingData(
                "There must be at least one origin covered by the rule".into()
            ));
        }

        // TODO: Validate each origin.

        self.allowed_origins = origins;
        Ok(self)
    }

    /// Add an origin to the list of allowed origins.
    ///
    /// Examples of valid origins:
    ///
    /// * `http://www.example.com:8000`
    /// * `https://*.example.com`
    /// * `https://*:8765`
    /// * `https://*`
    /// * `*`
    ///
    /// If an entry is `*`, there can be no other entries. There can be no more
    /// than one `https` entry.
    pub fn add_allowed_origin(mut self, origin: impl Into<String>)
    -> Result<Self, ValidationError> {
        let origin = origin.into();
        // TODO: Validate origin.
        self.allowed_origins.push(origin);
        Ok(self)
    }

    /// Set the list of operations the CORS rule allows.
    ///
    /// If the provided list is empty, returns [ValidationError::MissingData].
    pub fn with_allowed_operations(mut self, ops: Vec<CorsOperation>)
    -> Result<Self, ValidationError> {
        if ops.is_empty() {
            return Err(ValidationError::MissingData(
                "There must be at least one origin covered by the rule".into()
            ));
        }

        self.allowed_operations = ops;
        Ok(self)
    }

    /// Add a [CorsOperation] to the list of operations the CORS rule allows.
    pub fn add_allowed_operation(mut self, op: CorsOperation) -> Self {
        self.allowed_operations.push(op);
        self
    }

    /// Set the list of headers allowed in a pre-flight OPTION requests'
    /// `Access-Control-Request-Headers` header value.
    ///
    /// Each header may be:
    ///
    /// * A complete header name
    /// * A header name ending with an asterisk (`*`) to match multiple headers
    /// * An asterisk (`*) to match any header
    ///
    /// If an entry is `*`, there can be no other entries.
    ///
    /// The default is an empty list (no headers are allowed).
    // TODO: will I like this origins type?
    pub fn with_allowed_headers(mut self, headers: impl Into<Vec<String>>)
    -> Result<Self, ValidationError> {
        let headers = headers.into();

        if ! headers.is_empty() {
            // TODO: Validate headers
            self.allowed_headers = Some(headers);
        }

        Ok(self)
    }

    /// Add a header to the list of headers allowed in a pre-flight OPTION
    /// requests' `Access-Control-Request-Headers` header value.
    ///
    /// The header may be:
    ///
    /// * A complete header name
    /// * A header name ending with an asterisk (`*`) to match multipl headers
    /// * An asterisk (`*) to match any header
    ///
    /// If an entry is `*`, there can be no other entries.
    ///
    /// By default, no headers are allowed.
    pub fn add_allowed_header(mut self, header: impl Into<String>)
    -> Result<Self, ValidationError> {
        let header = header.into();
        // TODO: Validate header
        let headers = self.allowed_headers.get_or_insert_with(Vec::new);
        headers.push(header);
        Ok(self)
    }

    /// Set the list of headers that may be exposed to an application inside the
    /// client.
    ///
    /// Each entry must be a complete header name. If the list is empty, no
    /// headers will be exposed.
    pub fn with_exposed_headers(mut self, headers: impl Into<Vec<String>>)
    -> Result<Self, ValidationError> {
        let headers = headers.into();

        if ! headers.is_empty() {
            // TODO: Validate headers
            self.expose_headers = Some(headers);
        }

        Ok(self)
    }

    /// Add a header that may be exposed to an application inside the client.
    ///
    /// Each entry must be a complete header name.
    pub fn add_exposed_header(mut self, header: impl Into<String>)
    -> Result<Self, ValidationError> {
        let header = header.into();
        // TODO: Validate header
        let headers = self.expose_headers.get_or_insert_with(Vec::new);
        headers.push(header);
        Ok(self)
    }

    /// Set the maximum duration the browser may cache the response to a
    /// preflight request.
    ///
    /// The age must be non-negative and no more than one day.
    pub fn with_max_age(mut self, age: chrono::Duration)
    -> Result<Self, ValidationError> {
        if age < chrono::Duration::zero() || age > chrono::Duration::days(1) {
            return Err(ValidationError::OutOfBounds(
                "Age must be non-negative and no more than 1 day".into()
            ));
        }

        self.max_age = Some(age.num_seconds() as u16);
        Ok(self)
    }

    /// Create a [CorsRule] object.
    pub fn build(self) -> Result<CorsRule, ValidationError> {
        let cors_rule_name = self.name.ok_or_else(||
            ValidationError::MissingData(
                "The CORS rule must have a name".into()
            )
        )?;

        let max_age_seconds = self.max_age.ok_or_else(||
            ValidationError::MissingData(
                "A maximum age for client caching must be specified".into()
            )
        )?;

        if self.allowed_origins.is_empty() {
            Err(ValidationError::MissingData(
                "At least one origin must be allowed by the CORS rule".into()
            ))
        } else if self.allowed_operations.is_empty() {
            Err(ValidationError::MissingData(
                "At least one operation must be specified".into()
            ))
        } else {
            Ok(CorsRule {
                cors_rule_name,
                allowed_origins: self.allowed_origins,
                allowed_operations: self.allowed_operations,
                allowed_headers: self.allowed_headers,
                expose_headers: self.expose_headers,
                max_age_seconds,
            })
        }
    }
}

/// A rule to manage the automatic hiding or deletion of files.
///
/// See <https://www.backblaze.com/b2/docs/lifecycle_rules.html> for further
/// information.
#[derive(Debug, Serialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleRule {
    pub(crate) file_name_prefix: String,
    // The B2 docs don't give an upper limit. I can't imagine a reasonable rule
    // requiring anything close to u16::max() but if necessary we can make these
    // u32 in the future.
    #[serde(rename = "days_from_hiding_to_deleting")]
    delete_after: Option<u16>,
    #[serde(rename = "days_from_uploading_to_hiding")]
    hide_after: Option<u16>,
}

impl std::cmp::PartialOrd for LifecycleRule {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.file_name_prefix.partial_cmp(&other.file_name_prefix)
    }
}

impl std::cmp::Ord for LifecycleRule {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.file_name_prefix.cmp(&other.file_name_prefix)
    }
}

impl LifecycleRule {
    /// Get a builder for a `LifecycleRule`.
    pub fn builder() -> LifecycleRuleBuilder {
        LifecycleRuleBuilder::default()
    }
}

/// A builder for a [LifecycleRule].
///
/// See <https://www.backblaze.com/b2/docs/lifecycle_rules.html> for information
/// on bucket lifecycles.
#[derive(Default)]
pub struct LifecycleRuleBuilder {
    prefix: Option<String>,
    delete_after: Option<u16>,
    hide_after: Option<u16>,
}

impl LifecycleRuleBuilder {
    /// The filename prefix to select the files that are subject to the rule.
    ///
    /// A prefix of `""` will apply to all files, allowing the creation of rules
    /// that could delete **all** files.
    pub fn with_filename_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// The number of days to hide a file after it was uploaded.
    ///
    /// The supplied duration will be truncated to whole days. If provided, the
    /// number of days must be at least one.
    ///
    /// The maximum number of days supported is [u16::MAX].
    pub fn hide_after_upload(mut self, days: chrono::Duration)
    -> Result<Self, ValidationError> {
        let days = days.num_days();

        if days < 1 {
            Err(ValidationError::OutOfBounds(
                "Number of days must be greater than zero".into()
            ))
        } else if days > u16::MAX.into() {
            Err(ValidationError::OutOfBounds(format!(
                "Number of days cannot exceed {}", days
            )))
        } else {
            self.hide_after = Some(days as u16);
            Ok(self)
        }
    }

    /// The number of days to delete a file after it was hidden.
    ///
    /// The supplied duration will be truncated to whole days. If provided, the
    /// number of days must be at least one.
    ///
    /// The maximum number of days supported is [u16::MAX].
    ///
    /// # Notes
    ///
    /// The B2 service automatically hides files when a file with the same is
    /// uploaded (e.g., when a file changes). Files can also be explicitly
    /// hidden via [hide_file].
    pub fn delete_after_hide(mut self, days: chrono::Duration)
    -> Result<Self, ValidationError> {
        let days = days.num_days();

        if days < 1 {
            Err(ValidationError::OutOfBounds(
                "Number of days must be greater than zero".into()
            ))
        } else if days > u16::MAX.into() {
            Err(ValidationError::OutOfBounds(format!(
                "Number of days cannot exceed {}", days
            )))
        } else {
            self.delete_after = Some(days as u16);
            Ok(self)
        }
    }

    /// Create a [LifecycleRule].
    ///
    /// # Errors
    ///
    /// Returns [ValidationError::MissingData] if no filename prefix is
    /// provided, or [ValidationError::Incompatible] if the rule does not have
    /// at least one of a [hide_after_upload](Self::hide_after_upload) or
    /// [delete_after_hide](Self::delete_after_hide) rule set.
    pub fn build(self) -> Result<LifecycleRule, ValidationError> {
        if self.prefix.is_none() {
            Err(ValidationError::MissingData(
                "Rule must have a filename prefix".into()
            ))
        } else if self.hide_after.is_none() && self.delete_after.is_none() {
            Err(ValidationError::Incompatible(
                "The rule must have at least one of a hide or deletion rule"
                    .into()
            ))
        } else {
            Ok(LifecycleRule {
                file_name_prefix: self.prefix.unwrap(),
                delete_after: self.delete_after,
                hide_after: self.hide_after,
            })
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    #[serde(rename = "AES256")]
    Aes256,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "serialization::InnerSelfEncryption")]
#[serde(into = "serialization::InnerSelfEncryption")]
pub struct SelfManagedEncryption {
    algorithm: EncryptionAlgorithm,
    key: String,
    digest: String,
}

impl SelfManagedEncryption {
    pub fn new(algorithm: EncryptionAlgorithm, key: impl Into<String>)
    -> Self {
        let key = key.into();

        let digest = md5::compute(key.as_bytes());
        let digest = base64::encode(digest.0);

        let key = base64::encode(key.as_bytes());

        Self {
            algorithm,
            key,
            digest,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "serialization::InnerEncryptionConfig")]
#[serde(into = "serialization::InnerEncryptionConfig")]
pub enum DefaultServerSideEncryption {
    B2Managed(EncryptionAlgorithm),
    SelfManaged(SelfManagedEncryption),
    NoEncryption,
}

impl Default for DefaultServerSideEncryption {
    fn default() -> Self {
        Self::NoEncryption
    }
}

/// A request to create a new bucket.
///
/// Use [CreateBucketRequestBuilder] to create a `CreateBucketRequest`, then
/// pass it to [create_bucket].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBucketRequest {
    // account_id is provided by an Authorization.
    account_id: Option<String>,
    bucket_name: String,
    bucket_type: BucketType,
    bucket_info: Option<serde_json::Value>,
    cors_rules: Option<Vec<CorsRule>>,
    file_lock_enabled: bool,
    lifecycle_rules: Option<Vec<LifecycleRule>>,
    default_server_side_encryption: Option<DefaultServerSideEncryption>,
}

impl CreateBucketRequest {
    pub fn builder() -> CreateBucketRequestBuilder {
        CreateBucketRequestBuilder::default()
    }
}

/// A builder for a [CreateBucketRequest].
///
/// After creating the request, pass it to [create_bucket].
///
/// See <https://www.backblaze.com/b2/docs/b2_create_bucket.html> for further
/// information.
#[derive(Default)]
pub struct CreateBucketRequestBuilder {
    bucket_name: Option<String>,
    bucket_type: Option<BucketType>,
    bucket_info: Option<serde_json::Value>,
    cors_rules: Option<Vec<CorsRule>>,
    file_lock_enabled: bool,
    lifecycle_rules: Option<Vec<LifecycleRule>>,
    default_server_side_encryption: Option<DefaultServerSideEncryption>,
}

impl CreateBucketRequestBuilder {
    /// Create the bucket with the specified name.
    ///
    /// Bucket names:
    ///
    /// * must be globally unique
    /// * cmust be ontain only ASCII alphanumeric text and `-`
    /// * must be between 6 and 50 characters inclusive
    /// * must not begin with `b2-`
    pub fn with_name(mut self, name: impl Into<String>)
    -> Result<Self, ValidationError> {
        let name = validated_bucket_name(name)?;
        self.bucket_name = Some(name);
        Ok(self)
    }

    /// Create the bucket with the given [BucketType].
    pub fn with_type(mut self, typ: BucketType) -> Result<Self, ValidationError>
    {
        if matches!(typ, BucketType::Snapshot) {
            return Err(ValidationError::OutOfBounds(
                "Bucket type must be either Public or Private".into()
            ));
        }

        self.bucket_type = Some(typ);
        Ok(self)
    }

    /// Use the provided information with the bucket.
    ///
    /// This can contain arbitrary metadata for your own use. You can also set
    /// cache-control settings from here (but see
    /// [CreateBucketRequestBuilder::with_cache_control]).
    pub fn with_bucket_info(mut self, info: serde_json::Value)
    -> Result<Self, ValidationError> {
        self.bucket_info = Some(info);
        Ok(self)
    }

    // TODO: pub fn with_cache_control()

    /// Use the provided CORS rules for the bucket.
    ///
    /// See <https://www.backblaze.com/b2/docs/cors_rules.html> for further
    /// information.
    pub fn with_cors_rules(mut self, rules: impl Into<Vec<CorsRule>>) -> Self {
        let rules = rules.into();

        if ! rules.is_empty() {
            self.cors_rules = Some(rules);
        }

        self
    }

    /// Enable the file lock on the bucket.
    ///
    /// See <https://www.backblaze.com/b2/docs/file_lock.html> for further
    /// information.
    pub fn with_file_lock(mut self) -> Self {
        self.file_lock_enabled = true;
        self
    }

    /// Disable the file lock on the bucket.
    ///
    /// This is the default.
    pub fn without_file_lock(mut self) -> Self {
        self.file_lock_enabled = false;
        self
    }

    /// Use the provided list of [LifecycleRule]s for the bucket.
    ///
    /// No file within a bucket can be subject to multiple lifecycle rules. If
    /// any of the rules provided apply to multiple files or folders, we return
    /// a [ValidationError::ConflictingRules] with a map of the conflicting
    /// rules. The map's key is the broadest rule (highest in the path
    /// hierarchy).
    ///
    /// There can be duplicate entries in the map when rules involving
    /// subfolders exist.
    ///
    /// The empty string (`""`) matches all paths, so if provided it must be the
    /// only lifecycle rule. If it is provided along with other rules, all of
    /// those rules will be listed as a conflict.
    ///
    /// # Examples
    ///
    /// For the following input:
    ///
    /// ```ignore
    /// [
    ///     "Docs/Photos/",
    ///     "Legal/",
    ///     "Legal/Taxes/",
    ///     "Archive/",
    ///     "Archive/Temporary/",
    /// ]
    /// ```
    ///
    /// You will receive the error output:
    ///
    /// ```ignore
    /// {
    ///     "Legal/": [ "Legal/Taxes/" ],
    ///     "Archive/": [ "Archive/Temporary/" ],
    /// }
    /// ```
    ///
    /// For the following input:
    ///
    /// ```ignore
    /// [
    ///     "Docs/Photos/",
    ///     "Docs/",
    ///     "Docs/Documents/",
    ///     "Legal/Taxes/",
    ///     "Docs/Photos/Vacations/",
    ///     "Archive/",
    /// ]
    /// ```
    ///
    /// You will receive the error output (note the redundant listing):
    ///
    /// ```ignore
    /// {
    ///     "Docs/": [
    ///         "Docs/Documents/",
    ///         "Docs/Photos/",
    ///         "Docs/Photos/Vacations/",
    ///     ],
    ///     "Docs/Photos/": [ "Docs/Photos/Vacations/" ],
    /// }
    /// ```
    pub fn with_lifecycle_rules(mut self, rules: impl Into<Vec<LifecycleRule>>)
    -> Result<Self, ValidationError> {
        let rules = validated_lifecycle_rules(rules)?;
        self.lifecycle_rules = Some(rules);
        Ok(self)
    }

    /// Use the provided encryption settings on the bucket.
    pub fn with_encryption_settings(
        mut self,
        settings: DefaultServerSideEncryption
    ) -> Self {
        self.default_server_side_encryption = Some(settings);
        self
    }

    /// Create a [CreateBucketRequest].
    pub fn build(self) -> Result<CreateBucketRequest, ValidationError> {
        let bucket_name = self.bucket_name.ok_or_else(||
            ValidationError::MissingData(
                "The bucket must have a name".into()
            )
        )?;

        let bucket_type = self.bucket_type.ok_or_else(||
            ValidationError::MissingData(
                "The bucket must have a type set".into()
            )
        )?;

        Ok(CreateBucketRequest {
            account_id: None,
            bucket_name,
            bucket_type,
            bucket_info: self.bucket_info,
            cors_rules: self.cors_rules,
            file_lock_enabled: self.file_lock_enabled,
            lifecycle_rules: self.lifecycle_rules,
            default_server_side_encryption: self.default_server_side_encryption,
        })
    }
}

mod serialization {
    //! Our public encryption configuration type is sufficiently different from
    //! the JSON that we cannot simply deserialize it. We use the types here as
    //! an intermediate step.
    //!
    //! I think we could use a manual Serialize impl; we're using these anyway
    //! for consistency.

    use std::convert::TryFrom;
    use serde::{Serialize, Deserialize};


    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
    enum Mode {
        #[serde(rename = "SSE-B2")]
        B2Managed,
        #[serde(rename = "SSE-C")]
        SelfManaged,
    }

    #[derive(Debug, Default, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct InnerEncryptionConfig {
        mode: Option<Mode>,
        #[serde(skip_serializing_if = "Option::is_none")]
        algorithm: Option<super::EncryptionAlgorithm>,
        #[serde(skip_serializing_if = "Option::is_none")]
        customer_key: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        customer_key_md5: Option<String>,
    }

    impl TryFrom<InnerEncryptionConfig> for super::DefaultServerSideEncryption {
        type Error = &'static str;

        fn try_from(other: InnerEncryptionConfig) -> Result<Self, Self::Error> {
            if let Some(mode) = other.mode {
                if mode == Mode::B2Managed {
                    let algo = other.algorithm
                        .ok_or("Missing encryption algorithm")?;

                    Ok(Self::B2Managed(algo))
                } else { // Mode::SelfManaged
                    let algorithm = other.algorithm
                        .ok_or("Missing encryption algorithm")?;
                    let key = other.customer_key
                        .ok_or("Missing encryption key")?;
                    let digest = other.customer_key_md5
                        .ok_or("Missing encryption key digest")?;

                    Ok(Self::SelfManaged(
                        super::SelfManagedEncryption {
                            algorithm,
                            key,
                            digest,
                        }
                    ))
                }
            } else {
                Ok(Self::NoEncryption)
            }
        }
    }

    impl From<super::DefaultServerSideEncryption> for InnerEncryptionConfig {
        fn from(other: super::DefaultServerSideEncryption) -> Self {
            match other {
                super::DefaultServerSideEncryption::B2Managed(algorithm) => {
                    Self {
                        mode: Some(Mode::B2Managed),
                        algorithm: Some(algorithm),
                        ..Default::default()
                    }
                },
                super::DefaultServerSideEncryption::SelfManaged(enc) => {
                    Self {
                        mode: Some(Mode::SelfManaged),
                        algorithm: Some(enc.algorithm),
                        customer_key: Some(enc.key),
                        customer_key_md5: Some(enc.digest),
                    }
                },
                super::DefaultServerSideEncryption::NoEncryption => {
                    Self::default()
                },
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct InnerSelfEncryption {
        mode: Mode,
        algorithm: super::EncryptionAlgorithm,
        customer_key: String,
        customer_key_md5: String,
    }

    impl TryFrom<InnerSelfEncryption> for super::SelfManagedEncryption {
        type Error = &'static str;

        fn try_from(other: InnerSelfEncryption) -> Result<Self, Self::Error> {
            if other.mode != Mode::SelfManaged {
                Err("Not a self-managed encryption configuration")
            } else {
                Ok(Self {
                    algorithm: other.algorithm,
                    key: other.customer_key,
                    digest: other.customer_key_md5,
                })
            }
        }
    }

    impl From<super::SelfManagedEncryption> for InnerSelfEncryption {
        fn from(other: super::SelfManagedEncryption) -> Self {
            Self {
                mode: Mode::SelfManaged,
                algorithm: other.algorithm,
                customer_key: other.key,
                customer_key_md5: other.digest,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, from_value, to_value};

    #[test]
    fn no_encryption_to_json() {
        assert_eq!(
            to_value(DefaultServerSideEncryption::NoEncryption).unwrap(),
            json!({ "mode": Option::<String>::None })
        );
    }

    #[test]
    fn no_encryption_from_json() {
        let enc: DefaultServerSideEncryption = from_value(
            json!({ "mode": Option::<String>::None })
        ).unwrap();

        assert_eq!(enc, DefaultServerSideEncryption::NoEncryption);
    }

    #[test]
    fn b2_encryption_to_json() {
        let json = to_value(
            DefaultServerSideEncryption::B2Managed(EncryptionAlgorithm::Aes256)
        ).unwrap();

        assert_eq!(json, json!({ "mode": "SSE-B2", "algorithm": "AES256" }));
    }

    #[test]
    fn b2_encryption_from_json() {
        let enc: DefaultServerSideEncryption = from_value(
            json!({ "mode": "SSE-B2", "algorithm": "AES256" })
        ).unwrap();

        assert_eq!(
            enc,
            DefaultServerSideEncryption::B2Managed(EncryptionAlgorithm::Aes256)
        );
    }

    #[test]
    fn self_encryption_to_json() {
        let json = to_value(DefaultServerSideEncryption::SelfManaged(
            SelfManagedEncryption {
                algorithm: EncryptionAlgorithm::Aes256,
                key: "MY-ENCODED-KEY".into(),
                digest: "ENCODED-DIGEST".into(),
            }
        )).unwrap();

        assert_eq!(
            json,
            json!({
                "mode": "SSE-C",
                "algorithm": "AES256",
                "customerKey": "MY-ENCODED-KEY",
                "customerKeyMd5": "ENCODED-DIGEST",
            })
        );
    }

    #[test]
    fn self_encryption_from_json() {
        let enc: DefaultServerSideEncryption = from_value(
            json!({
                "mode": "SSE-C",
                "algorithm": "AES256",
                "customerKey": "MY-ENCODED-KEY",
                "customerKeyMd5": "ENCODED-DIGEST",
            })
        ).unwrap();

        assert_eq!(
            enc,
            DefaultServerSideEncryption::SelfManaged(
                SelfManagedEncryption {
                    algorithm: EncryptionAlgorithm::Aes256,
                    key: "MY-ENCODED-KEY".into(),
                    digest: "ENCODED-DIGEST".into(),
                }
            )
        );
    }
}
