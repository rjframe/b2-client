/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

//! B2 API calls for managing buckets.
//!
//! These functions deal with creating, deleting, and managing buckets (e.g.,
//! setting server-side encryption and file retention rules).
//!
//! A B2 account has a limit of 100 buckets. All bucket names must be globally
//! unique (unique across all accounts).

use std::{borrow::Cow, fmt};

use crate::{
    prelude::*,
    client::HttpClient,
    error::*,
    validate::*,
};

use serde::{Serialize, Deserialize};


/// A bucket classification for B2 buckets.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BucketType {
    /// A bucket where downloads are publicly-accessible.
    #[serde(rename = "allPublic")]
    Public,
    /// A bucket that restricts access to files.
    #[serde(rename = "allPrivate")]
    Private,
    /// A bucket containing B2 snapshots of other buckets.
    ///
    /// Snapshot buckets can only be created from the Backblaze web portal.
    #[serde(rename = "snapshot")]
    Snapshot,
}

impl fmt::Display for BucketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "allPublic"),
            Self::Private => write!(f, "allPrivate"),
            Self::Snapshot => write!(f, "snapshot"),
        }
    }
}

/// A valid CORS operation for B2 buckets.
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorsRule {
    cors_rule_name: String,
    allowed_origins: Vec<String>,
    allowed_operations: Vec<CorsOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_headers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    /// Create a human-recognizeable name for the CORS rule.
    ///
    /// Names can contains any ASCII letters, numbers, and '-'. It must be
    /// between 6 and 50 characters, inclusive. Names beginning with "b2-" are
    /// reserved.
    pub fn name(mut self, name: impl Into<String>)
    -> Result<Self, CorsRuleValidationError> {
        let name = validated_cors_rule_name(name)?;
        self.name = Some(name);
        Ok(self)
    }

    /// Set the list of origins covered by this rule.
    ///
    /// Examples of valid origins:
    ///
    /// * `http://www.example.com:8000`
    /// * `https://*.example.com`
    /// * `https://*:8765`
    /// * `https://*`
    /// * `https`
    /// * `*`
    ///
    /// If an entry is `*`, there can be no other entries. There can be no more
    /// than one `https` entry. An entry cannot have more than one '*'.
    ///
    /// Note that an origin such as `https` is broader than an origin of
    /// `https://*` because the latter is limited to the HTTPS scheme's default
    /// port, but the former is valid for all ports.
    ///
    /// At least one origin is required in a CORS rule.
    pub fn allowed_origins(mut self, origins: impl Into<Vec<String>>)
    -> Result<Self, ValidationError> {
        self.allowed_origins = validated_origins(origins)?;
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
    /// than one `https` entry. An entry cannot have more than one '*'.
    ///
    /// Note that an origin such as `https` is broader than an origin of
    /// `https://*` because the latter is limited to the HTTPS scheme's default
    /// port, but the former is valid for all ports.
    ///
    /// At least one origin is required in a CORS rule.
    ///
    /// # Notes
    ///
    /// If adding multiple origins, [Self::allowed_origins] will validate the
    /// provided origins more efficiently.
    pub fn add_allowed_origin(mut self, origin: impl Into<String>)
    -> Result<Self, ValidationError> {
        let origin = origin.into();

        // We push first because we need a list to be able to properly validate
        // an added origin.
        self.allowed_origins.push(origin);
        self.allowed_origins = validated_origins(self.allowed_origins)?;

        Ok(self)
    }

    /// Set the list of operations the CORS rule allows.
    ///
    /// If the provided list is empty, returns [ValidationError::MissingData].
    pub fn allowed_operations(mut self, ops: Vec<CorsOperation>)
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
    pub fn allowed_headers<H>(mut self, headers: impl Into<Vec<String>>)
    -> Result<Self, BadHeaderName> {
        let headers = headers.into();

        if ! headers.is_empty() {
            for header in headers.iter() {
                validated_http_header(header)?;
            }

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
    -> Result<Self, BadHeaderName> {
        let header = header.into();
        validated_http_header(&header)?;

        let headers = self.allowed_headers.get_or_insert_with(Vec::new);
        headers.push(header);
        Ok(self)
    }

    /// Set the list of headers that may be exposed to an application inside the
    /// client.
    ///
    /// Each entry must be a complete header name. If the list is empty, no
    /// headers will be exposed.
    pub fn exposed_headers(mut self, headers: impl Into<Vec<String>>)
    -> Result<Self, BadHeaderName> {
        let headers = headers.into();

        if ! headers.is_empty() {
            for header in headers.iter() {
                validated_http_header(header)?;
            }

            self.expose_headers = Some(headers);
        }

        Ok(self)
    }

    /// Add a header that may be exposed to an application inside the client.
    ///
    /// Each entry must be a complete header name.
    pub fn add_exposed_header(mut self, header: impl Into<String>)
    -> Result<Self, BadHeaderName> {
        let header = header.into();
        validated_http_header(&header)?;

        let headers = self.expose_headers.get_or_insert_with(Vec::new);
        headers.push(header);
        Ok(self)
    }

    /// Set the maximum duration the browser may cache the response to a
    /// preflight request.
    ///
    /// The age must be non-negative and no more than one day.
    pub fn max_age(mut self, age: chrono::Duration)
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
            // Instead of doing all this, we could serialize to a JSON string.
            // If we then made `CorsRule` a simple wrapper over `Value` we
            // wouldn't even need to serialize twice.
            let bytes: usize = cors_rule_name.len()
                + self.allowed_origins.iter().map(|s| s.len()).sum::<usize>()
                + self.allowed_operations.iter()
                    .map(|c| serde_json::to_string(c).unwrap().len())
                    .sum::<usize>()
                + self.allowed_headers.iter().map(|s| s.len()).sum::<usize>()
                + self.expose_headers.iter().map(|s| s.len()).sum::<usize>();

            if bytes >= 1000 {
                return Err(ValidationError::OutOfBounds(
                    "Maximum bytes of string data is 999".into()
                ));
            }

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
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleRule {
    pub(crate) file_name_prefix: String,
    // The B2 docs don't give an upper limit. I can't imagine a reasonable rule
    // requiring anything close to u16::max() but if necessary we can make these
    // u32 in the future.
    #[serde(rename = "daysFromHidingToDeleting")]
    delete_after: Option<u16>,
    #[serde(rename = "daysFromUploadingToHiding")]
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
    pub fn builder<'a>() -> LifecycleRuleBuilder<'a> {
        LifecycleRuleBuilder::default()
    }
}

/// A builder for a [LifecycleRule].
///
/// See <https://www.backblaze.com/b2/docs/lifecycle_rules.html> for information
/// on bucket lifecycles.
#[derive(Default)]
pub struct LifecycleRuleBuilder<'a> {
    prefix: Option<&'a str>,
    delete_after: Option<u16>,
    hide_after: Option<u16>,
}

impl<'a> LifecycleRuleBuilder<'a> {
    /// The filename prefix to select the files that are subject to the rule.
    ///
    /// A prefix of `""` will apply to all files, allowing the creation of rules
    /// that could delete **all** files.
    pub fn filename_prefix(mut self, prefix: &'a str)
    -> Result<Self, FileNameValidationError> {
        self.prefix = Some(validated_file_name(prefix)?);
        Ok(self)
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
    /// hidden via [hide_file](crate::file::hide_file).
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
                file_name_prefix: self.prefix.unwrap().to_owned(),
                delete_after: self.delete_after,
                hide_after: self.hide_after,
            })
        }
    }
}

/// Valid encryption algorithms for server-side encryption.
///
/// AES256 is the only supported algorithm.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    #[serde(rename = "AES256")]
    Aes256,
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AES256")
    }
}

/// Configuration for client-managed server-side encryption.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "serialization::InnerSelfEncryption")]
#[serde(into = "serialization::InnerSelfEncryption")]
pub struct SelfManagedEncryption {
    pub(crate) algorithm: EncryptionAlgorithm,
    pub(crate) key: String,
    pub(crate) digest: String,
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

/// Configuration for server-side encryption.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "serialization::InnerEncryptionConfig")]
#[serde(into = "serialization::InnerEncryptionConfig")]
pub enum ServerSideEncryption {
    /// Let the B2 service manage encryption settings.
    B2Managed(EncryptionAlgorithm),
    /// Provide the encryption configuration for the B2 service to use.
    SelfManaged(SelfManagedEncryption),
    /// Do not encrypt the bucket or file.
    NoEncryption,
}

impl Default for ServerSideEncryption {
    fn default() -> Self {
        Self::NoEncryption
    }
}

impl ServerSideEncryption {
    /// Generate the headers required when uploading files.
    pub(crate) fn to_headers(&self) -> Option<Vec<(&'static str, Cow<str>)>> {
        match self {
            Self::B2Managed(enc) => {
                Some(vec![
                    ("X-Bz-Server-Side-Encryption", Cow::from(enc.to_string()))
                ])
            },
            Self::SelfManaged(enc) => {
                Some(vec![
                    (
                        "X-Bz-Server-Side-Encryption",
                        Cow::from(enc.algorithm.to_string())
                    ),
                    (
                        "X-Bz-Server-Side-Encryption-Customer-Key",
                        Cow::from(&enc.key)
                    ),
                    (
                        "X-Bz-Server-Side-Encryption-Customer-Key-Md5",
                        Cow::from(&enc.digest)
                    )
                ])
            },
            Self::NoEncryption => None,
        }
    }
}

/// A request to create a new bucket.
///
/// Use [CreateBucketBuilder] to create a `CreateBucket`, then pass it to
/// [create_bucket].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBucket<'a> {
    // account_id is provided by an Authorization.
    account_id: Option<&'a str>,
    bucket_name: String,
    bucket_type: BucketType,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_info: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cors_rules: Option<Vec<CorsRule>>,
    file_lock_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle_rules: Option<Vec<LifecycleRule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_server_side_encryption: Option<ServerSideEncryption>,
}

impl<'a> CreateBucket<'a> {
    pub fn builder() -> CreateBucketBuilder {
        CreateBucketBuilder::default()
    }
}

/// A builder for a [CreateBucket].
///
/// After creating the request, pass it to [create_bucket].
///
/// See <https://www.backblaze.com/b2/docs/b2_create_bucket.html> for further
/// information.
#[derive(Default)]
pub struct CreateBucketBuilder {
    bucket_name: Option<String>,
    bucket_type: Option<BucketType>,
    bucket_info: Option<serde_json::Value>,
    cors_rules: Option<Vec<CorsRule>>,
    file_lock_enabled: bool,
    lifecycle_rules: Option<Vec<LifecycleRule>>,
    default_server_side_encryption: Option<ServerSideEncryption>,
}

impl CreateBucketBuilder {
    /// Create the bucket with the specified name.
    ///
    /// Bucket names:
    ///
    /// * must be globally unique
    /// * cmust be ontain only ASCII alphanumeric text and `-`
    /// * must be between 6 and 50 characters inclusive
    /// * must not begin with `b2-`
    pub fn name(mut self, name: impl Into<String>)
    -> Result<Self, BucketValidationError> {
        let name = validated_bucket_name(name)?;
        self.bucket_name = Some(name);
        Ok(self)
    }

    /// Create the bucket with the given [BucketType].
    pub fn bucket_type(mut self, typ: BucketType)
    -> Result<Self, ValidationError> {
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
    /// cache-control settings from here (but see [Self::cache_control]).
    // TODO: Validate CORS rules if provided.
    pub fn bucket_info(mut self, info: serde_json::Value)
    -> Result<Self, ValidationError> {
        self.bucket_info = Some(info);
        Ok(self)
    }

    // TODO: pub fn cache_control()

    /// Use the provided CORS rules for the bucket.
    ///
    /// See <https://www.backblaze.com/b2/docs/cors_rules.html> for further
    /// information.
    pub fn cors_rules(mut self, rules: impl Into<Vec<CorsRule>>)
    -> Result<Self, ValidationError> {
        let rules = rules.into();

        if rules.len() > 100 {
            return Err(ValidationError::OutOfBounds(
                "A bucket can have no more than 100 CORS rules".into()
            ));
        } else if ! rules.is_empty() {
            self.cors_rules = Some(rules);
        }

        Ok(self)
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
    /// a [LifecycleRuleValidationError::ConflictingRules] with a list of the
    /// conflicts.
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
    pub fn lifecycle_rules(mut self, rules: impl Into<Vec<LifecycleRule>>)
    -> Result<Self, LifecycleRuleValidationError> {
        let rules = validated_lifecycle_rules(rules)?;
        self.lifecycle_rules = Some(rules);

        Ok(self)
    }

    /// Use the provided encryption settings on the bucket.
    pub fn encryption_settings(mut self, settings: ServerSideEncryption) -> Self
    {
        self.default_server_side_encryption = Some(settings);
        self
    }

    /// Create a [CreateBucket].
    pub fn build<'a>(self) -> Result<CreateBucket<'a>, ValidationError> {
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

        Ok(CreateBucket {
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

/// Information from B2 concerning a file's retention settings.
#[derive(Debug, Deserialize)]
pub struct FileLockConfiguration {
    #[serde(rename = "isClientAuthorizedToRead")]
    can_read: bool,
    #[serde(rename = "isFileLockEnabled")]
    file_lock_enabled: bool,
    #[serde(rename = "value")]
    retention: FileRetentionPolicy,
}

impl FileLockConfiguration {
    /// Check whether a file lock is enabled.
    ///
    /// If not authorized to read the file lock configuration, returns `None`.
    pub fn lock_is_enabled(&self) -> Option<bool> {
        if self.can_read {
            Some(self.file_lock_enabled)
        } else {
            None
        }
    }

    /// Get the file lock's retention policy.
    ///
    /// If not authorized to read the file lock configuration, returns `None`.
    pub fn retention_policy(&self) -> Option<FileRetentionPolicy> {
        if self.can_read {
            Some(self.retention)
        } else {
            None
        }
    }
}

/// The B2 mode of a file's retention policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileRetentionMode {
    Governance,
    Compliance,
}

impl fmt::Display for FileRetentionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Governance => write!(f, "governance"),
            Self::Compliance => write!(f, "compliance"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum PeriodUnit { Days, Years }

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Period { duration: u32, unit: PeriodUnit }

impl From<Period> for chrono::Duration {
    fn from(other: Period) -> Self {
        match other.unit {
            PeriodUnit::Days => Self::days(other.duration as i64),
            PeriodUnit::Years => Self::weeks(other.duration as i64 * 52),
        }
    }
}

impl From<chrono::Duration> for Period {
    fn from(other: chrono::Duration) -> Self {
        Self {
            duration: other.num_days() as u32,
            unit: PeriodUnit::Days,
        }
    }
}

/// A file's B2 retention policy.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct FileRetentionPolicy {
    // `mode` and `period` must either both be set or both be (explicitly) null
    // in the JSON we send to B2.
    mode: Option<FileRetentionMode>,
    period: Option<Period>,
}

impl FileRetentionPolicy {
    pub fn new(mode: FileRetentionMode, duration: chrono::Duration) -> Self {
        Self {
            mode: Some(mode),
            period: Some(duration.into()),
        }
    }

    pub fn mode(&self) -> Option<FileRetentionMode> { self.mode }

    pub fn period(&self) -> Option<chrono::Duration> {
        self.period.map(|p| p.into())
    }
}

/// Response from B2 with the configured bucket encryption settings.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketEncryptionInfo {
    is_client_authorized_to_read: bool,
    value: Option<ServerSideEncryption>,
}

impl BucketEncryptionInfo {
    /// True if the authorization token allows access to the encryption
    /// settings.
    ///
    /// If this is `false`, then `settings` will return `None`.
    pub fn can_read(&self) -> bool { self.is_client_authorized_to_read }

    /// The [ServerSideEncryption] configuration on the bucket.
    pub fn settings(&self) -> Option<&ServerSideEncryption> {
        self.value.as_ref()
    }
}

/// A B2 bucket
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bucket {
    account_id: String,
    pub(crate) bucket_id: String,
    bucket_name: String,
    bucket_type: BucketType,
    bucket_info: serde_json::Value,
    cors_rules: Vec<CorsRule>,
    file_lock_configuration: FileRetentionPolicy,
    default_server_side_encryption: BucketEncryptionInfo,
    lifecycle_rules: Vec<LifecycleRule>,
    revision: u16,
    options: Option<Vec<String>>,
}

impl Bucket {
    pub fn account_id(&self) -> &str { &self.account_id }
    pub fn name(&self) -> &str { &self.bucket_name }
    pub fn bucket_type(&self) -> BucketType { self.bucket_type }
    pub fn info(&self) -> &serde_json::Value { &self.bucket_info }
    pub fn cors_rules(&self) -> &[CorsRule] { &self.cors_rules }

    pub fn retention_policy(&self) -> FileRetentionPolicy {
        self.file_lock_configuration
    }

    pub fn encryption_info(&self) -> &BucketEncryptionInfo {
        &self.default_server_side_encryption
    }

    pub fn lifecycle_rules(&self) -> &[LifecycleRule] { &self.lifecycle_rules }
    pub fn revision(&self) -> u16 { self.revision }
    pub fn options(&self) -> Option<&Vec<String>> { self.options.as_ref() }
}

/// Create a new [Bucket].
pub async fn create_bucket<C, E>(
    auth: &mut Authorization<C>,
    new_bucket_info: CreateBucket<'_>
) -> Result<Bucket, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::WriteBuckets);
    if new_bucket_info.file_lock_enabled {
        require_capability!(auth, Capability::WriteBucketRetentions);
    }
    if new_bucket_info.default_server_side_encryption.is_some() {
        require_capability!(auth, Capability::WriteBucketEncryption);
    }

    let mut new_bucket_info = new_bucket_info;
    new_bucket_info.account_id = Some(&auth.account_id);

    let res = auth.client.post(auth.api_url("b2_create_bucket"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::to_value(new_bucket_info)?)
        .send().await?;

    let new_bucket: B2Result<Bucket> = serde_json::from_slice(&res)?;
    new_bucket.into()
}

/// Delete the bucket with the given ID.
///
/// Returns a [Bucket] with the information of the newly-deleted bucket.
///
/// See <https://www.backblaze.com/b2/docs/b2_delete_bucket.html> for further
/// information.
pub async fn delete_bucket<C, E>(
    auth: &mut Authorization<C>,
    bucket_id: impl AsRef<str>
) -> Result<Bucket, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::DeleteBuckets);

    let res = auth.client.post(auth.api_url("b2_delete_bucket"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::json!({
            "accountId": &auth.account_id,
            "bucketId": bucket_id.as_ref(),
        }))
        .send().await?;

    let new_bucket: B2Result<Bucket> = serde_json::from_slice(&res)?;
    new_bucket.into()
}

// The B2 API intention is that only an ID or name is supplied when listing
// buckets.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
enum BucketRef {
    Id(String),
    Name(String),
}

#[derive(Debug, Clone, Copy)]
enum BucketFilter {
    Type(BucketType),
    All,
}

impl From<&BucketType> for BucketFilter {
    fn from(t: &BucketType) -> Self {
        Self::Type(*t)
    }
}

impl fmt::Display for BucketFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(t) => t.fmt(f),
            Self::All => write!(f, "all"),
        }
    }
}

/// A request to list one or all buckets.
///
/// Pass the `ListBuckets` object to [list_buckets] to obtain the desired bucket
/// information.
#[derive(Debug, Clone, Serialize)]
#[serde(into = "serialization::InnerListBuckets")]
pub struct ListBuckets<'a> {
    account_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket: Option<BucketRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_types: Option<Vec<BucketFilter>>,
}

impl<'a> ListBuckets<'a> {
    pub fn builder() -> ListBucketsBuilder {
        ListBucketsBuilder::default()
    }
}

/// A builder for a [ListBuckets] request.
#[derive(Default)]
pub struct ListBucketsBuilder {
    bucket: Option<BucketRef>,
    bucket_types: Option<Vec<BucketFilter>>,
}

impl ListBucketsBuilder {
    /// If provided, only list the bucket with the specified ID.
    ///
    /// This is mutually exclusive with [Self::bucket_name].
    pub fn bucket_id(mut self, id: impl Into<String>) -> Self {
        self.bucket = Some(BucketRef::Id(id.into()));
        self
    }

    /// If provided, only list the bucket with the specified name.
    ///
    /// This is mutually exclusive with [Self::bucket_id].
    pub fn bucket_name(mut self, name: impl Into<String>)
    -> Result<Self, BucketValidationError> {
        let name = validated_bucket_name(name)?;

        self.bucket = Some(BucketRef::Name(name));
        Ok(self)
    }

    /// If provided, only list buckets of the specified [BucketType]s.
    ///
    /// By default, all buckets are listed.
    pub fn bucket_types(mut self, types: &[BucketType]) -> Self {
        let types = types.iter().map(BucketFilter::from).collect();

        self.bucket_types = Some(types);
        self
    }

    /// List all bucket types.
    pub fn with_all_bucket_types(mut self) -> Self {
        self.bucket_types = Some(vec![BucketFilter::All]);
        self
    }

    /// Create a [ListBuckets].
    pub fn build<'a>(self) -> ListBuckets<'a> {
        ListBuckets {
            account_id: None,
            bucket: self.bucket,
            bucket_types: self.bucket_types,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct BucketList {
    buckets: Vec<Bucket>,
}

/// List buckets accessible by the [Authorization] according to the filter
/// provided by a [ListBuckets] object.
///
/// If your `Authorization` only has access to one bucket, then attempting to
/// list all buckets will result in an error with
/// [ErrorCode::Unauthorized](crate::error::ErrorCode::Unauthorized).
pub async fn list_buckets<C, E>(
    auth: &mut Authorization<C>,
    list_info: ListBuckets<'_>
) -> Result<Vec<Bucket>, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::ListBuckets);

    let mut list_info = list_info;
    list_info.account_id = Some(&auth.account_id);

    let res = auth.client.post(auth.api_url("b2_list_buckets"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::to_value(list_info)?)
        .send().await?;

    let buckets: B2Result<BucketList> = serde_json::from_slice(&res)?;
    buckets.map(|b| b.buckets).into()
}

/// A request to update one or more settings on a [Bucket].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBucket<'a> {
    account_id: Option<&'a str>,
    bucket_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_type: Option<BucketType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_info: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cors_rules: Option<Vec<CorsRule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_retention: Option<FileRetentionPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_server_side_encryption: Option<ServerSideEncryption>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle_rules: Option<Vec<LifecycleRule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    if_revision_is: Option<u16>,
}

impl<'a> UpdateBucket<'a> {
    pub fn builder() -> UpdateBucketBuilder {
        UpdateBucketBuilder::default()
    }
}

/// A builder to create an [UpdateBucket] request.
#[derive(Default)]
pub struct UpdateBucketBuilder {
    bucket_id: Option<String>,
    bucket_type: Option<BucketType>,
    bucket_info: Option<serde_json::Value>,
    cors_rules: Option<Vec<CorsRule>>,
    default_retention: Option<FileRetentionPolicy>,
    default_server_side_encryption: Option<ServerSideEncryption>,
    lifecycle_rules: Option<Vec<LifecycleRule>>,
    if_revision_is: Option<u16>,
}

impl UpdateBucketBuilder {
    /// The ID of the bucket to update.
    ///
    /// This is required.
    pub fn bucket_id(mut self, bucket_id: impl Into<String>) -> Self {
        self.bucket_id = Some(bucket_id.into());
        self
    }

    /// Change the bucket's [type](BucketType) to the one provided.
    pub fn bucket_type(mut self, typ: BucketType)
    -> Result<Self, ValidationError> {
        if matches!(typ, BucketType::Snapshot) {
            return Err(ValidationError::OutOfBounds(
                "Bucket type must be either Public or Private".into()
            ));
        }

        self.bucket_type = Some(typ);
        Ok(self)
    }

    /// Replace the current bucket information with the specified information.
    ///
    /// This can contain arbitrary metadata for your own use. You can also set
    /// cache-control settings from here (but see [Self::cache_control]).
    pub fn bucket_info(mut self, info: serde_json::Value)
    -> Self {
        self.bucket_info = Some(info);
        self
    }

    // TODO: pub fn cache_control()

    /// Replace the bucket's current provided CORS rules with the provided
    /// rules.
    ///
    /// See <https://www.backblaze.com/b2/docs/cors_rules.html> for further
    /// information.
    pub fn cors_rules(mut self, rules: impl Into<Vec<CorsRule>>)
    -> Result<Self, ValidationError> {
        let rules = rules.into();

        if rules.len() > 100 {
            return Err(ValidationError::OutOfBounds(
                "A bucket can have no more than 100 CORS rules".into()
            ));
        } else if ! rules.is_empty() {
            self.cors_rules = Some(rules);
        }

        Ok(self)
    }

    /// Replace the bucket's default retention policy.
    ///
    /// The [Authorization] must have
    /// [Capability::WriteBucketRetentions](crate::account::Capability::WriteBucketRetentions).
    pub fn retention_policy(mut self, policy: FileRetentionPolicy) -> Self {
        self.default_retention = Some(policy);
        self
    }

    /// Replace the bucket's server-side encryption settings.
    ///
    /// The [Authorization] must have
    /// [Capability::WriteBucketEncryption](crate::account::Capability::WriteBucketRetentions).
    pub fn encryption_settings(mut self, settings: ServerSideEncryption) -> Self
    {
        self.default_server_side_encryption = Some(settings);
        self
    }

    /// Replace the bucket's lifecycle rules with the provided list.
    ///
    /// See the documentation for [CreateBucketBuilder::lifecycle_rules] for
    /// the lifecycle requirements and examples.
    pub fn lifecycle_rules(mut self, rules: impl Into<Vec<LifecycleRule>>)
    -> Result<Self, LifecycleRuleValidationError> {
        let rules = validated_lifecycle_rules(rules)?;
        self.lifecycle_rules = Some(rules);

        Ok(self)
    }

    /// Only perform the update if the bucket's current revision is the provided
    /// version.
    pub fn if_revision_is(mut self, revision: u16) -> Self {
        self.if_revision_is = Some(revision);
        self
    }

    pub fn build<'a>(self) -> Result<UpdateBucket<'a>, ValidationError> {
        let bucket_id = self.bucket_id.ok_or_else(||
            ValidationError::MissingData(
                "The bucket ID to update must be specified".into()
            )
        )?;

        Ok(UpdateBucket {
            account_id: None,
            bucket_id,
            bucket_type: self.bucket_type,
            bucket_info: self.bucket_info,
            cors_rules: self.cors_rules,
            default_retention: self.default_retention,
            default_server_side_encryption: self.default_server_side_encryption,
            lifecycle_rules: self.lifecycle_rules,
            if_revision_is: self.if_revision_is,
        })
    }
}

/// Update one or more properties of a [Bucket].
///
/// See <https://www.backblaze.com/b2/docs/b2_update_bucket.html> for further
/// information.
pub async fn update_bucket<C, E>(
    auth: &mut Authorization<C>,
    bucket_info: UpdateBucket<'_>
) -> Result<Bucket, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::WriteBuckets);
    if bucket_info.default_retention.is_some() {
        require_capability!(auth, Capability::WriteBucketRetentions);
    }
    if bucket_info.default_server_side_encryption.is_some() {
        require_capability!(auth, Capability::WriteBucketEncryption);
    }

    let mut bucket_info = bucket_info;
    bucket_info.account_id = Some(&auth.account_id);

    let res = auth.client.post(auth.api_url("b2_update_bucket"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::to_value(bucket_info)?)
        .send().await?;

    let bucket: B2Result<Bucket> = serde_json::from_slice(&res)?;
    bucket.into()
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

    impl TryFrom<InnerEncryptionConfig> for super::ServerSideEncryption {
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

    impl From<super::ServerSideEncryption> for InnerEncryptionConfig {
        fn from(other: super::ServerSideEncryption) -> Self {
            match other {
                super::ServerSideEncryption::B2Managed(algorithm) => {
                    Self {
                        mode: Some(Mode::B2Managed),
                        algorithm: Some(algorithm),
                        ..Default::default()
                    }
                },
                super::ServerSideEncryption::SelfManaged(enc) => {
                    Self {
                        mode: Some(Mode::SelfManaged),
                        algorithm: Some(enc.algorithm),
                        customer_key: Some(enc.key),
                        customer_key_md5: Some(enc.digest),
                    }
                },
                super::ServerSideEncryption::NoEncryption => {
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

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct InnerListBuckets<'a> {
        account_id: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        bucket_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        bucket_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        bucket_types: Option<Vec<String>>,
    }

    impl<'a> From<super::ListBuckets<'a>> for InnerListBuckets<'a> {
        fn from(other: super::ListBuckets<'a>) -> Self {
            use super::BucketRef;

            let (bucket_id, bucket_name) = if let Some(bucket) = other.bucket {
                match bucket {
                    BucketRef::Id(s) => (Some(s), None),
                    BucketRef::Name(s) => (None, Some(s)),
                }
            } else {
                (None, None)
            };

            let bucket_types = other.bucket_types
                .map(|t| t.into_iter()
                    .map(|t| t.to_string()).collect()
                );

            Self {
                account_id: other.account_id,
                bucket_id,
                bucket_name,
                bucket_types,
            }
        }
    }
}

#[cfg(feature = "with_surf")]
#[cfg(test)]
mod tests_mocked {
    use super::*;
    use crate::{
        account::Capability,
        error::ErrorCode,
    };
    use surf_vcr::VcrMode;

    use crate::test_utils::{create_test_auth, create_test_client};


    #[async_std::test]
    async fn create_bucket_success() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/buckets.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteBuckets])
            .await;

        let req = CreateBucket::builder()
            .name("testing-new-b2-client")?
            .bucket_type(BucketType::Private)?
            .lifecycle_rules(vec![
                LifecycleRule::builder()
                    .filename_prefix("my-files/")?
                    .delete_after_hide(chrono::Duration::days(5))?
                    .build()?
            ])?
            .build()?;

        let bucket = create_bucket(&mut auth, req).await?;
        assert_eq!(bucket.bucket_name, "testing-new-b2-client");

        Ok(())
    }

    #[async_std::test]
    async fn create_bucket_already_exists() -> anyhow::Result<()> {
        // Rerunning this against the B2 API will only succeed if the bucket
        // already exists. An easy way to do it is to rerun the
        // create_bucket_success test above, then change the name here to match.
        //
        // We use a different name in this test so that we can use the same
        // cassette.
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/buckets.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteBuckets])
            .await;

        let req = CreateBucket::builder()
            .name("testing-b2-client")?
            .bucket_type(BucketType::Private)?
            .lifecycle_rules(vec![
                LifecycleRule::builder()
                    .filename_prefix("my-files/")?
                    .delete_after_hide(chrono::Duration::days(5))?
                    .build()?
            ])?
            .build()?;

        match create_bucket(&mut auth, req).await.unwrap_err() {
            Error::B2(e) =>
                assert_eq!(e.code(), ErrorCode::DuplicateBucketName),
            e => panic!("Unexpected error: {:?}", e),
        }

        Ok(())
    }

    #[async_std::test]
    async fn delete_bucket_success() -> anyhow::Result<()> {
        // Rerunning this test against the B2 API will require updating the
        // bucket ID.
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/buckets.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::DeleteBuckets])
            .await;

        let bucket = delete_bucket(&mut auth, "1df2dee6ab62f7f577c70e1a")
            .await?;

        assert_eq!(bucket.bucket_name, "testing-new-b2-client");

        Ok(())
    }

    #[async_std::test]
    async fn delete_bucket_does_not_exist() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/buckets.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::DeleteBuckets])
            .await;

        // B2 documentation says ErrorCode::BadRequest but this is what we get.
        match delete_bucket(&mut auth, "1234567").await.unwrap_err() {
            Error::B2(e) =>
                assert_eq!(e.code(), ErrorCode::BadBucketId),
            e => panic!("Unexpected error: {:?}", e),
        }

        Ok(())
    }

    #[async_std::test]
    async fn test_list_buckets() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/buckets.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::ListBuckets])
            .await;

        let buckets_req = ListBuckets::builder()
            .bucket_name("testing-b2-client")?
            .build();

        let buckets = list_buckets(&mut auth, buckets_req).await?;

        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].bucket_name, "testing-b2-client");

        Ok(())
    }

    #[async_std::test]
    async fn update_bucket_success() -> anyhow::Result<()> {
        // To run this against the B2 API the bucket_id below needs to be
        // changed to a valid ID.
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/buckets.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteBuckets])
            .await;

        let req = UpdateBucket::builder()
            .bucket_id("8d625eb63be2775577c70e1a")
            .bucket_type(BucketType::Private)?
            .lifecycle_rules(vec![
                LifecycleRule::builder()
                    .filename_prefix("my-files/")?
                    .delete_after_hide(chrono::Duration::days(5))?
                    .build()?
            ])?
            .build()?;

        let bucket = update_bucket(&mut auth, req).await?;
        assert_eq!(bucket.bucket_name, "testing-b2-client");

        Ok(())
    }

    #[async_std::test]
    async fn update_bucket_conflict() -> anyhow::Result<()> {
        // To run this against the B2 API the bucket_id below needs to be
        // changed to a valid ID.
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/buckets.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteBuckets])
            .await;

        let req = UpdateBucket::builder()
            .bucket_id("8d625eb63be2775577c70e1a")
            .bucket_type(BucketType::Private)?
            .if_revision_is(10)
            .build()?;

        match update_bucket(&mut auth, req).await.unwrap_err() {
            Error::B2(e) =>
                assert_eq!(e.code(), ErrorCode::Conflict),
            e => panic!("Unexpected error: {:?}", e),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, from_value, to_value};


    #[test]
    fn no_encryption_to_json() {
        assert_eq!(
            to_value(ServerSideEncryption::NoEncryption).unwrap(),
            json!({ "mode": Option::<String>::None })
        );
    }

    #[test]
    fn no_encryption_from_json() {
        let enc: ServerSideEncryption = from_value(
            json!({ "mode": Option::<String>::None })
        ).unwrap();

        assert_eq!(enc, ServerSideEncryption::NoEncryption);
    }

    #[test]
    fn b2_encryption_to_json() {
        let json = to_value(
            ServerSideEncryption::B2Managed(EncryptionAlgorithm::Aes256)
        ).unwrap();

        assert_eq!(json, json!({ "mode": "SSE-B2", "algorithm": "AES256" }));
    }

    #[test]
    fn b2_encryption_from_json() {
        let enc: ServerSideEncryption = from_value(
            json!({ "mode": "SSE-B2", "algorithm": "AES256" })
        ).unwrap();

        assert_eq!(
            enc,
            ServerSideEncryption::B2Managed(EncryptionAlgorithm::Aes256)
        );
    }

    #[test]
    fn self_encryption_to_json() {
        let json = to_value(ServerSideEncryption::SelfManaged(
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
        let enc: ServerSideEncryption = from_value(
            json!({
                "mode": "SSE-C",
                "algorithm": "AES256",
                "customerKey": "MY-ENCODED-KEY",
                "customerKeyMd5": "ENCODED-DIGEST",
            })
        ).unwrap();

        assert_eq!(
            enc,
            ServerSideEncryption::SelfManaged(
                SelfManagedEncryption {
                    algorithm: EncryptionAlgorithm::Aes256,
                    key: "MY-ENCODED-KEY".into(),
                    digest: "ENCODED-DIGEST".into(),
                }
            )
        );
    }

    #[test]
    fn deserialize_new_bucket_response() {
        let info = json!({
            "accountId": "abcdefg",
            "bucketId": "hijklmno",
            "bucketInfo": {},
            "bucketName": "some-bucket-name",
            "bucketType": "allPrivate",
            "corsRules": [],
            "defaultServerSideEncryption": {
                "isClientAuthorizedToRead": true,
                "value": {
                    "algorithm": null,
                    "mode": null,
                },
            },
            "fileLockConfiguration": {
                "isClientAuthorizedToRead": true,
                "value": {
                    "defaultRetention": {
                        "mode": null,
                        "period": null,
                    },
                    "isFileLockEnabled": false,
                },
            },
            "lifecycleRules": [
                {
                    "daysFromHidingToDeleting": 5,
                    "daysFromUploadingToHiding": null,
                    "fileNamePrefix": "my-files",
                },
            ],
            "options": ["s3"],
            "revision": 2,
        });

        let _: Bucket = from_value(info).unwrap();
    }

    #[test]
    fn cors_rule_validates_origins() -> anyhow::Result<()> {
        let valid_origins = [
            vec!["https://*".into(), "http://*".into()],
            vec!["*".into()],
            vec![
                "https://example.com".into(), "http://example.com:1234".into()
            ],
            vec![
                "https".into(), "http".into(), "http://example.com:1234".into()
            ],
            vec![
                "https://*:8765".into(), "http://www.example.com:4545".into()
            ],
            vec![
                "https://*.example.com".into(), "http://www.example.com".into()
            ],
        ];

        for origin_list in valid_origins {
            let _ = CorsRule::builder()
                .allowed_origins(origin_list)?;
        }

        let bad_origins = [
            vec!["*".into(), "https://*".into()],
            vec!["ftp://example.com".into()],
            vec!["ftp://*.*.example.com".into()],
            vec!["https://*:8765".into(), "www.example.com:4545".into()],
            vec![
                "https://*:8765".into(), "https://www.example.com:4545".into()
            ],
        ];

        for origin_list in bad_origins {
            let rule = CorsRule::builder()
                .allowed_origins(origin_list);

            assert!(rule.is_err(), "{:?}", rule);
        }

        Ok(())
    }

    // TODO: Test CorsRuleBuilder with allowed headers, etc.
}
