/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

//! B2 API calls for working with files.

use std::fmt;

use crate::{
    prelude::*,
    account::Capability,
    bucket::{
        FileRetentionMode,
        FileRetentionPolicy,
        ServerSideEncryption,
    },
    client::HttpClient,
    error::{ValidationError, Error},
    validate::{validated_file_info, validated_file_name},
    require_capability,
};

use serde::{Serialize, Deserialize};


#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "camelCase")]
enum LegalHoldValue {
    On,
    Off,
}

/// Determines whether there is a legal hold on a file.
#[derive(Debug, Serialize, Deserialize)]
pub struct FileLegalHold {
    #[serde(rename = "isClientAuthorizedToRead")]
    can_read: bool,
    value: Option<LegalHoldValue>,
}

/// The action taken that resulted in a [File] object returned by the B2 API.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FileAction {
    /// A large file upload has been started and is still in progress.
    Start,
    /// A file was uploaded.
    Upload,
    /// A file was copied from another file.
    Copy,
    /// The file (file version) has been marked as hidden.
    Hide,
    /// The file is a virtual folder.
    Folder,
}

// This is different than but very similar to bucket::FileRetentionPolicy.
#[derive(Debug, Deserialize)]
struct FileRetentionSetting {
    mode: Option<FileRetentionMode>,
    #[serde(rename = "retainUntilTimestamp")]
    retain_until: Option<i64>,
}

// This is different than but very similar to bucket::FileLockConfiguration.
/// The retention settings for a file.
#[derive(Debug, Deserialize)]
pub struct FileRetention {
    #[serde(rename = "isClientAuthorizedToRead")]
    can_read: bool,
    value: FileRetentionSetting,
}

/// A file stored in B2 with metadata.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct File {
    account_id: Option<String>,
    action: FileAction,
    bucket_id: String,
    // TODO: Make this an option? Only relevant when action is "upload", will be
    // 0 otherwise.
    content_length: u64,
    // Value is "none" for large files. TODO: Replace it with None?
    content_sha1: Option<String>, // Max 64 elements
    content_md5: Option<String>, // Max 32 elements
    content_type: Option<String>,
    file_id: String,
    file_info: serde_json::Value,
    file_name: String,
    file_retention: Option<FileRetention>,
    legal_hold: Option<FileLegalHold>,
    server_side_encryption: Option<ServerSideEncryption>,
    // Milliseconds since midnight, 1970-1-1
    // TODO: value is 0 if action is folder; use Option?
    // TODO: method to convert to UTC
    upload_timestamp: i64,
}

impl File {
    /// The action taken to result in this [File].
    pub fn action(&self) -> FileAction { self.action }

    /// The ID of the bucket containing the file.
    pub fn bucket_id(&self) -> &str { &self.bucket_id }

    /// The number of bytes stored in the file.
    ///
    /// Only meaningful when the [action](Self::action) is [FileAction::Upload]
    /// or [FileAction::Copy]; otherwise the value is `0`.
    pub fn content_length(&self) -> u64 { self.content_length }

    /// The SHA-1 checksum of the bytes in the file.
    ///
    /// There is no checksum for large files or when the [action](Self::action)
    /// is [FileAction::Hide] or [FileAction::Folder].
    pub fn sha1(&self) -> Option<&String> {
        match &self.content_sha1 {
            Some(v) => if v == "none" { None } else { Some(v) }
            None => None,
        }
    }

    /// The MD5 checksum of the bytes in the file.
    ///
    /// There is no checksum for large files or when the [action](Self::action)
    /// is [FileAction::Hide] or [FileAction::Folder].
    pub fn md5(&self) -> Option<&String> {
        self.content_md5.as_ref()
    }

    /// When [action](Self::action) is [FileAction::Upload],
    /// [FileAction::Start], or [FileAction::Copy], the file's MIME type.
    pub fn content_type(&self) -> Option<&String> {
        self.content_type.as_ref()
    }

    /// The B2 ID of the file.
    pub fn file_id(&self) -> &str { &self.file_id }

    /// User-specified and other file metadata.
    pub fn file_info(&self) -> &serde_json::Value {
        &self.file_info
    }

    /// The name of the file.
    pub fn file_name(&self) -> &str { &self.file_name }

    /// The file's retention policy.
    pub fn file_retention(&self) -> Option<&FileRetention> {
        self.file_retention.as_ref()
    }

    /// See if there is a legal hold on this file.
    ///
    /// Returns an error if the [Authorization] does not have
    /// [Capability::ReadFileLegalHolds].
    ///
    /// Returns `None` if a legal hold is not valid for the file type (e.g., the
    /// [action](Self::action) is `hide` or `folder`).
    pub fn has_legal_hold<E>(&self) -> Result<Option<bool>, Error<E>>
        where E: fmt::Debug + fmt::Display,
    {
        if let Some(hold) = &self.legal_hold {
            if ! hold.can_read {
                Err(Error::Unauthorized(Capability::ReadFileLegalHolds))
            } else if let Some(val) = &hold.value {
                match val {
                    LegalHoldValue::On => Ok(Some(true)),
                    LegalHoldValue::Off => Ok(Some(false)),
                }
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// The encryption settings for the file.
    pub fn encryption_settings(&self) -> Option<&ServerSideEncryption> {
        self.server_side_encryption.as_ref()
    }

    /// The date and time at which the file was uploaded.
    pub fn upload_time(&self) -> chrono::DateTime<chrono::Utc> {
        use chrono::{TimeZone as _, Utc};

        Utc.timestamp_millis(self.upload_timestamp)
    }
}

/// A large file that was cancelled prior to upload completion.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelledFileUpload {
    /// The ID of the cancelled file.
    pub file_id: String,
    /// The account that owns the file.
    pub account_id: String,
    /// The bucket the file was being uploaded to.
    pub bucket_id: String,
    /// The file's name.
    pub file_name: String,
}

/// Cancel the uploading of a large file and delete any parts already uploaded.
pub async fn cancel_large_file<C, E>(auth: &mut Authorization<C>, file: File)
-> Result<CancelledFileUpload, Error<E>>
    where C: HttpClient<Response=serde_json::Value, Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    cancel_large_file_by_id(auth, file.file_id).await
}

/// Cancel the uploading of a large file and delete any parts already uploaded.
pub async fn cancel_large_file_by_id<C, E>(
    auth: &mut Authorization<C>,
    id: impl AsRef<str>
) -> Result<CancelledFileUpload, Error<E>>
    where C: HttpClient<Response=serde_json::Value, Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::WriteFiles);

    let res = auth.client.post(auth.api_url("b2_cancel_large_file"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token)
        .with_body(serde_json::json!({ "fileId": id.as_ref() }))
        .send().await?;

    let info: B2Result<CancelledFileUpload> = serde_json::from_value(res)?;
    info.into()
}

/// A byte-range to retrieve a portion of a file.
///
/// Both `start` and `end` are inclusive.
#[derive(Debug, Clone, Serialize)]
#[serde(into = "String")]
pub struct ByteRange { start: u64, end: u64 }

impl From<ByteRange> for String {
    fn from(r: ByteRange) -> String {
        format!("bytes={}-{}", r.start, r.end)
    }
}

/// Describe the action to take with file metadata when copying a file.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum MetadataDirective {
    Copy,
    Replace,
}

impl ByteRange {
    // TODO: It would be reasonable to misremember/assume that the range is
    // exclusive of the end byte; should we use `new_inclusive` and
    // `new_exclusive` functions instead? This forces explicitly choosing one or
    // the other. Name them `new_end_xxx` to be truly clear?
    fn new(start: u64, end: u64) -> Result<Self, ValidationError> {
        if start < end {
            Ok(Self { start, end })
        } else {
            Err(ValidationError::Incompatible(format!(
                "Invalid start and end for range: {} to {}", start, end
            )))
        }
    }

    pub fn start(&self) -> u64 { self.start }
    pub fn end(&self) -> u64 { self.end }
}

/// A request to copy a file from a bucket, potentially to a different bucket.
///
/// Use [CopyFileBuilder] to create a `CopyFile`, then pass it to [copy_file].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyFile {
    source_file_id: String,
    destination_bucket_id: Option<String>,
    file_name: String,
    range: Option<ByteRange>,
    metadata_directive: MetadataDirective,
    content_type: Option<String>,
    file_info: Option<serde_json::Value>,
    file_retention: Option<FileRetentionPolicy>,
    legal_hold: Option<LegalHoldValue>,
    #[serde(rename = "sourceServerSideEncryption")]
    source_encryption: Option<ServerSideEncryption>,
    #[serde(rename = "destinationServerSideEncryption")]
    dest_encryption: Option<ServerSideEncryption>,
}

impl CopyFile {
    pub fn builder() -> CopyFileBuilder {
        CopyFileBuilder::default()
    }
}

/// A builder to create a [CopyFile] request.
///
/// See <https://www.backblaze.com/b2/docs/b2_copy_file.html> for further
/// information.
#[derive(Default)]
pub struct CopyFileBuilder {
    source_file_id: Option<String>,
    destination_bucket_id: Option<String>,
    file_name: Option<String>,
    range: Option<ByteRange>,
    metadata_directive: Option<MetadataDirective>,
    content_type: Option<String>,
    file_info: Option<serde_json::Value>,
    file_retention: Option<FileRetentionPolicy>,
    legal_hold: Option<LegalHoldValue>,
    source_encryption: Option<ServerSideEncryption>,
    dest_encryption: Option<ServerSideEncryption>,
}

impl CopyFileBuilder {
    /// Obtain the source file ID and encryption settings for the copy
    /// operation.
    pub fn source_file(mut self, file: &File) -> Self {
        self.source_encryption = file.server_side_encryption.clone();
        self.source_file_id(&file.file_id)
    }

    /// Set the source file ID of the file to copy.
    pub fn source_file_id(mut self, file: impl Into<String>) -> Self {
        self.source_file_id = Some(file.into());
        self
    }

    /// Set the destination bucket for the new file.
    ///
    /// If not provided, the same bucket ID as the source file is used.
    ///
    /// Both buckets must belong to the same account.
    pub fn destination_bucket_id(mut self, bucket: impl Into<String>) -> Self {
        self.destination_bucket_id = Some(bucket.into());
        self
    }

    /// Set the filename to use for the new file.
    pub fn destination_file_name(mut self, name: impl Into<String>)
    -> Result<Self, ValidationError> {
        self.file_name = Some(validated_file_name(name)?);
        Ok(self)
    }

    /// If provided, only copy the specified byte range of the source file.
    pub fn range(mut self, range: ByteRange) -> Self {
        self.range = Some(range);
        self
    }

    /// Determine whether to copy the source metadata to the new file.
    ///
    /// If [MetadataDirective::Copy] (the default), the source metadata will be
    /// copied to the new file.
    ///
    /// If [MetadataDirective::Replace], the new file's metadata will be empty
    /// or determined by the information provided via
    /// [content_type](Self::content_type) and [file_info](Self::file_info).
    pub fn metadata_directive(mut self, directive: MetadataDirective) -> Self {
        self.metadata_directive = Some(directive);
        self
    }

    /// Set the content-type of the file.
    ///
    /// The content-type can only be set if
    /// [metadata_directive](Self::metadata_directive) is
    /// [MetadataDirective::Replace].
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Set user-specified file metadata.
    ///
    /// The file information can only be set if
    /// [metadata_directive](Self::metadata_directive) is
    /// [MetadataDirective::Replace].
    pub fn file_info(mut self, info: serde_json::Value)
    -> Result<Self, ValidationError> {
        self.file_info = Some(validated_file_info(info)?);
        Ok(self)
    }

    /// Set the file-retention settings for the new file.
    ///
    /// Setting this requires [Capability::WriteFileRetentions].
    pub fn file_retention(mut self, retention: FileRetentionPolicy) -> Self {
        self.file_retention = Some(retention);
        self
    }

    /// Enable legal hold status for the new file.
    pub fn with_legal_hold(mut self) -> Self {
        self.legal_hold = Some(LegalHoldValue::On);
        self
    }

    /// Do not enable legal hold status for the new file.
    pub fn without_legal_hold(mut self) -> Self {
        self.legal_hold = Some(LegalHoldValue::Off);
        self
    }

    /// Specify the server-side encryption settings on the source file.
    ///
    /// Calling [source_file](Self::source_file) will set this from the file
    /// object.
    pub fn source_encryption_settings(mut self, settings: ServerSideEncryption)
    -> Self {
        self.source_encryption = Some(settings);
        self
    }

    /// Specify the server-side encryption settings for the destination file.
    ///
    /// If not provided, the bucket's default settings will be used.
    pub fn destination_encryption_settings(
        mut self,
        settings: ServerSideEncryption
    ) -> Self {
        self.dest_encryption = Some(settings);
        self
    }

    /// Create a [CopyFile] object.
    ///
    /// # Returns
    ///
    /// Returns [ValidationError::MissingData] if the source file or destination
    /// filename are not set.
    ///
    /// Returns [ValidationError::Incompatible] if the
    /// [metadata_directive](Self::metadata_directive) is
    /// [MetadataDirective::Copy] or was not provided AND
    /// [content_type](Self::content_type) or [file_info](Self::file_info) were
    /// set.
    pub fn build(self) -> Result<CopyFile, ValidationError> {
        let source_file_id = self.source_file_id.ok_or_else(||
            ValidationError::MissingData(
                "The source file ID is required".into()
            )
        )?;

        let file_name = self.file_name.ok_or_else(||
            ValidationError::MissingData(
                "The new file name must be specified".into()
            )
        )?;

        let metadata_directive = self.metadata_directive
            .unwrap_or(MetadataDirective::Copy);

        if matches!(metadata_directive, MetadataDirective::Copy) {
            if self.content_type.is_some() {
                return Err(ValidationError::Incompatible(
                    "When copying a file, a new content-type cannot be set"
                        .into()
                ));
            } else if self.file_info.is_some() {
                return Err(ValidationError::Incompatible(
                    "When copying a file, setting new file info is invalid"
                        .into()
                ));
            }
        }

        Ok(CopyFile {
            source_file_id,
            destination_bucket_id: self.destination_bucket_id,
            file_name,
            range: self.range,
            metadata_directive,
            content_type: self.content_type,
            file_info: self.file_info,
            file_retention: self.file_retention,
            legal_hold: self.legal_hold,
            source_encryption: self.source_encryption,
            dest_encryption: self.dest_encryption,
        })
    }
}

/// Copy an existing file to a new file, possibly on a different bucket.
///
/// The new file must be less than 5 GB. Use [copy_part] to copy larger files.
///
/// If copying from one bucket to another, both buckets must belong to the same
/// account.
pub async fn copy_file<C, E>(auth: &mut Authorization<C>, file: CopyFile)
-> Result<File, Error<E>>
    where C: HttpClient<Response=serde_json::Value, Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::WriteFiles);
    if file.file_retention.is_some() {
        require_capability!(auth, Capability::WriteFileRetentions);
    }
    if file.legal_hold.is_some() {
        require_capability!(auth, Capability::WriteFileLegalHolds);
    }
    if file.dest_encryption.is_some() {
        require_capability!(auth, Capability::WriteBucketEncryption);
    }

    let res = auth.client.post(auth.api_url("b2_copy_file"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token)
        .with_body(serde_json::to_value(file)?)
        .send().await?;

    let file: B2Result<File> = serde_json::from_value(res)?;
    file.into()
}

/// A request to prepare to upload a large file.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartLargeFile {
    bucket_id: String,
    file_name: String,
    content_type: String,
    file_info: Option<serde_json::Value>,
    file_retention: Option<FileRetentionPolicy>,
    legal_hold: Option<LegalHoldValue>,
    server_side_encryption: Option<ServerSideEncryption>,
}

impl StartLargeFile {
    fn builder() -> StartLargeFileBuilder {
        StartLargeFileBuilder::default()
    }
}

/// A builder for a [StartLargeFile] request.
#[derive(Debug, Default)]
pub struct StartLargeFileBuilder {
    bucket_id: Option<String>,
    file_name: Option<String>,
    content_type: Option<String>,
    file_info: Option<serde_json::Value>,
    file_retention: Option<FileRetentionPolicy>,
    legal_hold: Option<LegalHoldValue>,
    server_side_encryption: Option<ServerSideEncryption>,
}

// TODO: Many questions and TODOs also apply to other file creation objects
// (e.g., CopyFileBuilder).
impl StartLargeFileBuilder {
    /// Specify the bucket in which to store the new file.
    pub fn bucket_id(mut self, id: impl Into<String>) -> Self {
        self.bucket_id = Some(id.into());
        self
    }

    /// Set the file's name.
    pub fn file_name(mut self, name: impl Into<String>)
    -> Result<Self, ValidationError> {
        self.file_name = Some(validated_file_name(name)?);
        Ok(self)
    }

    /// Set the file's MIME type.
    ///
    /// If not specified, B2 will attempt to determine the file's type.
    pub fn content_type(mut self, mime: impl Into<String>) -> Self {
        // TODO: B2 has a map of auto-detected MIME types:
        // https://www.backblaze.com/b2/docs/content-types.html
        // How do we want to deal with that?
        self.content_type = Some(mime.into());
        self
    }

    // TODO: document data sharing - B2 uses more than just content-disposition
    // here
    /// Set file metadata.
    pub fn file_info(mut self, info: serde_json::Value)
    -> Result<Self, ValidationError> {
        self.file_info = Some(validated_file_info(info)?);
        Ok(self)
    }

    /// Set the retention policy for the file.
    pub fn file_retention(mut self, policy: FileRetentionPolicy) -> Self {
        self.file_retention = Some(policy);
        self
    }

    /// Enable a legal hold on the file.
    pub fn with_legal_hold(mut self) -> Self {
        self.legal_hold = Some(LegalHoldValue::On);
        self
    }

    /// Disable a legal hold on the file.
    pub fn without_legal_hold(mut self) -> Self {
        self.legal_hold = Some(LegalHoldValue::Off);
        self
    }

    /// Set the server-side encryption configuration for the file.
    pub fn encryption_settings(mut self, settings: ServerSideEncryption) -> Self
    {
        self.server_side_encryption = Some(settings);
        self
    }

    // TODO: sha1, last modified, content-disposition TODO: content-disposition,
    // content-language, expires, cache-control, content-encoding (see fileInfo
    // docs)
    // Store separately and merge into file_info in build()?

    pub fn build(self) -> Result<StartLargeFile, ValidationError> {
        self.validate_size()?;

        let bucket_id = self.bucket_id.ok_or_else(||
            ValidationError::MissingData(
                "The bucket ID in which to store the file must be present"
                    .into()
            )
        )?;

        let file_name = self.file_name.ok_or_else(||
            ValidationError::MissingData(
                "The file name must be specified".into()
            )
        )?;

        let content_type = self.content_type
            .unwrap_or_else(|| "b2/x-auto".into());

        Ok(StartLargeFile {
            bucket_id,
            file_name,
            content_type,
            file_info: self.file_info,
            file_retention: self.file_retention,
            legal_hold: self.legal_hold,
            server_side_encryption: self.server_side_encryption,
        })
    }

    fn validate_size(&self) -> Result<(), ValidationError> {
        let limit = {
            let enc = self.server_side_encryption.as_ref()
                .unwrap_or(&ServerSideEncryption::NoEncryption);

            if matches!(enc, ServerSideEncryption::NoEncryption) {
                7000
            } else {
                2048
            }
        };

        // Only the keys and values count against the max limit, so we need to
        // add them up rather than convert the entire Value to a string and
        // check its length.
        let info_len = self.file_info.as_ref()
            .map(|v| v.as_object())
            .flatten()
            .map(|obj| obj.iter()
                .fold(0, |acc, (k, v)| acc + k.len() + v.to_string().len())
            )
            .unwrap_or(0);

        let name_len = self.file_name
            .as_ref()
            .map(|v| v.to_string().len())
            .unwrap_or(0);

        if info_len + name_len <= limit {
            Ok(())
        } else {
            Err(ValidationError::OutOfBounds(format!(
                "file_name and file_info lengths must not exceed {} bytes",
                limit
            )))
        }
    }
}

/// Prepare to upload a large file in multiple parts.
///
/// After calling `start_large_file`, each thread uploading a file part should
/// call [get_upload_part_url] to obtain the upload URL for that part. Then call
/// [upload_part] to upload the relevant file part.
///
/// File parts can be copied from a bucket via [copy_part].
///
/// A large file size can be 100 MB to 10 TB (inclusive). See
/// <https://www.backblaze.com/b2/docs/large_files.html> for more information on
/// working with large files.
///
/// There must be at least two parts to a large file, with each part between 5
/// MB to 5 GB inclusive; the final part can be less than 5 MB but must contain
/// at least one byte.
///
/// See <https://www.backblaze.com/b2/docs/b2_start_large_file.html> for the B2
/// documentation on starting large file uploads.
///
/// The [Authorization] must have [Capability::WriteFiles].
pub async fn start_large_file<C, E>(
    auth: &mut Authorization<C>,
    file: StartLargeFile
) -> Result<File, Error<E>>
    where C: HttpClient<Response=serde_json::Value, Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::WriteFiles);
    if file.file_retention.is_some() {
        require_capability!(auth, Capability::WriteFileRetentions);
    }
    if file.legal_hold.is_some() {
        require_capability!(auth, Capability::WriteFileLegalHolds);
    }
    if file.server_side_encryption.is_some() {
        require_capability!(auth, Capability::WriteBucketEncryption);
    }

    let res = auth.client.post(auth.api_url("b2_start_large_file"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token)
        .with_body(serde_json::to_value(file)?)
        .send().await?;

    let file: B2Result<File> = serde_json::from_value(res)?;
    file.into()
}

#[cfg(all(test, feature = "with_surf"))]
mod tests_mocked {
    use super::*;
    use crate::{
        account::Capability,
        error::ErrorCode,
        test_utils::{create_test_auth, create_test_client},
    };
    use surf_vcr::VcrMode;


    #[async_std::test]
    async fn start_large_file_upload_success() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/large_file.yaml"
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteFiles])
            .await;

        let req = StartLargeFile::builder()
            .bucket_id("8d625eb63be2775577c70e1a")
            .file_name("test-large-file")?
            .build()?;

        let file = start_large_file(&mut auth, req).await?;
        assert_eq!(file.file_name(), "test-large-file");
        assert_eq!(file.action(), FileAction::Start);

        Ok(())
    }

    #[async_std::test]
    async fn cancel_large_file_upload_success() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/large_file.yaml"
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteFiles])
            .await;

        let file_info = cancel_large_file_by_id(
            &mut auth,
            concat!(
                "4_z8d625eb63be2775577c70e1a_f204261ca2ea2c4e1_d20211112",
                "_m211109_c002_v0001114_t0054"
            )
        ).await?;

        assert_eq!(file_info.file_name, "test-large-file");

        Ok(())
    }

    #[async_std::test]
    async fn cancel_large_file_upload_doesnt_exist() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/large_file.yaml"
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteFiles])
            .await;

        match cancel_large_file_by_id(&mut auth, "bad-id").await.unwrap_err() {
            Error::B2(e) => assert_eq!(e.code(), ErrorCode::BadRequest),
            _ => panic!("Unexpected error type"),
        }

        Ok(())
    }

    #[async_std::test]
    async fn copy_file_success() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/large_file.yaml"
        ).await?;

        let mut auth = create_test_auth(
            client,
            vec![Capability::WriteFiles, Capability::ReadFiles]
        ).await;

        let file = CopyFile::builder()
            .source_file_id(concat!(
                "4_z8d625eb63be2775577c70e1a_f111954e3108ff3f6_d20211118_",
                "m151810_c002_v0001168_t0010"
            ))
            .destination_file_name("new-file.txt")?
            .build()?;

        let new_file = copy_file(&mut auth, file).await?;
        assert_eq!(new_file.file_name, "new-file.txt");
        assert_eq!(new_file.action, FileAction::Copy);

        Ok(())
    }

    // TODO: test copy_file with a byte range.
}

#[cfg(test)]
mod tests {
    use super::*;


    #[async_std::test]
    async fn copy_file_bad_req_content_type() -> anyhow::Result<()> {
        let file = CopyFile::builder()
            .source_file_id(concat!(
                "4_z8d625eb63be2775577c70e1a_f111954e3108ff3f6_d20211118_",
                "m151810_c002_v0001168_t0010"
            ))
            .destination_file_name("new-file.txt")?
            .content_type("text/plain");

        match file.build().unwrap_err() {
            ValidationError::Incompatible(_) => {},
            e => panic!("Unexpected error type: {}", e),
        }

        Ok(())
    }
}
