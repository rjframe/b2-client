/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

//! Backblaze B2 API calls for working with files.
//!
//! See [the B2 documentation on uploading
//! files](https://www.backblaze.com/b2/docs/uploading.html) for an overview of
//! the process.
//!
//!
//! # Uploading Files
//!
//! For files larger than 5 GB, see [Uploading Large
//! Files](#uploading-large-files).
//!
//! To upload a file:
//!
//! 1. Authenticate with B2 to obtain an [Authorization] object.
//! 2. Create an [UploadFile] request.
//! 3. Call [get_upload_authorization] to get an [UploadAuthorization] for a
//!    bucket.
//! 4. Call [upload_file] with your `UploadAuthorization`, `UploadFile` request,
//!    and file data.
//!
//! You can upload multiple files with a single `UploadAuthorization`, but only
//! one at a time. To upload multiple files in parallel, each thread or task
//! needs to obtain its own `UploadAuthorization`.
//!
//!
//! # Uploading Large Files
//!
//! To upload a large file:
//!
//! 1. Authenticate with B2 to obtain an [Authorization] object.
//! 2. Create a [StartLargeFile] object with the destination bucket and new
//!    file's information, then pass it to [start_large_file]. You will receive
//!    a [File] object.
//! 3. Pass the [File] to [get_upload_part_authorization] to receive an
//!    [UploadPartAuthorization].
//!     * You can upload parts in separate threads for better performance; each
//!       thread must call [get_upload_part_authorization] and use its
//!       respective authorization when uploading data.
//! 4. Create an [UploadFilePart] object via the [UploadFilePartBuilder].
//! 5. Use the `UploadPartAuthorization` and `UploadFilePart` to call
//!    [upload_file_part] with the file data to upload.
//! 6. Call [UploadFilePart::create_next_part] to create a new upload part
//!    request.
//! 7. Repeat steps 5 and 6 until all parts have been uploaded.
//! 8. Call [finish_large_file_upload] to merge the file parts into a single
//!    [File]. After finishing the file, it can be treated like any other
//!    uploaded file.
//!
//! # Examples
//!
//! ```no_run
//! # fn calculate_sha1(data: &[u8]) -> String { String::default() }
//! use std::env;
//! use anyhow;
//! use b2_client::{self as b2, HttpClient as _};
//!
//! # #[cfg(feature = "with_surf")]
//! async fn upload_file(name: &str, bucket: b2::Bucket, data: &[u8])
//! -> anyhow::Result<b2::File> {
//!     let key = env::var("B2_KEY").ok().unwrap();
//!     let key_id = env::var("B2_KEY_ID").ok().unwrap();
//!
//!     let client = b2::client::SurfClient::default();
//!     let mut auth = b2::authorize_account(client, &key, &key_id).await?;
//!
//!     let mut upload_auth = b2::get_upload_authorization(&mut auth, &bucket)
//!         .await?;
//!
//!     let checksum = calculate_sha1(&data);
//!
//!     let file = b2::UploadFile::builder()
//!         .file_name(name)?
//!         .sha1_checksum(&checksum)
//!         .build()?;
//!
//!     Ok(b2::upload_file(&mut upload_auth, file, &data).await?)
//! }
//! ```
//!
//! ```no_run
//! # fn calculate_sha1(data: &[u8]) -> String { String::default() }
//! use std::env;
//! use anyhow;
//! use b2_client::{self as b2, HttpClient as _};
//!
//! # #[cfg(feature = "with_surf")]
//! async fn upload_large_file(
//!     name: &str,
//!     data_part1: &[u8],
//!     data_part2: &[u8],
//! ) -> anyhow::Result<b2::File> {
//!     let key = env::var("B2_KEY").ok().unwrap();
//!     let key_id = env::var("B2_KEY_ID").ok().unwrap();
//!
//!     let client = b2::client::SurfClient::default();
//!     let mut auth = b2::authorize_account(client, &key, &key_id).await?;
//!
//!     let file = b2::StartLargeFile::builder()
//!         .bucket_id("some-bucket-id")
//!         .file_name(name)?
//!         .content_type("text/plain")
//!         .build()?;
//!
//!     let file = b2::start_large_file(&mut auth, file).await?;
//!
//!     let mut upload_auth = b2::get_upload_part_authorization(
//!         &mut auth,
//!         &file
//!     ).await?;
//!
//!     // Assuming a `calculate_sha1` function is defined:
//!     let sha1 = calculate_sha1(&data_part1);
//!     let sha2 = calculate_sha1(&data_part2);
//!
//!     let upload_req = b2::UploadFilePart::builder()
//!         .part_sha1_checksum(&sha1)
//!         .build();
//!
//!     let _part1 = b2::upload_file_part(
//!         &mut upload_auth,
//!         &upload_req,
//!         &data_part1,
//!     ).await?;
//!
//!     let upload_req = upload_req.create_next_part(Some(&sha2))?;
//!
//!     let _part2 = b2::upload_file_part(
//!         &mut upload_auth,
//!         &upload_req,
//!         &data_part2,
//!     ).await?;
//!
//!     Ok(b2::finish_large_file_upload(
//!         &mut auth,
//!         &file,
//!         &[sha1, sha2],
//!     ).await?)
//! }
//! ```

use std::fmt;

use crate::{
    prelude::*,
    account::Capability,
    bucket::{
        Bucket,
        FileRetentionMode,
        FileRetentionPolicy,
        ServerSideEncryption,
    },
    client::{HeaderMap, HttpClient},
    error::*,
    types::ContentDisposition,
    validate::{
        validate_content_disposition,
        validate_file_metadata_size,
        validated_file_info,
        validated_file_name,
    },
};

pub use http_types::{
    cache::{CacheControl, Expires},
    content::ContentEncoding,
    mime::Mime,
};

use serde::{Serialize, Deserialize};


// Add a standard header to a serde_json::Map.
macro_rules! add_file_info {
    ($map:ident, $name:literal, $value:expr) => {
        if let Some(v) = $value {
            $map.insert($name.into(), serde_json::Value::from(v));
        }
    };
}

macro_rules! percent_encode {
    ($str:expr) => {
        percent_encoding::utf8_percent_encode(
            &$str,
            &crate::types::QUERY_ENCODE_SET
        ).to_string()
    };
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LegalHoldValue {
    On,
    Off,
}

impl fmt::Display for LegalHoldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::On => write!(f, "on"),
            Self::Off => write!(f, "off"),
        }
    }
}

/// Determines whether there is a legal hold on a file.
#[derive(Debug, Deserialize)]
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

// TODO: I may want to rename this to FileRetention since it's one of
// update_file_retention's parameters.
// This is different than but very similar to bucket::FileRetentionPolicy.
/// Sets the file retention mode and date/time during which the retention rule
/// applies.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct FileRetentionSetting {
    mode: Option<FileRetentionMode>,
    #[serde(rename = "retainUntilTimestamp")]
    retain_until: Option<i64>,
}

impl FileRetentionSetting {
    pub fn new(
        mode: FileRetentionMode,
        retain_until: chrono::DateTime<chrono::Utc>
    ) -> Result<Self, BadData<chrono::DateTime<chrono::Utc>>> {
        if retain_until > chrono::Utc::now() {
            Ok(Self {
                mode: Some(mode),
                retain_until: Some(retain_until.timestamp_millis()),
            })
        } else {
            Err(BadData {
                value: retain_until,
                msg: "retain_until must be in the future".into(),
            })
        }
    }
}

// This is different than but very similar to bucket::FileLockConfiguration.
/// The retention settings for a file.
#[derive(Debug, Deserialize)]
pub struct FileRetention {
    #[serde(rename = "isClientAuthorizedToRead")]
    can_read: bool,
    value: Option<FileRetentionSetting>,
}

impl FileRetention {
    /// Get the file retention settings.
    ///
    /// If not authorized to read the settings, returns `None`.
    pub fn settings(&self) -> Option<FileRetentionSetting> {
        if self.can_read {
            self.value
        } else {
            None
        }
    }
}

// TODO: Rename to FileMetadata?
/// Metadata of a file stored in B2.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct File {
    account_id: Option<String>,
    action: FileAction,
    bucket_id: String,
    // Only relevant when action is "upload", will be 0 otherwise.
    content_length: u64,
    // Value is "none" for large files.
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
    // If action is `Folder`, this will be 0.
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
    /// or [FileAction::Copy]; otherwise the value is `None`.
    pub fn content_length(&self) -> Option<u64> {
        match self.action {
            FileAction::Upload | FileAction::Copy => Some(self.content_length),
            _ => None,
        }
    }

    /// The SHA-1 checksum of the bytes in the file.
    ///
    /// There is no checksum for large files or when the [action](Self::action)
    /// is [FileAction::Hide] or [FileAction::Folder].
    pub fn sha1_checksum(&self) -> Option<&String> {
        match &self.content_sha1 {
            Some(v) => if v == "none" { None } else { Some(v) }
            None => None,
        }
    }

    /// The MD5 checksum of the bytes in the file.
    ///
    /// There is no checksum for large files or when the [action](Self::action)
    /// is [FileAction::Hide] or [FileAction::Folder].
    pub fn md5_checksum(&self) -> Option<&String> {
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
    ///
    /// If the [action](Self::action) is `Folder`, returns `None`.
    pub fn upload_time(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        use chrono::{TimeZone as _, Utc};

        match self.action {
            FileAction::Folder => None,
            _ => Some(Utc.timestamp_millis(self.upload_timestamp)),
        }
    }
}

/// A part of a large file currently being uploaded.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilePart {
    file_id: String,
    part_number: u16,
    content_length: u64,
    content_sha1: String,
    content_md5: Option<String>,
    server_side_encryption: Option<ServerSideEncryption>,
    upload_timestamp: i64,
}

impl FilePart {
    pub fn file_id(&self) -> &str { &self.file_id }
    pub fn part_number(&self) -> u16 { self.part_number }
    pub fn content_length(&self) -> u64 { self.content_length }
    pub fn sha1_checksum(&self) -> &str { &self.content_sha1 }
    pub fn md5_checksum(&self) -> Option<&String> { self.content_md5.as_ref() }

    pub fn encryption_settings(&self) -> Option<&ServerSideEncryption> {
        self.server_side_encryption.as_ref()
    }

    pub fn upload_timestamp(&self) -> chrono::DateTime<chrono::Utc> {
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedFile {
    pub file_id: String,
    pub file_name: String,
}

/// Cancel the uploading of a large file and delete any parts already uploaded.
pub async fn cancel_large_file<C, E>(auth: &mut Authorization<C>, file: File)
-> Result<CancelledFileUpload, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    cancel_large_file_by_id(auth, file.file_id).await
}

/// Cancel the uploading of a large file and delete any parts already uploaded.
///
/// See [cancel_large_file] for documentation on use.
pub async fn cancel_large_file_by_id<C, E>(
    auth: &mut Authorization<C>,
    id: impl AsRef<str>
) -> Result<CancelledFileUpload, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::WriteFiles);

    let res = auth.client.post(auth.api_url("b2_cancel_large_file"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::json!({ "fileId": id.as_ref() }))
        .send().await?;

    let info: B2Result<CancelledFileUpload> = serde_json::from_slice(&res)?;
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

impl fmt::Display for ByteRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bytes={}-{}", self.start, self.end)
    }
}

impl ByteRange {
    // TODO: It would be reasonable to misremember/assume that the range is
    // exclusive of the end byte; should we use `new_inclusive` and
    // `new_exclusive` (bounded/unbounded?) functions instead? This forces
    // explicitly choosing one or the other. Name them `new_end_xxx` to be truly
    // clear?
    pub fn new(start: u64, end: u64) -> Result<Self, ValidationError> {
        if start <= end {
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

/// Describe the action to take with file metadata when copying a file.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum MetadataDirective {
    Copy,
    Replace,
}

/// A request to copy a file from a bucket, potentially to a different bucket.
///
/// Use [CopyFileBuilder] to create a `CopyFile`, then pass it to [copy_file].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyFile<'a> {
    source_file_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_bucket_id: Option<String>,
    file_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    range: Option<ByteRange>,
    metadata_directive: MetadataDirective,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_info: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_retention: Option<FileRetentionPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    legal_hold: Option<LegalHoldValue>,
    #[serde(rename = "sourceServerSideEncryption")]
    #[serde(skip_serializing_if = "Option::is_none")]
    source_encryption: Option<ServerSideEncryption>,
    #[serde(rename = "destinationServerSideEncryption")]
    #[serde(skip_serializing_if = "Option::is_none")]
    dest_encryption: Option<ServerSideEncryption>,
}

impl<'a> CopyFile<'a> {
    pub fn builder() -> CopyFileBuilder<'a> {
        CopyFileBuilder::default()
    }
}

/// A builder to create a [CopyFile] request.
///
/// See <https://www.backblaze.com/b2/docs/b2_copy_file.html> for further
/// information.
#[derive(Default)]
pub struct CopyFileBuilder<'a> {
    source_file_id: Option<String>,
    destination_bucket_id: Option<String>,
    file_name: Option<&'a str>,
    range: Option<ByteRange>,
    metadata_directive: Option<MetadataDirective>,
    content_type: Option<String>,
    file_info: Option<serde_json::Value>,
    file_retention: Option<FileRetentionPolicy>,
    legal_hold: Option<LegalHoldValue>,
    source_encryption: Option<ServerSideEncryption>,
    dest_encryption: Option<ServerSideEncryption>,

    // To merge into file_info on build if metadata_directive is Replace:
    last_modified: Option<i64>,
    sha1_checksum: Option<&'a str>,
    content_disposition: Option<String>,
    content_language: Option<String>,
    expires: Option<String>,
    cache_control: Option<String>,
    content_encoding: Option<String>,
}

impl<'a> CopyFileBuilder<'a> {
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
    pub fn destination_file_name(mut self, name: &'a str)
    -> Result<Self, FileNameValidationError> {
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
    ///
    /// For the following headers, use their corresponding methods instead of
    /// setting the values here:
    ///
    /// * X-Bz-Info-src_last_modified_millis:
    ///   [last_modified](Self::last_modified)
    /// * X-Bz-Info-large_file_sha1: [sha1_checksum](Self::sha1_checksum)
    /// * Content-Disposition: [content_disposition](Self::content_disposition)
    /// * Content-Language: [content_language](Self::content_language)
    /// * Expires: [expiration](Self::expiration)
    /// * Cache-Control: [cache_control](Self::cache_control)
    /// * Content-Encoding: [content_encoding](Self::content_encoding)
    ///
    /// If any of the above are set here and via their methods, the value from
    /// the method will override the value specified here.
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

    /// The time of the file's last modification.
    pub fn last_modified(mut self, time: chrono::DateTime<chrono::Utc>) -> Self
    {
        self.last_modified = Some(time.timestamp_millis());
        self
    }

    /// The SHA1 checksum of the file's contents.
    ///
    /// B2 will use this to verify the accuracy of the file upload, and it will
    /// be returned in the header `X-Bz-Content-Sha1` when downloading the file.
    pub fn sha1_checksum(mut self, checksum: &'a str) -> Self {
        self.sha1_checksum = Some(checksum);
        self
    }

    /// The value to use for the `Content-Disposition` header when downloading
    /// the file.
    ///
    /// Note that the download request can override this value.
    pub fn content_disposition(mut self, disposition: ContentDisposition)
    -> Result<Self, ValidationError> {
        validate_content_disposition(&disposition.0, false)?;

        self.content_disposition = Some(percent_encode!(disposition.0));
        Ok(self)
    }

    /// The value to use for the `Content-Language` header when downloading the
    /// file.
    ///
    /// Note that the download request can override this value.
    pub fn content_language(mut self, language: impl Into<String>) -> Self {
        // TODO: validate content_language
        self.content_language = Some(percent_encode!(language.into()));
        self
    }

    /// The value to use for the `Expires` header when the file is downloaded.
    ///
    /// Note that the download request can override this value.
    pub fn expiration(mut self, expiration: Expires) -> Self {
        let expires = percent_encode!(expiration.value().to_string());

        self.expires = Some(expires);
        self
    }

    /// The value to use for the `Cache-Control` header when the file is
    /// downloaded.
    ///
    /// This would override the value set at the bucket level, and can be
    /// overriden by a download request.
    pub fn cache_control(mut self, cache_control: CacheControl) -> Self {
        self.cache_control = Some(cache_control.value().to_string());
        self
    }

    /// The value to use for the `Content-Encoding` header when the file is
    /// downloaded.
    ///
    /// Note that this can be overriden by a download request.
    pub fn content_encoding(mut self, encoding: ContentEncoding) -> Self {
        let encoding = percent_encode!(format!("{}", encoding.encoding()));
        self.content_encoding = Some(encoding);
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
    pub fn build(self) -> Result<CopyFile<'a>, ValidationError> {
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

        let file_info = if let Some(mut file_info) = self.file_info {
            let info_map = file_info.as_object_mut()
                .expect("file_info is not a JSON object");

            add_file_info!(info_map, "src_last_modified_millis",
                self.last_modified.map(|v| v.to_string()));
            add_file_info!(info_map, "large_file_sha1", self.sha1_checksum);
            add_file_info!(info_map, "b2-content-disposition",
                self.content_disposition);
            add_file_info!(info_map, "b2-content-language",
                self.content_language);
            add_file_info!(info_map, "b2-expires", self.expires);
            add_file_info!(info_map, "b2-content-encoding",
                self.content_encoding);

            Some(file_info)
        } else {
            None
        };

        validate_file_metadata_size(
            file_name,
            file_info.as_ref(),
            self.dest_encryption.as_ref()
        )?;

        Ok(CopyFile {
            source_file_id,
            destination_bucket_id: self.destination_bucket_id,
            file_name,
            range: self.range,
            metadata_directive,
            content_type: self.content_type,
            file_info,
            file_retention: self.file_retention,
            legal_hold: self.legal_hold,
            source_encryption: self.source_encryption,
            dest_encryption: self.dest_encryption,
        })
    }
}

/// Copy an existing file to a new file, possibly on a different bucket.
///
/// The new file must be less than 5 GB. Use [copy_file_part] to copy larger
/// files.
///
/// If copying from one bucket to another, both buckets must belong to the same
/// account.
pub async fn copy_file<'a, C, E>(
    auth: &mut Authorization<C>,
    file: CopyFile<'_>
) -> Result<File, Error<E>>
    where C: HttpClient<Error=Error<E>>,
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
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::to_value(file)?)
        .send().await?;

    let file: B2Result<File> = serde_json::from_slice(&res)?;
    file.into()
}

/// A request to copy from an existing file to a part of a large file.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyFilePart<'a> {
    source_file_id: &'a str,
    large_file_id: &'a str,
    part_number: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    range: Option<ByteRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_server_side_encryption: Option<&'a ServerSideEncryption>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_server_side_encryption: Option<&'a ServerSideEncryption>,
}

impl<'a> CopyFilePart<'a> {
    pub fn builder() -> CopyFilePartBuilder<'a> {
        CopyFilePartBuilder::default()
    }
}

/// A builder to create a [CopyFilePart] request.
#[derive(Default)]
pub struct CopyFilePartBuilder<'a> {
    source_file: Option<&'a str>,
    large_file: Option<&'a str>,
    part_number: Option<u16>,
    range: Option<ByteRange>,
    source_encryption: Option<&'a ServerSideEncryption>,
    dest_encryption: Option<&'a ServerSideEncryption>,
}

impl<'a> CopyFilePartBuilder<'a> {
    /// Set the source file to copy from and its encryption settings.
    pub fn source_file(mut self, file: &'a File) -> Self {
        self.source_file = Some(&file.file_id);
        self.source_encryption = file.server_side_encryption.as_ref();
        self
    }

    /// Set the source file to copy from.
    pub fn source_file_id(mut self, file: &'a str) -> Self {
        self.source_file = Some(file);
        self
    }

    /// Set the large file to copy data to and its encryption settings.
    pub fn destination_large_file(mut self, file: &'a File) -> Self {
        self.large_file = Some(&file.file_id);

        if let Some(enc) = self.dest_encryption {
            if ! matches!(enc, ServerSideEncryption::NoEncryption) {
                self.dest_encryption = Some(enc);
            }
        }

        self
    }

    /// Set  the large file to copy data to.
    pub fn destination_large_file_id(mut self, file: &'a str) -> Self {
        self.large_file = Some(file);
        self
    }

    /// Set the number of this part.
    ///
    /// Part numbers increment from 1 to 10,000 inclusive.
    pub fn part_number(mut self, part_num: u16) -> Result<Self, ValidationError>
    {
        #[allow(clippy::manual_range_contains)]
        if part_num < 1 || part_num > 10000 {
            return Err(ValidationError::OutOfBounds(format!(
                "part_num must be between 1 and 10,000 inclusive. Was {}",
                part_num
            )));
        }

        self.part_number = Some(part_num);
        Ok(self)
    }

    /// Set the range of bytes from the source file to copy.
    ///
    /// If no range is specified, the entire file is copied.
    pub fn range(mut self, range: ByteRange) -> Self {
        self.range = Some(range);
        self
    }

    /// Set the encryption settings of the source file.
    ///
    /// This must match the settings with which the file was encrypted.
    pub fn source_encryption_settings(mut self, enc: &'a ServerSideEncryption)
    -> Self {
        self.source_encryption = Some(enc);
        self
    }

    /// Set the encryption settings of the destination file.
    ///
    /// This must match the settings passed to [start_large_file].
    pub fn destination_encryption_settings(
        mut self,
        enc: &'a ServerSideEncryption
    ) -> Self {
        self.dest_encryption = Some(enc);
        self
    }

    /// Create a [CopyFilePart] request object.
    pub fn build(self) -> Result<CopyFilePart<'a>, ValidationError> {
        let source_file_id = self.source_file.ok_or_else(||
            ValidationError::MissingData("source_file is required".into())
        )?;

        let large_file_id = self.large_file.ok_or_else(||
            ValidationError::MissingData(
                "destination_large_file is required".into()
            )
        )?;

        let part_number = self.part_number.ok_or_else(||
            ValidationError::MissingData("part_number is required".into())
        )?;

        Ok(CopyFilePart {
            source_file_id,
            large_file_id,
            part_number,
            range: self.range,
            source_server_side_encryption: self.source_encryption,
            destination_server_side_encryption: self.dest_encryption,
        })
    }
}

/// Copy from an existing file to a new large file.
///
/// The [Authorization] must have [Capability::WriteFiles], and if the bucket is
/// private, [Capability::ReadFiles].
pub async fn copy_file_part<C, E>(
    auth: &mut Authorization<C>,
    file_part: CopyFilePart<'_>
) -> Result<FilePart, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::WriteFiles);

    let res = auth.client.post(auth.api_url("b2_copy_part"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::to_value(file_part)?)
        .send().await?;

    let part: B2Result<FilePart> = serde_json::from_slice(&res)?;
    part.into()
}

/// Declare whether to bypass file lock restrictions when performing an action
/// on a [File].
///
/// Bypassing governance rules requires [Capability::BypassGovernance].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BypassGovernance { Yes, No }

/// Delete a version of a file.
///
/// If the version is the file's latest version and there are older versions,
/// the most-recent older version will become the current version of the file.
///
/// If called on an unfinished large file, has the same effect as
/// [cancel_large_file].
pub async fn delete_file_version<C, E>(
    auth: &mut Authorization<C>,
    file: File,
    bypass_governance: BypassGovernance,
) -> Result<DeletedFile, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    delete_file_version_by_name_id(
        auth,
        &file.file_name,
        &file.file_id,
        bypass_governance
    ).await
}

/// Retrieve the headers that will be returned when the specified file is
/// downloaded.
///
/// See <https://www.backblaze.com/b2/docs/b2_download_file_by_id.html> for a
/// list of headers that may be returned.
pub async fn download_file_headers<C, E>(
    auth: &mut Authorization<C>,
    file: &File
) -> Result<HeaderMap, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    download_file_headers_by_id(auth, &file.file_id).await
}

/// Retrieve the headers that will be returned when the specified file is
/// downloaded.
///
/// See <https://www.backblaze.com/b2/docs/b2_download_file_by_id.html> for a
/// list of headers that may be returned.
pub async fn download_file_headers_by_id<C, E>(
    auth: &mut Authorization<C>,
    file_id: impl AsRef<str>
) -> Result<HeaderMap, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    // TODO: This is probably only required for private buckets; public buckets
    // don't require an authorization token, but the docs read as if this is
    // necessary if provided. Need to test, and if necessary allow downloading
    // the file without passing the authorization token.
    require_capability!(auth, Capability::ReadFiles);

    let res = auth.client.head(
            format!("{}?fileId={}",
                auth.download_url("b2_download_file_by_id"),
                file_id.as_ref()
            )
        )
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .send_keep_headers().await?;

    Ok(res.1)
}

#[derive(Debug)]
enum FileHandle<'a> {
    Id(&'a str),
    Name((String, &'a str)), // (Percent-encoded file name, bucket name)
}

/// A request to download a file or a portion of a file from the B2 API.
///
/// A simple file request can be created via [with_name](Self::with_name) or
/// [with_id](Self::with_id); for more complex requests use a
/// [DownloadFileBuilder].
///
/// If you use self-managed server-side encryption, you must use
/// [DownloadFileBuilder] to pass the encryption information.
///
/// See <https://www.backblaze.com/b2/docs/b2_download_file_by_id.html> for
/// information on downloading files, including the list of headers that may be
/// returned.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadFile<'a> {
    #[serde(skip_serializing)]
    file: FileHandle<'a>,
    #[serde(skip_serializing)]
    range: Option<ByteRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b2_content_disposition: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b2_content_language: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b2_expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b2_cache_control: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b2_content_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b2_content_type: Option<String>,
    #[serde(skip_serializing)]
    encryption: Option<ServerSideEncryption>,
}

impl<'a> DownloadFile<'a> {
    /// Download a file with the specified file ID.
    pub fn with_id(id: &'a str) -> Self {
        Self {
            file: FileHandle::Id(id),
            range: None,
            b2_content_disposition: None,
            b2_content_language: None,
            b2_expires: None,
            b2_cache_control: None,
            b2_content_encoding: None,
            b2_content_type: None,
            encryption: None,
        }
    }

    /// Download a file with the specified file name.
    ///
    /// The name will be percent-encoded.
    pub fn with_name(name: &str, bucket: &'a str) -> Self {
        Self {
            file: FileHandle::Name((percent_encode!(name), bucket)),
            range: None,
            b2_content_disposition: None,
            b2_content_language: None,
            b2_expires: None,
            b2_cache_control: None,
            b2_content_encoding: None,
            b2_content_type: None,
            encryption: None,
        }
    }

    pub fn builder() -> DownloadFileBuilder<'a> {
        DownloadFileBuilder::default()
    }

    /// Generate the public URL for a GET request for a file in a public bucket.
    ///
    /// A file in a public bucket does not require an authorization token to
    /// access, making this link suitable for distribution (e.g., embedding in a
    /// web page).
    ///
    /// You must provide an [Authorization] or [DownloadAuthorization] that has
    /// access to the file.
    pub fn public_url<'b, C, D, E>(&self, auth: D) -> String
        where C: HttpClient<Error=Error<E>> + 'b,
              D: Into<&'b DownloadAuth<'b, C>>,
              E: fmt::Debug + fmt::Display,
    {
        let auth = auth.into();

        match &self.file {
            FileHandle::Id(id) => format!(
                "{}?fileId={}",
                auth.download_url("b2_download_file_by_id"),
                id
            ),
            FileHandle::Name((name, bucket)) => format!(
                "{}/file/{}/{}?",
                auth.download_get_url(),
                bucket,
                name
            ),
        }
    }
}

#[derive(Default)]
pub struct DownloadFileBuilder<'a> {
    file: Option<FileHandle<'a>>,
    range: Option<ByteRange>,
    content_disposition: Option<&'a str>,
    content_language: Option<&'a str>,
    expires: Option<String>,
    cache_control: Option<String>,
    content_encoding: Option<String>,
    content_type: Option<String>,
    encryption: Option<ServerSideEncryption>,
}

impl<'a> DownloadFileBuilder<'a> {
    /// Download a file with the specified file name.
    ///
    /// The name will be percent-encoded.
    ///
    /// If both [file_name](Self::file_name) and [file_id](Self::file_id) are
    /// provided, the last one will be used.
    pub fn file_name(mut self, name: &str, bucket: &'a str) -> Self {
        self.file = Some(FileHandle::Name((percent_encode!(name), bucket)));
        self
    }

    /// Download a file with the specified file ID.
    ///
    /// If both [file_name](Self::file_name) and [file_id](Self::file_id) are
    /// provided, the last one will be used.
    pub fn file_id(mut self, id: &'a str) -> Self {
        self.file = Some(FileHandle::Id(id));
        self
    }

    /// Specify the byte range of the file to download.
    ///
    /// There will be a Content-Range header that specifies the bytes returned
    /// and the total number of bytes.
    ///
    /// The HTTP status code when a partial file is returned is `206 Partial
    /// Content` rather than `200 OK`.
    pub fn range(mut self, range: ByteRange) -> Self {
        self.range = Some(range);
        self
    }

    /// Override the Content-Disposition header of the response with the one
    /// provided.
    ///
    /// If including this header will exceed the 7,000 byte header limit (2,048
    /// bytes if using server-side encryption), the request will be rejected.
    pub fn content_disposition(mut self, disposition: &'a ContentDisposition)
    -> Result<Self, ValidationError> {
        validate_content_disposition(&disposition.0, false)?;
        self.content_disposition = Some(&disposition.0);
        Ok(self)
    }

    /// Override the Content-Language header of the response with the one
    /// provided.
    ///
    /// If including this header will exceed the 7,000 byte header limit (2,048
    /// bytes if using server-side encryption), the request will be rejected.
    pub fn content_language(mut self, language: &'a str) -> Self {
        // TODO: validate content_language
        self.content_language = Some(language);
        self
    }

    /// Override the Expires header of the response with the one provided.
    ///
    /// If including this header will exceed the 7,000 byte header limit (2,048
    /// bytes if using server-side encryption), the request will be rejected.
    pub fn expiration(mut self, expiration: Expires) -> Self {
        self.expires = Some(expiration.value().to_string());
        self
    }

    /// Override the Cache-Control header of the response with the one provided.
    ///
    /// If including this header will exceed the 7,000 byte header limit (2,048
    /// bytes if using server-side encryption), the request will be rejected.
    pub fn cache_control(mut self, cache_control: CacheControl) -> Self {
        self.cache_control = Some(cache_control.value().to_string());
        self
    }

    /// Override the Content-Encoding header of the response with the one
    /// provided.
    ///
    /// If including this header will exceed the 7,000 byte header limit (2,048
    /// bytes if using server-side encryption), the request will be rejected.
    pub fn content_encoding(mut self, encoding: ContentEncoding) -> Self {
        self.content_encoding = Some(format!("{}", encoding.encoding()));
        self
    }

    /// Override the Content-Type header of the response with the one provided.
    ///
    /// If including this header will exceed the 7,000 byte header limit (2,048
    /// bytes if using server-side encryption), the request will be rejected.
    pub fn content_type(mut self, content_type: impl Into<Mime>) -> Self {
        self.content_type = Some(content_type.into().to_string());
        self
    }

    /// Set the encryption settings to use for the file.
    ///
    /// This is required if using self-managed server-side encryption.
    pub fn encryption_settings(mut self, settings: ServerSideEncryption)
    -> Self {
        self.encryption = Some(settings);
        self
    }

    /// Build a [DownloadFile] request.
    pub fn build(self) -> Result<DownloadFile<'a>, ValidationError> {
        let file = self.file.ok_or_else(|| ValidationError::MissingData(
            "Must specify the file to download".into()
        ))?;

        Ok(DownloadFile {
            file,
            range: self.range,
            b2_content_disposition: self.content_disposition,
            b2_content_language: self.content_language,
            b2_expires: self.expires,
            b2_cache_control: self.cache_control,
            b2_content_encoding: self.content_encoding,
            b2_content_type: self.content_type,
            encryption: self.encryption,
        })
    }
}

/// Allow downloading files via an `Authorization` or `DownloadAuthorization`.
///
/// You do not need to use this type explicitly.
pub enum DownloadAuth<'a, C>
    where C: HttpClient
{
    Auth(&'a mut Authorization<C>),
    Download(&'a mut DownloadAuthorization<C>),
}

impl<'a, C> DownloadAuth<'a, C>
    where C: HttpClient,
{
    fn download_get_url(&self) -> &str {
        match self {
            Self::Auth(auth) => auth.download_get_url(),
            Self::Download(auth) => &auth.download_url,
        }
    }

    fn download_url(&self, endpoint: impl AsRef<str>) -> String {
        match self {
            Self::Auth(auth) => auth.download_url(endpoint),
            Self::Download(auth) =>
                format!("{}/b2api/v2/{}", auth.download_url, endpoint.as_ref())
        }
    }

    fn authorization_token(&self) -> &str {
        match self {
            Self::Auth(auth) => &auth.authorization_token,
            Self::Download(auth) => &auth.authorization_token,
        }
    }

    fn has_capability(&self, cap: Capability) -> bool {
        match self {
            Self::Auth(auth) => auth.has_capability(cap),
            _ => true,
        }
    }
}

impl<'a, C> From<&'a mut Authorization<C>> for DownloadAuth<'a, C>
    where C: HttpClient,
{
    fn from(auth: &'a mut Authorization<C>) -> Self {
        Self::Auth(auth)
    }
}

impl<'a, C> From<&'a mut DownloadAuthorization<C>> for DownloadAuth<'a, C>
    where C: HttpClient,
{
    fn from(auth: &'a mut DownloadAuthorization<C>) -> Self {
        Self::Download(auth)
    }
}

/// Download a file from the B2 service.
///
/// If downloading a file by name, you may provide a mutable reference to either
/// an [Authorization] or a [DownloadAuthorization].
///
/// Downloading files by ID requires an `Authorization`. If provided with a
/// `DownloadAuthorization`, returns `Error::MissingAuthorization`.
pub async fn download_file<'a, C, E>(
    auth: impl Into<DownloadAuth<'a, C>>,
    file: DownloadFile<'_>
) -> Result<(Vec<u8>, HeaderMap), Error<E>>
    where C: HttpClient<Error=Error<E>> + 'a,
          E: fmt::Debug + fmt::Display,
{
    match file.file {
        FileHandle::Id(_) => {
            match auth.into() {
                DownloadAuth::Auth(auth) => download_file_by_id(auth, file)
                    .await,
                _ => Err(Error::MissingAuthorization),
            }
        },
        FileHandle::Name(_) => download_file_by_name(auth, file).await
    }
}

async fn download_file_by_id<C, E>(
    auth: &mut Authorization<C>,
    file: DownloadFile<'_>
) -> Result<(Vec<u8>, HeaderMap), Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    // TODO: This is probably only required for private buckets; public buckets
    // don't require an authorization token, but the docs read as if this is
    // necessary if provided. Need to test, and if necessary allow downloading
    // the file without passing the authorization token.
    require_capability!(auth, Capability::ReadFiles);

    let file_id = match file.file {
        FileHandle::Id(id) => id,
        FileHandle::Name(_) => panic!("Call download_file_by_name() instead"),
    };

    let mut file_req = serde_json::to_value(&file)?;
    file_req["fileId"] = serde_json::Value::String(file_id.into());

    let mut req = auth.client.post(auth.download_url("b2_download_file_by_id"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(file_req);

    if let Some(range) = file.range {
        req = req.with_header("Range", &range.to_string())?;
    }

    if let Some(ServerSideEncryption::SelfManaged(enc)) = file.encryption {
        req = req
            .with_header(
                "X-Bz-Server-Side-Encryption-Customer-Algorithm",
                &enc.algorithm.to_string()
            )?
            .with_header(
                "X-Bz-Server-Side-Encryption-Customer-Key",
                &enc.key
            )?
            .with_header(
                "X-Bz-Server-Side-Encryption-Customer-Key-Md5",
                &enc.digest
            )?;
    }

    let (body, headers) = req.send_keep_headers().await?;

    // An error from Backblaze would successfully deserialize as Vec<u8>, so we
    // need to check for it specifically.
    let res: Result<B2Error, _> = serde_json::from_slice(&body);
    match res {
        Ok(e) => Err(e.into()),
        Err(_) => Ok((body, headers)),
    }
}

async fn download_file_by_name<'a, C, E>(
    auth: impl Into<DownloadAuth<'a, C>>,
    file: DownloadFile<'_>
) -> Result<(Vec<u8>, HeaderMap), Error<E>>
    where C: HttpClient<Error=Error<E>> + 'a,
          E: fmt::Debug + fmt::Display,
{
    let mut auth = auth.into();

    // TODO: This is probably only required for private buckets; public buckets
    // don't require an authorization token, but the docs read as if this is
    // necessary if provided. Need to test, and if necessary allow downloading
    // the file without passing the authorization token.
    require_capability!(auth, Capability::ReadFiles);
    assert!(matches!(file.file, FileHandle::Name(_)));

    let mut url = file.public_url(&auth).to_owned();

    macro_rules! add_param {
        ($str:ident, $name:literal, $obj:expr) => {
            $str.push_str($name);
            $str.push('=');
            $str.push_str($obj);
            $str.push('&'); // The trailing & will be ignored, so this is fine.
        };
    }

    macro_rules! add_opt_param {
        ($str:ident, $name:literal, $obj:expr) => {
            if let Some(s) = $obj {
                add_param!($str, $name, &s);
            }
        };
    }

    add_opt_param!(url, "b2ContentDisposition", file.b2_content_disposition);
    add_opt_param!(url, "b2ContentLanguage", file.b2_content_language);
    add_opt_param!(url, "b2Expires", file.b2_expires);
    add_opt_param!(url, "b2CacheControl", file.b2_cache_control);
    add_opt_param!(url, "b2ContentEncoding", file.b2_content_encoding);
    add_opt_param!(url, "b2ContentType", file.b2_content_type);

    if let Some(ServerSideEncryption::SelfManaged(enc)) = file.encryption {
        add_param!(url,
            "X-Bz-Server-Side-Encryption-Customer-Algorithm",
            &enc.algorithm.to_string()
        );
        add_param!(url,
            "X-Bz-Server-Side-Encryption-Customer-Key",
            &enc.key
        );
        add_param!(url,
            "X-Bz-Server-Side-Encryption-Customer-Key-Md5",
            &enc.digest
        );
    }

    let auth_token = auth.authorization_token().to_owned();

    let client = match auth {
        DownloadAuth::Auth(ref mut auth) => &mut auth.client,
        DownloadAuth::Download(ref mut auth) => &mut auth.client,
    };

    let mut req = client.get(url)
        .expect("Invalid URL")
        .with_header("Authorization", &auth_token).unwrap();

    if let Some(range) = file.range {
        req = req.with_header("Range", &range.to_string())?
    }

    let (body, headers) = req.send_keep_headers().await?;

    // An error from Backblaze would successfully deserialize as Vec<u8>, so we
    // need to check for it specifically.
    let res: Result<B2Error, _> = serde_json::from_slice(&body);
    match res {
        Ok(e) => Err(e.into()),
        Err(_) => Ok((body, headers)),
    }
}

/// Delete a version of a file.
///
/// If the version is the file's latest version and there are older versions,
/// the most-recent older version will become the current version of the file.
///
/// If called on an unfinished large file, has the same effect as
/// [cancel_large_file].
pub async fn delete_file_version_by_name_id<C, E>(
    auth: &mut Authorization<C>,
    file_name: impl AsRef<str>,
    file_id: impl AsRef<str>,
    bypass_governance: BypassGovernance,
) -> Result<DeletedFile, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::DeleteFiles);

    let mut body = serde_json::json!({
        "fileName": &file_name.as_ref(),
        "fileId": &file_id.as_ref(),
    });

    if matches!(bypass_governance, BypassGovernance::Yes) {
        require_capability!(auth, Capability::BypassGovernance);
        body["bypassGovernance"] = serde_json::Value::Bool(true);
    }

    let res = auth.client.post(auth.api_url("b2_delete_file_version"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(body)
        .send().await?;

    let file: B2Result<DeletedFile> = serde_json::from_slice(&res)?;
    file.into()
}

/// Complete the upload of a large file, merging all parts into a single [File].
///
/// This is the final step to uploading a large file. If the request times out,
/// it is recommended to call [get_file_info] to see if the file succeeded and
/// only repeat the call to `finish_large_file_upload` if the file is missing.
///
/// The `sha1_checksums` must be sorted ascending by part number.
///
/// The [Authorization] must have [Capability::WriteFiles].
pub async fn finish_large_file_upload<C, E>(
    auth: &mut Authorization<C>,
    file: &File,
    sha1_checksums: &[String],
) -> Result<File, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    finish_large_file_upload_by_id(auth, &file.file_id, sha1_checksums).await
}

/// Complete the upload of a large file, merging all parts into a single [File].
///
/// See [finish_large_file_upload] for documentation on use.
pub async fn finish_large_file_upload_by_id<C, E>(
    auth: &mut Authorization<C>,
    file_id: impl AsRef<str>,
    sha1_checksums: &[String],
) -> Result<File, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    use serde_json::json;

    require_capability!(auth, Capability::WriteFiles);

    let res = auth.client.post(auth.api_url("b2_finish_large_file"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(json!( {
            "fileId": file_id.as_ref(),
            "partSha1Array": &sha1_checksums,
        }))
        .send().await?;

    let file: B2Result<File> = serde_json::from_slice(&res)?;
    file.into()
}

/// Retrieve metadata about a file stored in B2.
///
/// See <https://www.backblaze.com/b2/docs/b2_get_file_info.html> for further
/// information.
///
/// # Errors
///
/// This function will return an error if the file ID does not exist or it is
/// for a large file that has not been finished yet.
pub async fn get_file_info<C, E>(
    auth: &mut Authorization<C>,
    file_id: impl AsRef<str>
) -> Result<File, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    use serde_json::json;

    require_capability!(auth, Capability::ReadFiles);

    let res = auth.client.post(auth.api_url("b2_get_file_info"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(json!({
            "fileId": file_id.as_ref(),
        }))
        .send().await?;

    let file_info: B2Result<File> = serde_json::from_slice(&res)?;
    match file_info {
        B2Result::Ok(mut info) => {
            if let Some(sha1) = &info.content_sha1 {
                if sha1 == "none" {
                    info.content_sha1 = None;
                }
            }

            Ok(info)
        },
        B2Result::Err(e) => Err(e.into()),
    }
}

/// A request to obtain a [DownloadAuthorization].
///
/// Use [DownloadAuthorizationRequestBuilder] to create a
/// `DownloadAuthorizationRequest`, then pass it to [get_download_authorization]
/// to obtain a [DownloadAuthorization].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadAuthorizationRequest<'a> {
    bucket_id: &'a str,
    file_name_prefix: &'a str,
    valid_duration_in_seconds: Duration,
    #[serde(skip_serializing_if = "Option::is_none")]
    b2_content_disposition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b2_content_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b2_expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b2_cache_control: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b2_content_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b2_content_type: Option<String>,
}

impl<'a> DownloadAuthorizationRequest<'a> {
    pub fn builder() -> DownloadAuthorizationRequestBuilder<'a> {
        DownloadAuthorizationRequestBuilder::default()
    }
}

/// A builder to create a [DownloadAuthorizationRequest].
///
/// After building the `DownloadAuthorizationRequest`, pass it to
/// [get_download_authorization] to obtain a [DownloadAuthorization]
///
/// The bucket ID, file name prefix, and valid duration are required.
///
/// See <https://www.backblaze.com/b2/docs/b2_get_download_authorization.html>
/// for furter information.
#[derive(Default)]
pub struct DownloadAuthorizationRequestBuilder<'a> {
    // Required:
    bucket_id: Option<&'a str>,
    file_name_prefix: Option<&'a str>,
    valid_duration_in_seconds: Option<Duration>,
    // Optional:
    b2_content_disposition: Option<String>,
    b2_content_language: Option<String>,
    b2_expires: Option<String>,
    b2_cache_control: Option<String>,
    b2_content_encoding: Option<String>,
    b2_content_type: Option<String>,
}

impl<'a> DownloadAuthorizationRequestBuilder<'a> {
    /// Create a download authorization for the specified bucket ID.
    pub fn bucket_id(mut self, id: &'a str) -> Self {
        self.bucket_id = Some(id);
        self
    }

    /// Use the given file name prefix to determine what files the
    /// [DownloadAuthorization] will allow access to.
    pub fn file_name_prefix(mut self, name: &'a str)
    -> Result<Self, FileNameValidationError> {

        self.file_name_prefix = Some(validated_file_name(name)?);
        Ok(self)
    }

    /// Specify the amount of time for which the [DownloadAuthorization] will be
    /// valid.
    ///
    /// This must be between one second and one week, inclusive.
    pub fn duration(mut self, dur: chrono::Duration)
    -> Result<Self, ValidationError> {
        if dur < chrono::Duration::seconds(1)
            || dur > chrono::Duration::weeks(1)
        {
            return Err(ValidationError::OutOfBounds(
                "Duration must be between 1 and 604,800 seconds, inclusive"
                    .into()
            ));
        }

        self.valid_duration_in_seconds = Some(Duration(dur));
        Ok(self)
    }

    /// If specified, download requests must have this content disposition. The
    /// grammar is specified in RFC 6266, except that parameter names containing
    /// a '*' are not allowed.
    pub fn content_disposition(mut self, disposition: ContentDisposition)
    -> Self {
        self.b2_content_disposition = Some(disposition.0);
        self
    }

    /// If specified, download requests must have this content language. The
    /// grammar is specified in RFC 2616.
    pub fn content_language<S: Into<String>>(mut self, lang: S) -> Self {
        // TODO: Validate language.
        self.b2_content_language = Some(lang.into());
        self
    }

    /// If specified, download requests must have this expiration.
    pub fn expiration(mut self, expiration: Expires) -> Self {
        self.b2_expires = Some(expiration.value().to_string());
        self
    }

    /// If specified, download requests must have this cache control.
    pub fn cache_control(mut self, cache_control: CacheControl) -> Self {
        self.b2_cache_control = Some(cache_control.value().to_string());
        self
    }

    /// If specified, download requests must have this content encoding.
    pub fn content_encoding(mut self, encoding: ContentEncoding) -> Self {
        self.b2_content_encoding = Some(format!("{}", encoding.encoding()));
        self
    }

    /// If specified, download requests must have this content type.
    pub fn content_type(mut self, content_type: impl Into<Mime>) -> Self {
        self.b2_content_type = Some(content_type.into().to_string());
        self
    }

    /// Build a [DownloadAuthorizationRequest].
    pub fn build(self)
    -> Result<DownloadAuthorizationRequest<'a>, ValidationError> {
        let bucket_id = self.bucket_id
            .ok_or_else(|| ValidationError::MissingData(
                "A bucket ID must be provided".into()
            ))?;
        let file_name_prefix = self.file_name_prefix
            .ok_or_else(|| ValidationError::MissingData(
                "A filename prefix must be provided".into()
            ))?;
        let valid_duration_in_seconds = self.valid_duration_in_seconds
            .ok_or_else(|| ValidationError::MissingData(
                "The duration of the authorization token must be set".into()
            ))?;

        Ok(DownloadAuthorizationRequest {
            bucket_id,
            file_name_prefix,
            valid_duration_in_seconds,
            b2_content_disposition: self.b2_content_disposition,
            b2_content_language: self.b2_content_language,
            b2_expires: self.b2_expires,
            b2_cache_control: self.b2_cache_control,
            b2_content_encoding: self.b2_content_encoding,
            b2_content_type: self.b2_content_type,
        })
    }
}

/// A capability token that authorizes downloading files from a private bucket.
#[derive(Debug)]
#[allow(dead_code)]
pub struct DownloadAuthorization<C>
    where C: HttpClient,
{
    client: C,
    api_url: String,
    download_url: String,

    bucket_id: String,
    file_name_prefix: String,
    authorization_token: String,
}

impl<C> DownloadAuthorization<C>
    where C: HttpClient + Clone,
{
    /// Get the ID of the bucket this `DownloadAuthorization` can access.
    pub fn bucket_id(&self) -> &str { &self.bucket_id }
    /// The file prefix that determines what files in the bucket are accessible
    /// via this `DownloadAuthorization`.
    pub fn file_name_prefix(&self) -> &str { &self.file_name_prefix }

    fn from_proto(
        proto: ProtoDownloadAuthorization,
        auth: &Authorization<C>,
    ) -> Self {
        Self {
            client: auth.client.clone(),
            api_url: auth.api_url.clone(),
            download_url: auth.download_url.clone(),
            bucket_id: proto.bucket_id,
            file_name_prefix: proto.file_name_prefix,
            authorization_token: proto.authorization_token,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProtoDownloadAuthorization {
    bucket_id: String,
    file_name_prefix: String,
    authorization_token: String,
}

/// Generate a download authorization token to download files with a specific
/// prefix from a private B2 bucket.
///
/// The [Authorization] token must have [Capability::ShareFiles].
///
/// The returned [DownloadAuthorization] can be passed to
/// [download_file](crate::file::download_file) in place of an [Authorization]
/// when downloading files by name.
///
/// See <https://www.backblaze.com/b2/docs/b2_get_download_authorization.html>
/// for further information.
///
/// # Examples
///
/// ```no_run
/// # #[cfg(feature = "with_surf")]
/// # use b2_client::{
/// #     client::{HttpClient, SurfClient},
/// #     account::authorize_account,
/// #     file::{DownloadAuthorizationRequest, get_download_authorization},
/// # };
/// # #[cfg(feature = "with_surf")]
/// # async fn f() -> anyhow::Result<()> {
/// let mut auth = authorize_account(
///     SurfClient::default(),
///     "MY KEY ID",
///     "MY KEY"
/// ).await?;
///
/// let download_req = DownloadAuthorizationRequest::builder()
///     .bucket_id("MY BUCKET ID")
///     .file_name_prefix("my/files/")?
///     .duration(chrono::Duration::seconds(60))?
///     .build()?;
///
/// let download_auth = get_download_authorization(&mut auth, download_req)
///     .await?;
/// # Ok(()) }
/// ```
pub async fn get_download_authorization<'a, C, E>(
    auth: &mut Authorization<C>,
    download_req: DownloadAuthorizationRequest<'_>
) -> Result<DownloadAuthorization<C>, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::ShareFiles);

    let res = auth.client.post(auth.api_url("b2_get_download_authorization"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::to_value(download_req)?)
        .send().await?;

    let proto_auth: B2Result<ProtoDownloadAuthorization> =
        serde_json::from_slice(&res)?;

    proto_auth.map(|a| DownloadAuthorization::from_proto(a, auth)).into()
}

/// An authorization to upload file contents to a B2 file.
#[derive(Deserialize)]
#[allow(dead_code)]
#[serde(rename_all = "camelCase")]
pub struct UploadPartAuthorization<'a, 'b, C, E>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    #[serde(skip_deserializing)]
    #[serde(default = "make_none")]
    auth: Option<&'a mut Authorization<C>>,
    #[serde(skip_deserializing)]
    #[serde(default = "make_none")]
    encryption: Option<&'b ServerSideEncryption>,
    file_id: String,
    upload_url: String,
    authorization_token: String,
}

fn make_none<T>() -> Option<T> { None }

/// Get an [UploadPartAuthorization] to upload data to a new B2 file.
///
/// Use the returned `UploadPartAuthorization` when calling [upload_file_part].
///
/// The `UploadPartAuthorization` is valid for 24 hours or until an endpoint
/// rejects an upload.
///
/// If uploading multiple parts concurrently, each thread or task needs its own
/// authorization.
///
/// The [Authorization] must have [Capability::WriteFiles].
///
/// # B2 API Difference
///
/// The equivalent B2 endpoint is called
/// [`b2_get_upload_url`](https://www.backblaze.com/b2/docs/b2_get_upload_part_url.html).
pub async fn get_upload_part_authorization<'a, 'b, C, E>(
    auth: &'a mut Authorization<C>,
    file: &'b File,
) -> Result<UploadPartAuthorization<'a, 'b, C, E>, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    get_upload_part_authorization_by_id(
        auth,
        &file.file_id,
        file.server_side_encryption.as_ref()
    ).await
}

/// Get an [UploadPartAuthorization] to upload data to a new B2 file.
///
/// See [get_upload_part_authorization] for documentation on retrieving the
/// authorization.
pub async fn get_upload_part_authorization_by_id<'a, 'b, C, E>(
    auth: &'a mut Authorization<C>,
    file_id: impl AsRef<str>,
    encryption: Option<&'b ServerSideEncryption>,
) -> Result<UploadPartAuthorization<'a, 'b, C, E>, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    use serde_json::json;

    require_capability!(auth, Capability::WriteFiles);

    let res = auth.client.post(auth.api_url("b2_get_upload_part_url"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(json!({ "fileId": file_id.as_ref() }))
        .send().await?;

    let upload_auth: B2Result<UploadPartAuthorization<'_, '_, _, _>> =
        serde_json::from_slice(&res)?;

    upload_auth.map(move |mut a| {
        a.auth = Some(auth);
        a.encryption = encryption;
        a
    }).into()
}

/// An authorization to upload a file to a B2 bucket.
#[derive(Deserialize)]
#[allow(dead_code)]
#[serde(rename_all = "camelCase")]
pub struct UploadAuthorization<'a, C, E>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    #[serde(skip_deserializing)]
    #[serde(default = "make_none")]
    auth: Option<&'a mut Authorization<C>>,
    bucket_id: String,
    upload_url: String,
    authorization_token: String,
}

impl<'a, C, E> UploadAuthorization<'a, C, E>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    pub fn bucket_id(&self) -> &str { &self.bucket_id }
}

/// Obtain an authorization to upload files to a bucket.
///
/// Use the returned [UploadAuthorization] when calling [upload_file].
///
/// For faster uploading, you can obtain multiple authorizations and upload
/// files concurrently.
///
/// The `UploadAuthorization` is valid for 24 hours or until an upload attempt
/// is rejected. You can make multiple file uploads with a single authorization.
///
/// The [Authorization] must have [Capability::WriteFiles].
///
/// # B2 API Difference
///
/// The equivalent B2 endpoint is called
/// [`b2_get_upload_url`](https://www.backblaze.com/b2/docs/b2_get_upload_url.html).
pub async fn get_upload_authorization<'a, 'b, C, E>(
    auth: &'a mut Authorization<C>,
    bucket: &'b Bucket,
) -> Result<UploadAuthorization<'a, C, E>, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    get_upload_authorization_by_id(auth, &bucket.bucket_id).await
}

/// Obtain an authorization to upload files to a bucket.
///
/// See [get_upload_authorization] for documentation on retrieving the
/// authorization.
pub async fn get_upload_authorization_by_id<'a, 'b, C, E>(
    auth: &'a mut Authorization<C>,
    bucket_id: impl AsRef<str>,
) -> Result<UploadAuthorization<'a, C, E>, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    use serde_json::json;

    require_capability!(auth, Capability::WriteFiles);

    let res = auth.client.post(auth.api_url("b2_get_upload_url"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(json!({ "bucketId": bucket_id.as_ref() }))
        .send().await?;

    let upload_auth: B2Result<UploadAuthorization<'_, _, _>> =
        serde_json::from_slice(&res)?;

    upload_auth.map(move |mut a| { a.auth = Some(auth); a }).into()
}

/// Hide a file so that it cannot be downloaded by name.
///
/// Previous versions of the file are still stored. See
/// <https://www.backblaze.com/b2/docs/file_versions.html> for information on
/// hiding files.
///
/// # Notes
///
/// Some  of the returned [File] fields are empty, `0`, or meaningless for
/// hidden files, such as [content_length](File::content_length) and
/// [sha1_checksum](File::sha1_checksum).
///
/// See <https://www.backblaze.com/b2/docs/b2_hide_file.html> for further
/// information.
pub async fn hide_file<C, E>(auth: &mut Authorization<C>, file: &File)
-> Result<File, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    hide_file_by_name(auth, &file.bucket_id, &file.file_name).await
}

/// Hide a file so that it cannot be downloaded by name.
///
/// Previous versions of the file are still stored. See
/// <https://www.backblaze.com/b2/docs/file_versions.html> for information on
/// hiding files.
///
/// # Notes
///
/// Some  of the returned [File] fields are empty, `0`, or meaningless for
/// hidden files, such as [content_length](File::content_length) and
/// [sha1_checksum](File::sha1_checksum).
///
/// See <https://www.backblaze.com/b2/docs/b2_hide_file.html> for further
/// information.
pub async fn hide_file_by_name<C, E>(
    auth: &mut Authorization<C>,
    bucket_id: impl AsRef<str>,
    file_name: impl AsRef<str>,
) -> Result<File, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    use serde_json::json;

    require_capability!(auth, Capability::WriteFiles);

    let res = auth.client.post(auth.api_url("b2_hide_file"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(json!({
            "bucketId": bucket_id.as_ref(),
            "fileName": file_name.as_ref(),
        }))
        .send().await?;

    let file: B2Result<File> = serde_json::from_slice(&res)?;
    file.into()
}

/// A request to list the names of files stored in a bucket.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct ListFileNames<'a> {
    bucket_id: &'a str,
    start_file_name: Option<String>,
    max_file_count: Option<u16>,
    prefix: Option<&'a str>,
    delimiter: Option<char>,
}

impl<'a> ListFileNames<'a> {
    pub fn builder() -> ListFileNamesBuilder<'a> {
        ListFileNamesBuilder::default()
    }
}

/// A builder for a [ListFileNames] request.
#[derive(Default)]
pub struct ListFileNamesBuilder<'a> {
    bucket_id: Option<&'a str>,
    start_file_name: Option<String>,
    max_file_count: Option<u16>,
    prefix: Option<&'a str>,
    delimiter: Option<char>,
}

impl<'a> ListFileNamesBuilder<'a> {
    /// The bucket ID from which to list files.
    pub fn bucket_id(mut self, id: &'a str) -> Self {
        self.bucket_id = Some(id);
        self
    }

    /// The file name with which to start the listing.
    pub fn start_file_name(mut self, file_name: impl Into<String>) -> Self {
        self.start_file_name = Some(file_name.into());
        self
    }

    /// The maximum number of files to return.
    ///
    /// The default is 100. The provided `count` will be clamped to a value
    /// between 1 and 10,000 inclusive.
    ///
    /// A single transaction has a limit of 1,000 files; values greater than
    /// 1,000 will incur charges for multiple transactions.
    ///
    /// If more than 10,000 files are needed, a new request must be made.
    pub fn max_file_count(mut self, count: u16) -> Self {
        use std::cmp::Ord as _;

        self.max_file_count = Some(count.clamp(1, 10_000));
        self
    }

    /// Set the filename prefix to filter the file listing.
    ///
    /// If not set, all files are matched.
    ///
    /// See <https://www.backblaze.com/b2/docs/b2_list_file_names.html> for
    /// information on file prefixes and delimiters, and their interaction with
    /// each other.
    pub fn prefix(mut self, prefix: &'a str)
    -> Result<Self, FileNameValidationError> {
        self.prefix = Some(validated_file_name(prefix)?);
        Ok(self)
    }

    /// Set the delimiter to use to simulate a hierarchical filesystem.
    ///
    /// See <https://www.backblaze.com/b2/docs/b2_list_file_names.html> for
    /// information on file prefixes and delimiters, and their interaction with
    /// each other.
    pub fn delimiter(mut self, delimiter: char)
    -> Result<Self, FileNameValidationError> {
        // Because this is for a filename, we're assuming no control characters
        // are allowed. B2 explicitly forbids ASCII control characters; not sure
        // of their UTF support...
        if delimiter.is_ascii_control() {
            Err(FileNameValidationError::InvalidChar(delimiter))
        } else {
            self.delimiter = Some(delimiter);
            Ok(self)
        }
    }

    /// Build a [ListFileNames] request.
    ///
    /// Returns an error if the bucket ID has not been set.
    pub fn build(self) -> Result<ListFileNames<'a>, MissingData> {
        let bucket_id = self.bucket_id.ok_or_else(||
            MissingData::new("bucket_id")
        )?;

        Ok(ListFileNames {
            bucket_id,
            start_file_name: self.start_file_name,
            max_file_count: self.max_file_count,
            prefix: self.prefix,
            delimiter: self.delimiter,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileNameList {
    files: Vec<File>,
    next_file_name: Option<String>,
}

/// Get a list of file names in a bucket.
///
/// See <https://www.backblaze.com/b2/docs/b2_list_file_names.html> for more
/// information, including setting filename prefixes for filtering and a
/// delimiter for working with virtual folders.
#[allow(clippy::needless_lifetimes)] // False positive.
pub async fn list_file_names<'a, C, E>(
    auth: &mut Authorization<C>,
    request: ListFileNames<'a>,
) -> Result<(Vec<File>, Option<ListFileNames<'a>>), Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::ListFiles);

    let res = auth.client.post(auth.api_url("b2_list_file_names"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::to_value(&request)?)
        .send().await?;

    let files: B2Result<FileNameList> = serde_json::from_slice(&res)?;
    match files {
        B2Result::Ok(files) => {
            if let Some(next_file) = files.next_file_name {
                let mut request = request;
                request.start_file_name = Some(next_file);

                Ok((files.files, Some(request)))
            } else {
                Ok((files.files, None))
            }
        },
        B2Result::Err(e) => Err(e.into()),
    }
}

/// A request to list the names of files stored in a bucket.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct ListFileVersions<'a> {
    bucket_id: &'a str,
    start_file_name: Option<String>,
    start_file_id: Option<String>,
    max_file_count: Option<u16>,
    prefix: Option<&'a str>,
    delimiter: Option<char>,
}

impl<'a> ListFileVersions<'a> {
    pub fn builder() -> ListFileVersionsBuilder<'a> {
        ListFileVersionsBuilder::default()
    }
}

/// A builder for a [ListFileVersions] request.
#[derive(Default)]
pub struct ListFileVersionsBuilder<'a> {
    bucket_id: Option<&'a str>,
    start_file_name: Option<String>,
    start_file_id: Option<String>,
    max_file_count: Option<u16>,
    prefix: Option<&'a str>,
    delimiter: Option<char>,
}

impl<'a> ListFileVersionsBuilder<'a> {
    /// The bucket ID from which to list files.
    pub fn bucket_id(mut self, id: &'a str) -> Self {
        self.bucket_id = Some(id);
        self
    }

    /// The file name with which to start the listing.
    ///
    /// If the file ID is also specified, the name and ID pair is the starting
    /// point of the listing.
    pub fn start_file_name(mut self, file_name: impl Into<String>) -> Self {
        self.start_file_name = Some(file_name.into());
        self
    }

    /// The first file ID to return in the listing.
    ///
    /// If a file ID is provided, then the corresponding filename is required.
    pub fn start_file_id(mut self, file_id: impl Into<String>) -> Self {
        self.start_file_id = Some(file_id.into());
        self
    }

    /// The maximum number of files to return.
    ///
    /// The default is 100. The provided `count` will be clamped to a value
    /// between 1 and 10,000 inclusive.
    ///
    /// A single transaction has a limit of 1,000 files; values greater than
    /// 1,000 will incur charges for multiple transactions.
    ///
    /// If more than 10,000 files are needed, a new request must be made.
    pub fn max_file_count(mut self, count: u16) -> Self {
        use std::cmp::Ord as _;

        self.max_file_count = Some(count.clamp(1, 10_000));
        self
    }

    /// Set the filename prefix to filter the file listing.
    ///
    /// If not set, all files are matched.
    ///
    /// See <https://www.backblaze.com/b2/docs/b2_list_file_names.html> for
    /// information on file prefixes and delimiters, and their interaction with
    /// each other.
    pub fn prefix(mut self, prefix: &'a str)
    -> Result<Self, FileNameValidationError> {
        self.prefix = Some(validated_file_name(prefix)?);
        Ok(self)
    }

    /// Set the delimiter to use to simulate a hierarchical filesystem.
    ///
    /// See <https://www.backblaze.com/b2/docs/b2_list_file_names.html> for
    /// information on file prefixes and delimiters, and their interaction with
    /// each other.
    pub fn delimiter(mut self, delimiter: char)
    -> Result<Self, FileNameValidationError> {
        // Because this is for a filename, we're assuming no control characters
        // are allowed. B2 explicitly forbids ASCII control characters; not sure
        // of their UTF support...
        if delimiter.is_ascii_control() {
            Err(FileNameValidationError::InvalidChar(delimiter))
        } else {
            self.delimiter = Some(delimiter);
            Ok(self)
        }
    }

    /// Build a [ListFileVersions] request.
    ///
    /// Returns an error if the bucket ID has not been set.
    pub fn build(self) -> Result<ListFileVersions<'a>, MissingData> {
        let bucket_id = self.bucket_id.ok_or_else(||
            MissingData::new("bucket_id")
        )?;

        if self.start_file_id.is_some() && self.start_file_name.is_none() {
            return Err(MissingData::new("start_file_name")
                .with_message(
                    "If start_file_id is specified, start_file_name is required"
                )
            );
        }

        Ok(ListFileVersions {
            bucket_id,
            start_file_name: self.start_file_name,
            start_file_id: self.start_file_id,
            max_file_count: self.max_file_count,
            prefix: self.prefix,
            delimiter: self.delimiter,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileVersionList {
    files: Vec<File>,
    next_file_name: Option<String>,
    next_file_id: Option<String>,
}

/// List all versions of the files contained in a bucket.
///
/// Files are listed in alphabetical order by filename, then by upload timestamp
/// sorted descending.
///
/// See <https://www.backblaze.com/b2/docs/b2_list_file_versions.html> for more
/// information.
#[allow(clippy::needless_lifetimes)] // False positive.
pub async fn list_file_versions<'a, C, E>(
    auth: &mut Authorization<C>,
    request: ListFileVersions<'a>,
) -> Result<(Vec<File>, Option<ListFileVersions<'a>>), Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::ListFiles);

    let res = auth.client.post(auth.api_url("b2_list_file_versions"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::to_value(&request)?)
        .send().await?;

    let files: B2Result<FileVersionList> = serde_json::from_slice(&res)?;
    match files {
        B2Result::Ok(files) => {
            let mut request = request;

            if files.next_file_name.is_some() {
                request.start_file_name = files.next_file_name;
                request.start_file_id = files.next_file_id;

                Ok((files.files, Some(request)))
            } else {
                Ok((files.files, None))
            }
        },
        B2Result::Err(e) => Err(e.into()),
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListFileParts<'a> {
    file_id: &'a str,
    start_part_number: Option<u16>,
    max_part_count: Option<u16>,
}

impl<'a> ListFileParts<'a> {
    pub fn builder() -> ListFilePartsBuilder<'a> {
        ListFilePartsBuilder::default()
    }
}

#[derive(Default)]
pub struct ListFilePartsBuilder<'a> {
    file_id: Option<&'a str>,
    start_part_number: Option<u16>,
    max_part_count: Option<u16>,
}

impl<'a> ListFilePartsBuilder<'a> {
    /// A [File] returned by [start_large_file].
    pub fn file(mut self, file: &'a File) -> Self {
        self.file_id = Some(&file.file_id);
        self
    }

    /// The ID of a [File] returned by [start_large_file].
    pub fn file_id(mut self, id: &'a str) -> Self {
        self.file_id = Some(id);
        self
    }

    /// The first part to return in the listing.
    pub fn start_part_number(mut self, num: u16) -> Self {
        self.start_part_number = Some(num);
        self
    }

    /// The maximum number of parts to return.
    ///
    /// The default is 100. The provided `count` will be clamped to a value
    /// between 1 and 1,000 inclusive.
    ///
    /// If more than 1,000 parts are needed, a new request must be made.
    pub fn max_part_count(mut self, count: u16) -> Self {
        use std::cmp::Ord as _;

        self.max_part_count = Some(count.clamp(1, 1_000));
        self
    }

    pub fn build(self) -> Result<ListFileParts<'a>, MissingData> {
        let file_id = self.file_id.ok_or_else(||
            MissingData::new("file_id")
        )?;

        Ok(ListFileParts {
            file_id,
            start_part_number: self.start_part_number,
            max_part_count: self.max_part_count,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FilePartList {
    parts: Vec<FilePart>,
    next_part_number: Option<u16>,
}

/// List the parts of a large file that has not yet been completed.
#[allow(clippy::needless_lifetimes)] // False positive.
pub async fn list_file_parts<'a, C, E>(
    auth: &mut Authorization<C>,
    request: ListFileParts<'a>,
) -> Result<(Vec<FilePart>, Option<ListFileParts<'a>>), Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::WriteFiles);

    let res = auth.client.post(auth.api_url("b2_list_parts"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::to_value(&request)?)
        .send().await?;

    let parts: B2Result<FilePartList> = serde_json::from_slice(&res)?;
    match parts {
        B2Result::Ok(parts) => {
            if let Some(next_part) = parts.next_part_number {
                let mut request = request;
                request.start_part_number = Some(next_part);

                Ok((parts.parts, Some(request)))
            } else {
                Ok((parts.parts, None))
            }
        },
        B2Result::Err(e) => Err(e.into()),
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct ListUnfinishedLargeFiles<'a> {
    bucket_id: &'a str,
    name_prefix: Option<&'a str>,
    start_file_id: Option<String>,
    max_file_count: Option<u16>,
}

impl<'a> ListUnfinishedLargeFiles<'a> {
    pub fn builder() -> ListUnfinishedLargeFilesBuilder<'a> {
        ListUnfinishedLargeFilesBuilder::default()
    }
}

#[derive(Default)]
pub struct ListUnfinishedLargeFilesBuilder<'a> {
    bucket_id: Option<&'a str>,
    name_prefix: Option<&'a str>,
    start_file_id: Option<String>,
    max_file_count: Option<u16>,
}

impl<'a> ListUnfinishedLargeFilesBuilder<'a> {
    /// The bucket ID from which to list files.
    pub fn bucket_id(mut self, id: &'a str) -> Self {
        self.bucket_id = Some(id);
        self
    }

    /// Set the filename prefix to filter the file listing.
    ///
    /// If not set, all files are matched.
    pub fn prefix(mut self, prefix: &'a str)
    -> Result<Self, FileNameValidationError> {
        self.name_prefix = Some(validated_file_name(prefix)?);
        Ok(self)
    }

    /// The file ID with which to start the listing.
    pub fn start_file_id(mut self, file_id: impl Into<String>) -> Self {
        self.start_file_id = Some(file_id.into());
        self
    }

    /// The maximum number of files to return.
    ///
    /// The default is 100. The provided `count` will be clamped to a value
    /// between 1 and 100 inclusive.
    ///
    /// If more than 100 files are needed, a new request must be made.
    pub fn max_file_count(mut self, count: u16) -> Self {
        use std::cmp::Ord as _;

        self.max_file_count = Some(count.clamp(1, 10_000));
        self
    }

    /// Create a [ListUnfinishedLargeFiles] request.
    pub fn build(self) -> Result<ListUnfinishedLargeFiles<'a>, MissingData> {
        let bucket_id = self.bucket_id.ok_or_else(||
            MissingData::new("bucket_id")
        )?;

        Ok(ListUnfinishedLargeFiles {
            bucket_id,
            name_prefix: self.name_prefix,
            start_file_id: self.start_file_id,
            max_file_count: self.max_file_count,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileIdList {
    files: Vec<File>,
    next_file_id: Option<String>,
}

/// Get a list of the unfinished large files stored by B2.
///
/// If there are more files, returns a [ListUnfinishedLargeFiles] request that
/// will begin with the next file.
///
/// See <https://www.backblaze.com/b2/docs/b2_list_unfinished_large_files.html>
/// for further information.
#[allow(clippy::needless_lifetimes)] // False positive.
pub async fn list_unfinished_large_files<'a, C, E>(
    auth: &mut Authorization<C>,
    request: ListUnfinishedLargeFiles<'a>
) -> Result<(Vec<File>, Option<ListUnfinishedLargeFiles<'a>>), Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::ListFiles);

    let res = auth.client.post(auth.api_url("b2_list_unfinished_large_files"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::to_value(&request)?)
        .send().await?;

    let files: B2Result<FileIdList> = serde_json::from_slice(&res)?;
    match files {
        B2Result::Ok(files) => {
            if let Some(next_file_id) = files.next_file_id {
                let mut request = request;
                request.start_file_id = Some(next_file_id);

                Ok((files.files, Some(request)))
            } else {
                Ok((files.files, None))
            }
        },
        B2Result::Err(e) => Err(e.into()),
    }
}

/// A request to prepare to upload a large file.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartLargeFile<'a> {
    bucket_id: &'a str,
    file_name: String,
    content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_info: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_retention: Option<FileRetentionPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    legal_hold: Option<LegalHoldValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_side_encryption: Option<ServerSideEncryption>,
}

impl<'a> StartLargeFile<'a> {
    pub fn builder() -> StartLargeFileBuilder<'a> {
        StartLargeFileBuilder::default()
    }
}

/// A builder for a [StartLargeFile] request.
#[derive(Debug, Default)]
pub struct StartLargeFileBuilder<'a> {
    bucket_id: Option<&'a str>,
    file_name: Option<String>,
    content_type: Option<String>,
    file_info: Option<serde_json::Value>,
    file_retention: Option<FileRetentionPolicy>,
    legal_hold: Option<LegalHoldValue>,
    server_side_encryption: Option<ServerSideEncryption>,

    // To merge into file_info on build:
    last_modified: Option<i64>,
    sha1_checksum: Option<&'a str>,
    content_disposition: Option<String>,
    content_language: Option<String>,
    expires: Option<String>,
    cache_control: Option<String>,
    content_encoding: Option<String>,
}

impl<'a> StartLargeFileBuilder<'a> {
    /// Specify the bucket in which to store the new file.
    pub fn bucket_id(mut self, id: &'a str) -> Self {
        self.bucket_id = Some(id);
        self
    }

    /// Set the file's name.
    ///
    /// The provided name will be percent-encoded.
    pub fn file_name(mut self, name: impl AsRef<str>)
    -> Result<Self, FileNameValidationError> {
        let name = validated_file_name(name.as_ref())?;

        self.file_name = Some(percent_encode!(name));
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

    /// Set file metadata to be returned in headers when downloading the file.
    ///
    /// For the following headers, use their corresponding methods instead of
    /// setting the values here:
    ///
    /// * X-Bz-Info-src_last_modified_millis:
    ///   [last_modified](Self::last_modified)
    /// * X-Bz-Info-large_file_sha1: [sha1_checksum](Self::sha1_checksum)
    /// * Content-Disposition: [content_disposition](Self::content_disposition)
    /// * Content-Language: [content_language](Self::content_language)
    /// * Expires: [expiration](Self::expiration)
    /// * Cache-Control: [cache_control](Self::cache_control)
    /// * Content-Encoding: [content_encoding](Self::content_encoding)
    ///
    /// If any of the above are set here and via their methods, the value from
    /// the method will override the value specified here.
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

    /// The time of the file's last modification.
    pub fn last_modified(mut self, time: chrono::DateTime<chrono::Utc>) -> Self
    {
        self.last_modified = Some(time.timestamp_millis());
        self
    }

    /// The SHA1 checksum of the file's contents.
    ///
    /// B2 will use this to verify the accuracy of the file upload, and it will
    /// be returned in the header `X-Bz-Content-Sha1` when downloading the file.
    pub fn sha1_checksum(mut self, checksum: &'a str) -> Self {
        self.sha1_checksum = Some(checksum);
        self
    }

    /// The value to use for the `Content-Disposition` header when downloading
    /// the file.
    ///
    /// Parameter continuations are not supported.
    ///
    /// Note that the download request can override this value.
    pub fn content_disposition(mut self, disposition: ContentDisposition)
    -> Result<Self, ValidationError> {
        validate_content_disposition(&disposition.0, false)?;

        self.content_disposition = Some(percent_encode!(disposition.0));
        Ok(self)
    }

    /// The value to use for the `Content-Language` header when downloading the
    /// file.
    ///
    /// Note that the download request can override this value.
    pub fn content_language(mut self, language: impl Into<String>) -> Self {
        // TODO: validate content_language
        self.content_language = Some(percent_encode!(language.into()));
        self
    }

    /// The value to use for the `Expires` header when the file is downloaded.
    ///
    /// Note that the download request can override this value.
    pub fn expiration(mut self, expiration: Expires) -> Self {
        let expires = percent_encode!(expiration.value().to_string());

        self.expires = Some(expires);
        self
    }

    /// The value to use for the `Cache-Control` header when the file is
    /// downloaded.
    ///
    /// This would override the value set at the bucket level, and can be
    /// overriden by a download request.
    pub fn cache_control(mut self, cache_control: CacheControl) -> Self {
        self.cache_control = Some(cache_control.value().to_string());
        self
    }

    /// The value to use for the `Content-Encoding` header when the file is
    /// downloaded.
    ///
    /// Note that this can be overriden by a download request.
    pub fn content_encoding(mut self, encoding: ContentEncoding) -> Self {
        let encoding = percent_encode!(format!("{}", encoding.encoding()));
        self.content_encoding = Some(encoding);
        self
    }

    pub fn build(self) -> Result<StartLargeFile<'a>, ValidationError> {
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

        let file_info = if let Some(mut file_info) = self.file_info {
            let info_map = file_info.as_object_mut()
                .expect("file_info is not a JSON object");

            add_file_info!(info_map, "src_last_modified_millis",
                self.last_modified.map(|v| v.to_string()));
            add_file_info!(info_map, "large_file_sha1", self.sha1_checksum);
            add_file_info!(info_map, "b2-content-disposition",
                self.content_disposition);
            add_file_info!(info_map, "b2-content-language",
                self.content_language);
            add_file_info!(info_map, "b2-expires", self.expires);
            add_file_info!(info_map, "b2-cache-control", self.cache_control);
            add_file_info!(info_map, "b2-content-encoding",
                self.content_encoding);

            Some(file_info)
        } else {
            None
        };

        validate_file_metadata_size(
            &file_name,
            file_info.as_ref(),
            self.server_side_encryption.as_ref()
        )?;

        Ok(StartLargeFile {
            bucket_id,
            file_name,
            content_type,
            file_info,
            file_retention: self.file_retention,
            legal_hold: self.legal_hold,
            server_side_encryption: self.server_side_encryption,
        })
    }
}

/// Prepare to upload a large file in multiple parts.
///
/// After calling `start_large_file`, each thread uploading a file part should
/// call [get_upload_part_authorization] to obtain an upload authorization.
/// Then call [upload_file_part] to upload the relevant file part.
///
/// File parts can be copied from an existing file via [copy_file_part].
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
// TODO: Return a LargeFile or FileInProgress type? It would only matter for
// something like `copy_file_part` where it provides type-safety when passing
// both a source file and the large (destination) file IDs together.
pub async fn start_large_file<'a, C, E>(
    auth: &mut Authorization<C>,
    file: StartLargeFile<'_>
) -> Result<File, Error<E>>
    where C: HttpClient<Error=Error<E>>,
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
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::to_value(file)?)
        .send().await?;

    let file: B2Result<File> = serde_json::from_slice(&res)?;
    file.into()
}

/// A request to enable or disable a legal hold on a specific file.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFileLegalHold<'a> {
    file_name: &'a str,
    file_id: &'a str,
    legal_hold: LegalHoldValue,
}

impl<'a> UpdateFileLegalHold<'a> {
    /// Create a request to enable a legal hold for the specified file.
    pub fn enable_for(file: &'a File) -> Self {
        Self {
            file_name: &file.file_name,
            file_id: &file.file_id,
            legal_hold: LegalHoldValue::On,
        }
    }

    /// Create a request to disable a legal hold for the specified file.
    pub fn disable_for(file: &'a File) -> Self {
        Self {
            file_name: &file.file_name,
            file_id: &file.file_id,
            legal_hold: LegalHoldValue::Off,
        }
    }

    /// Use a builder to create a legal hold update request.
    pub fn builder() -> UpdateFileLegalHoldBuilder<'a> {
        UpdateFileLegalHoldBuilder::default()
    }
}

/// A builder for an [UpdateFileLegalHold] request.
#[derive(Default)]
pub struct UpdateFileLegalHoldBuilder<'a> {
    file_name: Option<&'a str>,
    file_id: Option<&'a str>,
    legal_hold: Option<LegalHoldValue>,
}

impl<'a> UpdateFileLegalHoldBuilder<'a> {
    /// Update the legal hold status for the specified file.
    pub fn file(mut self, file: &'a File) -> Self {
        self.file_name = Some(&file.file_name);
        self.file_id = Some(&file.file_id);
        self
    }

    /// Update the legal hold status for a file with the specified name.
    ///
    /// Setting the [file_id](Self::file_id) is also required.
    pub fn file_name(mut self, file_name: &'a str)
    -> Result<Self, FileNameValidationError> {
        self.file_name = Some(validated_file_name(file_name)?);
        Ok(self)
    }

    /// Update the legal hold status for a file with the specified ID.
    ///
    /// Setting the [file_name](Self::file_name) is also required.
    pub fn file_id(mut self, file_id: &'a str) -> Self {
        self.file_id = Some(file_id);
        self
    }

    /// Enable a legal hold.
    pub fn with_legal_hold(mut self) -> Self {
        self.legal_hold = Some(LegalHoldValue::On);
        self
    }

    /// Disable a legal hold.
    pub fn without_legal_hold(mut self) -> Self {
        self.legal_hold = Some(LegalHoldValue::Off);
        self
    }

    /// Build an [UpdateFileLegalHold] request.
    ///
    /// Returns an error if any of the file name, file ID, or legal hold status
    /// are not specified.
    pub fn build(self) -> Result<UpdateFileLegalHold<'a>, MissingData> {
        let file_name = self.file_name.ok_or_else(||
            MissingData::new("file_name")
        )?;
        let file_id = self.file_id.ok_or_else(||
            MissingData::new("file_id")
        )?;
        let legal_hold = self.legal_hold.ok_or_else(||
            MissingData::new("legal_hold")
        )?;

        Ok(UpdateFileLegalHold {
            file_name,
            file_id,
            legal_hold,
        })
    }
}

// TODO: B2 returns the same data we sent it. Not sure there's a reason to do
// the same - change or continue returning ()?
/// Enable or disable a legal hold on a file.
pub async fn update_file_legal_hold<C, E>(
    auth: &mut Authorization<C>,
    file_update: UpdateFileLegalHold<'_>
) -> Result<(), Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::WriteFileLegalHolds);

    let res = auth.client.post(auth.api_url("b2_update_file_legal_hold"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::to_value(file_update)?)
        .send().await?;

    let res: B2Result<UpdateFileLegalHold> = serde_json::from_slice(&res)?;
    res.map(|_| ()).into()
}

/// A request to update file retention settings on a file.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFileRetention<'a> {
    file_name: &'a str,
    file_id: &'a str,
    file_retention: FileRetentionSetting,
    #[serde(skip_serializing_if = "Option::is_none")]
    bypass_governance: Option<BypassGovernance>,
}

impl<'a> UpdateFileRetention<'a> {
    pub fn builder() -> UpdateFileRetentionBuilder<'a> {
        UpdateFileRetentionBuilder::default()
    }
}

/// A builder for an [UpdateFileRetention] request.
#[derive(Default)]
pub struct UpdateFileRetentionBuilder<'a> {
    file_name: Option<&'a str>,
    file_id: Option<&'a str>,
    file_retention: Option<FileRetentionSetting>,
    bypass_governance: Option<BypassGovernance>,
}

impl<'a> UpdateFileRetentionBuilder<'a> {
    /// The file to update.
    pub fn file(mut self, file: &'a File) -> Self {
        self.file_name = Some(&file.file_name);
        self.file_id = Some(&file.file_id);
        self
    }

    /// The name of the file to update.
    ///
    /// The file ID is also required.
    pub fn file_name(mut self, file_name: &'a str)
    -> Result<Self, FileNameValidationError> {
        self.file_name = Some(validated_file_name(file_name)?);
        Ok(self)
    }

    /// The ID of the file to update.
    ///
    /// The file name is also required.
    pub fn file_id(mut self, file_id: &'a str) -> Self {
        self.file_id = Some(file_id);
        self
    }

    /// The new file retention settings for the file.
    ///
    /// See
    /// <https://www.backblaze.com/b2/docs/file_lock.html#b2_api_file_lock_parameters>
    /// for more information.
    pub fn file_retention(mut self, retention: FileRetentionSetting) -> Self {
        self.file_retention = Some(retention);
        self
    }

    /// Bypass governance rules to allow deleting or shortening an existing
    /// governance-mode retention setting.
    ///
    /// The authorization must include [Capability::BypassGovernance].
    pub fn bypass_governance(mut self) -> Self {
        self.bypass_governance = Some(BypassGovernance::Yes);
        self
    }

    /// Create an [UpdateFileRetention] request.
    pub fn build(self) -> Result<UpdateFileRetention<'a>, MissingData> {
        let file_name = self.file_name.ok_or_else(||
            MissingData::new("file_name")
        )?;
        let file_id = self.file_id.ok_or_else(||
            MissingData::new("file_id")
        )?;
        let file_retention = self.file_retention.ok_or_else(||
            MissingData::new("file_retention")
        )?;

        Ok(UpdateFileRetention {
            file_name,
            file_id,
            file_retention,
            bypass_governance: self.bypass_governance,
        })
    }
}

// TODO: B2 returns the same data we sent it. Not sure there's a reason to do
// the same - change or continue returning ()?
/// Modify the file lock retention settings for a file.
///
/// Any attempt to delete or modify a locked file during the retention period
/// will fail.
///
/// The retention settings for files locked with [FileRetentionMode::Governance]
/// can be deleted or shortened only by accounts with
/// [Capability::BypassGovernance].
///
/// The retention settings for files locked with [FileRetentionMode::Compliance]
/// cannot be removed or shortened, but their retention dates can be extended.
///
/// The bucket containing the file must have File Lock enabled.
pub async fn update_file_retention<C, E>(
    auth: &mut Authorization<C>,
    retention_update: UpdateFileRetention<'_>,
) -> Result<(), Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    require_capability!(auth, Capability::WriteFileRetentions);
    if matches!(retention_update.bypass_governance, Some(BypassGovernance::Yes))
    {
        require_capability!(auth, Capability::BypassGovernance);
    }

    let res = auth.client.post(auth.api_url("b2_update_file_retention"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_body_json(serde_json::to_value(retention_update)?)
        .send().await?;

    let res: B2Result<UpdateFileRetention> = serde_json::from_slice(&res)?;
    res.map(|_| ()).into()
}

/// A request to upload a file to B2.
///
/// Use [UploadFileBuilder] to create an `UploadFile`.
pub struct UploadFile<'a> {
    file_name: String,
    content_type: String,
    sha1_checksum: &'a str,
    file_info: Option<serde_json::Value>,
    legal_hold: Option<LegalHoldValue>,
    file_retention: Option<(FileRetentionMode, i64)>,
    encryption: Option<ServerSideEncryption>,
}

impl<'a> UploadFile<'a> {
    pub fn builder() -> UploadFileBuilder<'a> {
        UploadFileBuilder::default()
    }
}

/// A builder to create an [UploadFile] request.
///
/// The [file_name](Self::file_name) and [sha1_checksum](Self::sha1_checksum)
/// are required.
///
/// The combined length limit of
/// [content_disposition](Self::content_disposition),
/// [content_language](Self::content_language), [expiration](Self::expiration),
/// [cache_control](Self::cache_control),
/// [content_encoding](Self::content_encoding), and custom headers is 7,000
/// bytes, unless self-managed encryption and/or file locks are enabled, in
/// which case the limit is 2,048 bytes.
#[derive(Default)]
pub struct UploadFileBuilder<'a> {
    file_name: Option<String>,
    content_type: Option<String>,
    sha1_checksum: Option<&'a str>,
    last_modified: Option<i64>,
    file_info: Option<serde_json::Value>,

    // To merge into file_info on build.
    content_disposition: Option<String>,
    content_language: Option<String>,
    expires: Option<String>,
    cache_control: Option<String>,
    content_encoding: Option<String>,

    legal_hold: Option<LegalHoldValue>,
    file_retention_mode: Option<FileRetentionMode>,
    file_retention_time: Option<i64>,
    encryption: Option<ServerSideEncryption>,
}

impl<'a> UploadFileBuilder<'a> {
    /// The name of the file.
    ///
    /// The provided name will be percent-encoded.
    pub fn file_name(mut self, name: impl AsRef<str>)
    -> Result<Self, FileNameValidationError> {
        let name = validated_file_name(name.as_ref())?;

        self.file_name = Some(percent_encode!(name));
        Ok(self)
    }

    /// The MIME type of the file's contents.
    ///
    /// This will be returned in the `Content-Type` header when downloading the
    /// file.
    ///
    /// If not specified, B2 will attempt to automatically set the content-type,
    /// defaulting to `application/octet-stream` if unable to determine its
    /// type.
    ///
    /// B2-recognized content-types can be viewed
    /// [here](https://www.backblaze.com/b2/docs/content-types.html)
    pub fn content_type(mut self, content_type: impl Into<Mime>) -> Self {
        self.content_type = Some(content_type.into().to_string());
        self
    }

    /// The SHA1 checksum of the file's contents.
    ///
    /// B2 will use this to verify the accuracy of the file upload, and it will
    /// be returned in the header `X-Bz-Content-Sha1` when downloading the file.
    pub fn sha1_checksum(mut self, checksum: &'a str) -> Self {
        self.sha1_checksum = Some(checksum);
        self
    }

    /// The time of the file's last modification.
    pub fn last_modified(mut self, time: chrono::DateTime<chrono::Utc>) -> Self
    {
        self.last_modified = Some(time.timestamp_millis());
        self
    }

    /// The value to use for the `Content-Disposition` header when downloading
    /// the file.
    ///
    /// Note that the download request can override this value.
    pub fn content_disposition(mut self, disposition: ContentDisposition)
    -> Result<Self, ValidationError> {
        validate_content_disposition(&disposition.0, false)?;

        self.content_disposition = Some(percent_encode!(disposition.0));
        Ok(self)
    }

    /// The value to use for the `Content-Language` header when downloading the
    /// file.
    ///
    /// Note that the download request can override this value.
    pub fn content_language(mut self, language: impl Into<String>) -> Self {
        // TODO: validate content_language
        self.content_language = Some(percent_encode!(language.into()));
        self
    }

    /// The value to use for the `Expires` header when the file is downloaded.
    ///
    /// Note that the download request can override this value.
    pub fn expiration(mut self, expiration: Expires) -> Self {
        let expires = percent_encode!(expiration.value().to_string());

        self.expires = Some(expires);
        self
    }

    /// The value to use for the `Cache-Control` header when the file is
    /// downloaded.
    ///
    /// This would override the value set at the bucket level, and can be
    /// overriden by a download request.
    pub fn cache_control(mut self, cache_control: CacheControl) -> Self {
        self.cache_control = Some(cache_control.value().to_string());
        self
    }

    /// The value to use for the `Content-Encoding` header when the file is
    /// downloaded.
    ///
    /// Note that this can be overriden by a download request.
    pub fn content_encoding(mut self, encoding: ContentEncoding) -> Self {
        let encoding = percent_encode!(format!("{}", encoding.encoding()));
        self.content_encoding = Some(encoding);
        self
    }

    /// Set user-specified file metadata.
    ///
    /// For the following headers, use their corresponding methods instead of
    /// setting the values here:
    ///
    /// * X-Bz-Info-src_last_modified_millis:
    ///   [last_modified](Self::last_modified)
    /// * X-Bz-Info-large_file_sha1: [sha1_checksum](Self::sha1_checksum)
    /// * Content-Disposition: [content_disposition](Self::content_disposition)
    /// * Content-Language: [content_language](Self::content_language)
    /// * Expires: [expiration](Self::expiration)
    /// * Cache-Control: [cache_control](Self::cache_control)
    /// * Content-Encoding: [content_encoding](Self::content_encoding)
    ///
    /// If any of the above are set here and via their methods, the value from
    /// the method will override the value specified here.
    ///
    /// Any header names that do not begin with "`X-Bz-Info-`" will have it
    /// prepended to the supplied name.
    pub fn file_info(mut self, info: serde_json::Value)
    -> Result<Self, ValidationError> {
        let mut file_info = validated_file_info(info)?;

        if let Some(map) = file_info.as_object_mut() {
            let mut key_updates = vec![];

            for key in map.keys() {
                if ! key.starts_with("X-Bz-Info-") {
                    key_updates.push(key.to_owned());
                }
            }

            for old_key in key_updates.into_iter() {
                let val = map.remove(&old_key).unwrap();
                let mut new_key = String::from("X-Bz-Info-");
                new_key.push_str(&old_key);

                map.insert(new_key, val);
            }
        }

        self.file_info = Some(file_info);
        Ok(self)
    }

    /// Set a legal hold on the file.
    pub fn with_legal_hold(mut self) -> Self {
        self.legal_hold = Some(LegalHoldValue::On);
        self
    }

    /// Disable a legal hold on the file.
    pub fn without_legal_hold(mut self) -> Self {
        self.legal_hold = Some(LegalHoldValue::Off);
        self
    }

    /// Set the file retention mode for the file.
    ///
    /// The bucket must be File Lock-enabled and the [Authorization] must have
    /// [Capability::WriteFileRetentions].
    pub fn file_retention_mode(mut self, mode: FileRetentionMode) -> Self {
        self.file_retention_mode = Some(mode);
        self
    }

    /// Set the expiration date and time of a file lock.
    ///
    /// The bucket must be File Lock-enabled and the [Authorization] must have
    /// [Capability::WriteFileRetentions].
    pub fn retain_until(mut self, time: chrono::DateTime<chrono::Utc>)
    -> Self {
        self.file_retention_time = Some(time.timestamp_millis());
        self
    }

    /// Set the encryption settings to use for the file.
    pub fn encryption_settings(mut self, settings: ServerSideEncryption)
    -> Self {
        self.encryption = Some(settings);
        self
    }

    /// Build an [UploadFile] request.
    pub fn build(self) -> Result<UploadFile<'a>, ValidationError> {
        let file_name = self.file_name.ok_or_else(||
            ValidationError::MissingData("Filename is required".into())
        )?;

        let content_type = self.content_type
            .unwrap_or_else(|| "b2/x-auto".into());

        let sha1_checksum = self.sha1_checksum.unwrap_or("do_not_verify");

        if self.file_retention_mode.is_some()
            ^ self.file_retention_time.is_some()
        {
            return Err(ValidationError::BadFormat(
                "File retention policy is not fully configured".into()
            ));
        }

        let file_info = if let Some(mut file_info) = self.file_info {
            let info_map = file_info.as_object_mut()
                .expect("file_info is not a JSON object");

            add_file_info!(info_map, "X-Bz-info-src_last_modified_millis",
                self.last_modified.map(|v| v.to_string()));
            add_file_info!(info_map, "X-Bz-info-b2-content-disposition",
                self.content_disposition);
            add_file_info!(info_map, "X-Bz-info-b2-content-language",
                self.content_language);
            add_file_info!(info_map, "X-Bz-info-b2-expires", self.expires);
            add_file_info!(info_map, "X-Bz-info-b2-content-encoding",
                self.content_encoding);

            Some(file_info)
        } else {
            None
        };

        validate_file_metadata_size(
            &file_name,
            file_info.as_ref(),
            self.encryption.as_ref()
        )?;

        let file_retention = self.file_retention_mode
            .zip(self.file_retention_time);

        Ok(UploadFile {
            file_name,
            content_type,
            sha1_checksum,
            file_info,
            legal_hold: self.legal_hold,
            file_retention,
            encryption: self.encryption,
        })
    }
}

/// Upload a file to a B2 bucket.
///
/// You must first call [get_upload_authorization] to obtain an authorization to
/// upload files to the bucket; then pass that authorization to `upload_file`.
pub async fn upload_file<C, E>(
    auth: &mut UploadAuthorization<'_, C, E>,
    upload: UploadFile<'_>,
    data: &[u8],
) -> Result<File, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    // Unwrap safety: an `UploadAuthorization` can only be created from
    // `get_upload_authorization`, which will always embed an `Authorization`
    // reference before returning.
    let inner_auth = auth.auth.as_mut().unwrap();

    require_capability!(inner_auth, Capability::WriteFiles);

    if upload.file_retention.is_some() {
        // We check this here rather than when we need it below to satisfy the
        // borrow checker.
        require_capability!(inner_auth, Capability::WriteFileRetentions);
    }

    let mut req = inner_auth.client.post(&auth.upload_url)
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token)?
        .with_header("X-Bz-File-Name", &upload.file_name)?
        .with_header("Content-Type", &upload.content_type)?
        .with_header("Content-Length", &data.len().to_string())?
        .with_header("X-Bz-Content-Sha1", upload.sha1_checksum)?;

    if let Some(mut file_info) = upload.file_info {
        let info_map = file_info.as_object_mut()
            .expect("file_info is not a JSON object");

        macro_rules! add_metadata_header {
            ($header_name:literal) => {
                if let Some(val) = info_map.remove($header_name) {
                    req = req.with_header($header_name, val.as_str().unwrap())?
                }
            };
        }

        add_metadata_header!("X-Bz-Info-src_last_modified_millis");
        add_metadata_header!("X-Bz-Info-b2-content-disposition");
        add_metadata_header!("X-Bz-Info-b2-content-language");
        add_metadata_header!("X-Bz-Info-b2-expires");
        add_metadata_header!("X-Bz-Info-b2-cache-control");
        add_metadata_header!("X-Bz-Info-content-encoding");

        for (key, val) in info_map.into_iter() {
            req = req.with_header(key, &val.to_string())?;
        }
    }

    if let Some(legal_hold) = upload.legal_hold {
        req = req.with_header("X-Bz-File-Legal-Hold", &legal_hold.to_string())?;
    }

    if let Some((mode, timestamp)) = upload.file_retention {
        req = req
            .with_header("X-Bz-File-Retention-Mode", &mode.to_string())?
            .with_header("X-Bz-File-Retention-Retain-Until-Timestamp",
                &timestamp.to_string())?;
    }

    if let Some(enc) = upload.encryption {
        if let Some(headers) = enc.to_headers() {
            for (header, value) in headers.into_iter() {
                req = req.with_header(header, &value)?;
            }
        }
    }

    let res = req.with_body(data).send().await?;

    let file: B2Result<File> = serde_json::from_slice(&res)?;
    file.into()
}

/// A request to upload part of a large file.
#[derive(Clone)]
pub struct UploadFilePart<'a> {
    part_number: u16,
    content_sha1: &'a str,
    encryption: Option<ServerSideEncryption>,
}

impl<'a> UploadFilePart<'a> {
    pub fn builder() -> UploadFilePartBuilder<'a> {
        UploadFilePartBuilder::default()
    }

    /// Create a request to upload the next part.
    pub fn create_next_part(mut self, sha1_checksum: Option<&'a str>)
    -> Result<Self, ValidationError> {
        self.content_sha1 = sha1_checksum.unwrap_or("do_not_verify");

        if self.part_number < 10_000 {
            self.part_number += 1;
            Ok(self)
        } else {
            Err(ValidationError::OutOfBounds(
                "The maximum part number is 10,000.".into()
            ))
        }
    }
}

/// A builder for an [UploadFilePart] request.
pub struct UploadFilePartBuilder<'a> {
    part_number: u16,
    content_sha1: &'a str,
    encryption: Option<ServerSideEncryption>,
}

impl<'a> Default for UploadFilePartBuilder<'a> {
    fn default() -> Self {
        Self {
            part_number: 1,
            content_sha1: "do_not_verify",
            encryption: None,
        }
    }
}

impl<'a> UploadFilePartBuilder<'a> {
    /// Set the number of this part.
    ///
    /// Part numbers increment from 1 to 10,000 inclusive and will be clamped to
    /// that range if necessary.
    pub fn part_number(mut self, num: u16) -> Self {
        use std::cmp::Ord as _;

        self.part_number = num.clamp(1, 10_000);
        self
    }

    /// The SHA1 checkum of this part of the file.
    ///
    /// If not provided, the file part will not be immediately verified. The
    /// SHA1 checksums are required to [finish the file
    /// upload](finish_large_file_upload), so they will be verified either when
    /// you upload the part or at the end of the process.
    pub fn part_sha1_checksum(mut self, sha1: &'a str) -> Self {
        self.content_sha1 = sha1;
        self
    }

    /// Set the encryption settings for the source file.
    ///
    /// This must match the settings passed to [start_large_file].
    pub fn server_side_encryption(mut self, encryption: ServerSideEncryption)
    -> Self {
        self.encryption = Some(encryption);
        self
    }

    /// Create an [UploadFilePart] request to pass to [upload_file_part].
    pub fn build(self) -> UploadFilePart<'a> {
        UploadFilePart {
            part_number: self.part_number,
            content_sha1: self.content_sha1,
            encryption: self.encryption,
        }
    }
}

/// Upload a part of a large file to B2.
///
/// Once all parts are uploaded, call [finish_large_file_upload] to merge the
/// parts into a single file.
///
/// If you make two uploads with the same part number, the second upload to
/// complete will overwrite the first.
///
/// The [Authorization] used to create the given [UploadPartAuthorization] must
/// have [Capability::WriteFiles].
///
/// A large file must have at least two parts, and all parts except the last
/// must be at least 5 MB in size. See
/// <https://www.backblaze.com/b2/docs/uploading.html> for further information
/// on uploading files.
///
/// Some errors will requiring obtaining a new [UploadPartAuthorization]. See
/// the B2 documentation for
/// [b2_upload_part](https://www.backblaze.com/b2/docs/b2_upload_part.html) or
/// [uploading files](https://www.backblaze.com/b2/docs/uploading.html) for
/// information on these errors.
///
/// # Parameters
///
/// * `auth`: An upload authorization obtained via
///   [get_upload_part_authorization].
/// * `part_num`: The part number of this part; it must be between 1 and 10,000
///   inclusive and increment by one for each part.
/// * `sha1_checksum`: The SHA1 checksum of this part of the file. You may pass
///   `None` to defer verification until finishing the file.
/// * `data`: The data part of the file.
///
/// Uploading a file part without a checksum is not recommended as it prevents
/// B2 from determining if the file part is corrupt, allowing you to immediately
/// retry.
// TODO: Stream-based data upload to avoid requiring all data be in RAM at once.
pub async fn upload_file_part<C, E>(
    auth: &mut UploadPartAuthorization<'_, '_, C, E>,
    upload: &UploadFilePart<'_>,
    data: &[u8],
) -> Result<FilePart, Error<E>>
    where C: HttpClient<Error=Error<E>>,
          E: fmt::Debug + fmt::Display,
{
    // Unwrap safety: an `UploadPartAuthorization` can only be created from
    // `get_upload_part_authorization`, which will always embed an
    // `Authorization` reference before returning.
    let inner_auth = auth.auth.as_mut().unwrap();

    require_capability!(inner_auth, Capability::WriteFiles);

    let mut req = inner_auth.client.post(&auth.upload_url)
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token).unwrap()
        .with_header("X-Bz-Part-Number", &upload.part_number.to_string())?
        .with_header("Content-Length", &data.len().to_string())?
        .with_header("X-Bz-Content-Sha1", upload.content_sha1)?;

    if let Some(enc) = &upload.encryption {
        if let Some(headers) = enc.to_headers() {
            for (header, value) in headers.into_iter() {
                req = req.with_header(header, &value)?;
            }
        }
    }

    let res = req.with_body(data).send().await?;

    let part: B2Result<FilePart> = serde_json::from_slice(&res)?;
    part.into()
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
            "test_sessions/large_file.yaml",
            None, None
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
            "test_sessions/large_file.yaml",
            None, None
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
            "test_sessions/large_file.yaml",
            None, None
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
    async fn test_get_download_authorization() -> Result<(), anyhow::Error> {
        use http_types::cache::CacheDirective;

        // I need two copies of an identical expiration, but it doesn't
        // implement Clone.
        let (expires1, expires2) = {
            use http_types::Trailers;

            let mut header = Trailers::new();
            header.insert("Expires", "Fri, 21 Jan 2022 14:10:49 GMT");

            let e1 = Expires::from_headers(header.as_ref())
                .unwrap().unwrap().value().to_string();
            let e2 = Expires::from_headers(header.as_ref()).unwrap().unwrap();

            (e1, e2)
        };

        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/auth_account.yaml",
            #[allow(clippy::option_map_unit_fn)]
            Some(Box::new(move |req| {
                use surf_vcr::Body;

                if let Body::Str(body) = &mut req.body {
                    let body_json: Result<serde_json::Value, _> =
                        serde_json::from_str(body);

                    if let Ok(mut body) = body_json {
                        body.get_mut("b2Expires")
                            .map(|v| *v = serde_json::json!(expires1));

                        req.body = Body::Str(body.to_string());
                    }
                }
            })),
            None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::ShareFiles])
            .await;

        let mut cache_control = CacheControl::new();
        cache_control.push(CacheDirective::MustRevalidate);

        let req = DownloadAuthorizationRequest::builder()
            .bucket_id("8d625eb63be2775577c70e1a")
            .file_name_prefix("files/")?
            .duration(chrono::Duration::seconds(30))?
            .content_disposition(
                ContentDisposition("Attachment; filename=example.html".into())
            )
            .expiration(expires2)
            .cache_control(cache_control)
            .build()?;

        let download_auth = get_download_authorization(&mut auth, req).await?;
        assert_eq!(download_auth.bucket_id(), "8d625eb63be2775577c70e1a");

        Ok(())
    }

    #[async_std::test]
    async fn test_get_download_authorization_with_only_required_data()
    -> Result<(), anyhow::Error> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/auth_account.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::ShareFiles])
            .await;

        let req = DownloadAuthorizationRequest::builder()
            .bucket_id("8d625eb63be2775577c70e1a")
            .file_name_prefix("files/")?
            .duration(chrono::Duration::seconds(30))?
            .build()?;

        let download_auth = get_download_authorization(&mut auth, req).await?;
        assert_eq!(download_auth.bucket_id(), "8d625eb63be2775577c70e1a");

        Ok(())
    }

    #[async_std::test]
    async fn obtain_part_upload_authorization() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/large_file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteFiles])
            .await;

        let file = StartLargeFile::builder()
            .bucket_id("8d625eb63be2775577c70e1a")
            .file_name("Test-large-file.txt")?
            .content_type("text/plain")
            .build()?;

        let file = start_large_file(&mut auth, file).await?;
        let upload_auth = get_upload_part_authorization(&mut auth, &file)
            .await?;

        assert_eq!(upload_auth.file_id, file.file_id);

        Ok(())
    }

    #[async_std::test]
    async fn obtain_upload_authorization() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteFiles])
            .await;

        let upload_auth = get_upload_authorization_by_id(
            &mut auth,
            "8d625eb63be2775577c70e1a"
        ).await?;

        assert_eq!(upload_auth.bucket_id, "8d625eb63be2775577c70e1a");

        Ok(())
    }

    #[async_std::test]
    async fn upload_file_success() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteFiles])
            .await;

        let mut upload_auth = get_upload_authorization_by_id(
            &mut auth,
            "8d625eb63be2775577c70e1a"
        ).await?;

        let file = UploadFile::builder()
            .file_name("test-file-upload.txt")?
            .sha1_checksum("81fe8bfe87576c3ecb22426f8e57847382917acf")
            .build()?;

        let file = upload_file(&mut upload_auth, file, b"abcd").await?;

        assert_eq!(file.action, FileAction::Upload);

        Ok(())
    }

    #[async_std::test]
    async fn copy_file_success() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/large_file.yaml",
            None, None
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

    #[async_std::test]
    async fn copy_file_part_success() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/large_file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(
            client,
            vec![Capability::WriteFiles, Capability::ReadFiles]
        ).await;

        let file = StartLargeFile::builder()
            .bucket_id("8d625eb63be2775577c70e1a")
            .file_name("Test-large-file2.txt")?
            .content_type("text/plain")
            .build()?;

        let file = start_large_file(&mut auth, file).await?;

        let part1 = CopyFilePart::builder()
            .source_file_id(concat!(
                "4_z8d625eb63be2775577c70e1a_f111954e3108ff3f6_d20211118_",
                "m151810_c002_v0001168_t0010"
            ))
            .destination_large_file(&file)
            .part_number(1)?
            .build()?;

        let part2 = CopyFilePart::builder()
            .source_file_id(concat!(
                "4_z8d625eb63be2775577c70e1a_f111954e3108ff3f6_d20211118_",
                "m151810_c002_v0001168_t0010"
            ))
            .destination_large_file(&file)
            .part_number(2)?
            .range(ByteRange::new(0, 3)?)
            .build()?;

        let part1 = copy_file_part(&mut auth, part1).await?;
        let part2 = copy_file_part(&mut auth, part2).await?;

        assert_eq!(part1.part_number, 1);
        assert_eq!(part2.part_number, 2);

        let _file = cancel_large_file(&mut auth, file).await?;
        Ok(())
    }

    // TODO: File header tests.

    #[async_std::test]
    async fn download_file_by_id_success() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::ReadFiles])
            .await;

        let req = DownloadFile::with_id(concat!("4_z8d625eb63be2775577c70e1a_f",
            "111954e3108ff3f6_d20211118_m151810_c002_v0001168_t0010"));

        let (file, _headers) = download_file(&mut auth, req).await?;
        assert_eq!(file, b"Some text\n");

        Ok(())
    }

    #[async_std::test]
    async fn download_file_by_name_success() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::ReadFiles])
            .await;

        let req = DownloadFile::with_name("test-file.txt", "testing-b2-client");

        let (file, _headers) = download_file(&mut auth, req).await?;
        assert_eq!(file, b"Some text\n");

        Ok(())
    }

    #[async_std::test]
    async fn download_file_by_name_via_download_authorization_success()
    -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(
            client,
            vec![Capability::ReadFiles, Capability::ShareFiles]
        ).await;

        let req = DownloadAuthorizationRequest::builder()
            .bucket_id("8d625eb63be2775577c70e1a")
            .file_name_prefix("test")?
            .duration(chrono::Duration::seconds(30))?
            .build()?;

        let mut download_auth = get_download_authorization(
            &mut auth,
            req
        ).await?;

        let req = DownloadFile::with_name("test-file.txt", "testing-b2-client");

        let (file, _headers) = download_file(&mut download_auth, req).await?;
        assert_eq!(file, b"Some text\n");

        Ok(())
    }

    /* TODO: Setup, write these tests.
    #[async_std::test]
    async fn download_file_not_authorized() -> anyhow::Result<()> {
        todo!()
    }

    #[async_std::test]
    async fn download_public_file_without_read_cap() -> anyhow::Result<()> {
        todo!()
    }
    */

    #[async_std::test]
    async fn download_file_range_success() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::ReadFiles])
            .await;

        let req = DownloadFile::builder()
            .file_name("test-file.txt", "testing-b2-client")
            .range(ByteRange::new(5, 8)?)
            .build()?;

        let (file, _headers) = download_file(&mut auth, req).await?;
        assert_eq!(file, b"text");

        Ok(())
    }

    // TODO: Test download with custom headers.

    #[async_std::test]
    async fn delete_file_success() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/delete_file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(
            client,
            vec![Capability::DeleteFiles, Capability::WriteFiles]
        ).await;

        let mut upload_auth = get_upload_authorization_by_id(
            &mut auth,
            "8d625eb63be2775577c70e1a"
        ).await?;

        let file = UploadFile::builder()
            .file_name("test-file-upload.txt")?
            .sha1_checksum("81fe8bfe87576c3ecb22426f8e57847382917acf")
            .build()?;

        let file = upload_file(&mut upload_auth, file, b"abcd").await?;


        let _ = delete_file_version(&mut auth, file, BypassGovernance::No)
            .await?;

        Ok(())
    }

    #[async_std::test]
    async fn upload_large_file_full_process() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/large_file.yaml",
            Some(Box::new(|req| {
                use surf_vcr::Body;

                if let Body::Str(body) = &mut req.body {
                    if body.starts_with("aaaaa") {
                        // We don't need to store 5 MB of nothing for our test.
                        req.body = Body::Str("aaaaa for 5 MB of data".into());
                    }
                }
            })),
            None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteFiles])
            .await;

        let file = StartLargeFile::builder()
            .bucket_id("8d625eb63be2775577c70e1a")
            .file_name("Test-large-file.txt")?
            .content_type("text/plain")
            .build()?;

        let file = start_large_file(&mut auth, file).await?;
        let mut upload_auth = get_upload_part_authorization(&mut auth, &file)
            .await?;

        // All but the last part must be at least 5MB.
        let data1: Vec<u8> = [b'a'].iter().cycle().take(5*1024*1024)
            .cloned().collect();

        let upload = UploadFilePart::builder()
            .part_number(1)
            .part_sha1_checksum("61b8d6600ac94d912874f569a9341120f680c9f8")
            .build();


        let _part1 = upload_file_part(&mut upload_auth, &upload, &data1).await?;

        let upload = upload.create_next_part(
            Some("924f61661a3472da74307a35f2c8d22e07e84a4d")
        )?;

        let _part2 = upload_file_part(&mut upload_auth, &upload, b"bcd").await?;

        let file = finish_large_file_upload(
            &mut auth,
            &file,
            &[
                "61b8d6600ac94d912874f569a9341120f680c9f8".into(),
                "924f61661a3472da74307a35f2c8d22e07e84a4d".into(),
            ]
        ).await?;

        assert_eq!(file.action, FileAction::Upload);

        Ok(())
    }

    #[async_std::test]
    async fn test_get_file_info() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::ReadFiles])
            .await;

        let file_info = get_file_info(
            &mut auth,
            concat!("4_z8d625eb63be2775577c70e1a_f1187926dea44b322_d20211230",
                "_m171512_c002_v0001110_t0055")
        ).await?;

        assert_eq!(
            file_info.content_sha1,
            Some(String::from("81fe8bfe87576c3ecb22426f8e57847382917acf"))
        );

        Ok(())
    }

    #[async_std::test]
    async fn test_hide_file() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteFiles])
            .await;

        let file = hide_file_by_name(
            &mut auth,
            "8d625eb63be2775577c70e1a",
            "test-file.txt"
        ).await?;

        assert_eq!(file.action, FileAction::Hide);

        Ok(())
    }

    #[async_std::test]
    async fn test_list_file_names() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None,
            Some(std::boxed::Box::new(move |res| {
                use surf_vcr::Body;

                if let Body::Str(body) = &mut res.body {
                    let body_json: Result<serde_json::Value, _> =
                        serde_json::from_str(body);

                    if let Ok(mut body) = body_json {
                        if let Some(files) = body.get_mut("files") {
                            let files = files.as_array_mut().unwrap();

                            for file in files.iter_mut() {
                                file["accountId"] = serde_json::Value::String(
                                    "hidden account id".into()
                                );
                            }
                        }

                        res.body = Body::Str(body.to_string());
                    }
                }
            }))
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::ListFiles])
            .await;

        let req = ListFileNames::builder()
            .bucket_id("8d625eb63be2775577c70e1a")
            .max_file_count(5)
            .build().unwrap();

        let (files, next_req) = list_file_names(&mut auth, req).await?;

        assert_eq!(files.len(), 2);
        assert!(next_req.is_none());

        Ok(())
    }

    #[async_std::test]
    async fn test_list_file_versions() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None,
            Some(std::boxed::Box::new(move |res| {
                use surf_vcr::Body;

                if let Body::Str(body) = &mut res.body {
                    let body_json: Result<serde_json::Value, _> =
                        serde_json::from_str(body);

                    if let Ok(mut body) = body_json {
                        if let Some(files) = body.get_mut("files") {
                            let files = files.as_array_mut().unwrap();

                            for file in files.iter_mut() {
                                file["accountId"] = serde_json::Value::String(
                                    "hidden account id".into()
                                );
                            }
                        }

                        res.body = Body::Str(body.to_string());
                    }
                }
            }))
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::ListFiles])
            .await;

        let req = ListFileVersions::builder()
            .bucket_id("8d625eb63be2775577c70e1a")
            .max_file_count(5)
            .build().unwrap();

        let (files, next_req) = list_file_versions(&mut auth, req).await?;

        assert_eq!(files.len(), 4);
        assert!(next_req.is_none());

        Ok(())
    }

    #[async_std::test]
    async fn test_list_file_parts() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/large_file.yaml",
            Some(Box::new(|req| {
                use surf_vcr::Body;

                if let Body::Str(body) = &mut req.body {
                    if body.starts_with("aaaaa") {
                        // We don't need to store 5 MB of nothing for our test.
                        req.body = Body::Str("aaaaa for 5 MB of data".into());
                    }
                }
            })),
            None
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::WriteFiles])
            .await;

        // We need a large file that hasn't been finished yet.
        let file = {
            let file = StartLargeFile::builder()
                .bucket_id("8d625eb63be2775577c70e1a")
                .file_name("unfinished-file.txt")?
                .content_type("text/plain")
                .build()?;

            let file = start_large_file(&mut auth, file).await?;
            let mut upload_auth = get_upload_part_authorization(
                &mut auth,
                &file
            ).await?;

            // All but the last part must be at least 5MB.
            let data1: Vec<u8> = [b'a'].iter().cycle().take(5*1024*1024)
                .cloned().collect();

            let upload = UploadFilePart::builder()
                .part_sha1_checksum("61b8d6600ac94d912874f569a9341120f680c9f8")
                .build();

            let _part1 = upload_file_part(&mut upload_auth, &upload, &data1)
                .await?;

            let upload = upload.create_next_part(
                Some("924f61661a3472da74307a35f2c8d22e07e84a4d")
            )?;

            let _part2 = upload_file_part(&mut upload_auth, &upload, b"bcd")
                .await?;

            file
        };

        let req = ListFileParts::builder()
            .file_id(&file.file_id)
            .max_part_count(5)
            .build().unwrap();

        let (parts, next_req) = list_file_parts(&mut auth, req).await?;

        assert_eq!(parts.len(), 2);
        assert!(next_req.is_none());

        let _ = cancel_large_file(&mut auth, file).await?;

        Ok(())
    }

    #[async_std::test]
    async fn test_list_unfinished_files() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/large_file.yaml",
            None,
            Some(std::boxed::Box::new(move |res| {
                use surf_vcr::Body;

                if let Body::Str(body) = &mut res.body {
                    let body_json: Result<serde_json::Value, _> =
                        serde_json::from_str(body);

                    if let Ok(mut body) = body_json {
                        if let Some(files) = body.get_mut("files") {
                            let files = files.as_array_mut().unwrap();

                            for file in files.iter_mut() {
                                file["accountId"] = serde_json::Value::String(
                                    "hidden account id".into()
                                );
                            }
                        }

                        res.body = Body::Str(body.to_string());
                    }
                }
            }))
        ).await?;

        let mut auth = create_test_auth(client, vec![Capability::ListFiles])
            .await;

        let list_files = ListUnfinishedLargeFiles::builder()
            .bucket_id("8d625eb63be2775577c70e1a")
            .build()?;

        let (files, next_req) = list_unfinished_large_files(
            &mut auth,
            list_files
        ).await?;

        assert_eq!(files.len(), 2);
        assert!(next_req.is_none());

        Ok(())
    }

    #[async_std::test]
    async fn test_update_legal_hold() -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(
            client,
            vec![Capability::WriteFileLegalHolds]
        ).await;

        let update = UpdateFileLegalHold::builder()
            .file_name("test-file.txt")?
            .file_id(concat!("4_zcd120e962b02c7a577e70e1a_f100e7b2902e23bf1",
                    "_d20220205_m134630_c002_v0001141_t0007"))
            .with_legal_hold()
            .build()?;

        update_file_legal_hold(&mut auth, update).await?;

        Ok(())
    }

    #[async_std::test]
    async fn test_update_legal_hold_fails_when_not_allowed_by_bucket()
    -> anyhow::Result<()> {
        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(
            client,
            vec![Capability::WriteFileLegalHolds]
        ).await;

        let update = UpdateFileLegalHold::builder()
            .file_name("test-file.txt")?
            .file_id(concat!("4_z8d625eb63be2775577c70e1a_f107f7b2843696d21",
                "_d20220201_m191409_c002_v0001094_t0020"))
            .with_legal_hold()
            .build()?;

        let res = update_file_legal_hold(&mut auth, update).await;
        assert!(res.is_err());

        Ok(())
    }

    #[async_std::test]
    async fn test_update_file_retention_settings()
    -> anyhow::Result<()> {
        use chrono::{Utc, TimeZone as _};

        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(
            client,
            vec![Capability::WriteFileRetentions]
        ).await;

        let retain_until = Utc.ymd(3000, 1, 1).and_hms(0, 0, 0);

        let update = UpdateFileRetention::builder()
            .file_name("test-file.txt")?
            .file_id(concat!("4_zcd120e962b02c7a577e70e1a_f100e7b2902e23bf1",
                "_d20220205_m134630_c002_v0001141_t0007"))
            .file_retention(FileRetentionSetting::new(
                FileRetentionMode::Governance,
                retain_until
            )?)
            .build()?;

        update_file_retention(&mut auth, update).await?;

        Ok(())
    }

    #[async_std::test]
    async fn test_update_file_retention_settings_fails_when_bucket_disallows()
    -> anyhow::Result<()> {
        use chrono::{Utc, TimeZone as _};

        let client = create_test_client(
            VcrMode::Replay,
            "test_sessions/file.yaml",
            None, None
        ).await?;

        let mut auth = create_test_auth(
            client,
            vec![Capability::WriteFileRetentions]
        ).await;

        let retain_until = Utc.ymd(3000, 1, 1).and_hms(0, 0, 0);

        let update = UpdateFileRetention::builder()
            .file_name("test-file.txt")?
            .file_id(concat!("4_z8d625eb63be2775577c70e1a_f107f7b2843696d21",
                "_d20220201_m191409_c002_v0001094_t0020"))
            .file_retention(FileRetentionSetting::new(
                FileRetentionMode::Governance,
                retain_until
            )?)
            .build()?;

        let res = update_file_retention(&mut auth, update).await;
        assert!(res.is_err());

        Ok(())
    }
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
