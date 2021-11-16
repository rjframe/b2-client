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
};

use serde::{Serialize, Deserialize};


#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "camelCase")]
enum LegalHoldValue {
    On,
    Off,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileLegalHold {
    #[serde(rename = "isClientAuthorizedToRead")]
    can_read: bool,
    value: Option<LegalHoldValue>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FileAction {
    /// A large file upload has been started and is still in progress.
    Start,
    /// A file was uploaded.
    Upload,
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
#[derive(Debug, Deserialize)]
pub struct FileRetention {
    #[serde(rename = "isClientAuthorizedToRead")]
    can_read: bool,
    value: FileRetentionSetting,
}

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
    file_retention: Option<FileRetention>, // WRONG
    legal_hold: Option<FileLegalHold>,
    server_side_encryption: Option<ServerSideEncryption>,
    // Milliseconds since midnight, 1970-1-1
    // TODO: value is 0 if action is folder; use Option?
    // TODO: method to convert to UTC
    upload_timestamp: i64,
}

impl File {
    pub fn action(&self) -> FileAction { self.action }
    pub fn bucket_id(&self) -> &str { &self.bucket_id }
    pub fn content_length(&self) -> u64 { self.content_length }

    pub fn sha1(&self) -> Option<&String> {
        self.content_sha1.as_ref()
    }

    pub fn content_type(&self) -> Option<&String> {
        self.content_type.as_ref()
    }

    pub fn file_id(&self) -> &str { &self.file_id }

    pub fn file_info(&self) -> &serde_json::Value {
        &self.file_info
    }

    pub fn file_name(&self) -> &str { &self.file_name }

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

    pub fn encryption_settings(&self) -> Option<&ServerSideEncryption> {
        self.server_side_encryption.as_ref()
    }

    pub fn upload_time(&self) -> chrono::DateTime<chrono::Utc> {
        use chrono::{TimeZone as _, Utc};

        Utc.timestamp_millis(self.upload_timestamp)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelledFileUpload {
    pub file_id: String,
    account_id: String, // TODO: Make pub? Remove?
    pub bucket_id: String,
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
    let res = auth.client.post(auth.api_url("b2_cancel_large_file"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token)
        .with_body(&serde_json::json!({ "fileId": id.as_ref() }))
        .send().await?;

    let info: B2Result<CancelledFileUpload> = serde_json::from_value(res)?;
    info.into()
}

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

impl StartLargeFileBuilder {
    pub fn bucket_id(mut self, id: impl Into<String>) -> Self {
        self.bucket_id = Some(id.into());
        self
    }

    pub fn file_name(mut self, name: impl Into<String>) -> Self {
        self.file_name = Some(name.into());
        self
    }

    pub fn content_type(mut self, mime: impl Into<String>) -> Self {
        // TODO: B2 has a map of auto-detected MIME types:
        // https://www.backblaze.com/b2/docs/content-types.html
        // How do we want to deal with that?
        self.content_type = Some(mime.into());
        self
    }

    // TODO: document data sharing - B2 uses more than just content-disposition
    // here
    pub fn file_info(mut self, info: serde_json::Value) -> Self {
        self.file_info = Some(info);
        self
    }

    pub fn file_retention(mut self, policy: FileRetentionPolicy) -> Self {
        self.file_retention = Some(policy);
        self
    }

    pub fn with_legal_hold(mut self) -> Self {
        self.legal_hold = Some(LegalHoldValue::On);
        self
    }

    pub fn without_legal_hold(mut self) -> Self {
        self.legal_hold = Some(LegalHoldValue::Off);
        self
    }

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
    let res = auth.client.post(auth.api_url("b2_start_large_file"))
        .expect("Invalid URL")
        .with_header("Authorization", &auth.authorization_token)
        .with_body(&serde_json::to_value(file)?)
        .send().await?;

    let file: B2Result<File> = serde_json::from_value(res)?;
    file.into()
}

#[cfg(all(test, feature = "with_surf"))]
mod tests {
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

        let mut auth = create_test_auth(client, vec![Capability::WriteBuckets])
            .await;

        let req = StartLargeFile::builder()
            .bucket_id("8d625eb63be2775577c70e1a")
            .file_name("test-large-file")
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

        let mut auth = create_test_auth(client, vec![Capability::WriteBuckets])
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

        let mut auth = create_test_auth(client, vec![Capability::WriteBuckets])
            .await;

        match cancel_large_file_by_id(&mut auth, "bad-id").await.unwrap_err() {
            Error::B2(e) => assert_eq!(e.code(), ErrorCode::BadRequest),
            _ => panic!("Unexpected error type"),
        }

        Ok(())
    }
}
