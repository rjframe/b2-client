/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

//! A Backblaze B2 API library that can send and receive data via arbitrary HTTP
//! clients.
//!
//! The full API is supported.
//!
//! # Examples
//!
//! ```no_run
//! # fn calculate_sha1(data: &[u8]) -> String { String::default() }
//! # use anyhow;
//! use std::env;
//! use b2_client as b2;
//!
//! # #[cfg(feature = "with_surf")]
//! # async fn upload_file() -> anyhow::Result<()> {
//! let key = env::var("B2_KEY").ok().unwrap();
//! let key_id = env::var("B2_KEY_ID").ok().unwrap();
//!
//! let client = b2::client::SurfClient::default();
//! let mut auth = b2::authorize_account(client, &key, &key_id).await?;
//!
//! let mut upload_auth = b2::get_upload_authorization_by_id(
//!     &mut auth,
//!     "my-bucket-id"
//! ).await?;
//!
//! let file = b2::UploadFile::builder()
//!     .file_name("my-file.txt")?
//!     .sha1_checksum("61b8d6600ac94d912874f569a9341120f680c9f8")
//!     .build()?;
//!
//! let data = b"very important information";
//!
//! let file_info = b2::upload_file(&mut upload_auth, file, data).await?;
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Differences from the B2 Service API
//!
//! * The B2 endpoint `b2_get_upload_part_url` is
//!   [get_upload_part_authorization].
//! * The B2 endpoint `b2_get_upload_url` is [get_upload_authorization].
//! * The word "file" is often added for clarity; e.g., the B2 endpoint
//!   `b2_copy_part` is [copy_file_part].

// Increase the recursion limit for a macro in a test in validate.rs.
#![cfg_attr(test, recursion_limit = "256")]


pub mod account;
pub mod bucket;
pub mod file;

pub mod client;
pub mod error;

mod types;
mod validate;

pub mod prelude {
    #![allow(unused_imports)]

    pub(crate) use super::{
        account::{Authorization, Capability},
        types::{B2Result, Duration},
        require_capability,
    };
}

macro_rules! require_capability {
    ($auth:expr, $cap:expr) => {
        if ! $auth.has_capability($cap) {
            return Err($crate::error::Error::Unauthorized($cap));
        }
    }
}
pub(crate) use require_capability;


pub use account::*;
pub use bucket::*;
pub use file::*;

pub use client::HttpClient;
pub use error::Error;

#[cfg(all(test, feature = "with_surf"))]
pub(crate) mod test_utils {
    use std::boxed::Box;
    use crate::{
        account::{Authorization, Capability, Capabilities},
        client::SurfClient,
    };
    use surf_vcr::*;
    use surf::http::Method;


    /// Create a SurfClient with the surf-vcr middleware.
    ///
    /// We remove the following data from the recorded sessions:
    ///
    /// * From request/response headers and bodies:
    ///     * `accountId`
    ///     * `authorizationToken`
    ///     * `keys` dictionary (response only)
    ///
    /// The `keys` dictionary in a response is replaced with a single key object
    /// containing fake data.
    ///
    /// The potentially-senstive data that we do not remove includes:
    ///
    /// * From request/response bodies:
    ///     * `applicationKeyId`
    ///     * `bucketId`
    ///
    /// You may optionally pass in functions to make additional modifications to
    /// a response or request as needed for specific tests. Note that if the
    /// response body is not valid JSON, nothing in the response can be
    /// modified.
    pub async fn create_test_client(
        mode: VcrMode, cassette: &'static str,
        req_mod: Option<Box<dyn Fn(&mut VcrRequest) + Send + Sync + 'static>>,
        res_mod: Option<Box<dyn Fn(&mut VcrResponse) + Send + Sync + 'static>>,
    ) -> std::result::Result<SurfClient, VcrError> {
        #![allow(clippy::option_map_unit_fn)]

        let vcr = VcrMiddleware::new(mode, cassette).await.unwrap()
            .with_modify_request(move |req| {
                let val = match req.method {
                    Method::Get => "Basic hidden-account-id".into(),
                    _ => "hidden-authorization-token".into(),
                };

                req.headers.entry("authorization".into())
                    .and_modify(|v| *v = vec![val]);

                req.headers.entry("user-agent".into())
                    .and_modify(|v| {
                        // We need to replace the version number with a constant
                        // value.

                        let range = if v[0].len() > 7 {
                            let start = v[0][7..]
                                .find(|c| char::is_ascii_digit(&c))
                                .expect("User-agent string is incorrect");

                            let end = v[0][start..].find(';')
                                .expect("User-agent string is incorrect");

                            Some((start + 7, end + start))
                        } else {
                            None
                        };

                        if let Some((start, end)) = range {
                            v[0].replace_range(start..end, "version");
                        }
                    });

                if let Body::Str(body) = &mut req.body {
                    let body_json: Result<serde_json::Value, _> =
                        serde_json::from_str(body);

                    if let Ok(mut body) = body_json {
                        body.get_mut("accountId")
                            .map(|v| *v =
                                serde_json::json!("hidden-account-id"));

                        req.body = Body::Str(body.to_string());
                    }
                };

                if let Some(req_mod) = req_mod.as_ref() {
                    req_mod(req);
                }
            })
            .with_modify_response(move |res| {
                // If the response isn't JSON, there's nothing we need to
                // modify.
                let mut json: serde_json::Value = match &mut res.body {
                    Body::Str(s) => match serde_json::from_str(s) {
                        Ok(json) => json,
                        Err(_) => return,
                    },
                    _ => return,
                };

                json = hide_response_account_id(json);

                json.get_mut("authorizationToken")
                    .map(|v| *v = serde_json::json!(
                        "hidden-authorization-token")
                    );

                json.get_mut("keys")
                    .map(|v| *v = serde_json::json!([{
                        "accountId": "hidden-account-id",
                        "applicationKeyId": "hidden-app-key-id",
                        "bucketId": "abcdefghijklmnop",
                        "capabilities": [
                            "listFiles",
                            "readFiles",
                        ],
                        "expirationTimestamp": null,
                        "keyName": "dev-b2-client-tester",
                        "namePrefix": null,
                        "options": ["s3"],
                        "nextApplicationId": null,
                    }]));

                res.body = Body::Str(json.to_string());

                if let Some(res_mod) = res_mod.as_ref() {
                    res_mod(res);
                }
            });

        let surf = surf::Client::new()
            .with(vcr);

        let client = SurfClient::default()
            .with_client(surf);

        Ok(client)
    }

    fn hide_response_account_id(mut json: serde_json::Value)
    -> serde_json::Value {
        #![allow(clippy::option_map_unit_fn)]

        if let Some(buckets) = json.get_mut("buckets")
            .and_then(|b| b.as_array_mut())
        {
            for bucket in buckets.iter_mut() {
                bucket.get_mut("accountId")
                    .map(|v| *v = serde_json::json!("hidden-account-id"));
            }
        }

        json.get_mut("accountId")
            .map(|v| *v = serde_json::json!("hidden-account-id"));

        json
    }

    /// Create an [Authorization] with the specified capabilities.
    ///
    /// If the `B2_CLIENT_TEST_KEY` and `B2_CLIENT_TEST_KEY_ID` environment
    /// variables are set, their values are used to make an authorization
    /// request against the B2 API.
    ///
    /// Otherwise, a fake authorization is created with values usable for
    /// pre-recorded sessions in unit tests.
    pub async fn create_test_auth(
        client: SurfClient,
        capabilities: Vec<Capability>
    ) -> Authorization<SurfClient> {
        use super::account::authorize_account;

        let key = std::env::var("B2_CLIENT_TEST_KEY").ok();
        let key_id = std::env::var("B2_CLIENT_TEST_KEY_ID").ok();

        assert!(key.as_ref().xor(key_id.as_ref()).is_none(),
            concat!(
                "Either both or neither of the B2_CLIENT_TEST_KEY and ",
                "B2_CLIENT_TEST_KEY_ID environment variables must be set"
            )
        );

        if let Some(key) = key {
            let auth = authorize_account(client, &key, &key_id.unwrap())
                .await.unwrap();

            for cap in capabilities {
                assert!(auth.capabilities().has_capability(cap));
            }

            auth
        } else {
            Authorization::new(
                client,
                "some-account-id".into(),
                "some-key-id".into(),
                Capabilities::new(capabilities, None, None, None),
                "https://api002.backblazeb2.com".into(),
                "https://f002.backblazeb2.com".into(),
                100000000,
                5000000,
                "https://s3.us-west-002.backblazeb2.com".into(),
            )
        }
    }
}
