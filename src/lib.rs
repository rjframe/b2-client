/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

//! A Backblaze B2 API library that can send and receive data via arbitrary HTTP
//! clients.

pub mod account;
pub mod bucket;
pub mod client;
pub mod error;
mod types;
mod validate;

pub mod prelude {
    #![allow(unused_imports)]

    pub use super::{
        account::Authorization,
    };

    pub(crate) use super::types::{
        B2Result,
        Duration,
    };
}

pub use account::*;
pub use bucket::*;
pub use client::HttpClient;
pub use error::Error;

#[cfg(all(test, feature = "with_surf"))]
pub(crate) mod test_utils {
    use crate::{
        account::{Authorization, Capability, Capabilities},
        client::{SurfClient, HttpClient},
    };
    use surf_vcr::{Body, VcrMiddleware, VcrMode, VcrError};
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
    /// We probably should remove them for safety; we could store a
    /// cryptographic hash of the data so that we can still test against their
    /// values. In the meantime, create new objects for the tests as needed, and
    /// delete them afterward.
    pub async fn create_test_client(mode: VcrMode, cassette: &'static str)
    -> std::result::Result<SurfClient, VcrError> {
        #![allow(clippy::option_map_unit_fn)]

        let vcr = VcrMiddleware::new(mode, cassette).await.unwrap()
            .with_modify_request(|req| {
                let val = match req.method {
                    Method::Get => "Basic hidden-account-id".into(),
                    _ => "hidden-authorization-token".into(),
                };

                req.headers.entry("authorization".into())
                    .and_modify(|v| *v = vec![val]);

                let body = match &mut req.body {
                    Body::Str(s) => s,
                    _ => panic!("Response body was in bytes"),
                };

                let body: Result<serde_json::Value, _> =
                    serde_json::from_str(body);

                if let Ok(mut body) = body {
                    body.get_mut("accountId")
                        .map(|v| *v = serde_json::json!("hidden-account-id"));

                    req.body = Body::Str(body.to_string());
                }
            })
            .with_modify_response(|res| {
                let body = match &mut res.body {
                    Body::Str(s) => s,
                    _ => panic!("Response body was in bytes"),
                };

                let mut body: serde_json::Value = serde_json::from_str(body)
                    .unwrap();

                // TODO: It would be better/safer to walk through all
                // dictionaries/arrays and check their keys for these instead of
                // adding them as I find them.
                if let Some(buckets) = body.get_mut("buckets") {
                    if let Some(buckets) = buckets.as_array_mut() {
                        for bucket in buckets.iter_mut() {
                            bucket.get_mut("accountId")
                                .map(|v|
                                    *v = serde_json::json!("hidden-account-id")
                                );
                        }
                    }
                }

                body.get_mut("accountId")
                    .map(|v| *v = serde_json::json!("hidden-account-id"));

                body.get_mut("authorizationToken")
                    .map(|v| *v = serde_json::json!("hidden-authorization-token"));

                body.get_mut("keys")
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

                res.body = Body::Str(body.to_string());
            });

        let surf = surf::Client::new()
            .with(vcr);

        let client = SurfClient::new()
            .with_client(surf);

        Ok(client)
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
                "https://f002.backblaze.com".into(),
                100000000,
                5000000,
                "https://s3.us-west-002.backblazeb2.com".into(),
            )
        }
    }
}
