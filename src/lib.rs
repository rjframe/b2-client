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

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::{
        account::{Authorization, Capability, Capabilities},
        client::{SurfClient, HttpClient},
    };
    use surf_vcr::{VcrMiddleware, VcrMode, VcrError};


    /// Create a SurfClient with the surf-vcr middleware.
    pub async fn create_test_client(mode: VcrMode, cassette: &'static str)
    -> std::result::Result<SurfClient, VcrError> {
        let surf = surf::Client::new()
            .with(VcrMiddleware::new(mode, cassette).await?);

        let client = SurfClient::new()
            .with_client(surf);

        Ok(client)
    }

    /// Create a fake authorization to allow us to run tests without calling the
    /// authorize_account function.
    pub fn get_test_key(client: SurfClient, capabilities: Vec<Capability>)
    -> Authorization<SurfClient> {
        Authorization::new(
            client,
            "abcdefg".into(),
            "4_002d2e6b27577ea0000000002_019f9ac2_4af224_acct_BzTNBWOKUVQvIMyHK3tXHG7YqDQ=".into(),
            Capabilities::new(capabilities, None, None, None),
            "http://localhost:8765".into(),
            "http://localhost:8765/download".into(),
            100000000,
            5000000,
            "http://localhost:8765/s3api".into(),
        )
    }
}
