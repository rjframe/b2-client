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
