#![allow(dead_code)]
#![allow(unused_imports)]

use std::env;

use anyhow::anyhow;
use b2_client::{self as b2, client};


fn usage() -> String{
    concat!("Usage: upload_and_download <bucket ID>\n\n",
        "Expects environment variables `B2_CLIENT_KEY` and `B2_CLIENT_KEY_ID`",
        " to be defined.").into()
}

async fn do_main() -> anyhow::Result<()> {
    let bucket_id = {
        let mut args = env::args();
        args.next();

        args.next().ok_or_else(|| anyhow!(usage()))?
    };

    let (key, key_id) = {
        let key = env::var("B2_CLIENT_KEY").ok();
        let key_id = env::var("B2_CLIENT_KEY_ID").ok();

        if key.is_none() || key_id.is_none() { return Err(anyhow!(usage())); }

        (key.unwrap(), key_id.unwrap())
    };

    let client = client();
    let mut auth = b2::authorize_account(client, &key, &key_id).await?;

    println!("* Obtaining authorization to upload a file.");
    let mut upload_auth = b2::get_upload_authorization_by_id(
        &mut auth,
        &bucket_id
    ).await?;

    println!("* Uploading file.");
    let upload_request = b2::UploadFile::builder()
        .file_name("my-test-file.txt")?
        .content_type("text/plain")
        .sha1_checksum("81fe8bfe87576c3ecb22426f8e57847382917acf")
        .build()?;

    let file = b2::upload_file(&mut upload_auth, upload_request, b"abcd")
        .await?;

    println!("* Downloading file.");
    let download_request = b2::DownloadFile::with_id(&file.file_id());
    let (downloaded, _headers) = b2::download_file(&mut auth, download_request)
        .await?;

    assert_eq!(downloaded, b"abcd");

    println!("\nUpload and download is complete.");
    Ok(())
}


fn main() -> anyhow::Result<()> { main_runner() }

#[cfg(any(feature = "with_surf", feature = "with_isahc"))]
fn main_runner() -> anyhow::Result<()> { async_std::task::block_on(do_main()) }

#[cfg(feature = "with_hyper")]
fn main_runner() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(do_main())
}

#[cfg(feature = "with_surf")]
pub fn client() -> client::SurfClient { client::SurfClient::default() }

#[cfg(feature = "with_hyper")]
pub fn client() -> client::HyperClient { client::HyperClient::default() }

#[cfg(feature = "with_isahc")]
pub fn client() -> client::IsahcClient { client::IsahcClient::default() }


// Allow us to build when running `cargo test` on the main project without
// features. You can ignore this.
#[cfg(not(any(feature="with_hyper", feature="with_surf",
    feature="with_isahc")))]
mod empty {
    pub fn main_runner() -> anyhow::Result<()> {
        Err(anyhow::anyhow!(
            "You must compile this example with an HTTP client"
        ))
    }

    pub fn client() -> NoClient { NoClient }

    #[derive(Default, Clone)]
    pub struct NoClient;

    #[async_trait::async_trait]
    impl b2_client::HttpClient for NoClient {
        type Error = b2_client::Error<&'static str>;

        fn get(&mut self, _url: impl AsRef<str>)
        -> Result<&mut Self, b2_client::error::ValidationError> { Ok(self) }
        fn head(&mut self, _url: impl AsRef<str>)
        -> Result<&mut Self, b2_client::error::ValidationError> { Ok(self) }
        fn post(&mut self, _url: impl AsRef<str>)
        -> Result<&mut Self, b2_client::error::ValidationError> { Ok(self) }

        fn with_header<S: AsRef<str>>(&mut self, _name: S, _value: S)
        -> Result<&mut Self, b2_client::error::ValidationError> { Ok(self) }
        fn with_body(&mut self, _data: impl Into<Vec<u8>>)
        -> &mut Self { self }
        fn with_body_json(&mut self, _body: serde_json::Value)
        -> &mut Self { self }
        fn read_body_from_file(&mut self, _path: impl Into<std::path::PathBuf>)
        -> &mut Self { self }

        fn user_agent(&mut self, _user_agent_string: impl Into<String>)
        -> Result<&mut Self, b2_client::error::ValidationError> { Ok(self) }

        async fn send(&mut self) -> Result<Vec<u8>, Self::Error> {
            Err(b2_client::Error::Client(""))
        }

        async fn send_keep_headers(&mut self)
        -> Result<(Vec<u8>, b2_client::client::HeaderMap), Self::Error> {
            Err(b2_client::Error::Client(""))
        }
    }
}
#[cfg(not(any(feature="with_hyper", feature="with_surf",
    feature="with_isahc")))]
pub use empty::*;
