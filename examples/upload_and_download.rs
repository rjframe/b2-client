use std::env;

use anyhow::anyhow;
use b2_client::{self as b2, client, HttpClient};

fn usage() -> String{
    concat!("Usage: upload_and_download <bucket ID>\n\n",
        "Expects environment variables `B2_CLIENT_KEY` and `B2_CLIENT_KEY_ID`",
        " to be defined.").into()
}


fn main() -> anyhow::Result<()> { main_runner() }

#[cfg(feature = "with_surf")]
fn main_runner() -> anyhow::Result<()> { async_std::task::block_on(do_main()) }

#[cfg(feature = "with_hyper")]
fn main_runner() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(do_main())
}

#[cfg(feature = "with_isahc")]
fn main_runner() -> anyhow::Result<()> { async_std::task::block_on(do_main()) }


#[cfg(feature = "with_surf")]
pub fn client() -> client::SurfClient { client::SurfClient::new() }

#[cfg(feature = "with_hyper")]
pub fn client() -> client::HyperClient { client::HyperClient::new() }

#[cfg(feature = "with_isahc")]
pub fn client() -> client::IsahcClient { client::IsahcClient::new() }


async fn do_main() -> anyhow::Result<()> {
    let bucket_id = {
        let mut args = env::args();
        args.next();

        args.next().ok_or_else(|| anyhow!(usage()))?
    };

    let (key, key_id) = {
        let key = env::var("B2_CLIENT_KEY").ok();
        let key_id = env::var("B2_CLIENT_KEY_ID").ok();

        if key.is_none() || key_id.is_none() {
            return Err(anyhow!(concat!("B2 key and ID expected in ",
                "environment variables `B2_CLIENT_KEY` and ",
                "`B2_CLIENT_KEY_ID`")));
        }

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
