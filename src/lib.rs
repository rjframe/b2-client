pub mod account;
pub mod client;
pub mod error;

#[cfg(feature = "with_surf")]
pub(crate) type Requestor = client::SurfClient;

#[cfg(feature = "with_hyper")]
pub(crate) type Requestor = client::HyperClient;

pub use error::Error;
