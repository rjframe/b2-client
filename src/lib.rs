pub mod account;
pub mod client;
pub mod error;

#[cfg(feature = "with_surf")]
pub(crate) type Requestor = client::SurfRequest;

#[cfg(feature = "with_surf")]
pub(crate) type Error = error::Error<surf::Error>;

#[cfg(feature = "with_hyper")]
pub(crate) type Requestor = client::HyperRequest;

#[cfg(feature = "with_hyper")]
pub(crate) type Error = error::Error<hyper::Error>;
