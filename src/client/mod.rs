mod common;

#[cfg(feature = "async")]
pub mod impl_async;
#[cfg(feature = "async")]
pub use impl_async::PendingApproval;
#[cfg(not(feature = "async"))]
pub mod impl_blocking;
#[cfg(not(feature = "async"))]
pub use impl_blocking::PendingApproval;

pub use self::common::{Result, SdkmsClient, SdkmsClientBuilder};
