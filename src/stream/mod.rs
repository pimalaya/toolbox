#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "imap")]
pub mod imap;
#[cfg(feature = "jmap")]
pub mod jmap;
#[cfg(feature = "smtp")]
pub mod smtp;
mod stream;

#[doc(inline)]
pub use stream::*;
