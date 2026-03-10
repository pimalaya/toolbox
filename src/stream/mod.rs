#[cfg(feature = "imap")]
pub mod imap;
#[cfg(feature = "smtp")]
pub mod smtp;
mod stream;

#[doc(inline)]
pub use stream::*;
