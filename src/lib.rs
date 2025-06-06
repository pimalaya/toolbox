#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

#[cfg(feature = "build")]
pub mod build;
#[cfg(feature = "terminal")]
pub mod terminal;
