//! # Delta Chat Core Library

#![recursion_limit = "256"]
#![forbid(unsafe_code)]
#![warn(
    unused,
    clippy::correctness,
    missing_debug_implementations,
    missing_docs,
    clippy::all,
    clippy::wildcard_imports,
    clippy::needless_borrow,
    clippy::cast_lossless,
    clippy::unused_async,
    clippy::explicit_iter_loop,
    clippy::explicit_into_iter_loop,
    clippy::cloned_instead_of_copied,
    clippy::manual_is_variant_and
)]
#![cfg_attr(not(test), warn(clippy::arithmetic_side_effects))]
#![cfg_attr(not(test), forbid(clippy::indexing_slicing))]
#![cfg_attr(not(test), forbid(clippy::string_slice))]
#![allow(
    clippy::match_bool,
    clippy::mixed_read_write_in_expression,
    clippy::bool_assert_comparison,
    clippy::manual_split_once,
    clippy::format_push_string,
    clippy::bool_to_int_with_if
)]

#[macro_use]
extern crate num_derive;
#[macro_use]
extern crate smallvec;
#[macro_use]
extern crate rusqlite;
#[macro_use]
extern crate strum_macros;

#[macro_use]
pub mod log;

#[cfg(feature = "internals")]
#[macro_use]
pub mod sql;
#[cfg(not(feature = "internals"))]
#[macro_use]
mod sql;

pub mod headerdef;

pub(crate) mod events;
pub use events::*;

mod aheader;
pub mod blob;
pub mod calls;
pub mod chat;
pub mod chatlist;
pub mod config;
mod configure;
pub mod constants;
pub mod contact;
pub mod context;
mod decrypt;
pub mod download;
mod e2ee;
pub mod ephemeral;
mod imap;
pub mod imex;
pub mod key;
pub mod location;
pub mod login_param;
pub mod message;
mod mimefactory;
pub mod mimeparser;
pub mod oauth2;
mod param;
#[cfg(not(feature = "internals"))]
mod pgp;
#[cfg(feature = "internals")]
pub mod pgp;
pub mod provider;
pub mod qr;
pub mod qr_code_generator;
pub mod quota;
pub mod release;
mod scheduler;
pub mod securejoin;
mod simplify;
mod smtp;
pub mod stock_str;
pub mod storage_usage;
mod sync;
mod timesmearing;
mod token;
mod transport;
mod update_helper;
pub mod webxdc;
#[macro_use]
mod dehtml;
mod authres;
pub mod color;
pub mod html;
pub mod net;
pub mod plaintext;
pub mod push;
mod stats;
pub use stats::SecurejoinSource;
pub use stats::SecurejoinUiPath;
pub mod summary;

mod debug_logging;
pub mod receive_imf;
pub mod tools;

pub mod accounts;
pub mod peer_channels;
pub mod reaction;

#[cfg(feature = "internals")]
pub mod internals_for_benches;

/// If set IMAP/incoming and SMTP/outgoing MIME messages will be printed.
pub const DCC_MIME_DEBUG: &str = "DCC_MIME_DEBUG";

#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod tests;
