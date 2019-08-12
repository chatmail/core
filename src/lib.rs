#![deny(clippy::correctness)]
// TODO: make all of these errors, such that clippy actually passes.
#![warn(clippy::all, clippy::perf, clippy::not_unsafe_ptr_arg_deref)]
// This is nice, but for now just annoying.
#![allow(clippy::unreadable_literal)]
#![feature(ptr_wrapping_offset_from)]

#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate num_derive;
#[macro_use]
extern crate smallvec;
#[macro_use]
extern crate rusqlite;
extern crate strum;
#[macro_use]
extern crate strum_macros;

#[macro_use]
mod log;
#[macro_use]
pub mod error;

pub mod aheader;
pub mod chatlist;
pub mod config;
pub mod constants;
pub mod contact;
pub mod context;
pub mod imap;
pub mod key;
pub mod keyring;
pub mod oauth2;
pub mod param;
pub mod peerstate;
pub mod pgp;
pub mod smtp;
pub mod sql;
pub mod stock;
pub mod types;
#[macro_use]
pub mod x;

pub mod dc_array;
pub mod dc_chat;
pub mod dc_configure;
pub mod dc_dehtml;
pub mod dc_e2ee;
pub mod dc_imex;
pub mod dc_job;
pub mod dc_jobthread;
pub mod dc_location;
pub mod dc_loginparam;
pub mod dc_lot;
pub mod dc_mimefactory;
pub mod dc_mimeparser;
pub mod dc_move;
pub mod dc_msg;
pub mod dc_qr;
pub mod dc_receive_imf;
pub mod dc_saxparser;
pub mod dc_securejoin;
pub mod dc_simplify;
pub mod dc_strencode;
pub mod dc_token;
pub mod dc_tools;

pub use self::constants::*;

#[cfg(test)]
pub mod test_utils;
