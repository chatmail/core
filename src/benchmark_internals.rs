//! Re-exports of internal functions needed for benchmarks.
#![allow(missing_docs)] // Not necessary to put a doc comment on the pub functions here

use anyhow::Result;
use deltachat_contact_tools::EmailAddress;
use std::collections::BTreeMap;

use crate::chat::ChatId;
use crate::context::Context;
use crate::key;
use crate::key::DcKey;
use crate::mimeparser::MimeMessage;
pub use crate::pgp;

use self::pgp::KeyPair;

pub fn key_from_asc(data: &str) -> Result<(key::SignedSecretKey, BTreeMap<String, String>)> {
    key::SignedSecretKey::from_asc(data)
}

pub async fn store_self_keypair(context: &Context, keypair: &KeyPair) -> Result<()> {
    crate::key::store_self_keypair(context, keypair).await
}

pub async fn parse_and_get_text(context: &Context, imf_raw: &[u8]) -> Result<String> {
    let mime_parser = MimeMessage::from_bytes(context, imf_raw, None).await?;
    Ok(mime_parser.parts.into_iter().next().unwrap().msg)
}

pub async fn save_broadcast_shared_secret(
    context: &Context,
    chat_id: ChatId,
    secret: &str,
) -> Result<()> {
    crate::chat::save_broadcast_shared_secret(context, chat_id, secret).await
}

pub fn create_dummy_keypair(addr: &str) -> Result<KeyPair> {
    pgp::create_keypair(EmailAddress::new(addr)?)
}
