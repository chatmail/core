//! # Token module.
//!
//! Functions to read/write token from/to the database. A token is any string associated with a key.
//!
//! Tokens are used in SecureJoin verification protocols.

use anyhow::Result;
use deltachat_derive::{FromSql, ToSql};

use crate::context::Context;
use crate::tools::{create_id, time};

/// Token namespace
#[derive(
    Debug, Default, Display, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive, ToSql, FromSql,
)]
#[repr(u32)]
pub enum Namespace {
    #[default]
    Unknown = 0,
    Auth = 110,
    InviteNumber = 100,
}

/// Saves a token to the database.
pub async fn save(
    context: &Context,
    namespace: Namespace,
    foreign_key: Option<&str>,
    token: &str,
) -> Result<()> {
    context
        .sql
        .execute(
            "INSERT INTO tokens (namespc, foreign_key, token, timestamp) VALUES (?, ?, ?, ?)",
            (namespace, foreign_key.unwrap_or(""), token, time()),
        )
        .await?;
    Ok(())
}

/// Looks up most recently created token for a namespace / foreign key combination.
///
/// As there may be more than one such valid token,
/// (eg. when a qr code token is withdrawn, recreated and revived later),
/// use lookup() for qr-code creation only;
/// do not use lookup() to check for token validity.
///
/// To check if a given token is valid, use exists().
pub async fn lookup(
    context: &Context,
    namespace: Namespace,
    foreign_key: Option<&str>,
) -> Result<Option<String>> {
    context
        .sql
        .query_get_value(
            "SELECT token FROM tokens WHERE namespc=? AND foreign_key=? ORDER BY timestamp DESC LIMIT 1",
            (namespace, foreign_key.unwrap_or("")),
        )
        .await
}

pub async fn lookup_or_new(
    context: &Context,
    namespace: Namespace,
    foreign_key: Option<&str>,
) -> Result<String> {
    if let Some(token) = lookup(context, namespace, foreign_key).await? {
        return Ok(token);
    }

    let token = create_id();
    save(context, namespace, foreign_key, &token).await?;
    Ok(token)
}

pub async fn exists(context: &Context, namespace: Namespace, token: &str) -> Result<bool> {
    let exists = context
        .sql
        .exists(
            "SELECT COUNT(*) FROM tokens WHERE namespc=? AND token=?;",
            (namespace, token),
        )
        .await?;
    Ok(exists)
}

/// Looks up foreign key by auth token.
///
/// Returns None if auth token is not valid.
/// Returns an empty string if the token corresponds to "setup contact" rather than group join.
pub async fn auth_foreign_key(context: &Context, token: &str) -> Result<Option<String>> {
    context
        .sql
        .query_row_optional(
            "SELECT foreign_key FROM tokens WHERE namespc=? AND token=?",
            (Namespace::Auth, token),
            |row| {
                let foreign_key: String = row.get(0)?;
                Ok(foreign_key)
            },
        )
        .await
}

/// Resets all tokens corresponding to the `foreign_key`.
///
/// `foreign_key` is a group ID to reset all group tokens
/// or empty string to reset all setup contact tokens.
pub async fn delete(context: &Context, foreign_key: &str) -> Result<()> {
    context
        .sql
        .execute("DELETE FROM tokens WHERE foreign_key=?", (foreign_key,))
        .await?;
    Ok(())
}
