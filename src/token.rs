//! # Token module.
//!
//! Functions to read/write token from/to the database. A token is any string associated with a key.
//!
//! Tokens are used in SecureJoin verification protocols.

use anyhow::Result;
use deltachat_derive::{FromSql, ToSql};

use crate::chat::ChatId;
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
    foreign_id: Option<ChatId>,
    token: &str,
) -> Result<()> {
    match foreign_id {
        Some(foreign_id) => context
            .sql
            .execute(
                "INSERT INTO tokens (namespc, foreign_id, token, timestamp) VALUES (?, ?, ?, ?);",
                (namespace, foreign_id, token, time()),
            )
            .await?,
        None => {
            context
                .sql
                .execute(
                    "INSERT INTO tokens (namespc, token, timestamp) VALUES (?, ?, ?);",
                    (namespace, token, time()),
                )
                .await?
        }
    };

    Ok(())
}

/// Lookup most recently created token for a namespace/chat combination.
///
/// As there may be more than one valid token for a chat-id,
/// (eg. when a qr code token is withdrawn, recreated and revived later),
/// use lookup() for qr-code creation only;
/// do not use lookup() to check for token validity.
///
/// To check if a given token is valid, use exists().
pub async fn lookup(
    context: &Context,
    namespace: Namespace,
    chat: Option<ChatId>,
) -> Result<Option<String>> {
    let token = match chat {
        Some(chat_id) => {
            context
                .sql
                .query_get_value(
                    "SELECT token FROM tokens WHERE namespc=? AND foreign_id=? ORDER BY timestamp DESC LIMIT 1;",
                    (namespace, chat_id),
                )
                .await?
        }
        // foreign_id is declared as `INTEGER DEFAULT 0` in the schema.
        None => {
            context
                .sql
                .query_get_value(
                    "SELECT token FROM tokens WHERE namespc=? AND foreign_id=0 ORDER BY timestamp DESC LIMIT 1;",
                    (namespace,),
                )
                .await?
        }
    };
    Ok(token)
}

pub async fn lookup_or_new(
    context: &Context,
    namespace: Namespace,
    foreign_id: Option<ChatId>,
) -> Result<String> {
    if let Some(token) = lookup(context, namespace, foreign_id).await? {
        return Ok(token);
    }

    let token = create_id();
    save(context, namespace, foreign_id, &token).await?;
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

/// Looks up ChatId by auth token.
///
/// Returns None if auth token is not valid.
/// Returns zero/unset ChatId if the token corresponds to "setup contact" rather than group join.
pub async fn auth_chat_id(context: &Context, token: &str) -> Result<Option<ChatId>> {
    let chat_id: Option<ChatId> = context
        .sql
        .query_row_optional(
            "SELECT foreign_id FROM tokens WHERE namespc=? AND token=?",
            (Namespace::Auth, token),
            |row| {
                let chat_id: ChatId = row.get(0)?;
                Ok(chat_id)
            },
        )
        .await?;
    Ok(chat_id)
}

pub async fn delete(context: &Context, namespace: Namespace, token: &str) -> Result<()> {
    context
        .sql
        .execute(
            "DELETE FROM tokens WHERE namespc=? AND token=?;",
            (namespace, token),
        )
        .await?;
    Ok(())
}
