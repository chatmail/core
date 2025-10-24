//! Supporting code for the QR-code invite.
//!
//! QR-codes are decoded into a more general-purpose [`Qr`] struct normally.  This makes working
//! with it rather hard, so here we have a wrapper type that specifically deals with Secure-Join
//! QR-codes so that the Secure-Join code can have more guarantees when dealing with this.

use anyhow::{Error, Result, bail};

use crate::contact::ContactId;
use crate::key::Fingerprint;
use crate::qr::Qr;

/// Represents the data from a QR-code scan.
///
/// There are methods to conveniently access fields present in both variants.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum QrInvite {
    Contact {
        contact_id: ContactId,
        fingerprint: Fingerprint,
        invitenumber: String,
        authcode: String,
    },
    Group {
        contact_id: ContactId,
        fingerprint: Fingerprint,
        name: String,
        grpid: String,
        invitenumber: String,
        authcode: String,
    },
    Broadcast {
        contact_id: ContactId,
        fingerprint: Fingerprint,
        name: String,
        grpid: String,
        invitenumber: String,
        authcode: String,
    },
}

impl QrInvite {
    /// The contact ID of the inviter.
    ///
    /// The actual QR-code contains a URL-encoded email address, but upon scanning this is
    /// translated to a contact ID.
    pub fn contact_id(&self) -> ContactId {
        match self {
            Self::Contact { contact_id, .. }
            | Self::Group { contact_id, .. }
            | Self::Broadcast { contact_id, .. } => *contact_id,
        }
    }

    /// The fingerprint of the inviter.
    pub fn fingerprint(&self) -> &Fingerprint {
        match self {
            Self::Contact { fingerprint, .. }
            | Self::Group { fingerprint, .. }
            | Self::Broadcast { fingerprint, .. } => fingerprint,
        }
    }

    /// The `INVITENUMBER` of the setup-contact/secure-join protocol.
    pub fn invitenumber(&self) -> &str {
        match self {
            Self::Contact { invitenumber, .. }
            | Self::Group { invitenumber, .. }
            | Self::Broadcast { invitenumber, .. } => invitenumber,
        }
    }

    /// The `AUTH` code of the setup-contact/secure-join protocol.
    pub fn authcode(&self) -> &str {
        match self {
            Self::Contact { authcode, .. }
            | Self::Group { authcode, .. }
            | Self::Broadcast { authcode, .. } => authcode,
        }
    }
}

impl TryFrom<Qr> for QrInvite {
    type Error = Error;

    fn try_from(qr: Qr) -> Result<Self> {
        match qr {
            Qr::AskVerifyContact {
                contact_id,
                fingerprint,
                invitenumber,
                authcode,
            } => Ok(QrInvite::Contact {
                contact_id,
                fingerprint,
                invitenumber,
                authcode,
            }),
            Qr::AskVerifyGroup {
                grpname,
                grpid,
                contact_id,
                fingerprint,
                invitenumber,
                authcode,
            } => Ok(QrInvite::Group {
                contact_id,
                fingerprint,
                name: grpname,
                grpid,
                invitenumber,
                authcode,
            }),
            Qr::AskJoinBroadcast {
                name,
                grpid,
                contact_id,
                fingerprint,
                authcode,
                invitenumber,
            } => Ok(QrInvite::Broadcast {
                name,
                grpid,
                contact_id,
                fingerprint,
                authcode,
                invitenumber,
            }),
            _ => bail!("Unsupported QR type"),
        }
    }
}

impl rusqlite::types::ToSql for QrInvite {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let json = serde_json::to_string(self)
            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
        let val = rusqlite::types::Value::Text(json);
        let out = rusqlite::types::ToSqlOutput::Owned(val);
        Ok(out)
    }
}

impl rusqlite::types::FromSql for QrInvite {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        String::column_result(value).and_then(|val| {
            serde_json::from_str(&val)
                .map_err(|err| rusqlite::types::FromSqlError::Other(Box::new(err)))
        })
    }
}
