//! # Legacy generic return values for C API.

use std::borrow::Cow;

use anyhow::Error;

use crate::message::MessageState;
use crate::qr::Qr;
use crate::summary::{Summary, SummaryPrefix};

/// An object containing a set of values.
/// The meaning of the values is defined by the function returning the object.
/// Lot objects are created
/// eg. by chatlist.get_summary() or dc_msg_get_summary().
///
/// *Lot* is used in the meaning *heap* here.
// The QR code grew too large.  So be it.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Lot {
    Summary(Summary),
    Qr(Qr),
    Error(String),
}

#[repr(u8)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Meaning {
    #[default]
    None = 0,
    Text1Draft = 1,
    Text1Username = 2,
    Text1Self = 3,
}

impl Lot {
    pub fn get_text1(&self) -> Option<Cow<'_, str>> {
        match self {
            Self::Summary(summary) => match &summary.prefix {
                None => None,
                Some(SummaryPrefix::Draft(text)) => Some(Cow::Borrowed(text)),
                Some(SummaryPrefix::Username(username)) => Some(Cow::Borrowed(username)),
                Some(SummaryPrefix::Me(text)) => Some(Cow::Borrowed(text)),
            },
            Self::Qr(qr) => match qr {
                Qr::AskVerifyContact { .. } => None,
                Qr::AskVerifyGroup { grpname, .. } => Some(Cow::Borrowed(grpname)),
                Qr::AskJoinBroadcast { name, .. } => Some(Cow::Borrowed(name)),
                Qr::FprOk { .. } => None,
                Qr::FprMismatch { .. } => None,
                Qr::FprWithoutAddr { fingerprint, .. } => Some(Cow::Borrowed(fingerprint)),
                Qr::Account { domain } => Some(Cow::Borrowed(domain)),
                Qr::Backup2 { .. } => None,
                Qr::BackupTooNew { .. } => None,
                Qr::Proxy { host, port, .. } => Some(Cow::Owned(format!("{host}:{port}"))),
                Qr::Addr { draft, .. } => draft.as_deref().map(Cow::Borrowed),
                Qr::Url { url } => Some(Cow::Borrowed(url)),
                Qr::Text { text } => Some(Cow::Borrowed(text)),
                Qr::WithdrawVerifyContact { .. } => None,
                Qr::WithdrawVerifyGroup { grpname, .. } => Some(Cow::Borrowed(grpname)),
                Qr::ReviveVerifyContact { .. } => None,
                Qr::ReviveVerifyGroup { grpname, .. } => Some(Cow::Borrowed(grpname)),
                Qr::Login { address, .. } => Some(Cow::Borrowed(address)),
            },
            Self::Error(err) => Some(Cow::Borrowed(err)),
        }
    }

    pub fn get_text2(&self) -> Option<Cow<'_, str>> {
        match self {
            Self::Summary(summary) => Some(summary.truncated_text(160)),
            Self::Qr(_) => None,
            Self::Error(_) => None,
        }
    }

    pub fn get_text1_meaning(&self) -> Meaning {
        match self {
            Self::Summary(summary) => match &summary.prefix {
                None => Meaning::None,
                Some(SummaryPrefix::Draft(_text)) => Meaning::Text1Draft,
                Some(SummaryPrefix::Username(_username)) => Meaning::Text1Username,
                Some(SummaryPrefix::Me(_text)) => Meaning::Text1Self,
            },
            Self::Qr(qr) => match qr {
                Qr::Addr {
                    draft: Some(_draft),
                    ..
                } => Meaning::Text1Draft,
                _ => Meaning::None,
            },
            Self::Error(_err) => Meaning::None,
        }
    }

    pub fn get_state(&self) -> LotState {
        match self {
            Self::Summary(summary) => summary.state.into(),
            Self::Qr(qr) => match qr {
                Qr::AskVerifyContact { .. } => LotState::QrAskVerifyContact,
                Qr::AskVerifyGroup { .. } => LotState::QrAskVerifyGroup,
                Qr::AskJoinBroadcast { .. } => LotState::QrAskJoinBroadcast,
                Qr::FprOk { .. } => LotState::QrFprOk,
                Qr::FprMismatch { .. } => LotState::QrFprMismatch,
                Qr::FprWithoutAddr { .. } => LotState::QrFprWithoutAddr,
                Qr::Account { .. } => LotState::QrAccount,
                Qr::Backup2 { .. } => LotState::QrBackup2,
                Qr::BackupTooNew { .. } => LotState::QrBackupTooNew,
                Qr::Proxy { .. } => LotState::QrProxy,
                Qr::Addr { .. } => LotState::QrAddr,
                Qr::Url { .. } => LotState::QrUrl,
                Qr::Text { .. } => LotState::QrText,
                Qr::WithdrawVerifyContact { .. } => LotState::QrWithdrawVerifyContact,
                Qr::WithdrawVerifyGroup { .. } => LotState::QrWithdrawVerifyGroup,
                Qr::ReviveVerifyContact { .. } => LotState::QrReviveVerifyContact,
                Qr::ReviveVerifyGroup { .. } => LotState::QrReviveVerifyGroup,
                Qr::Login { .. } => LotState::QrLogin,
            },
            Self::Error(_err) => LotState::QrError,
        }
    }

    pub fn get_id(&self) -> u32 {
        match self {
            Self::Summary(_) => Default::default(),
            Self::Qr(qr) => match qr {
                Qr::AskVerifyContact { contact_id, .. } => contact_id.to_u32(),
                Qr::AskVerifyGroup { .. } => Default::default(),
                Qr::AskJoinBroadcast { .. } => Default::default(),
                Qr::FprOk { contact_id } => contact_id.to_u32(),
                Qr::FprMismatch { contact_id } => contact_id.unwrap_or_default().to_u32(),
                Qr::FprWithoutAddr { .. } => Default::default(),
                Qr::Account { .. } => Default::default(),
                Qr::Backup2 { .. } => Default::default(),
                Qr::BackupTooNew { .. } => Default::default(),
                Qr::Proxy { .. } => Default::default(),
                Qr::Addr { contact_id, .. } => contact_id.to_u32(),
                Qr::Url { .. } => Default::default(),
                Qr::Text { .. } => Default::default(),
                Qr::WithdrawVerifyContact { contact_id, .. } => contact_id.to_u32(),
                Qr::WithdrawVerifyGroup { .. } => Default::default(),
                Qr::ReviveVerifyContact { contact_id, .. } => contact_id.to_u32(),
                Qr::ReviveVerifyGroup { .. } => Default::default(),
                Qr::Login { .. } => Default::default(),
            },
            Self::Error(_) => Default::default(),
        }
    }

    pub fn get_timestamp(&self) -> i64 {
        match self {
            Self::Summary(summary) => summary.timestamp,
            Self::Qr(_) => Default::default(),
            Self::Error(_) => Default::default(),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum LotState {
    #[default]
    Undefined = 0,

    // Qr States
    /// id=contact
    QrAskVerifyContact = 200,

    /// text1=groupname
    QrAskVerifyGroup = 202,

    /// text1=broadcast_name
    QrAskJoinBroadcast = 204,

    /// id=contact
    QrFprOk = 210,

    /// id=contact
    QrFprMismatch = 220,

    /// text1=formatted fingerprint
    QrFprWithoutAddr = 230,

    /// text1=domain
    QrAccount = 250,

    QrBackup2 = 252,

    QrBackupTooNew = 255,

    /// text1=address, text2=protocol
    QrProxy = 271,

    /// id=contact
    QrAddr = 320,

    /// text1=text
    QrText = 330,

    /// text1=URL
    QrUrl = 332,

    /// text1=error string
    QrError = 400,

    QrWithdrawVerifyContact = 500,

    /// text1=groupname
    QrWithdrawVerifyGroup = 502,

    QrReviveVerifyContact = 510,

    /// text1=groupname
    QrReviveVerifyGroup = 512,

    /// text1=email_address
    QrLogin = 520,

    // Message States
    MsgInFresh = 10,
    MsgInNoticed = 13,
    MsgInSeen = 16,
    MsgOutPreparing = 18,
    MsgOutDraft = 19,
    MsgOutPending = 20,
    MsgOutFailed = 24,
    MsgOutDelivered = 26,
    MsgOutMdnRcvd = 28,
}

impl From<MessageState> for LotState {
    fn from(s: MessageState) -> Self {
        use MessageState::*;
        match s {
            Undefined => LotState::Undefined,
            InFresh => LotState::MsgInFresh,
            InNoticed => LotState::MsgInNoticed,
            InSeen => LotState::MsgInSeen,
            OutPreparing => LotState::MsgOutPreparing,
            OutDraft => LotState::MsgOutDraft,
            OutPending => LotState::MsgOutPending,
            OutFailed => LotState::MsgOutFailed,
            OutDelivered => LotState::MsgOutDelivered,
            OutMdnRcvd => LotState::MsgOutMdnRcvd,
        }
    }
}

impl From<Summary> for Lot {
    fn from(summary: Summary) -> Self {
        Lot::Summary(summary)
    }
}

impl From<Qr> for Lot {
    fn from(qr: Qr) -> Self {
        Lot::Qr(qr)
    }
}

// Make it easy to convert errors into the final `Lot`.
impl From<Error> for Lot {
    fn from(error: Error) -> Self {
        Lot::Error(error.to_string())
    }
}
