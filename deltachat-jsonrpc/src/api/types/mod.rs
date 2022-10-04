use deltachat::qr::Qr;
use serde::Serialize;
use typescript_type_def::TypeDef;

pub mod account;
pub mod chat;
pub mod chat_list;
pub mod contact;
pub mod location;
pub mod message;
pub mod provider_info;
pub mod webxdc;

pub fn color_int_to_hex_string(color: u32) -> String {
    format!("{:#08x}", color).replace("0x", "#")
}

fn maybe_empty_string_to_option(string: String) -> Option<String> {
    if string.is_empty() {
        None
    } else {
        Some(string)
    }
}

#[derive(Serialize, TypeDef)]
#[serde(rename = "Qr", rename_all = "camelCase")]
#[serde(tag = "type")]
pub enum QrObject {
    AskVerifyContact {
        contact_id: u32,
        fingerprint: String,
        invitenumber: String,
        authcode: String,
    },
    AskVerifyGroup {
        grpname: String,
        grpid: String,
        contact_id: u32,
        fingerprint: String,
        invitenumber: String,
        authcode: String,
    },
    FprOk {
        contact_id: u32,
    },
    FprMismatch {
        contact_id: Option<u32>,
    },
    FprWithoutAddr {
        fingerprint: String,
    },
    Account {
        domain: String,
    },
    WebrtcInstance {
        domain: String,
        instance_pattern: String,
    },
    Addr {
        contact_id: u32,
        draft: Option<String>,
    },
    Url {
        url: String,
    },
    Text {
        text: String,
    },
    WithdrawVerifyContact {
        contact_id: u32,
        fingerprint: String,
        invitenumber: String,
        authcode: String,
    },
    WithdrawVerifyGroup {
        grpname: String,
        grpid: String,
        contact_id: u32,
        fingerprint: String,
        invitenumber: String,
        authcode: String,
    },
    ReviveVerifyContact {
        contact_id: u32,
        fingerprint: String,
        invitenumber: String,
        authcode: String,
    },
    ReviveVerifyGroup {
        grpname: String,
        grpid: String,
        contact_id: u32,
        fingerprint: String,
        invitenumber: String,
        authcode: String,
    },
    Login {
        address: String,
    },
}

impl From<Qr> for QrObject {
    fn from(qr: Qr) -> Self {
        match qr {
            Qr::AskVerifyContact {
                contact_id,
                fingerprint,
                invitenumber,
                authcode,
            } => {
                let contact_id = contact_id.to_u32();
                let fingerprint = fingerprint.to_string();
                QrObject::AskVerifyContact {
                    contact_id,
                    fingerprint,
                    invitenumber,
                    authcode,
                }
            }
            Qr::AskVerifyGroup {
                grpname,
                grpid,
                contact_id,
                fingerprint,
                invitenumber,
                authcode,
            } => {
                let contact_id = contact_id.to_u32();
                let fingerprint = fingerprint.to_string();
                QrObject::AskVerifyGroup {
                    grpname,
                    grpid,
                    contact_id,
                    fingerprint,
                    invitenumber,
                    authcode,
                }
            }
            Qr::FprOk { contact_id } => {
                let contact_id = contact_id.to_u32();
                QrObject::FprOk { contact_id }
            }
            Qr::FprMismatch { contact_id } => {
                let contact_id = contact_id.map(|contact_id| contact_id.to_u32());
                QrObject::FprMismatch { contact_id }
            }
            Qr::FprWithoutAddr { fingerprint } => QrObject::FprWithoutAddr { fingerprint },
            Qr::Account { domain } => QrObject::Account { domain },
            Qr::WebrtcInstance {
                domain,
                instance_pattern,
            } => QrObject::WebrtcInstance {
                domain,
                instance_pattern,
            },
            Qr::Addr { contact_id, draft } => {
                let contact_id = contact_id.to_u32();
                QrObject::Addr { contact_id, draft }
            }
            Qr::Url { url } => QrObject::Url { url },
            Qr::Text { text } => QrObject::Text { text },
            Qr::WithdrawVerifyContact {
                contact_id,
                fingerprint,
                invitenumber,
                authcode,
            } => {
                let contact_id = contact_id.to_u32();
                let fingerprint = fingerprint.to_string();
                QrObject::WithdrawVerifyContact {
                    contact_id,
                    fingerprint,
                    invitenumber,
                    authcode,
                }
            }
            Qr::WithdrawVerifyGroup {
                grpname,
                grpid,
                contact_id,
                fingerprint,
                invitenumber,
                authcode,
            } => {
                let contact_id = contact_id.to_u32();
                let fingerprint = fingerprint.to_string();
                QrObject::WithdrawVerifyGroup {
                    grpname,
                    grpid,
                    contact_id,
                    fingerprint,
                    invitenumber,
                    authcode,
                }
            }
            Qr::ReviveVerifyContact {
                contact_id,
                fingerprint,
                invitenumber,
                authcode,
            } => {
                let contact_id = contact_id.to_u32();
                let fingerprint = fingerprint.to_string();
                QrObject::ReviveVerifyContact {
                    contact_id,
                    fingerprint,
                    invitenumber,
                    authcode,
                }
            }
            Qr::ReviveVerifyGroup {
                grpname,
                grpid,
                contact_id,
                fingerprint,
                invitenumber,
                authcode,
            } => {
                let contact_id = contact_id.to_u32();
                let fingerprint = fingerprint.to_string();
                QrObject::ReviveVerifyGroup {
                    grpname,
                    grpid,
                    contact_id,
                    fingerprint,
                    invitenumber,
                    authcode,
                }
            }
            Qr::Login { address, .. } => QrObject::Login { address },
        }
    }
}
