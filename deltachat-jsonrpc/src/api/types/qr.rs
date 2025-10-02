use deltachat::qr::Qr;
use serde::Serialize;
use typescript_type_def::TypeDef;

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "Qr", rename_all = "camelCase")]
#[serde(tag = "kind")]
pub enum QrObject {
    /// Ask the user whether to verify the contact.
    ///
    /// If the user agrees, pass this QR code to [`crate::securejoin::join_securejoin`].
    AskVerifyContact {
        /// ID of the contact.
        contact_id: u32,
        /// Fingerprint of the contact key as scanned from the QR code.
        fingerprint: String,
        /// Invite number.
        invitenumber: String,
        /// Authentication code.
        authcode: String,
    },
    /// Ask the user whether to join the group.
    AskVerifyGroup {
        /// Group name.
        grpname: String,
        /// Group ID.
        grpid: String,
        /// ID of the contact.
        contact_id: u32,
        /// Fingerprint of the contact key as scanned from the QR code.
        fingerprint: String,
        /// Invite number.
        invitenumber: String,
        /// Authentication code.
        authcode: String,
    },
    /// Contact fingerprint is verified.
    ///
    /// Ask the user if they want to start chatting.
    FprOk {
        /// Contact ID.
        contact_id: u32,
    },
    /// Scanned fingerprint does not match the last seen fingerprint.
    FprMismatch {
        /// Contact ID.
        contact_id: Option<u32>,
    },
    /// The scanned QR code contains a fingerprint but no e-mail address.
    FprWithoutAddr {
        /// Key fingerprint.
        fingerprint: String,
    },
    /// Ask the user if they want to create an account on the given domain.
    Account {
        /// Server domain name.
        domain: String,
    },
    /// Provides a backup that can be retrieved using iroh-net based backup transfer protocol.
    Backup2 {
        /// Authentication token.
        auth_token: String,
        /// Iroh node address.
        node_addr: String,
    },
    BackupTooNew {},
    /// Ask the user if they want to use the given service for video chats.
    WebrtcInstance {
        domain: String,
        instance_pattern: String,
    },
    /// Ask the user if they want to use the given proxy.
    ///
    /// Note that HTTP(S) URLs without a path
    /// and query parameters are treated as HTTP(S) proxy URL.
    /// UI may want to still offer to open the URL
    /// in the browser if QR code contents
    /// starts with `http://` or `https://`
    /// and the QR code was not scanned from
    /// the proxy configuration screen.
    Proxy {
        /// Proxy URL.
        ///
        /// This is the URL that is going to be added.
        url: String,
        /// Host extracted from the URL to display in the UI.
        host: String,
        /// Port extracted from the URL to display in the UI.
        port: u16,
    },
    /// Contact address is scanned.
    ///
    /// Optionally, a draft message could be provided.
    /// Ask the user if they want to start chatting.
    Addr {
        /// Contact ID.
        contact_id: u32,
        /// Draft message.
        draft: Option<String>,
    },
    /// URL scanned.
    ///
    /// Ask the user if they want to open a browser or copy the URL to clipboard.
    Url {
        url: String,
    },
    /// Text scanned.
    ///
    /// Ask the user if they want to copy the text to clipboard.
    Text {
        text: String,
    },
    /// Ask the user if they want to withdraw their own QR code.
    WithdrawVerifyContact {
        /// Contact ID.
        contact_id: u32,
        /// Fingerprint of the contact key as scanned from the QR code.
        fingerprint: String,
        /// Invite number.
        invitenumber: String,
        /// Authentication code.
        authcode: String,
    },
    /// Ask the user if they want to withdraw their own group invite QR code.
    WithdrawVerifyGroup {
        /// Group name.
        grpname: String,
        /// Group ID.
        grpid: String,
        /// Contact ID.
        contact_id: u32,
        /// Fingerprint of the contact key as scanned from the QR code.
        fingerprint: String,
        /// Invite number.
        invitenumber: String,
        /// Authentication code.
        authcode: String,
    },
    /// Ask the user if they want to revive their own QR code.
    ReviveVerifyContact {
        /// Contact ID.
        contact_id: u32,
        /// Fingerprint of the contact key as scanned from the QR code.
        fingerprint: String,
        /// Invite number.
        invitenumber: String,
        /// Authentication code.
        authcode: String,
    },
    /// Ask the user if they want to revive their own group invite QR code.
    ReviveVerifyGroup {
        /// Contact ID.
        grpname: String,
        /// Group ID.
        grpid: String,
        /// Contact ID.
        contact_id: u32,
        /// Fingerprint of the contact key as scanned from the QR code.
        fingerprint: String,
        /// Invite number.
        invitenumber: String,
        /// Authentication code.
        authcode: String,
    },
    /// `dclogin:` scheme parameters.
    ///
    /// Ask the user if they want to login with the email address.
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
            Qr::Backup2 {
                ref node_addr,
                auth_token,
            } => QrObject::Backup2 {
                node_addr: serde_json::to_string(node_addr).unwrap_or_default(),
                auth_token,
            },
            Qr::BackupTooNew {} => QrObject::BackupTooNew {},
            Qr::Proxy { url, host, port } => QrObject::Proxy { url, host, port },
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
