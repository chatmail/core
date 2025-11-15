use deltachat::qr::Qr;
use serde::Deserialize;
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
    /// Ask the user whether to join the broadcast channel.
    AskJoinBroadcast {
        /// The user-visible name of this broadcast channel
        name: String,
        /// A string of random characters,
        /// uniquely identifying this broadcast channel across all databases/clients.
        /// Called `grpid` for historic reasons:
        /// The id of multi-user chats is always called `grpid` in the database
        /// because groups were once the only multi-user chats.
        grpid: String,
        /// ID of the contact who owns the broadcast channel and created the QR code.
        contact_id: u32,
        /// Fingerprint of the broadcast channel owner's key as scanned from the QR code.
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
    /// Ask the user if they want to withdraw their own broadcast channel invite QR code.
    WithdrawJoinBroadcast {
        /// Broadcast name.
        name: String,
        /// ID, uniquely identifying this chat. Called grpid for historic reasons.
        grpid: String,
        /// Contact ID. Always `ContactId::SELF`.
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
    /// Ask the user if they want to revive their own broadcast channel invite QR code.
    ReviveJoinBroadcast {
        /// Broadcast name.
        name: String,
        /// Globally unique chat ID. Called grpid for historic reasons.
        grpid: String,
        /// Contact ID. Always `ContactId::SELF`.
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
            Qr::AskJoinBroadcast {
                name,
                grpid,
                contact_id,
                fingerprint,
                authcode,
                invitenumber,
            } => {
                let contact_id = contact_id.to_u32();
                let fingerprint = fingerprint.to_string();
                QrObject::AskJoinBroadcast {
                    name,
                    grpid,
                    contact_id,
                    fingerprint,
                    authcode,
                    invitenumber,
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
            Qr::WithdrawJoinBroadcast {
                name,
                grpid,
                contact_id,
                fingerprint,
                invitenumber,
                authcode,
            } => {
                let contact_id = contact_id.to_u32();
                let fingerprint = fingerprint.to_string();
                QrObject::WithdrawJoinBroadcast {
                    name,
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
            Qr::ReviveJoinBroadcast {
                name,
                grpid,
                contact_id,
                fingerprint,
                invitenumber,
                authcode,
            } => {
                let contact_id = contact_id.to_u32();
                let fingerprint = fingerprint.to_string();
                QrObject::ReviveJoinBroadcast {
                    name,
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

#[derive(Deserialize, TypeDef, schemars::JsonSchema)]
pub enum SecurejoinSource {
    /// Because of some problem, it is unknown where the QR code came from.
    Unknown,
    /// The user opened a link somewhere outside Delta Chat
    ExternalLink,
    /// The user clicked on a link in a message inside Delta Chat
    InternalLink,
    /// The user clicked "Paste from Clipboard" in the QR scan activity
    Clipboard,
    /// The user clicked "Load QR code as image" in the QR scan activity
    ImageLoaded,
    /// The user scanned a QR code
    Scan,
}

#[derive(Deserialize, TypeDef, schemars::JsonSchema)]
pub enum SecurejoinUiPath {
    /// The UI path is unknown, or the user didn't open the QR code screen at all.
    Unknown,
    /// The user directly clicked on the QR icon in the main screen
    QrIcon,
    /// The user first clicked on the `+` button in the main screen,
    /// and then on "New Contact"
    NewContact,
}

impl From<SecurejoinSource> for deltachat::SecurejoinSource {
    fn from(value: SecurejoinSource) -> Self {
        match value {
            SecurejoinSource::Unknown => deltachat::SecurejoinSource::Unknown,
            SecurejoinSource::ExternalLink => deltachat::SecurejoinSource::ExternalLink,
            SecurejoinSource::InternalLink => deltachat::SecurejoinSource::InternalLink,
            SecurejoinSource::Clipboard => deltachat::SecurejoinSource::Clipboard,
            SecurejoinSource::ImageLoaded => deltachat::SecurejoinSource::ImageLoaded,
            SecurejoinSource::Scan => deltachat::SecurejoinSource::Scan,
        }
    }
}

impl From<SecurejoinUiPath> for deltachat::SecurejoinUiPath {
    fn from(value: SecurejoinUiPath) -> Self {
        match value {
            SecurejoinUiPath::Unknown => deltachat::SecurejoinUiPath::Unknown,
            SecurejoinUiPath::QrIcon => deltachat::SecurejoinUiPath::QrIcon,
            SecurejoinUiPath::NewContact => deltachat::SecurejoinUiPath::NewContact,
        }
    }
}
