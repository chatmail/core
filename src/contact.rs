//! Contacts module

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context as _, Result, bail, ensure};
use async_channel::{self as channel, Receiver, Sender};
use base64::Engine as _;
pub use deltachat_contact_tools::may_be_valid_addr;
use deltachat_contact_tools::{
    self as contact_tools, ContactAddress, VcardContact, addr_normalize, sanitize_name,
    sanitize_name_and_addr,
};
use deltachat_derive::{FromSql, ToSql};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use tokio::task;
use tokio::time::{Duration, timeout};

use crate::blob::BlobObject;
use crate::chat::ChatId;
use crate::color::str_to_color;
use crate::config::Config;
use crate::constants::{self, Blocked, Chattype};
use crate::context::Context;
use crate::events::EventType;
use crate::key::{
    DcKey, Fingerprint, SignedPublicKey, load_self_public_key, self_fingerprint,
    self_fingerprint_opt,
};
use crate::log::{LogExt, warn};
use crate::message::MessageState;
use crate::mimeparser::AvatarAction;
use crate::param::{Param, Params};
use crate::sync::{self, Sync::*};
use crate::tools::{SystemTime, duration_to_str, get_abs_path, normalize_text, time, to_lowercase};
use crate::{chat, chatlist_events, ensure_and_debug_assert_ne, stock_str};

/// Time during which a contact is considered as seen recently.
const SEEN_RECENTLY_SECONDS: i64 = 600;

/// Contact ID, including reserved IDs.
///
/// Some contact IDs are reserved to identify special contacts.  This
/// type can represent both the special as well as normal contacts.
#[derive(
    Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ContactId(u32);

impl ContactId {
    /// Undefined contact. Used as a placeholder for trashed messages.
    pub const UNDEFINED: ContactId = ContactId::new(0);

    /// The owner of the account.
    ///
    /// The email-address is set by `set_config` using "addr".
    pub const SELF: ContactId = ContactId::new(1);

    /// ID of the contact for info messages.
    pub const INFO: ContactId = ContactId::new(2);

    /// ID of the contact for device messages.
    pub const DEVICE: ContactId = ContactId::new(5);
    pub(crate) const LAST_SPECIAL: ContactId = ContactId::new(9);

    /// Address to go with [`ContactId::DEVICE`].
    ///
    /// This is used by APIs which need to return an email address for this contact.
    pub const DEVICE_ADDR: &'static str = "device@localhost";

    /// Creates a new [`ContactId`].
    pub const fn new(id: u32) -> ContactId {
        ContactId(id)
    }

    /// Whether this is a special [`ContactId`].
    ///
    /// Some [`ContactId`]s are reserved for special contacts like [`ContactId::SELF`],
    /// [`ContactId::INFO`] and [`ContactId::DEVICE`].  This function indicates whether this
    /// [`ContactId`] is any of the reserved special [`ContactId`]s (`true`) or whether it
    /// is the [`ContactId`] of a real contact (`false`).
    pub fn is_special(&self) -> bool {
        self.0 <= Self::LAST_SPECIAL.0
    }

    /// Numerical representation of the [`ContactId`].
    ///
    /// Each contact ID has a unique numerical representation which is used in the database
    /// (via [`rusqlite::ToSql`]) and also for FFI purposes.  In Rust code you should never
    /// need to use this directly.
    pub const fn to_u32(&self) -> u32 {
        self.0
    }

    /// Sets display name for existing contact.
    ///
    /// Display name may be an empty string,
    /// in which case the name displayed in the UI
    /// for this contact will switch to the
    /// contact's authorized name.
    pub async fn set_name(self, context: &Context, name: &str) -> Result<()> {
        self.set_name_ex(context, Sync, name).await
    }

    pub(crate) async fn set_name_ex(
        self,
        context: &Context,
        sync: sync::Sync,
        name: &str,
    ) -> Result<()> {
        let row = context
            .sql
            .transaction(|transaction| {
                let authname;
                let name_or_authname = if !name.is_empty() {
                    name
                } else {
                    authname = transaction.query_row(
                        "SELECT authname FROM contacts WHERE id=?",
                        (self,),
                        |row| {
                            let authname: String = row.get(0)?;
                            Ok(authname)
                        },
                    )?;
                    &authname
                };
                let is_changed = transaction.execute(
                    "UPDATE contacts SET name=?1, name_normalized=?2 WHERE id=?3 AND name!=?1",
                    (name, normalize_text(name_or_authname), self),
                )? > 0;
                if is_changed {
                    update_chat_names(context, transaction, self)?;
                    let (addr, fingerprint) = transaction.query_row(
                        "SELECT addr, fingerprint FROM contacts WHERE id=?",
                        (self,),
                        |row| {
                            let addr: String = row.get(0)?;
                            let fingerprint: String = row.get(1)?;
                            Ok((addr, fingerprint))
                        },
                    )?;
                    Ok(Some((addr, fingerprint)))
                } else {
                    Ok(None)
                }
            })
            .await?;
        if row.is_some() {
            context.emit_event(EventType::ContactsChanged(Some(self)));
        }

        if sync.into()
            && let Some((addr, fingerprint)) = row
        {
            if fingerprint.is_empty() {
                chat::sync(
                    context,
                    chat::SyncId::ContactAddr(addr),
                    chat::SyncAction::Rename(name.to_string()),
                )
                .await
                .log_err(context)
                .ok();
            } else {
                chat::sync(
                    context,
                    chat::SyncId::ContactFingerprint(fingerprint),
                    chat::SyncAction::Rename(name.to_string()),
                )
                .await
                .log_err(context)
                .ok();
            }
        }
        Ok(())
    }

    /// Mark contact as bot.
    pub(crate) async fn mark_bot(&self, context: &Context, is_bot: bool) -> Result<()> {
        context
            .sql
            .execute("UPDATE contacts SET is_bot=? WHERE id=?;", (is_bot, self.0))
            .await?;
        Ok(())
    }

    /// Reset gossip timestamp in all chats with this contact.
    pub(crate) async fn regossip_keys(&self, context: &Context) -> Result<()> {
        context
            .sql
            .execute(
                "UPDATE chats
                 SET gossiped_timestamp=0
                 WHERE EXISTS (SELECT 1 FROM chats_contacts
                               WHERE chats_contacts.chat_id=chats.id
                               AND chats_contacts.contact_id=?
                               AND chats_contacts.add_timestamp >= chats_contacts.remove_timestamp)",
                (self,),
            )
            .await?;
        Ok(())
    }

    /// Updates the origin of the contacts, but only if `origin` is higher than the current one.
    pub(crate) async fn scaleup_origin(
        context: &Context,
        ids: &[Self],
        origin: Origin,
    ) -> Result<()> {
        context
            .sql
            .transaction(|transaction| {
                let mut stmt = transaction
                    .prepare("UPDATE contacts SET origin=?1 WHERE id = ?2 AND origin < ?1")?;
                for id in ids {
                    stmt.execute((origin, id))?;
                }
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Returns contact address.
    pub async fn addr(&self, context: &Context) -> Result<String> {
        let addr = context
            .sql
            .query_row("SELECT addr FROM contacts WHERE id=?", (self,), |row| {
                let addr: String = row.get(0)?;
                Ok(addr)
            })
            .await?;
        Ok(addr)
    }
}

impl fmt::Display for ContactId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if *self == ContactId::UNDEFINED {
            write!(f, "Contact#Undefined")
        } else if *self == ContactId::SELF {
            write!(f, "Contact#Self")
        } else if *self == ContactId::INFO {
            write!(f, "Contact#Info")
        } else if *self == ContactId::DEVICE {
            write!(f, "Contact#Device")
        } else if self.is_special() {
            write!(f, "Contact#Special{}", self.0)
        } else {
            write!(f, "Contact#{}", self.0)
        }
    }
}

/// Allow converting [`ContactId`] to an SQLite type.
impl rusqlite::types::ToSql for ContactId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let val = rusqlite::types::Value::Integer(i64::from(self.0));
        let out = rusqlite::types::ToSqlOutput::Owned(val);
        Ok(out)
    }
}

/// Allow converting an SQLite integer directly into [`ContactId`].
impl rusqlite::types::FromSql for ContactId {
    fn column_result(value: rusqlite::types::ValueRef) -> rusqlite::types::FromSqlResult<Self> {
        i64::column_result(value).and_then(|val| {
            val.try_into()
                .map(ContactId::new)
                .map_err(|_| rusqlite::types::FromSqlError::OutOfRange(val))
        })
    }
}

/// Returns a vCard containing contacts with the given ids.
pub async fn make_vcard(context: &Context, contacts: &[ContactId]) -> Result<String> {
    let now = time();
    let mut vcard_contacts = Vec::with_capacity(contacts.len());
    for id in contacts {
        let c = Contact::get_by_id(context, *id).await?;
        let key = c.public_key(context).await?.map(|k| k.to_base64());
        let profile_image = match c.get_profile_image_ex(context, false).await? {
            None => None,
            Some(path) => tokio::fs::read(path)
                .await
                .log_err(context)
                .ok()
                .map(|data| base64::engine::general_purpose::STANDARD.encode(data)),
        };
        vcard_contacts.push(VcardContact {
            addr: c.addr,
            authname: c.authname,
            key,
            profile_image,
            biography: Some(c.status).filter(|s| !s.is_empty()),
            // Use the current time to not reveal our or contact's online time.
            timestamp: Ok(now),
        });
    }

    // XXX: newline at the end of vCard is trimmed
    // for compatibility with core <=1.155.3
    // Newer core should be able to deal with
    // trailing CRLF as the fix
    // <https://github.com/deltachat/deltachat-core-rust/pull/6522>
    // is merged.
    Ok(contact_tools::make_vcard(&vcard_contacts)
        .trim_end()
        .to_string())
}

/// Imports contacts from the given vCard.
///
/// Returns the ids of successfully processed contacts in the order they appear in `vcard`,
/// regardless of whether they are just created, modified or left untouched.
pub async fn import_vcard(context: &Context, vcard: &str) -> Result<Vec<ContactId>> {
    let contacts = contact_tools::parse_vcard(vcard);
    let mut contact_ids = Vec::with_capacity(contacts.len());
    for c in &contacts {
        let Ok(id) = import_vcard_contact(context, c)
            .await
            .with_context(|| format!("import_vcard_contact() failed for {}", c.addr))
            .log_err(context)
        else {
            continue;
        };
        contact_ids.push(id);
    }
    Ok(contact_ids)
}

async fn import_vcard_contact(context: &Context, contact: &VcardContact) -> Result<ContactId> {
    let addr = ContactAddress::new(&contact.addr).context("Invalid address")?;
    // Importing a vCard is also an explicit user action like creating a chat with the contact. We
    // mustn't use `Origin::AddressBook` here because the vCard may be created not by us, also we
    // want `contact.authname` to be saved as the authname and not a locally given name.
    let origin = Origin::CreateChat;
    let key = contact.key.as_ref().and_then(|k| {
        SignedPublicKey::from_base64(k)
            .with_context(|| {
                format!(
                    "import_vcard_contact: Cannot decode key for {}",
                    contact.addr
                )
            })
            .log_err(context)
            .ok()
    });

    let fingerprint;
    if let Some(public_key) = key {
        fingerprint = public_key.dc_fingerprint().hex();

        context
            .sql
            .execute(
                "INSERT INTO public_keys (fingerprint, public_key)
                 VALUES (?, ?)
                 ON CONFLICT (fingerprint)
                 DO NOTHING",
                (&fingerprint, public_key.to_bytes()),
            )
            .await?;
    } else {
        fingerprint = String::new();
    }

    let (id, modified) =
        match Contact::add_or_lookup_ex(context, &contact.authname, &addr, &fingerprint, origin)
            .await
        {
            Err(e) => return Err(e).context("Contact::add_or_lookup() failed"),
            Ok((ContactId::SELF, _)) => return Ok(ContactId::SELF),
            Ok(val) => val,
        };
    if modified != Modifier::None {
        context.emit_event(EventType::ContactsChanged(Some(id)));
    }
    if modified != Modifier::Created {
        return Ok(id);
    }
    let path = match &contact.profile_image {
        Some(image) => match BlobObject::store_from_base64(context, image)? {
            None => {
                warn!(
                    context,
                    "import_vcard_contact: Could not decode avatar for {}.", contact.addr
                );
                None
            }
            Some(path) => Some(path),
        },
        None => None,
    };
    if let Some(path) = path
        && let Err(e) = set_profile_image(context, id, &AvatarAction::Change(path)).await
    {
        warn!(
            context,
            "import_vcard_contact: Could not set avatar for {}: {e:#}.", contact.addr
        );
    }
    if let Some(biography) = &contact.biography
        && let Err(e) = set_status(context, id, biography.to_owned()).await
    {
        warn!(
            context,
            "import_vcard_contact: Could not set biography for {}: {e:#}.", contact.addr
        );
    }
    Ok(id)
}

/// An object representing a single contact in memory.
///
/// The contact object is not updated.
/// If you want an update, you have to recreate the object.
///
/// The library makes sure
/// only to use names _authorized_ by the contact in `To:` or `Cc:`.
/// *Given-names* as "Daddy" or "Honey" are not used there.
/// For this purpose, internally, two names are tracked -
/// authorized name and given name.
/// By default, these names are equal, but functions working with contact names
/// only affect the given name.
#[derive(Debug)]
pub struct Contact {
    /// The contact ID.
    pub id: ContactId,

    /// Contact name. It is recommended to use `Contact::get_name`,
    /// `Contact::get_display_name` or `Contact::get_name_n_addr` to access this field.
    /// May be empty, initially set to `authname`.
    name: String,

    /// Name authorized by the contact himself. Only this name may be spread to others,
    /// e.g. in To:-lists. May be empty. It is recommended to use `Contact::get_authname`,
    /// to access this field.
    authname: String,

    /// E-Mail-Address of the contact. It is recommended to use `Contact::get_addr` to access this field.
    addr: String,

    /// OpenPGP key fingerprint.
    /// Non-empty iff the contact is a key-contact,
    /// identified by this fingerprint.
    fingerprint: Option<String>,

    /// Blocked state. Use contact_is_blocked to access this field.
    pub blocked: bool,

    /// Time when the contact was seen last time, Unix time in seconds.
    last_seen: i64,

    /// The origin/source of the contact.
    pub origin: Origin,

    /// Parameters as Param::ProfileImage
    pub param: Params,

    /// Last seen message signature for this contact, to be displayed in the profile.
    status: String,

    /// If the contact is a bot.
    is_bot: bool,
}

/// Possible origins of a contact.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    FromPrimitive,
    ToPrimitive,
    FromSql,
    ToSql,
)]
#[repr(u32)]
pub enum Origin {
    /// Unknown origin. Can be used as a minimum origin to specify that the caller does not care
    /// about origin of the contact.
    #[default]
    Unknown = 0,

    /// The contact is a mailing list address, needed to unblock mailing lists
    MailinglistAddress = 0x2,

    /// Hidden on purpose, e.g. addresses with the word "noreply" in it
    Hidden = 0x8,

    /// From: of incoming messages of unknown sender
    IncomingUnknownFrom = 0x10,

    /// Cc: of incoming messages of unknown sender
    IncomingUnknownCc = 0x20,

    /// To: of incoming messages of unknown sender
    IncomingUnknownTo = 0x40,

    /// Address scanned but not verified.
    UnhandledQrScan = 0x80,

    /// Address scanned from a SecureJoin QR code, but not verified yet.
    UnhandledSecurejoinQrScan = 0x81,

    /// Reply-To: of incoming message of known sender
    /// Contacts with at least this origin value are shown in the contact list.
    IncomingReplyTo = 0x100,

    /// Cc: of incoming message of known sender
    IncomingCc = 0x200,

    /// additional To:'s of incoming message of known sender
    IncomingTo = 0x400,

    /// a chat was manually created for this user, but no message yet sent
    CreateChat = 0x800,

    /// message sent by us
    OutgoingBcc = 0x1000,

    /// message sent by us
    OutgoingCc = 0x2000,

    /// message sent by us
    OutgoingTo = 0x4000,

    /// internal use
    Internal = 0x40000,

    /// address is in our address book
    AddressBook = 0x80000,

    /// set on Alice's side for contacts like Bob that have scanned the QR code offered by her. Only means the contact has once been established using the "securejoin" procedure in the past, getting the current key verification status requires calling contact_is_verified() !
    SecurejoinInvited = 0x0100_0000,

    /// Set on Bob's side for contacts scanned from a QR code.
    /// Only means the contact has been scanned from the QR code,
    /// but does not mean that securejoin succeeded
    /// or the key has not changed since the last scan.
    /// Getting the current key verification status requires calling contact_is_verified() !
    SecurejoinJoined = 0x0200_0000,

    /// contact added manually by create_contact(), this should be the largest origin as otherwise the user cannot modify the names
    ManuallyCreated = 0x0400_0000,
}

impl Origin {
    /// Contacts that are known, i. e. they came in via accepted contacts or
    /// themselves an accepted contact. Known contacts are shown in the
    /// contact list when one creates a chat and wants to add members etc.
    pub fn is_known(self) -> bool {
        self >= Origin::IncomingReplyTo
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Modifier {
    None,
    Modified,
    Created,
}

impl Contact {
    /// Loads a single contact object from the database.
    ///
    /// Returns an error if the contact does not exist.
    ///
    /// For contact ContactId::SELF (1), the function returns sth.
    /// like "Me" in the selected language and the email address
    /// defined by set_config().
    ///
    /// For contact ContactId::DEVICE, the function overrides
    /// the contact name and status with localized address.
    pub async fn get_by_id(context: &Context, contact_id: ContactId) -> Result<Self> {
        let contact = Self::get_by_id_optional(context, contact_id)
            .await?
            .with_context(|| format!("contact {contact_id} not found"))?;
        Ok(contact)
    }

    /// Loads a single contact object from the database.
    ///
    /// Similar to [`Contact::get_by_id()`] but returns `None` if the contact does not exist.
    pub async fn get_by_id_optional(
        context: &Context,
        contact_id: ContactId,
    ) -> Result<Option<Self>> {
        if let Some(mut contact) = context
            .sql
            .query_row_optional(
                "SELECT c.name, c.addr, c.origin, c.blocked, c.last_seen,
                c.authname, c.param, c.status, c.is_bot, c.fingerprint
               FROM contacts c
              WHERE c.id=?;",
                (contact_id,),
                |row| {
                    let name: String = row.get(0)?;
                    let addr: String = row.get(1)?;
                    let origin: Origin = row.get(2)?;
                    let blocked: Option<bool> = row.get(3)?;
                    let last_seen: i64 = row.get(4)?;
                    let authname: String = row.get(5)?;
                    let param: String = row.get(6)?;
                    let status: Option<String> = row.get(7)?;
                    let is_bot: bool = row.get(8)?;
                    let fingerprint: Option<String> =
                        Some(row.get(9)?).filter(|s: &String| !s.is_empty());
                    let contact = Self {
                        id: contact_id,
                        name,
                        authname,
                        addr,
                        fingerprint,
                        blocked: blocked.unwrap_or_default(),
                        last_seen,
                        origin,
                        param: param.parse().unwrap_or_default(),
                        status: status.unwrap_or_default(),
                        is_bot,
                    };
                    Ok(contact)
                },
            )
            .await?
        {
            if contact_id == ContactId::SELF {
                contact.name = stock_str::self_msg(context).await;
                contact.authname = context
                    .get_config(Config::Displayname)
                    .await?
                    .unwrap_or_default();
                contact.addr = context
                    .get_config(Config::ConfiguredAddr)
                    .await?
                    .unwrap_or_default();
                if let Some(self_fp) = self_fingerprint_opt(context).await? {
                    contact.fingerprint = Some(self_fp.to_string());
                }
                contact.status = context
                    .get_config(Config::Selfstatus)
                    .await?
                    .unwrap_or_default();
            } else if contact_id == ContactId::DEVICE {
                contact.name = stock_str::device_messages(context).await;
                contact.addr = ContactId::DEVICE_ADDR.to_string();
                contact.status = stock_str::device_messages_hint(context).await;
            }
            Ok(Some(contact))
        } else {
            Ok(None)
        }
    }

    /// Returns `true` if this contact is blocked.
    pub fn is_blocked(&self) -> bool {
        self.blocked
    }

    /// Returns last seen timestamp.
    pub fn last_seen(&self) -> i64 {
        self.last_seen
    }

    /// Returns `true` if this contact was seen recently.
    #[expect(clippy::arithmetic_side_effects)]
    pub fn was_seen_recently(&self) -> bool {
        time() - self.last_seen <= SEEN_RECENTLY_SECONDS
    }

    /// Check if a contact is blocked.
    pub async fn is_blocked_load(context: &Context, id: ContactId) -> Result<bool> {
        let blocked = context
            .sql
            .query_row("SELECT blocked FROM contacts WHERE id=?", (id,), |row| {
                let blocked: bool = row.get(0)?;
                Ok(blocked)
            })
            .await?;
        Ok(blocked)
    }

    /// Block the given contact.
    pub async fn block(context: &Context, id: ContactId) -> Result<()> {
        set_blocked(context, Sync, id, true).await
    }

    /// Unblock the given contact.
    pub async fn unblock(context: &Context, id: ContactId) -> Result<()> {
        set_blocked(context, Sync, id, false).await
    }

    /// Add a single contact as a result of an _explicit_ user action.
    ///
    /// We assume, the contact name, if any, is entered by the user and is used "as is" therefore,
    /// normalize() is *not* called for the name. If the contact is blocked, it is unblocked.
    ///
    /// To add a number of contacts, see `add_address_book()` which is much faster for adding
    /// a bunch of addresses.
    ///
    /// May result in a `#DC_EVENT_CONTACTS_CHANGED` event.
    pub async fn create(context: &Context, name: &str, addr: &str) -> Result<ContactId> {
        Self::create_ex(context, Sync, name, addr).await
    }

    pub(crate) async fn create_ex(
        context: &Context,
        sync: sync::Sync,
        name: &str,
        addr: &str,
    ) -> Result<ContactId> {
        let (name, addr) = sanitize_name_and_addr(name, addr);
        let addr = ContactAddress::new(&addr)?;

        let (contact_id, sth_modified) =
            Contact::add_or_lookup(context, &name, &addr, Origin::ManuallyCreated)
                .await
                .context("add_or_lookup")?;
        let blocked = Contact::is_blocked_load(context, contact_id).await?;
        match sth_modified {
            Modifier::None => {}
            Modifier::Modified | Modifier::Created => {
                context.emit_event(EventType::ContactsChanged(Some(contact_id)))
            }
        }
        if blocked {
            set_blocked(context, Nosync, contact_id, false).await?;
        }

        if sync.into() && sth_modified != Modifier::None {
            chat::sync(
                context,
                chat::SyncId::ContactAddr(addr.to_string()),
                chat::SyncAction::Rename(name.to_string()),
            )
            .await
            .log_err(context)
            .ok();
        }
        Ok(contact_id)
    }

    /// Mark messages from a contact as noticed.
    pub async fn mark_noticed(context: &Context, id: ContactId) -> Result<()> {
        context
            .sql
            .execute(
                "UPDATE msgs SET state=? WHERE from_id=? AND state=?;",
                (MessageState::InNoticed, id, MessageState::InFresh),
            )
            .await?;
        Ok(())
    }

    /// Returns whether contact is a bot.
    pub fn is_bot(&self) -> bool {
        self.is_bot
    }

    /// Looks up a known and unblocked contact with a given e-mail address.
    /// To get a list of all known and unblocked contacts, use contacts_get_contacts().
    ///
    ///
    /// **POTENTIAL SECURITY ISSUE**: If there are multiple contacts with this address
    /// (e.g. an address-contact and a key-contact),
    /// this looks up the most recently seen contact,
    /// i.e. which contact is returned depends on which contact last sent a message.
    /// If the user just clicked on a mailto: link, then this is the best thing you can do.
    /// But **DO NOT** internally represent contacts by their email address
    /// and do not use this function to look them up;
    /// otherwise this function will sometimes look up the wrong contact.
    /// Instead, you should internally represent contacts by their ids.
    ///
    /// Known and unblocked contacts will be returned by `get_contacts()`.
    ///
    /// To validate an e-mail address independently of the contact database
    /// use `may_be_valid_addr()`.
    ///
    /// Returns the contact ID of the contact belonging to the e-mail address or 0 if there is no
    /// contact that is or was introduced by an accepted contact.
    pub async fn lookup_id_by_addr(
        context: &Context,
        addr: &str,
        min_origin: Origin,
    ) -> Result<Option<ContactId>> {
        Self::lookup_id_by_addr_ex(context, addr, min_origin, Some(Blocked::Not)).await
    }

    /// The same as `lookup_id_by_addr()`, but internal function. Currently also allows looking up
    /// not unblocked contacts.
    pub(crate) async fn lookup_id_by_addr_ex(
        context: &Context,
        addr: &str,
        min_origin: Origin,
        blocked: Option<Blocked>,
    ) -> Result<Option<ContactId>> {
        if addr.is_empty() {
            bail!("lookup_id_by_addr: empty address");
        }

        let addr_normalized = addr_normalize(addr);

        if context.is_configured().await? && context.is_self_addr(addr).await? {
            return Ok(Some(ContactId::SELF));
        }

        let id = context
            .sql
            .query_get_value(
                "SELECT id FROM contacts
                 WHERE addr=?1 COLLATE NOCASE
                     AND id>?2 AND origin>=?3 AND (? OR blocked=?)
                 ORDER BY
                     (
                         SELECT COUNT(*) FROM chats c
                         INNER JOIN chats_contacts cc
                         ON c.id=cc.chat_id
                         WHERE c.type=?
                             AND c.id>?
                             AND c.blocked=?
                             AND cc.contact_id=contacts.id
                     ) DESC,
                     last_seen DESC, fingerprint DESC
                 LIMIT 1",
                (
                    &addr_normalized,
                    ContactId::LAST_SPECIAL,
                    min_origin as u32,
                    blocked.is_none(),
                    blocked.unwrap_or(Blocked::Not),
                    Chattype::Single,
                    constants::DC_CHAT_ID_LAST_SPECIAL,
                    blocked.unwrap_or(Blocked::Not),
                ),
            )
            .await?;
        Ok(id)
    }

    pub(crate) async fn add_or_lookup(
        context: &Context,
        name: &str,
        addr: &ContactAddress,
        origin: Origin,
    ) -> Result<(ContactId, Modifier)> {
        Self::add_or_lookup_ex(context, name, addr, "", origin).await
    }

    /// Lookup a contact and create it if it does not exist yet.
    /// If `fingerprint` is non-empty, a key-contact with this fingerprint is added / looked up.
    /// Otherwise, an address-contact with `addr` is added / looked up.
    /// A name and an "origin" can be given.
    ///
    /// The "origin" is where the address comes from -
    /// from-header, cc-header, addressbook, qr, manual-edit etc.
    /// In general, "better" origins overwrite the names of "worse" origins -
    /// Eg. if we got a name in cc-header and later in from-header, the name will change -
    /// this does not happen the other way round.
    ///
    /// The "best" origin are manually created contacts -
    /// names given manually can only be overwritten by further manual edits
    /// (until they are set empty again or reset to the name seen in the From-header).
    ///
    /// These manually edited names are _never_ used for sending on the wire -
    /// this should avoid sending sth. as "Mama" or "Daddy" to some 3rd party.
    /// Instead, for the wire, we use so called "authnames"
    /// that can only be set and updated by a From-header.
    ///
    /// The different names used in the function are:
    /// - "name": name passed as function argument, belonging to the given origin
    /// - "row_name": current name used in the database, typically set to "name"
    /// - "row_authname": name as authorized from a contact, set only through a From-header
    ///   Depending on the origin, both, "row_name" and "row_authname" are updated from "name".
    ///
    /// Returns the contact_id and a `Modifier` value indicating if a modification occurred.
    pub(crate) async fn add_or_lookup_ex(
        context: &Context,
        name: &str,
        addr: &str,
        fingerprint: &str,
        mut origin: Origin,
    ) -> Result<(ContactId, Modifier)> {
        let mut sth_modified = Modifier::None;

        ensure!(
            !addr.is_empty() || !fingerprint.is_empty(),
            "Can not add_or_lookup empty address"
        );
        ensure!(origin != Origin::Unknown, "Missing valid origin");

        if context.is_configured().await? && context.is_self_addr(addr).await? {
            return Ok((ContactId::SELF, sth_modified));
        }

        if !fingerprint.is_empty() && context.is_configured().await? {
            let fingerprint_self = self_fingerprint(context)
                .await
                .context("self_fingerprint")?;
            if fingerprint == fingerprint_self {
                return Ok((ContactId::SELF, sth_modified));
            }
        }

        let mut name = sanitize_name(name);
        if origin <= Origin::OutgoingTo {
            // The user may accidentally have written to a "noreply" address with another MUA:
            if addr.contains("noreply")
                || addr.contains("no-reply")
                || addr.starts_with("notifications@")
                // Filter out use-once addresses (like reply+AEJDGPOECLAP...@reply.github.com):
                || (addr.len() > 50 && addr.contains('+'))
            {
                info!(context, "hiding contact {}", addr);
                origin = Origin::Hidden;
                // For these kind of email addresses, sender and address often don't belong together
                // (like hocuri <notifications@github.com>). In this example, hocuri shouldn't
                // be saved as the displayname for notifications@github.com.
                name = "".to_string();
            }
        }

        // If the origin indicates that user entered the contact manually, from the address book or
        // from the QR-code scan (potentially from the address book of their other phone), then name
        // should go into the "name" column and never into "authname" column, to avoid leaking it
        // into the network.
        let manual = matches!(
            origin,
            Origin::ManuallyCreated | Origin::AddressBook | Origin::UnhandledQrScan
        );

        let mut update_addr = false;

        let row_id = context
            .sql
            .transaction(|transaction| {
                let row = transaction
                    .query_row(
                        "SELECT id, name, addr, origin, authname
                         FROM contacts
                         WHERE fingerprint=?1 AND
                         (?1<>'' OR addr=?2 COLLATE NOCASE)",
                        (fingerprint, addr),
                        |row| {
                            let row_id: u32 = row.get(0)?;
                            let row_name: String = row.get(1)?;
                            let row_addr: String = row.get(2)?;
                            let row_origin: Origin = row.get(3)?;
                            let row_authname: String = row.get(4)?;

                            Ok((row_id, row_name, row_addr, row_origin, row_authname))
                        },
                    )
                    .optional()?;

                let row_id;
                if let Some((id, row_name, row_addr, row_origin, row_authname)) = row {
                    let update_name = manual && name != row_name;
                    let update_authname = !manual
                        && name != row_authname
                        && !name.is_empty()
                        && (origin >= row_origin
                            || origin == Origin::IncomingUnknownFrom
                            || row_authname.is_empty());

                    row_id = id;
                    if origin >= row_origin && addr != row_addr {
                        update_addr = true;
                    }
                    if update_name || update_authname || update_addr || origin > row_origin {
                        let new_name = if update_name {
                            name.to_string()
                        } else {
                            row_name
                        };
                        let new_authname = if update_authname {
                            name.to_string()
                        } else {
                            row_authname
                        };

                        transaction.execute(
                            "UPDATE contacts SET name=?, name_normalized=?, addr=?, origin=?, authname=? WHERE id=?",
                            (
                                &new_name,
                                normalize_text(
                                    if !new_name.is_empty() {
                                        &new_name
                                    } else {
                                        &new_authname
                                    }),
                                if update_addr {
                                    addr.to_string()
                                } else {
                                    row_addr
                                },
                                if origin > row_origin {
                                    origin
                                } else {
                                    row_origin
                                },
                                &new_authname,
                                row_id,
                            ),
                        )?;

                        if update_name || update_authname {
                            let contact_id = ContactId::new(row_id);
                            update_chat_names(context, transaction, contact_id)?;
                        }
                        sth_modified = Modifier::Modified;
                    }
                } else {
                    transaction.execute(
                        "
INSERT INTO contacts (name, name_normalized, addr, fingerprint, origin, authname)
VALUES (?, ?, ?, ?, ?, ?)
                        ",
                        (
                            if manual { &name } else { "" },
                            normalize_text(&name),
                            &addr,
                            fingerprint,
                            origin,
                            if manual { "" } else { &name },
                        ),
                    )?;

                    sth_modified = Modifier::Created;
                    row_id = u32::try_from(transaction.last_insert_rowid())?;
                    if fingerprint.is_empty() {
                        info!(context, "Added contact id={row_id} addr={addr}.");
                    } else {
                        info!(
                            context,
                            "Added contact id={row_id} fpr={fingerprint} addr={addr}."
                        );
                    }
                }
                Ok(row_id)
            })
            .await?;

        let contact_id = ContactId::new(row_id);

        Ok((contact_id, sth_modified))
    }

    /// Add a number of contacts.
    ///
    /// Typically used to add the whole address book from the OS. As names here are typically not
    /// well formatted, we call `normalize()` for each name given.
    ///
    /// No email-address is added twice.
    /// Trying to add email-addresses that are already in the contact list,
    /// results in updating the name unless the name was changed manually by the user.
    /// If any email-address or any name is really updated,
    /// the event `DC_EVENT_CONTACTS_CHANGED` is sent.
    ///
    /// To add a single contact entered by the user, you should prefer `Contact::create`,
    /// however, for adding a bunch of addresses, this function is much faster.
    ///
    /// The `addr_book` is a multiline string in the format `Name one\nAddress one\nName two\nAddress two`.
    ///
    /// Returns the number of modified contacts.
    #[expect(clippy::arithmetic_side_effects)]
    pub async fn add_address_book(context: &Context, addr_book: &str) -> Result<usize> {
        let mut modify_cnt = 0;

        for (name, addr) in split_address_book(addr_book) {
            let (name, addr) = sanitize_name_and_addr(name, addr);
            match ContactAddress::new(&addr) {
                Ok(addr) => {
                    match Contact::add_or_lookup(context, &name, &addr, Origin::AddressBook).await {
                        Ok((_, modified)) => {
                            if modified != Modifier::None {
                                modify_cnt += 1
                            }
                        }
                        Err(err) => {
                            warn!(
                                context,
                                "Failed to add address {} from address book: {}", addr, err
                            );
                        }
                    }
                }
                Err(err) => {
                    warn!(context, "{:#}.", err);
                }
            }
        }
        if modify_cnt > 0 {
            context.emit_event(EventType::ContactsChanged(None));
        }

        Ok(modify_cnt)
    }

    /// Returns known and unblocked contacts.
    ///
    /// To get information about a single contact, see get_contact().
    /// By default, key-contacts are listed.
    ///
    /// * `listflags` - A combination of flags:
    ///   - `DC_GCL_ADD_SELF` - Add SELF unless filtered by other parameters.
    ///   - `DC_GCL_ADDRESS` - List address-contacts instead of key-contacts.
    /// * `query` - A string to filter the list.
    pub async fn get_all(
        context: &Context,
        listflags: u32,
        query: Option<&str>,
    ) -> Result<Vec<ContactId>> {
        let self_addrs = context
            .get_all_self_addrs()
            .await?
            .into_iter()
            .collect::<HashSet<_>>();
        let mut add_self = false;
        let mut ret = Vec::new();
        let flag_add_self = (listflags & constants::DC_GCL_ADD_SELF) != 0;
        let flag_address = (listflags & constants::DC_GCL_ADDRESS) != 0;
        let minimal_origin = if context.get_config_bool(Config::Bot).await? {
            Origin::Unknown
        } else {
            Origin::IncomingReplyTo
        };
        if query.is_some() {
            let query_lowercased = query.unwrap_or("").to_lowercase();
            let s3str_like_cmd = format!("%{}%", query_lowercased);
            context
                .sql
                .query_map(
                    "
SELECT c.id, c.addr FROM contacts c
WHERE c.id>?
    AND (c.fingerprint='')=?
    AND c.origin>=?
    AND c.blocked=0
    AND (IFNULL(c.name_normalized,IIF(c.name='',c.authname,c.name)) LIKE ? OR c.addr LIKE ?)
ORDER BY c.origin>=? DESC, c.last_seen DESC, c.id DESC
                    ",
                    (
                        ContactId::LAST_SPECIAL,
                        flag_address,
                        minimal_origin,
                        &s3str_like_cmd,
                        &query_lowercased,
                        Origin::CreateChat,
                    ),
                    |row| {
                        let id: ContactId = row.get(0)?;
                        let addr: String = row.get(1)?;
                        Ok((id, addr))
                    },
                    |rows| {
                        for row in rows {
                            let (id, addr) = row?;
                            if !self_addrs.contains(&addr) {
                                ret.push(id);
                            }
                        }
                        Ok(())
                    },
                )
                .await?;

            if let Some(query) = query {
                let self_addr = context
                    .get_config(Config::ConfiguredAddr)
                    .await?
                    .unwrap_or_default();
                let self_name = context
                    .get_config(Config::Displayname)
                    .await?
                    .unwrap_or_default();
                let self_name2 = stock_str::self_msg(context);

                if self_addr.contains(query)
                    || self_name.contains(query)
                    || self_name2.await.contains(query)
                {
                    add_self = true;
                }
            } else {
                add_self = true;
            }
        } else {
            add_self = true;

            context
                .sql
                .query_map(
                    "SELECT id, addr FROM contacts
                 WHERE id>?
                 AND (fingerprint='')=?
                 AND origin>=?
                 AND blocked=0
                 ORDER BY origin>=? DESC, last_seen DESC, id DESC",
                    (
                        ContactId::LAST_SPECIAL,
                        flag_address,
                        minimal_origin,
                        Origin::CreateChat,
                    ),
                    |row| {
                        let id: ContactId = row.get(0)?;
                        let addr: String = row.get(1)?;
                        Ok((id, addr))
                    },
                    |rows| {
                        for row in rows {
                            let (id, addr) = row?;
                            if !self_addrs.contains(&addr) {
                                ret.push(id);
                            }
                        }
                        Ok(())
                    },
                )
                .await?;
        }

        if flag_add_self && add_self {
            ret.push(ContactId::SELF);
        }

        Ok(ret)
    }

    /// Adds blocked mailinglists and broadcast channels as pseudo-contacts
    /// to allow unblocking them as if they are contacts
    /// (this way, only one unblock-ffi is needed and only one set of ui-functions,
    /// from the users perspective,
    /// there is not much difference in an email- and a mailinglist-address)
    async fn update_blocked_mailinglist_contacts(context: &Context) -> Result<()> {
        context
            .sql
            .transaction(move |transaction| {
                let mut stmt = transaction.prepare(
                    "SELECT name, grpid, type FROM chats WHERE (type=? OR type=?) AND blocked=?",
                )?;
                let rows = stmt.query_map(
                    (Chattype::Mailinglist, Chattype::InBroadcast, Blocked::Yes),
                    |row| {
                        let name: String = row.get(0)?;
                        let grpid: String = row.get(1)?;
                        let typ: Chattype = row.get(2)?;
                        Ok((name, grpid, typ))
                    },
                )?;
                let blocked_mailinglists = rows.collect::<std::result::Result<Vec<_>, _>>()?;
                for (name, grpid, typ) in blocked_mailinglists {
                    let count = transaction.query_row(
                        "SELECT COUNT(id) FROM contacts WHERE addr=?",
                        [&grpid],
                        |row| {
                            let count: isize = row.get(0)?;
                            Ok(count)
                        },
                    )?;
                    if count == 0 {
                        transaction.execute("INSERT INTO contacts (addr) VALUES (?)", [&grpid])?;
                    }

                    let fingerprint = if typ == Chattype::InBroadcast {
                        // Set some fingerprint so that is_pgp_contact() returns true,
                        // and the contact isn't marked with a letter icon.
                        "Blocked_broadcast"
                    } else {
                        ""
                    };
                    // Always do an update in case the blocking is reset or name is changed.
                    transaction.execute(
                        "
UPDATE contacts
SET name=?, name_normalized=IIF(?1='',name_normalized,?), origin=?, blocked=1, fingerprint=?
WHERE addr=?
                        ",
                        (
                            &name,
                            normalize_text(&name),
                            Origin::MailinglistAddress,
                            fingerprint,
                            &grpid,
                        ),
                    )?;
                }
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Get blocked contacts.
    pub async fn get_all_blocked(context: &Context) -> Result<Vec<ContactId>> {
        Contact::update_blocked_mailinglist_contacts(context)
            .await
            .context("cannot update blocked mailinglist contacts")?;

        let list = context
            .sql
            .query_map_vec(
                "SELECT id FROM contacts WHERE id>? AND blocked!=0 ORDER BY last_seen DESC, id DESC;",
                (ContactId::LAST_SPECIAL,),
                |row| {
                    let contact_id: ContactId = row.get(0)?;
                    Ok(contact_id)
                }
            )
            .await?;
        Ok(list)
    }

    /// Returns a textual summary of the encryption state for the contact.
    ///
    /// This function returns a string explaining the encryption state
    /// of the contact and if the connection is encrypted the
    /// fingerprints of the keys involved.
    pub async fn get_encrinfo(context: &Context, contact_id: ContactId) -> Result<String> {
        ensure!(
            !contact_id.is_special(),
            "Can not provide encryption info for special contact"
        );

        let contact = Contact::get_by_id(context, contact_id).await?;
        let addr = context
            .get_config(Config::ConfiguredAddr)
            .await?
            .unwrap_or_default();

        let Some(fingerprint_other) = contact.fingerprint() else {
            return Ok(stock_str::encr_none(context).await);
        };
        let fingerprint_other = fingerprint_other.to_string();

        let stock_message = if contact.public_key(context).await?.is_some() {
            stock_str::messages_e2e_encrypted(context).await
        } else {
            stock_str::encr_none(context).await
        };

        let finger_prints = stock_str::finger_prints(context).await;
        let mut ret = format!("{stock_message}\n{finger_prints}:");

        let fingerprint_self = load_self_public_key(context)
            .await?
            .dc_fingerprint()
            .to_string();
        if addr < contact.addr {
            cat_fingerprint(
                &mut ret,
                &stock_str::self_msg(context).await,
                &addr,
                &fingerprint_self,
            );
            cat_fingerprint(
                &mut ret,
                contact.get_display_name(),
                &contact.addr,
                &fingerprint_other,
            );
        } else {
            cat_fingerprint(
                &mut ret,
                contact.get_display_name(),
                &contact.addr,
                &fingerprint_other,
            );
            cat_fingerprint(
                &mut ret,
                &stock_str::self_msg(context).await,
                &addr,
                &fingerprint_self,
            );
        }

        Ok(ret)
    }

    /// Delete a contact so that it disappears from the corresponding lists.
    /// Depending on whether there are ongoing chats, deletion is done by physical deletion or hiding.
    /// The contact is deleted from the local device.
    ///
    /// May result in a `#DC_EVENT_CONTACTS_CHANGED` event.
    pub async fn delete(context: &Context, contact_id: ContactId) -> Result<()> {
        ensure!(!contact_id.is_special(), "Can not delete special contact");

        context
            .sql
            .transaction(move |transaction| {
                // make sure, the transaction starts with a write command and becomes EXCLUSIVE by that -
                // upgrading later may be impossible by races.
                let deleted_contacts = transaction.execute(
                    "DELETE FROM contacts WHERE id=?
                     AND (SELECT COUNT(*) FROM chats_contacts WHERE contact_id=?)=0;",
                    (contact_id, contact_id),
                )?;
                if deleted_contacts == 0 {
                    transaction.execute(
                        "UPDATE contacts SET origin=? WHERE id=?;",
                        (Origin::Hidden, contact_id),
                    )?;
                }
                Ok(())
            })
            .await?;

        context.emit_event(EventType::ContactsChanged(None));
        Ok(())
    }

    /// Updates `param` column in the database.
    pub async fn update_param(&self, context: &Context) -> Result<()> {
        context
            .sql
            .execute(
                "UPDATE contacts SET param=? WHERE id=?",
                (self.param.to_string(), self.id),
            )
            .await?;
        Ok(())
    }

    /// Updates `status` column in the database.
    pub async fn update_status(&self, context: &Context) -> Result<()> {
        context
            .sql
            .execute(
                "UPDATE contacts SET status=? WHERE id=?",
                (&self.status, self.id),
            )
            .await?;
        Ok(())
    }

    /// Get the ID of the contact.
    pub fn get_id(&self) -> ContactId {
        self.id
    }

    /// Get email address. The email address is always set for a contact.
    pub fn get_addr(&self) -> &str {
        &self.addr
    }

    /// Returns true if the contact is a key-contact.
    /// Otherwise it is an addresss-contact.
    pub fn is_key_contact(&self) -> bool {
        self.fingerprint.is_some() || self.id == ContactId::SELF
    }

    /// Returns OpenPGP fingerprint of a contact.
    ///
    /// `None` for address-contacts.
    pub fn fingerprint(&self) -> Option<Fingerprint> {
        if let Some(fingerprint) = &self.fingerprint {
            fingerprint.parse().ok()
        } else {
            None
        }
    }

    /// Returns OpenPGP public key of a contact.
    ///
    /// Returns `None` if the contact is not a key-contact
    /// or if the key is not available.
    /// It is possible for a key-contact to not have a key,
    /// e.g. if only the fingerprint is known from a QR-code.
    pub async fn public_key(&self, context: &Context) -> Result<Option<SignedPublicKey>> {
        if self.id == ContactId::SELF {
            return Ok(Some(load_self_public_key(context).await?));
        }

        if let Some(fingerprint) = &self.fingerprint {
            if let Some(public_key_bytes) = context
                .sql
                .query_row_optional(
                    "SELECT public_key
                     FROM public_keys
                     WHERE fingerprint=?",
                    (fingerprint,),
                    |row| {
                        let bytes: Vec<u8> = row.get(0)?;
                        Ok(bytes)
                    },
                )
                .await?
            {
                let public_key = SignedPublicKey::from_slice(&public_key_bytes)?;
                Ok(Some(public_key))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Get name authorized by the contact.
    pub fn get_authname(&self) -> &str {
        &self.authname
    }

    /// Get the contact name. This is the name as modified by the local user.
    /// May be an empty string.
    ///
    /// This name is typically used in a form where the user can edit the name of a contact.
    /// To get a fine name to display in lists etc., use `Contact::get_display_name` or `Contact::get_name_n_addr`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get display name. This is the name as defined by the contact himself,
    /// modified by the user or, if both are unset, the email address.
    ///
    /// This name is typically used in lists.
    /// To get the name editable in a formular, use `Contact::get_name`.
    pub fn get_display_name(&self) -> &str {
        if !self.name.is_empty() {
            return &self.name;
        }
        if !self.authname.is_empty() {
            return &self.authname;
        }
        &self.addr
    }

    /// Get a summary of name and address.
    ///
    /// The returned string is either "Name (email@domain.com)" or just
    /// "email@domain.com" if the name is unset.
    ///
    /// The result should only be used locally and never sent over the network
    /// as it leaks the local contact name.
    ///
    /// The summary is typically used when asking the user something about the contact.
    /// The attached email address makes the question unique, eg. "Chat with Alan Miller (am@uniquedomain.com)?"
    pub fn get_name_n_addr(&self) -> String {
        if !self.name.is_empty() {
            format!("{} ({})", self.name, self.addr)
        } else if !self.authname.is_empty() {
            format!("{} ({})", self.authname, self.addr)
        } else {
            (&self.addr).into()
        }
    }

    /// Get the contact's profile image.
    /// This is the image set by each remote user on their own
    /// using set_config(context, "selfavatar", image).
    pub async fn get_profile_image(&self, context: &Context) -> Result<Option<PathBuf>> {
        self.get_profile_image_ex(context, true).await
    }

    /// Get the contact's profile image.
    /// This is the image set by each remote user on their own
    /// using set_config(context, "selfavatar", image).
    async fn get_profile_image_ex(
        &self,
        context: &Context,
        show_fallback_icon: bool,
    ) -> Result<Option<PathBuf>> {
        if self.id == ContactId::SELF {
            if let Some(p) = context.get_config(Config::Selfavatar).await? {
                return Ok(Some(PathBuf::from(p))); // get_config() calls get_abs_path() internally already
            }
        } else if self.id == ContactId::DEVICE {
            return Ok(Some(chat::get_device_icon(context).await?));
        }
        if show_fallback_icon && !self.id.is_special() && !self.is_key_contact() {
            return Ok(Some(chat::get_unencrypted_icon(context).await?));
        }
        if let Some(image_rel) = self.param.get(Param::ProfileImage)
            && !image_rel.is_empty()
        {
            return Ok(Some(get_abs_path(context, Path::new(image_rel))));
        }
        Ok(None)
    }

    /// Returns a color for the contact.
    /// For self-contact this returns gray if own keypair doesn't exist yet.
    /// See also [`self::get_color`].
    pub fn get_color(&self) -> u32 {
        get_color(self.id == ContactId::SELF, &self.addr, &self.fingerprint())
    }

    /// Returns a color for the contact.
    /// Ensures that the color isn't gray. For self-contact this generates own keypair if it doesn't
    /// exist yet.
    /// See also [`self::get_color`].
    pub async fn get_or_gen_color(&self, context: &Context) -> Result<u32> {
        let mut fpr = self.fingerprint();
        if fpr.is_none() && self.id == ContactId::SELF {
            fpr = Some(load_self_public_key(context).await?.dc_fingerprint());
        }
        Ok(get_color(self.id == ContactId::SELF, &self.addr, &fpr))
    }

    /// Gets the contact's status.
    ///
    /// Status is the last signature received in a message from this contact.
    pub fn get_status(&self) -> &str {
        self.status.as_str()
    }

    /// Returns whether end-to-end encryption to the contact is available.
    pub async fn e2ee_avail(&self, context: &Context) -> Result<bool> {
        if self.id == ContactId::SELF {
            // We don't need to check if we have our own key.
            return Ok(true);
        }
        Ok(self.public_key(context).await?.is_some())
    }

    /// Returns true if the contact
    /// can be added to verified chats.
    ///
    /// If contact is verified
    /// UI should display green checkmark after the contact name
    /// in contact list items and
    /// in chat member list items.
    ///
    /// In contact profile view, use this function only if there is no chat with the contact,
    /// otherwise use is_chat_protected().
    /// Use [Self::get_verifier_id] to display the verifier contact
    /// in the info section of the contact profile.
    pub async fn is_verified(&self, context: &Context) -> Result<bool> {
        // We're always sort of secured-verified as we could verify the key on this device any time with the key
        // on this device
        if self.id == ContactId::SELF {
            return Ok(true);
        }

        Ok(self.get_verifier_id(context).await?.is_some())
    }

    /// Returns the `ContactId` that verified the contact.
    ///
    /// If this returns Some(_),
    /// display green checkmark in the profile and "Introduced by ..." line
    /// with the name of the contact.
    ///
    /// If this returns `Some(None)`, then the contact is verified,
    /// but it's unclear by whom.
    pub async fn get_verifier_id(&self, context: &Context) -> Result<Option<Option<ContactId>>> {
        let verifier_id: u32 = context
            .sql
            .query_get_value("SELECT verifier FROM contacts WHERE id=?", (self.id,))
            .await?
            .with_context(|| format!("Contact {} does not exist", self.id))?;

        if verifier_id == 0 {
            Ok(None)
        } else if verifier_id == self.id.to_u32() {
            Ok(Some(None))
        } else {
            Ok(Some(Some(ContactId::new(verifier_id))))
        }
    }

    /// Returns the number of real (i.e. non-special) contacts in the database.
    pub async fn get_real_cnt(context: &Context) -> Result<usize> {
        if !context.sql.is_open().await {
            return Ok(0);
        }

        let count = context
            .sql
            .count(
                "SELECT COUNT(*) FROM contacts WHERE id>?;",
                (ContactId::LAST_SPECIAL,),
            )
            .await?;
        Ok(count)
    }

    /// Returns true if a contact with this ID exists.
    pub async fn real_exists_by_id(context: &Context, contact_id: ContactId) -> Result<bool> {
        if contact_id.is_special() {
            return Ok(false);
        }

        let exists = context
            .sql
            .exists("SELECT COUNT(*) FROM contacts WHERE id=?;", (contact_id,))
            .await?;
        Ok(exists)
    }
}

/// Returns a color for a contact having given attributes.
///
/// The color is calculated from contact's fingerprint (for key-contacts) or email address (for
/// address-contacts; should be lowercased to avoid allocation) and can be used for an fallback
/// avatar with white initials as well as for headlines in bubbles of group chats.
pub fn get_color(is_self: bool, addr: &str, fingerprint: &Option<Fingerprint>) -> u32 {
    if let Some(fingerprint) = fingerprint {
        str_to_color(&fingerprint.hex())
    } else if is_self {
        0x808080
    } else {
        str_to_color(&to_lowercase(addr))
    }
}

// Updates the names of the chats which use the contact name.
//
// This is one of the few duplicated data, however, getting the chat list is easier this way.
fn update_chat_names(
    context: &Context,
    transaction: &rusqlite::Connection,
    contact_id: ContactId,
) -> Result<()> {
    let chat_id: Option<ChatId> = transaction.query_row(
            "SELECT id FROM chats WHERE type=? AND id IN(SELECT chat_id FROM chats_contacts WHERE contact_id=?)",
            (Chattype::Single, contact_id),
            |row| {
                let chat_id: ChatId = row.get(0)?;
                Ok(chat_id)
            }
        ).optional()?;

    if let Some(chat_id) = chat_id {
        let (addr, name, authname) = transaction.query_row(
            "SELECT addr, name, authname
                     FROM contacts
                     WHERE id=?",
            (contact_id,),
            |row| {
                let addr: String = row.get(0)?;
                let name: String = row.get(1)?;
                let authname: String = row.get(2)?;
                Ok((addr, name, authname))
            },
        )?;

        let chat_name = if !name.is_empty() {
            name
        } else if !authname.is_empty() {
            authname
        } else {
            addr
        };

        let count = transaction.execute(
            "UPDATE chats SET name=?1, name_normalized=?2 WHERE id=?3 AND name!=?1",
            (&chat_name, normalize_text(&chat_name), chat_id),
        )?;

        if count > 0 {
            // Chat name updated
            context.emit_event(EventType::ChatModified(chat_id));
            chatlist_events::emit_chatlist_items_changed_for_contact(context, contact_id);
        }
    }

    Ok(())
}

pub(crate) async fn set_blocked(
    context: &Context,
    sync: sync::Sync,
    contact_id: ContactId,
    new_blocking: bool,
) -> Result<()> {
    ensure!(
        !contact_id.is_special(),
        "Can't block special contact {contact_id}"
    );
    let contact = Contact::get_by_id(context, contact_id).await?;

    if contact.blocked != new_blocking {
        context
            .sql
            .execute(
                "UPDATE contacts SET blocked=? WHERE id=?;",
                (i32::from(new_blocking), contact_id),
            )
            .await?;

        // also (un)block all chats with _only_ this contact - we do not delete them to allow a
        // non-destructive blocking->unblocking.
        // (Maybe, beside normal chats (type=100) we should also block group chats with only this user.
        // However, I'm not sure about this point; it may be confusing if the user wants to add other people;
        // this would result in recreating the same group...)
        if context
            .sql
            .execute(
                r#"
UPDATE chats
SET blocked=?
WHERE type=? AND id IN (
  SELECT chat_id FROM chats_contacts WHERE contact_id=?
);
"#,
                (new_blocking, Chattype::Single, contact_id),
            )
            .await
            .is_ok()
        {
            Contact::mark_noticed(context, contact_id).await?;
            context.emit_event(EventType::ContactsChanged(Some(contact_id)));
        }

        // also unblock mailinglist
        // if the contact is a mailinglist address explicitly created to allow unblocking
        if !new_blocking
            && contact.origin == Origin::MailinglistAddress
            && let Some((chat_id, ..)) = chat::get_chat_id_by_grpid(context, &contact.addr).await?
        {
            chat_id.unblock_ex(context, Nosync).await?;
        }

        if sync.into() {
            let action = match new_blocking {
                true => chat::SyncAction::Block,
                false => chat::SyncAction::Unblock,
            };
            let sync_id = if let Some(fingerprint) = contact.fingerprint() {
                chat::SyncId::ContactFingerprint(fingerprint.hex())
            } else {
                chat::SyncId::ContactAddr(contact.addr.clone())
            };

            chat::sync(context, sync_id, action)
                .await
                .log_err(context)
                .ok();
        }
    }

    chatlist_events::emit_chatlist_changed(context);
    Ok(())
}

/// Set profile image for a contact.
///
/// The given profile image is expected to be already in the blob directory
/// as profile images can be set only by receiving messages, this should be always the case, however.
///
/// For contact SELF, the image is not saved in the contact-database but as Config::Selfavatar.
pub(crate) async fn set_profile_image(
    context: &Context,
    contact_id: ContactId,
    profile_image: &AvatarAction,
) -> Result<()> {
    let mut contact = Contact::get_by_id(context, contact_id).await?;
    let changed = match profile_image {
        AvatarAction::Change(profile_image) => {
            if contact_id == ContactId::SELF {
                context
                    .set_config_ex(Nosync, Config::Selfavatar, Some(profile_image))
                    .await?;
            } else {
                contact.param.set(Param::ProfileImage, profile_image);
            }
            true
        }
        AvatarAction::Delete => {
            if contact_id == ContactId::SELF {
                context
                    .set_config_ex(Nosync, Config::Selfavatar, None)
                    .await?;
            } else {
                contact.param.remove(Param::ProfileImage);
            }
            true
        }
    };
    if changed {
        contact.update_param(context).await?;
        context.emit_event(EventType::ContactsChanged(Some(contact_id)));
        chatlist_events::emit_chatlist_item_changed_for_contact_chat(context, contact_id).await;
    }
    Ok(())
}

/// Sets contact status.
///
/// For contact SELF, the status is not saved in the contact table, but as Config::Selfstatus.
pub(crate) async fn set_status(
    context: &Context,
    contact_id: ContactId,
    status: String,
) -> Result<()> {
    if contact_id == ContactId::SELF {
        context
            .set_config_ex(Nosync, Config::Selfstatus, Some(&status))
            .await?;
    } else {
        let mut contact = Contact::get_by_id(context, contact_id).await?;

        if contact.status != status {
            contact.status = status;
            contact.update_status(context).await?;
            context.emit_event(EventType::ContactsChanged(Some(contact_id)));
        }
    }
    Ok(())
}

/// Updates last seen timestamp of the contact if it is earlier than the given `timestamp`.
#[expect(clippy::arithmetic_side_effects)]
pub(crate) async fn update_last_seen(
    context: &Context,
    contact_id: ContactId,
    timestamp: i64,
) -> Result<()> {
    ensure!(
        !contact_id.is_special(),
        "Can not update special contact last seen timestamp"
    );

    if context
        .sql
        .execute(
            "UPDATE contacts SET last_seen = ?1 WHERE last_seen < ?1 AND id = ?2",
            (timestamp, contact_id),
        )
        .await?
        > 0
        && timestamp > time() - SEEN_RECENTLY_SECONDS
    {
        context.emit_event(EventType::ContactsChanged(Some(contact_id)));
        context
            .scheduler
            .interrupt_recently_seen(contact_id, timestamp)
            .await;
    }
    Ok(())
}

/// Marks contact `contact_id` as verified by `verifier_id`.
///
/// `verifier_id == None` means that the verifier is unknown.
pub(crate) async fn mark_contact_id_as_verified(
    context: &Context,
    contact_id: ContactId,
    verifier_id: Option<ContactId>,
) -> Result<()> {
    ensure_and_debug_assert_ne!(contact_id, ContactId::SELF,);
    ensure_and_debug_assert_ne!(
        Some(contact_id),
        verifier_id,
        "Contact cannot be verified by self",
    );
    let by_self = verifier_id == Some(ContactId::SELF);
    let mut verifier_id = verifier_id.unwrap_or(contact_id);
    context
        .sql
        .transaction(|transaction| {
            let contact_fingerprint: String = transaction.query_row(
                "SELECT fingerprint FROM contacts WHERE id=?",
                (contact_id,),
                |row| row.get(0),
            )?;
            if contact_fingerprint.is_empty() {
                bail!("Non-key-contact {contact_id} cannot be verified");
            }
            if verifier_id != ContactId::SELF {
                let (verifier_fingerprint, verifier_verifier_id): (String, ContactId) = transaction
                    .query_row(
                        "SELECT fingerprint, verifier FROM contacts WHERE id=?",
                        (verifier_id,),
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?;
                if verifier_fingerprint.is_empty() {
                    bail!(
                        "Contact {contact_id} cannot be verified by non-key-contact {verifier_id}"
                    );
                }
                ensure!(
                    verifier_id == contact_id || verifier_verifier_id != ContactId::UNDEFINED,
                    "Contact {contact_id} cannot be verified by unverified contact {verifier_id}",
                );
                if verifier_verifier_id == verifier_id {
                    // Avoid introducing incorrect reverse chains: if the verifier itself has an
                    // unknown verifier, it may be `contact_id` actually (directly or indirectly) on
                    // the other device (which is needed for getting "verified by unknown contact"
                    // in the first place).
                    verifier_id = contact_id;
                }
            }
            transaction.execute(
                "UPDATE contacts SET verifier=?1
                 WHERE id=?2 AND (verifier=0 OR verifier=id OR ?3)",
                (verifier_id, contact_id, by_self),
            )?;
            Ok(())
        })
        .await?;
    Ok(())
}

#[expect(clippy::arithmetic_side_effects)]
fn cat_fingerprint(ret: &mut String, name: &str, addr: &str, fingerprint: &str) {
    *ret += &format!("\n\n{name} ({addr}):\n{fingerprint}");
}

fn split_address_book(book: &str) -> Vec<(&str, &str)> {
    book.lines()
        .collect::<Vec<&str>>()
        .chunks(2)
        .filter_map(|chunk| {
            let name = chunk.first()?;
            let addr = chunk.get(1)?;
            Some((*name, *addr))
        })
        .collect()
}

#[derive(Debug)]
pub(crate) struct RecentlySeenInterrupt {
    contact_id: ContactId,
    timestamp: i64,
}

#[derive(Debug)]
pub(crate) struct RecentlySeenLoop {
    /// Task running "recently seen" loop.
    handle: task::JoinHandle<()>,

    interrupt_send: Sender<RecentlySeenInterrupt>,
}

impl RecentlySeenLoop {
    pub(crate) fn new(context: Context) -> Self {
        let (interrupt_send, interrupt_recv) = channel::bounded(1);

        let handle = task::spawn(Self::run(context, interrupt_recv));
        Self {
            handle,
            interrupt_send,
        }
    }

    #[expect(clippy::arithmetic_side_effects)]
    async fn run(context: Context, interrupt: Receiver<RecentlySeenInterrupt>) {
        type MyHeapElem = (Reverse<i64>, ContactId);

        let now = SystemTime::now();
        let now_ts = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Priority contains all recently seen sorted by the timestamp
        // when they become not recently seen.
        //
        // Initialize with contacts which are currently seen, but will
        // become unseen in the future.
        let mut unseen_queue: BinaryHeap<MyHeapElem> = context
            .sql
            .query_map_collect(
                "SELECT id, last_seen FROM contacts
                 WHERE last_seen > ?",
                (now_ts - SEEN_RECENTLY_SECONDS,),
                |row| {
                    let contact_id: ContactId = row.get("id")?;
                    let last_seen: i64 = row.get("last_seen")?;
                    Ok((Reverse(last_seen + SEEN_RECENTLY_SECONDS), contact_id))
                },
            )
            .await
            .unwrap_or_default();

        loop {
            let now = SystemTime::now();
            let (until, contact_id) =
                if let Some((Reverse(timestamp), contact_id)) = unseen_queue.peek() {
                    (
                        UNIX_EPOCH
                            + Duration::from_secs((*timestamp).try_into().unwrap_or(u64::MAX))
                            + Duration::from_secs(1),
                        Some(contact_id),
                    )
                } else {
                    // Sleep for 24 hours.
                    (now + Duration::from_secs(86400), None)
                };

            if let Ok(duration) = until.duration_since(now) {
                info!(
                    context,
                    "Recently seen loop waiting for {} or interrupt",
                    duration_to_str(duration)
                );

                match timeout(duration, interrupt.recv()).await {
                    Err(_) => {
                        // Timeout, notify about contact.
                        if let Some(contact_id) = contact_id {
                            context.emit_event(EventType::ContactsChanged(Some(*contact_id)));
                            chatlist_events::emit_chatlist_item_changed_for_contact_chat(
                                &context,
                                *contact_id,
                            )
                            .await;
                            unseen_queue.pop();
                        }
                    }
                    Ok(Err(err)) => {
                        warn!(
                            context,
                            "Error receiving an interruption in recently seen loop: {}", err
                        );
                        // Maybe the sender side is closed.
                        // Terminate the loop to avoid looping indefinitely.
                        return;
                    }
                    Ok(Ok(RecentlySeenInterrupt {
                        contact_id,
                        timestamp,
                    })) => {
                        // Received an interrupt.
                        if contact_id != ContactId::UNDEFINED {
                            unseen_queue
                                .push((Reverse(timestamp + SEEN_RECENTLY_SECONDS), contact_id));
                        }
                    }
                }
            } else {
                info!(
                    context,
                    "Recently seen loop is not waiting, event is already due."
                );

                // Event is already in the past.
                if let Some(contact_id) = contact_id {
                    context.emit_event(EventType::ContactsChanged(Some(*contact_id)));
                    chatlist_events::emit_chatlist_item_changed_for_contact_chat(
                        &context,
                        *contact_id,
                    )
                    .await;
                }
                unseen_queue.pop();
            }
        }
    }

    pub(crate) fn try_interrupt(&self, contact_id: ContactId, timestamp: i64) {
        self.interrupt_send
            .try_send(RecentlySeenInterrupt {
                contact_id,
                timestamp,
            })
            .ok();
    }

    #[cfg(test)]
    pub(crate) async fn interrupt(&self, contact_id: ContactId, timestamp: i64) {
        self.interrupt_send
            .send(RecentlySeenInterrupt {
                contact_id,
                timestamp,
            })
            .await
            .unwrap();
    }

    pub(crate) async fn abort(self) {
        self.handle.abort();

        // Await aborted task to ensure the `Future` is dropped
        // with all resources moved inside such as the `Context`
        // reference to `InnerContext`.
        self.handle.await.ok();
    }
}

#[cfg(test)]
mod contact_tests;
