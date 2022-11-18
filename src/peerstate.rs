//! # [Autocrypt Peer State](https://autocrypt.org/level1.html#peer-state-management) module.

use std::collections::HashSet;
use std::fmt;

use crate::aheader::{Aheader, EncryptPreference};
use crate::chat::{self, is_contact_in_chat, Chat};
use crate::chatlist::Chatlist;
use crate::constants::Chattype;
use crate::contact::{addr_cmp, Contact, Origin};
use crate::context::Context;
use crate::decrypt::DecryptionInfo;
use crate::events::EventType;
use crate::key::{DcKey, Fingerprint, SignedPublicKey};
use crate::message::Message;
use crate::mimeparser::SystemMessage;
use crate::sql::Sql;
use crate::stock_str;
use anyhow::{Context as _, Result};
use num_traits::FromPrimitive;

#[derive(Debug)]
pub enum PeerstateKeyType {
    GossipKey,
    PublicKey,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive)]
#[repr(u8)]
pub enum PeerstateVerifiedStatus {
    Unverified = 0,
    //Verified = 1, // not used
    BidirectVerified = 2,
}

/// Peerstate represents the state of an Autocrypt peer.
pub struct Peerstate {
    pub addr: String,
    pub last_seen: i64,
    pub last_seen_autocrypt: i64,
    pub prefer_encrypt: EncryptPreference,
    pub public_key: Option<SignedPublicKey>,
    pub public_key_fingerprint: Option<Fingerprint>,
    pub gossip_key: Option<SignedPublicKey>,
    pub gossip_timestamp: i64,
    pub gossip_key_fingerprint: Option<Fingerprint>,
    pub verified_key: Option<SignedPublicKey>,
    pub verified_key_fingerprint: Option<Fingerprint>,
    pub to_save: Option<ToSave>,
    pub fingerprint_changed: bool,
}

impl PartialEq for Peerstate {
    fn eq(&self, other: &Peerstate) -> bool {
        self.addr == other.addr
            && self.last_seen == other.last_seen
            && self.last_seen_autocrypt == other.last_seen_autocrypt
            && self.prefer_encrypt == other.prefer_encrypt
            && self.public_key == other.public_key
            && self.public_key_fingerprint == other.public_key_fingerprint
            && self.gossip_key == other.gossip_key
            && self.gossip_timestamp == other.gossip_timestamp
            && self.gossip_key_fingerprint == other.gossip_key_fingerprint
            && self.verified_key == other.verified_key
            && self.verified_key_fingerprint == other.verified_key_fingerprint
            && self.to_save == other.to_save
            && self.fingerprint_changed == other.fingerprint_changed
    }
}

impl Eq for Peerstate {}

impl fmt::Debug for Peerstate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Peerstate")
            .field("addr", &self.addr)
            .field("last_seen", &self.last_seen)
            .field("last_seen_autocrypt", &self.last_seen_autocrypt)
            .field("prefer_encrypt", &self.prefer_encrypt)
            .field("public_key", &self.public_key)
            .field("public_key_fingerprint", &self.public_key_fingerprint)
            .field("gossip_key", &self.gossip_key)
            .field("gossip_timestamp", &self.gossip_timestamp)
            .field("gossip_key_fingerprint", &self.gossip_key_fingerprint)
            .field("verified_key", &self.verified_key)
            .field("verified_key_fingerprint", &self.verified_key_fingerprint)
            .field("to_save", &self.to_save)
            .field("fingerprint_changed", &self.fingerprint_changed)
            .finish()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum ToSave {
    Timestamps = 0x01,
    All = 0x02,
}

impl Peerstate {
    pub fn from_header(header: &Aheader, message_time: i64) -> Self {
        Peerstate {
            addr: header.addr.clone(),
            last_seen: message_time,
            last_seen_autocrypt: message_time,
            prefer_encrypt: header.prefer_encrypt,
            public_key: Some(header.public_key.clone()),
            public_key_fingerprint: Some(header.public_key.fingerprint()),
            gossip_key: None,
            gossip_key_fingerprint: None,
            gossip_timestamp: 0,
            verified_key: None,
            verified_key_fingerprint: None,
            to_save: Some(ToSave::All),
            fingerprint_changed: false,
        }
    }

    pub fn from_gossip(gossip_header: &Aheader, message_time: i64) -> Self {
        Peerstate {
            addr: gossip_header.addr.clone(),
            last_seen: 0,
            last_seen_autocrypt: 0,

            // Non-standard extension. According to Autocrypt 1.1.0 gossip headers SHOULD NOT
            // contain encryption preference.
            //
            // Delta Chat includes encryption preference to ensure new users introduced to a group
            // learn encryption preferences of other members immediately and don't send unencrypted
            // messages to a group where everyone prefers encryption.
            prefer_encrypt: gossip_header.prefer_encrypt,

            public_key: None,
            public_key_fingerprint: None,
            gossip_key: Some(gossip_header.public_key.clone()),
            gossip_key_fingerprint: Some(gossip_header.public_key.fingerprint()),
            gossip_timestamp: message_time,
            verified_key: None,
            verified_key_fingerprint: None,
            to_save: Some(ToSave::All),
            fingerprint_changed: false,
        }
    }

    pub async fn from_addr(context: &Context, addr: &str) -> Result<Option<Peerstate>> {
        let query = "SELECT addr, last_seen, last_seen_autocrypt, prefer_encrypted, public_key, \
                     gossip_timestamp, gossip_key, public_key_fingerprint, gossip_key_fingerprint, \
                     verified_key, verified_key_fingerprint \
                     FROM acpeerstates \
                     WHERE addr=? COLLATE NOCASE LIMIT 1;";
        Self::from_stmt(context, query, paramsv![addr]).await
    }

    pub async fn from_fingerprint(
        context: &Context,
        fingerprint: &Fingerprint,
    ) -> Result<Option<Peerstate>> {
        let query = "SELECT addr, last_seen, last_seen_autocrypt, prefer_encrypted, public_key, \
                     gossip_timestamp, gossip_key, public_key_fingerprint, gossip_key_fingerprint, \
                     verified_key, verified_key_fingerprint \
                     FROM acpeerstates  \
                     WHERE public_key_fingerprint=? \
                     OR gossip_key_fingerprint=? \
                     ORDER BY public_key_fingerprint=? DESC LIMIT 1;";
        let fp = fingerprint.hex();
        Self::from_stmt(context, query, paramsv![fp, fp, fp]).await
    }

    pub async fn from_verified_fingerprint_or_addr(
        context: &Context,
        fingerprint: &Fingerprint,
        addr: &str,
    ) -> Result<Option<Peerstate>> {
        let query = "SELECT addr, last_seen, last_seen_autocrypt, prefer_encrypted, public_key, \
                     gossip_timestamp, gossip_key, public_key_fingerprint, gossip_key_fingerprint, \
                     verified_key, verified_key_fingerprint \
                     FROM acpeerstates  \
                     WHERE verified_key_fingerprint=? \
                     OR addr=? COLLATE NOCASE \
                     ORDER BY verified_key_fingerprint=? DESC, last_seen DESC LIMIT 1;";
        let fp = fingerprint.hex();
        Self::from_stmt(context, query, paramsv![fp, addr, fp]).await
    }

    async fn from_stmt(
        context: &Context,
        query: &str,
        params: impl rusqlite::Params,
    ) -> Result<Option<Peerstate>> {
        let peerstate = context
            .sql
            .query_row_optional(query, params, |row| {
                // all the above queries start with this: SELECT
                //   addr, last_seen, last_seen_autocrypt, prefer_encrypted,
                //   public_key, gossip_timestamp, gossip_key, public_key_fingerprint,
                //   gossip_key_fingerprint, verified_key, verified_key_fingerprint

                let res = Peerstate {
                    addr: row.get("addr")?,
                    last_seen: row.get("last_seen")?,
                    last_seen_autocrypt: row.get("last_seen_autocrypt")?,
                    prefer_encrypt: EncryptPreference::from_i32(row.get("prefer_encrypted")?)
                        .unwrap_or_default(),
                    public_key: row
                        .get("public_key")
                        .ok()
                        .and_then(|blob: Vec<u8>| SignedPublicKey::from_slice(&blob).ok()),
                    public_key_fingerprint: row
                        .get::<_, Option<String>>("public_key_fingerprint")?
                        .map(|s| s.parse::<Fingerprint>())
                        .transpose()
                        .unwrap_or_default(),
                    gossip_key: row
                        .get("gossip_key")
                        .ok()
                        .and_then(|blob: Vec<u8>| SignedPublicKey::from_slice(&blob).ok()),
                    gossip_key_fingerprint: row
                        .get::<_, Option<String>>("gossip_key_fingerprint")?
                        .map(|s| s.parse::<Fingerprint>())
                        .transpose()
                        .unwrap_or_default(),
                    gossip_timestamp: row.get("gossip_timestamp")?,
                    verified_key: row
                        .get("verified_key")
                        .ok()
                        .and_then(|blob: Vec<u8>| SignedPublicKey::from_slice(&blob).ok()),
                    verified_key_fingerprint: row
                        .get::<_, Option<String>>("verified_key_fingerprint")?
                        .map(|s| s.parse::<Fingerprint>())
                        .transpose()
                        .unwrap_or_default(),
                    to_save: None,
                    fingerprint_changed: false,
                };

                Ok(res)
            })
            .await?;
        Ok(peerstate)
    }

    /// Re-calculate `self.public_key_fingerprint` and `self.gossip_key_fingerprint`.
    /// If one of them was changed, `self.fingerprint_changed` is set to `true`.
    ///
    /// Call this after you changed `self.public_key` or `self.gossip_key`.
    pub fn recalc_fingerprint(&mut self) {
        if let Some(ref public_key) = self.public_key {
            let old_public_fingerprint = self.public_key_fingerprint.take();
            self.public_key_fingerprint = Some(public_key.fingerprint());

            if old_public_fingerprint.is_none()
                || self.public_key_fingerprint.is_none()
                || old_public_fingerprint != self.public_key_fingerprint
            {
                self.to_save = Some(ToSave::All);
                if old_public_fingerprint.is_some() {
                    self.fingerprint_changed = true;
                }
            }
        }

        if let Some(ref gossip_key) = self.gossip_key {
            let old_gossip_fingerprint = self.gossip_key_fingerprint.take();
            self.gossip_key_fingerprint = Some(gossip_key.fingerprint());

            if old_gossip_fingerprint.is_none()
                || self.gossip_key_fingerprint.is_none()
                || old_gossip_fingerprint != self.gossip_key_fingerprint
            {
                self.to_save = Some(ToSave::All);

                // Warn about gossip key change only if there is no public key obtained from
                // Autocrypt header, which overrides gossip key.
                if old_gossip_fingerprint.is_some() && self.public_key_fingerprint.is_none() {
                    self.fingerprint_changed = true;
                }
            }
        }
    }

    pub fn degrade_encryption(&mut self, message_time: i64) {
        self.prefer_encrypt = EncryptPreference::Reset;
        self.last_seen = message_time;
        self.to_save = Some(ToSave::All);
    }

    pub fn apply_header(&mut self, header: &Aheader, message_time: i64) {
        if !addr_cmp(&self.addr, &header.addr) {
            return;
        }

        if message_time > self.last_seen {
            self.last_seen = message_time;
            self.last_seen_autocrypt = message_time;
            self.to_save = Some(ToSave::Timestamps);
            if (header.prefer_encrypt == EncryptPreference::Mutual
                || header.prefer_encrypt == EncryptPreference::NoPreference)
                && header.prefer_encrypt != self.prefer_encrypt
            {
                self.prefer_encrypt = header.prefer_encrypt;
                self.to_save = Some(ToSave::All)
            }

            if self.public_key.as_ref() != Some(&header.public_key) {
                self.public_key = Some(header.public_key.clone());
                self.recalc_fingerprint();
                self.to_save = Some(ToSave::All);
            }
        }
    }

    pub fn apply_gossip(&mut self, gossip_header: &Aheader, message_time: i64) {
        if self.addr.to_lowercase() != gossip_header.addr.to_lowercase() {
            return;
        }

        if message_time > self.gossip_timestamp {
            self.gossip_timestamp = message_time;
            self.to_save = Some(ToSave::Timestamps);
            if self.gossip_key.as_ref() != Some(&gossip_header.public_key) {
                self.gossip_key = Some(gossip_header.public_key.clone());
                self.recalc_fingerprint();
                self.to_save = Some(ToSave::All)
            }

            // This is non-standard.
            //
            // According to Autocrypt 1.1.0 gossip headers SHOULD NOT
            // contain encryption preference, but we include it into
            // Autocrypt-Gossip and apply it one way (from
            // "nopreference" to "mutual").
            //
            // This is compatible to standard clients, because they
            // can't distinguish it from the case where we have
            // contacted the client in the past and received this
            // preference via Autocrypt header.
            if self.last_seen_autocrypt == 0
                && self.prefer_encrypt == EncryptPreference::NoPreference
                && gossip_header.prefer_encrypt == EncryptPreference::Mutual
            {
                self.prefer_encrypt = EncryptPreference::Mutual;
                self.to_save = Some(ToSave::All);
            }
        };
    }

    pub fn render_gossip_header(&self, min_verified: PeerstateVerifiedStatus) -> Option<String> {
        if let Some(key) = self.peek_key(min_verified) {
            let header = Aheader::new(
                self.addr.clone(),
                key.clone(), // TODO: avoid cloning
                // Autocrypt 1.1.0 specification says that
                // `prefer-encrypt` attribute SHOULD NOT be included,
                // but we include it anyway to propagate encryption
                // preference to new members in group chats.
                if self.last_seen_autocrypt > 0 {
                    self.prefer_encrypt
                } else {
                    EncryptPreference::NoPreference
                },
            );
            Some(header.to_string())
        } else {
            None
        }
    }

    pub fn take_key(mut self, min_verified: PeerstateVerifiedStatus) -> Option<SignedPublicKey> {
        match min_verified {
            PeerstateVerifiedStatus::BidirectVerified => self.verified_key.take(),
            PeerstateVerifiedStatus::Unverified => {
                self.public_key.take().or_else(|| self.gossip_key.take())
            }
        }
    }

    pub fn peek_key(&self, min_verified: PeerstateVerifiedStatus) -> Option<&SignedPublicKey> {
        match min_verified {
            PeerstateVerifiedStatus::BidirectVerified => self.verified_key.as_ref(),
            PeerstateVerifiedStatus::Unverified => {
                self.public_key.as_ref().or(self.gossip_key.as_ref())
            }
        }
    }

    pub fn set_verified(
        &mut self,
        which_key: PeerstateKeyType,
        fingerprint: &Fingerprint,
        verified: PeerstateVerifiedStatus,
    ) -> bool {
        if verified == PeerstateVerifiedStatus::BidirectVerified {
            match which_key {
                PeerstateKeyType::PublicKey => {
                    if self.public_key_fingerprint.is_some()
                        && self.public_key_fingerprint.as_ref().unwrap() == fingerprint
                    {
                        self.to_save = Some(ToSave::All);
                        self.verified_key = self.public_key.clone();
                        self.verified_key_fingerprint = self.public_key_fingerprint.clone();
                        true
                    } else {
                        false
                    }
                }
                PeerstateKeyType::GossipKey => {
                    if self.gossip_key_fingerprint.is_some()
                        && self.gossip_key_fingerprint.as_ref().unwrap() == fingerprint
                    {
                        self.to_save = Some(ToSave::All);
                        self.verified_key = self.gossip_key.clone();
                        self.verified_key_fingerprint = self.gossip_key_fingerprint.clone();
                        true
                    } else {
                        false
                    }
                }
            }
        } else {
            false
        }
    }

    pub async fn save_to_db(&self, sql: &Sql, create: bool) -> Result<()> {
        if self.to_save == Some(ToSave::All) || create {
            sql.execute(
                if create {
                    "INSERT INTO acpeerstates ( \
                         last_seen, \
                         last_seen_autocrypt, \
                         prefer_encrypted, \
                         public_key, \
                         gossip_timestamp, \
                         gossip_key, \
                         public_key_fingerprint, \
                         gossip_key_fingerprint, \
                         verified_key, \
                         verified_key_fingerprint, \
                         addr \
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)"
                } else {
                    "UPDATE acpeerstates \
                 SET last_seen=?, \
                 last_seen_autocrypt=?, \
                 prefer_encrypted=?, \
                 public_key=?, \
                 gossip_timestamp=?, \
                 gossip_key=?, \
                 public_key_fingerprint=?, \
                 gossip_key_fingerprint=?, \
                 verified_key=?, \
                 verified_key_fingerprint=? \
                 WHERE addr=?"
                },
                paramsv![
                    self.last_seen,
                    self.last_seen_autocrypt,
                    self.prefer_encrypt as i64,
                    self.public_key.as_ref().map(|k| k.to_bytes()),
                    self.gossip_timestamp,
                    self.gossip_key.as_ref().map(|k| k.to_bytes()),
                    self.public_key_fingerprint.as_ref().map(|fp| fp.hex()),
                    self.gossip_key_fingerprint.as_ref().map(|fp| fp.hex()),
                    self.verified_key.as_ref().map(|k| k.to_bytes()),
                    self.verified_key_fingerprint.as_ref().map(|fp| fp.hex()),
                    self.addr,
                ],
            )
            .await?;
        } else if self.to_save == Some(ToSave::Timestamps) {
            sql.execute(
                "UPDATE acpeerstates SET last_seen=?, last_seen_autocrypt=?, gossip_timestamp=? \
                 WHERE addr=?;",
                paramsv![
                    self.last_seen,
                    self.last_seen_autocrypt,
                    self.gossip_timestamp,
                    self.addr
                ],
            )
            .await?;
        }

        Ok(())
    }

    pub fn has_verified_key(&self, fingerprints: &HashSet<Fingerprint>) -> bool {
        if let Some(vkc) = &self.verified_key_fingerprint {
            fingerprints.contains(vkc) && self.verified_key.is_some()
        } else {
            false
        }
    }

    /// Add an info message to all the chats with this contact, informing about
    /// a [`PeerstateChange`].
    ///
    /// Also, in the case of an address change (AEAP), replace the old address
    /// with the new address in all chats.
    async fn handle_setup_change(
        &self,
        context: &Context,
        timestamp: i64,
        change: PeerstateChange,
    ) -> Result<()> {
        if context.is_self_addr(&self.addr).await? {
            // Do not try to search all the chats with self.
            return Ok(());
        }

        let contact_id = context
            .sql
            .query_get_value(
                "SELECT id FROM contacts WHERE addr=? COLLATE NOCASE;",
                paramsv![self.addr],
            )
            .await?
            .with_context(|| format!("contact with peerstate.addr {:?} not found", &self.addr))?;

        let chats = Chatlist::try_load(context, 0, None, Some(contact_id)).await?;
        let msg = match &change {
            PeerstateChange::FingerprintChange => {
                stock_str::contact_setup_changed(context, self.addr.clone()).await
            }
            PeerstateChange::Aeap(new_addr) => {
                let old_contact = Contact::load_from_db(context, contact_id).await?;
                stock_str::aeap_addr_changed(
                    context,
                    old_contact.get_display_name(),
                    &self.addr,
                    new_addr,
                )
                .await
            }
        };
        for (chat_id, msg_id) in chats.iter() {
            let timestamp_sort = if let Some(msg_id) = msg_id {
                let lastmsg = Message::load_from_db(context, *msg_id).await?;
                lastmsg.timestamp_sort
            } else {
                context
                    .sql
                    .query_get_value(
                        "SELECT created_timestamp FROM chats WHERE id=?;",
                        paramsv![chat_id],
                    )
                    .await?
                    .unwrap_or(0)
            };

            if let PeerstateChange::Aeap(new_addr) = &change {
                let chat = Chat::load_from_db(context, *chat_id).await?;

                if chat.typ == Chattype::Group && !chat.is_protected() {
                    // Don't add an info_msg to the group, in order not to make the user think
                    // that the address was automatically replaced in the group.
                    continue;
                }

                // For security reasons, for now, we only do the AEAP transition if the fingerprint
                // is verified (that's what from_verified_fingerprint_or_addr() does).
                // In order to not have inconsistent group membership state, we then only do the
                // transition in verified groups and in broadcast lists.
                if (chat.typ == Chattype::Group && chat.is_protected())
                    || chat.typ == Chattype::Broadcast
                {
                    chat::remove_from_chat_contacts_table(context, *chat_id, contact_id).await?;

                    let (new_contact_id, _) =
                        Contact::add_or_lookup(context, "", new_addr, Origin::IncomingUnknownFrom)
                            .await?;
                    if !is_contact_in_chat(context, *chat_id, new_contact_id).await? {
                        chat::add_to_chat_contacts_table(context, *chat_id, new_contact_id).await?;
                    }

                    context.emit_event(EventType::ChatModified(*chat_id));
                }
            }

            chat::add_info_msg_with_cmd(
                context,
                *chat_id,
                &msg,
                SystemMessage::Unknown,
                timestamp_sort,
                Some(timestamp),
                None,
                None,
            )
            .await?;
        }

        Ok(())
    }

    /// Adds a warning to all the chats corresponding to peerstate if fingerprint has changed.
    pub(crate) async fn handle_fingerprint_change(
        &self,
        context: &Context,
        timestamp: i64,
    ) -> Result<()> {
        if self.fingerprint_changed {
            self.handle_setup_change(context, timestamp, PeerstateChange::FingerprintChange)
                .await?;
        }
        Ok(())
    }
}

/// Do an AEAP transition, if necessary.
/// AEAP stands for "Automatic Email Address Porting."
///
/// In `drafts/aeap_mvp.md` there is a "big picture" overview over AEAP.
pub async fn maybe_do_aeap_transition(
    context: &Context,
    info: &mut DecryptionInfo,
    mime_parser: &crate::mimeparser::MimeMessage,
) -> Result<()> {
    if let Some(peerstate) = &mut info.peerstate {
        if let Some(from) = &mime_parser.from {
            // If the from addr is different from the peerstate address we know,
            // we may want to do an AEAP transition.
            if !addr_cmp(&peerstate.addr, &from.addr)
                // Check if it's a chat message; we do this to avoid
                // some accidental transitions if someone writes from multiple
                // addresses with an MUA.
                && mime_parser.has_chat_version()
                // Check if the message is signed correctly.
                // If it's not signed correctly, the whole autocrypt header will be mostly
                // ignored anyway and the message shown as not encrypted, so we don't
                // have to handle this case.
                && !mime_parser.signatures.is_empty()
                // Check if the From: address was also in the signed part of the email.
                // Without this check, an attacker could replay a message from Alice 
                // to Bob. Then Bob's device would do an AEAP transition from Alice's
                // to the attacker's address, allowing for easier phishing.
                && mime_parser.from_is_signed
                && info.message_time > peerstate.last_seen
            {
                // Add info messages to chats with this (verified) contact
                //
                peerstate
                    .handle_setup_change(
                        context,
                        info.message_time,
                        PeerstateChange::Aeap(info.from.clone()),
                    )
                    .await?;

                peerstate.addr = info.from.clone();
                let header = info.autocrypt_header.as_ref().context(
                    "Internal error: Tried to do an AEAP transition without an autocrypt header??",
                )?;
                peerstate.apply_header(header, info.message_time);
                peerstate.to_save = Some(ToSave::All);

                // We don't know whether a peerstate with this address already existed, or a
                // new one should be created, so just try both create=false and create=true,
                // and if this fails, create=true, one will succeed (this is a very cold path,
                // so performance doesn't really matter).
                peerstate.save_to_db(&context.sql, true).await?;
                peerstate.save_to_db(&context.sql, false).await?;
            }
        }
    }

    Ok(())
}

enum PeerstateChange {
    /// The contact's public key fingerprint changed, likely because
    /// the contact uses a new device and didn't transfer their key.
    FingerprintChange,
    /// The contact changed their address to the given new address
    /// (Automatic Email Address Porting).
    Aeap(String),
}

/// Removes duplicate peerstates from `acpeerstates` database table.
///
/// Normally there should be no more than one peerstate per address.
/// However, the database does not enforce this condition.
///
/// Previously there were bugs that caused creation of additional
/// peerstates when existing peerstate could not be read due to a
/// temporary database error or a failure to parse stored data.  This
/// procedure fixes the problem by removing duplicate records.
pub(crate) async fn deduplicate_peerstates(sql: &Sql) -> Result<()> {
    sql.execute(
        "DELETE FROM acpeerstates
         WHERE id NOT IN (
         SELECT MIN(id)
         FROM acpeerstates
         GROUP BY addr
         )",
        paramsv![],
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::alice_keypair;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_peerstate_save_to_db() {
        let ctx = crate::test_utils::TestContext::new().await;
        let addr = "hello@mail.com";

        let pub_key = alice_keypair().public;

        let mut peerstate = Peerstate {
            addr: addr.into(),
            last_seen: 10,
            last_seen_autocrypt: 11,
            prefer_encrypt: EncryptPreference::Mutual,
            public_key: Some(pub_key.clone()),
            public_key_fingerprint: Some(pub_key.fingerprint()),
            gossip_key: Some(pub_key.clone()),
            gossip_timestamp: 12,
            gossip_key_fingerprint: Some(pub_key.fingerprint()),
            verified_key: Some(pub_key.clone()),
            verified_key_fingerprint: Some(pub_key.fingerprint()),
            to_save: Some(ToSave::All),
            fingerprint_changed: false,
        };

        assert!(
            peerstate.save_to_db(&ctx.ctx.sql, true).await.is_ok(),
            "failed to save to db"
        );

        let peerstate_new = Peerstate::from_addr(&ctx.ctx, addr)
            .await
            .expect("failed to load peerstate from db")
            .expect("no peerstate found in the database");

        // clear to_save, as that is not persissted
        peerstate.to_save = None;
        assert_eq!(peerstate, peerstate_new);
        let peerstate_new2 = Peerstate::from_fingerprint(&ctx.ctx, &pub_key.fingerprint())
            .await
            .expect("failed to load peerstate from db")
            .expect("no peerstate found in the database");
        assert_eq!(peerstate, peerstate_new2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_peerstate_double_create() {
        let ctx = crate::test_utils::TestContext::new().await;
        let addr = "hello@mail.com";
        let pub_key = alice_keypair().public;

        let peerstate = Peerstate {
            addr: addr.into(),
            last_seen: 10,
            last_seen_autocrypt: 11,
            prefer_encrypt: EncryptPreference::Mutual,
            public_key: Some(pub_key.clone()),
            public_key_fingerprint: Some(pub_key.fingerprint()),
            gossip_key: None,
            gossip_timestamp: 12,
            gossip_key_fingerprint: None,
            verified_key: None,
            verified_key_fingerprint: None,
            to_save: Some(ToSave::All),
            fingerprint_changed: false,
        };

        assert!(
            peerstate.save_to_db(&ctx.ctx.sql, true).await.is_ok(),
            "failed to save"
        );
        assert!(
            peerstate.save_to_db(&ctx.ctx.sql, true).await.is_ok(),
            "double-call with create failed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_peerstate_with_empty_gossip_key_save_to_db() {
        let ctx = crate::test_utils::TestContext::new().await;
        let addr = "hello@mail.com";

        let pub_key = alice_keypair().public;

        let mut peerstate = Peerstate {
            addr: addr.into(),
            last_seen: 10,
            last_seen_autocrypt: 11,
            prefer_encrypt: EncryptPreference::Mutual,
            public_key: Some(pub_key.clone()),
            public_key_fingerprint: Some(pub_key.fingerprint()),
            gossip_key: None,
            gossip_timestamp: 12,
            gossip_key_fingerprint: None,
            verified_key: None,
            verified_key_fingerprint: None,
            to_save: Some(ToSave::All),
            fingerprint_changed: false,
        };

        assert!(
            peerstate.save_to_db(&ctx.ctx.sql, true).await.is_ok(),
            "failed to save"
        );

        let peerstate_new = Peerstate::from_addr(&ctx.ctx, addr)
            .await
            .expect("failed to load peerstate from db");

        // clear to_save, as that is not persissted
        peerstate.to_save = None;
        assert_eq!(Some(peerstate), peerstate_new);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_peerstate_load_db_defaults() {
        let ctx = crate::test_utils::TestContext::new().await;
        let addr = "hello@mail.com";

        // Old code created peerstates with this code and updated
        // other values later.  If UPDATE failed, other columns had
        // default values, in particular fingerprints were set to
        // empty strings instead of NULL. This should not be the case
        // anymore, but the regression test still checks that defaults
        // can be loaded without errors.
        ctx.ctx
            .sql
            .execute("INSERT INTO acpeerstates (addr) VALUES(?)", paramsv![addr])
            .await
            .expect("Failed to write to the database");

        let peerstate = Peerstate::from_addr(&ctx.ctx, addr)
            .await
            .expect("Failed to load peerstate from db")
            .expect("Loaded peerstate is empty");

        // Check that default values for fingerprints are treated like
        // NULL.
        assert_eq!(peerstate.public_key_fingerprint, None);
        assert_eq!(peerstate.gossip_key_fingerprint, None);
        assert_eq!(peerstate.verified_key_fingerprint, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_peerstate_degrade_reordering() {
        let addr = "example@example.org";
        let pub_key = alice_keypair().public;
        let header = Aheader::new(addr.to_string(), pub_key, EncryptPreference::Mutual);

        let mut peerstate = Peerstate {
            addr: addr.to_string(),
            last_seen: 0,
            last_seen_autocrypt: 0,
            prefer_encrypt: EncryptPreference::NoPreference,
            public_key: None,
            public_key_fingerprint: None,
            gossip_key: None,
            gossip_timestamp: 0,
            gossip_key_fingerprint: None,
            verified_key: None,
            verified_key_fingerprint: None,
            to_save: None,
            fingerprint_changed: false,
        };
        assert_eq!(peerstate.prefer_encrypt, EncryptPreference::NoPreference);

        peerstate.apply_header(&header, 100);
        assert_eq!(peerstate.prefer_encrypt, EncryptPreference::Mutual);

        peerstate.degrade_encryption(300);
        assert_eq!(peerstate.prefer_encrypt, EncryptPreference::Reset);

        // This has message time 200, while encryption was degraded at timestamp 300.
        // Because of reordering, header should not be applied.
        peerstate.apply_header(&header, 200);
        assert_eq!(peerstate.prefer_encrypt, EncryptPreference::Reset);

        // Same header will be applied in the future.
        peerstate.apply_header(&header, 400);
        assert_eq!(peerstate.prefer_encrypt, EncryptPreference::Mutual);
    }
}
