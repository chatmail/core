//! # [Autocrypt Peer State](https://autocrypt.org/level1.html#peer-state-management) module.

use std::mem;

use anyhow::{Context as _, Error, Result};
use deltachat_contact_tools::{addr_cmp, ContactAddress};
use num_traits::FromPrimitive;

use crate::aheader::{Aheader, EncryptPreference};
use crate::chat::{self, Chat};
use crate::chatlist::Chatlist;
use crate::config::Config;
use crate::constants::Chattype;
use crate::contact::{Contact, Origin};
use crate::context::Context;
use crate::events::EventType;
use crate::key::{DcKey, Fingerprint, SignedPublicKey};
use crate::log::{info, warn};
use crate::message::Message;
use crate::mimeparser::SystemMessage;
use crate::sql::Sql;
use crate::{chatlist_events, stock_str};

/// Type of the public key stored inside the peerstate.
#[derive(Debug)]
pub enum PeerstateKeyType {
    /// Public key sent in the `Autocrypt-Gossip` header.
    GossipKey,

    /// Public key sent in the `Autocrypt` header.
    PublicKey,
}

/// Peerstate represents the state of an Autocrypt peer.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Peerstate {
    /// E-mail address of the contact.
    pub addr: String,

    /// Timestamp of the latest peerstate update.
    ///
    /// Updated when a message is received from a contact,
    /// either with or without `Autocrypt` header.
    pub last_seen: i64,

    /// Timestamp of the latest `Autocrypt` header reception.
    pub last_seen_autocrypt: i64,

    /// Encryption preference of the contact.
    pub prefer_encrypt: EncryptPreference,

    /// Public key of the contact received in `Autocrypt` header.
    pub public_key: Option<SignedPublicKey>,

    /// Fingerprint of the contact public key.
    pub public_key_fingerprint: Option<Fingerprint>,

    /// Public key of the contact received in `Autocrypt-Gossip` header.
    pub gossip_key: Option<SignedPublicKey>,

    /// Timestamp of the latest `Autocrypt-Gossip` header reception.
    ///
    /// It is stored to avoid applying outdated gossiped key
    /// from delayed or reordered messages.
    pub gossip_timestamp: i64,

    /// Fingerprint of the contact gossip key.
    pub gossip_key_fingerprint: Option<Fingerprint>,

    /// Public key of the contact at the time it was verified,
    /// either directly or via gossip from the verified contact.
    pub verified_key: Option<SignedPublicKey>,

    /// Fingerprint of the verified public key.
    pub verified_key_fingerprint: Option<Fingerprint>,

    /// The address that introduced this verified key.
    pub verifier: Option<String>,

    /// Secondary public verified key of the contact.
    /// It could be a contact gossiped by another verified contact in a shared group
    /// or a key that was previously used as a verified key.
    pub secondary_verified_key: Option<SignedPublicKey>,

    /// Fingerprint of the secondary verified public key.
    pub secondary_verified_key_fingerprint: Option<Fingerprint>,

    /// The address that introduced secondary verified key.
    pub secondary_verifier: Option<String>,

    /// Row ID of the key in the `keypairs` table
    /// that we think the peer knows as verified.
    pub backward_verified_key_id: Option<i64>,

    /// True if it was detected
    /// that the fingerprint of the key used in chats with
    /// opportunistic encryption was changed after Peerstate creation.
    pub fingerprint_changed: bool,
}

impl Peerstate {
    /// Creates a peerstate from the `Autocrypt` header.
    pub fn from_header(header: &Aheader, message_time: i64) -> Self {
        Self::from_public_key(
            &header.addr,
            message_time,
            header.prefer_encrypt,
            &header.public_key,
        )
    }

    /// Creates a peerstate from the given public key.
    pub fn from_public_key(
        addr: &str,
        last_seen: i64,
        prefer_encrypt: EncryptPreference,
        public_key: &SignedPublicKey,
    ) -> Self {
        Peerstate {
            addr: addr.to_string(),
            last_seen,
            last_seen_autocrypt: last_seen,
            prefer_encrypt,
            public_key: Some(public_key.clone()),
            public_key_fingerprint: Some(public_key.dc_fingerprint()),
            gossip_key: None,
            gossip_key_fingerprint: None,
            gossip_timestamp: 0,
            verified_key: None,
            verified_key_fingerprint: None,
            verifier: None,
            secondary_verified_key: None,
            secondary_verified_key_fingerprint: None,
            secondary_verifier: None,
            backward_verified_key_id: None,
            fingerprint_changed: false,
        }
    }

    /// Create a peerstate from the `Autocrypt-Gossip` header.
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
            gossip_key_fingerprint: Some(gossip_header.public_key.dc_fingerprint()),
            gossip_timestamp: message_time,
            verified_key: None,
            verified_key_fingerprint: None,
            verifier: None,
            secondary_verified_key: None,
            secondary_verified_key_fingerprint: None,
            secondary_verifier: None,
            backward_verified_key_id: None,
            fingerprint_changed: false,
        }
    }

    /// Loads peerstate corresponding to the given address from the database.
    pub async fn from_addr(context: &Context, addr: &str) -> Result<Option<Peerstate>> {
        if context.is_self_addr(addr).await? {
            return Ok(None);
        }
        let query = "SELECT addr, last_seen, last_seen_autocrypt, prefer_encrypted, public_key, \
                     gossip_timestamp, gossip_key, public_key_fingerprint, gossip_key_fingerprint, \
                     verified_key, verified_key_fingerprint, \
                     verifier, \
                     secondary_verified_key, secondary_verified_key_fingerprint, \
                     secondary_verifier, \
                     backward_verified_key_id \
                     FROM acpeerstates \
                     WHERE addr=? COLLATE NOCASE LIMIT 1;";
        Self::from_stmt(context, query, (addr,)).await
    }

    /// Loads peerstate corresponding to the given fingerprint from the database.
    pub async fn from_fingerprint(
        context: &Context,
        fingerprint: &Fingerprint,
    ) -> Result<Option<Peerstate>> {
        // NOTE: If it's our key fingerprint, this returns None currently.
        let query = "SELECT addr, last_seen, last_seen_autocrypt, prefer_encrypted, public_key, \
                     gossip_timestamp, gossip_key, public_key_fingerprint, gossip_key_fingerprint, \
                     verified_key, verified_key_fingerprint, \
                     verifier, \
                     secondary_verified_key, secondary_verified_key_fingerprint, \
                     secondary_verifier, \
                     backward_verified_key_id \
                     FROM acpeerstates  \
                     WHERE public_key_fingerprint=? \
                     OR gossip_key_fingerprint=? \
                     ORDER BY public_key_fingerprint=? DESC LIMIT 1;";
        let fp = fingerprint.hex();
        Self::from_stmt(context, query, (&fp, &fp, &fp)).await
    }

    /// Loads peerstate by address or verified fingerprint.
    ///
    /// If the address is different but verified fingerprint is the same,
    /// peerstate with corresponding verified fingerprint is preferred.
    pub async fn from_verified_fingerprint_or_addr(
        context: &Context,
        fingerprint: &Fingerprint,
        addr: &str,
    ) -> Result<Option<Peerstate>> {
        if context.is_self_addr(addr).await? {
            return Ok(None);
        }
        let query = "SELECT addr, last_seen, last_seen_autocrypt, prefer_encrypted, public_key, \
                     gossip_timestamp, gossip_key, public_key_fingerprint, gossip_key_fingerprint, \
                     verified_key, verified_key_fingerprint, \
                     verifier, \
                     secondary_verified_key, secondary_verified_key_fingerprint, \
                     secondary_verifier, \
                     backward_verified_key_id \
                     FROM acpeerstates  \
                     WHERE verified_key_fingerprint=? \
                     OR addr=? COLLATE NOCASE \
                     ORDER BY verified_key_fingerprint=? DESC, addr=? COLLATE NOCASE DESC, \
                     last_seen DESC LIMIT 1;";
        let fp = fingerprint.hex();
        Self::from_stmt(context, query, (&fp, addr, &fp, addr)).await
    }

    async fn from_stmt(
        context: &Context,
        query: &str,
        params: impl rusqlite::Params + Send,
    ) -> Result<Option<Peerstate>> {
        let peerstate = context
            .sql
            .query_row_optional(query, params, |row| {
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
                    verifier: {
                        let verifier: Option<String> = row.get("verifier")?;
                        verifier.filter(|s| !s.is_empty())
                    },
                    secondary_verified_key: row
                        .get("secondary_verified_key")
                        .ok()
                        .and_then(|blob: Vec<u8>| SignedPublicKey::from_slice(&blob).ok()),
                    secondary_verified_key_fingerprint: row
                        .get::<_, Option<String>>("secondary_verified_key_fingerprint")?
                        .map(|s| s.parse::<Fingerprint>())
                        .transpose()
                        .unwrap_or_default(),
                    secondary_verifier: {
                        let secondary_verifier: Option<String> = row.get("secondary_verifier")?;
                        secondary_verifier.filter(|s| !s.is_empty())
                    },
                    backward_verified_key_id: row.get("backward_verified_key_id")?,
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
            self.public_key_fingerprint = Some(public_key.dc_fingerprint());

            if old_public_fingerprint.is_some()
                && old_public_fingerprint != self.public_key_fingerprint
            {
                self.fingerprint_changed = true;
            }
        }

        if let Some(ref gossip_key) = self.gossip_key {
            let old_gossip_fingerprint = self.gossip_key_fingerprint.take();
            self.gossip_key_fingerprint = Some(gossip_key.dc_fingerprint());

            if old_gossip_fingerprint.is_none()
                || self.gossip_key_fingerprint.is_none()
                || old_gossip_fingerprint != self.gossip_key_fingerprint
            {
                // Warn about gossip key change only if there is no public key obtained from
                // Autocrypt header, which overrides gossip key.
                if old_gossip_fingerprint.is_some() && self.public_key_fingerprint.is_none() {
                    self.fingerprint_changed = true;
                }
            }
        }
    }

    /// Reset Autocrypt peerstate.
    ///
    /// Used when it is detected that the contact no longer uses Autocrypt.
    pub fn degrade_encryption(&mut self, message_time: i64) {
        self.prefer_encrypt = EncryptPreference::Reset;
        self.last_seen = message_time;
    }

    /// Updates peerstate according to the given `Autocrypt` header.
    pub fn apply_header(&mut self, context: &Context, header: &Aheader, message_time: i64) {
        if !addr_cmp(&self.addr, &header.addr) {
            return;
        }

        if message_time >= self.last_seen {
            self.last_seen = message_time;
            self.last_seen_autocrypt = message_time;
            if (header.prefer_encrypt == EncryptPreference::Mutual
                || header.prefer_encrypt == EncryptPreference::NoPreference)
                && header.prefer_encrypt != self.prefer_encrypt
            {
                self.prefer_encrypt = header.prefer_encrypt;
            }

            if self.public_key.as_ref() != Some(&header.public_key) {
                self.public_key = Some(header.public_key.clone());
                self.recalc_fingerprint();
            }
        } else {
            warn!(
                context,
                "Ignoring outdated Autocrypt header because message_time={} < last_seen={}.",
                message_time,
                self.last_seen
            );
        }
    }

    /// Updates peerstate according to the given `Autocrypt-Gossip` header.
    pub fn apply_gossip(&mut self, gossip_header: &Aheader, message_time: i64) {
        if self.addr.to_lowercase() != gossip_header.addr.to_lowercase() {
            return;
        }

        if message_time >= self.gossip_timestamp {
            self.gossip_timestamp = message_time;
            if self.gossip_key.as_ref() != Some(&gossip_header.public_key) {
                self.gossip_key = Some(gossip_header.public_key.clone());
                self.recalc_fingerprint();
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
            }
        };
    }

    /// Converts the peerstate into the contact public key.
    ///
    /// Similar to [`Self::peek_key`], but consumes the peerstate and returns owned key.
    pub fn take_key(mut self, verified: bool) -> Option<SignedPublicKey> {
        if verified {
            self.verified_key.take()
        } else {
            self.public_key.take().or_else(|| self.gossip_key.take())
        }
    }

    /// Returns a reference to the contact public key.
    ///
    /// `verified` determines the required verification status of the key.
    /// If verified key is requested, returns the verified key,
    /// otherwise returns the Autocrypt key.
    ///
    /// Returned key is suitable for sending in `Autocrypt-Gossip` header.
    ///
    /// Returns `None` if there is no suitable public key.
    pub fn peek_key(&self, verified: bool) -> Option<&SignedPublicKey> {
        if verified {
            self.verified_key.as_ref()
        } else {
            self.public_key.as_ref().or(self.gossip_key.as_ref())
        }
    }

    /// Returns a reference to the contact's public key fingerprint.
    ///
    /// Similar to [`Self::peek_key`], but returns the fingerprint instead of the key.
    fn peek_key_fingerprint(&self, verified: bool) -> Option<&Fingerprint> {
        if verified {
            self.verified_key_fingerprint.as_ref()
        } else {
            self.public_key_fingerprint
                .as_ref()
                .or(self.gossip_key_fingerprint.as_ref())
        }
    }

    /// Returns true if the key used for opportunistic encryption in the 1:1 chat
    /// is the same as the verified key.
    ///
    /// Note that verified groups always use the verified key no matter if the
    /// opportunistic key matches or not.
    pub(crate) fn is_using_verified_key(&self) -> bool {
        let verified = self.peek_key_fingerprint(true);

        verified.is_some() && verified == self.peek_key_fingerprint(false)
    }

    pub(crate) async fn is_backward_verified(&self, context: &Context) -> Result<bool> {
        let Some(backward_verified_key_id) = self.backward_verified_key_id else {
            return Ok(false);
        };

        let self_key_id = context.get_config_i64(Config::KeyId).await?;

        let backward_verified = backward_verified_key_id == self_key_id;
        Ok(backward_verified)
    }

    /// Set this peerstate to verified;
    /// make sure to call `self.save_to_db` to save these changes.
    ///
    /// Params:
    ///
    /// * key: The new verified key.
    /// * fingerprint: Only set to verified if the key's fingerprint matches this.
    /// * verifier:
    ///   The address which introduces the given contact.
    ///   If we are verifying the contact, use that contacts address.
    pub fn set_verified(
        &mut self,
        key: SignedPublicKey,
        fingerprint: Fingerprint,
        verifier: String,
    ) -> Result<()> {
        if key.dc_fingerprint() == fingerprint {
            self.verified_key = Some(key);
            self.verified_key_fingerprint = Some(fingerprint);
            self.verifier = Some(verifier);
            Ok(())
        } else {
            Err(Error::msg(format!(
                "{fingerprint} is not peer's key fingerprint",
            )))
        }
    }

    /// Sets the gossiped key as the secondary verified key.
    ///
    /// If gossiped key is the same as the current verified key,
    /// do nothing to avoid overwriting secondary verified key
    /// which may be different.
    pub fn set_secondary_verified_key(&mut self, gossip_key: SignedPublicKey, verifier: String) {
        let fingerprint = gossip_key.dc_fingerprint();
        if self.verified_key_fingerprint.as_ref() != Some(&fingerprint) {
            self.secondary_verified_key = Some(gossip_key);
            self.secondary_verified_key_fingerprint = Some(fingerprint);
            self.secondary_verifier = Some(verifier);
        }
    }

    /// Saves the peerstate to the database.
    pub async fn save_to_db(&self, sql: &Sql) -> Result<()> {
        self.save_to_db_ex(sql, None).await
    }

    /// Saves the peerstate to the database.
    ///
    /// * `old_addr`: Old address of the peerstate in case of an AEAP transition.
    pub(crate) async fn save_to_db_ex(&self, sql: &Sql, old_addr: Option<&str>) -> Result<()> {
        let trans_fn = |t: &mut rusqlite::Transaction| {
            let verified_key_fingerprint =
                self.verified_key_fingerprint.as_ref().map(|fp| fp.hex());
            if let Some(old_addr) = old_addr {
                // We are doing an AEAP transition to the new address and the SQL INSERT below will
                // save the existing peerstate as belonging to this new address. We now need to
                // "unverify" the peerstate that belongs to the current address in case if the
                // contact later wants to move back to the current address. Otherwise the old entry
                // will be just found and updated instead of doing AEAP. We can't just delete the
                // existing peerstate as this would break encryption to it. This is critical for
                // non-verified groups -- if we can't encrypt to the old address, we can't securely
                // remove it from the group (to add the new one instead).
                //
                // NB: We check that `verified_key_fingerprint` hasn't changed to protect from
                // possible races.
                t.execute(
                    "UPDATE acpeerstates
                     SET verified_key=NULL, verified_key_fingerprint='', verifier=''
                     WHERE addr=? AND verified_key_fingerprint=?",
                    (old_addr, &verified_key_fingerprint),
                )?;
            }
            t.execute(
                "INSERT INTO acpeerstates (
                    last_seen,
                    last_seen_autocrypt,
                    prefer_encrypted,
                    public_key,
                    gossip_timestamp,
                    gossip_key,
                    public_key_fingerprint,
                    gossip_key_fingerprint,
                    verified_key,
                    verified_key_fingerprint,
                    verifier,
                    secondary_verified_key,
                    secondary_verified_key_fingerprint,
                    secondary_verifier,
                    backward_verified_key_id,
                    addr)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT (addr)
                    DO UPDATE SET
                    last_seen = excluded.last_seen,
                    last_seen_autocrypt = excluded.last_seen_autocrypt,
                    prefer_encrypted = excluded.prefer_encrypted,
                    public_key = excluded.public_key,
                    gossip_timestamp = excluded.gossip_timestamp,
                    gossip_key = excluded.gossip_key,
                    public_key_fingerprint = excluded.public_key_fingerprint,
                    gossip_key_fingerprint = excluded.gossip_key_fingerprint,
                    verified_key = excluded.verified_key,
                    verified_key_fingerprint = excluded.verified_key_fingerprint,
                    verifier = excluded.verifier,
                    secondary_verified_key = excluded.secondary_verified_key,
                    secondary_verified_key_fingerprint = excluded.secondary_verified_key_fingerprint,
                    secondary_verifier = excluded.secondary_verifier,
                    backward_verified_key_id = excluded.backward_verified_key_id",
                (
                    self.last_seen,
                    self.last_seen_autocrypt,
                    self.prefer_encrypt as i64,
                    self.public_key.as_ref().map(|k| k.to_bytes()),
                    self.gossip_timestamp,
                    self.gossip_key.as_ref().map(|k| k.to_bytes()),
                    self.public_key_fingerprint.as_ref().map(|fp| fp.hex()),
                    self.gossip_key_fingerprint.as_ref().map(|fp| fp.hex()),
                    self.verified_key.as_ref().map(|k| k.to_bytes()),
                    &verified_key_fingerprint,
                    self.verifier.as_deref().unwrap_or(""),
                    self.secondary_verified_key.as_ref().map(|k| k.to_bytes()),
                    self.secondary_verified_key_fingerprint
                        .as_ref()
                        .map(|fp| fp.hex()),
                    self.secondary_verifier.as_deref().unwrap_or(""),
                    self.backward_verified_key_id,
                    &self.addr,
                ),
            )?;
            Ok(())
        };
        sql.transaction(trans_fn).await
    }

    /// Returns the address that verified the contact
    pub fn get_verifier(&self) -> Option<&str> {
        self.verifier.as_deref()
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
                (&self.addr,),
            )
            .await?
            .with_context(|| format!("contact with peerstate.addr {:?} not found", &self.addr))?;

        let chats = Chatlist::try_load(context, 0, None, Some(contact_id)).await?;
        let msg = match &change {
            PeerstateChange::FingerprintChange => {
                stock_str::contact_setup_changed(context, &self.addr).await
            }
            PeerstateChange::Aeap(new_addr) => {
                let old_contact = Contact::get_by_id(context, contact_id).await?;
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
                chat_id.created_timestamp(context).await?
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
                    match ContactAddress::new(new_addr) {
                        Ok(new_addr) => {
                            let (new_contact_id, _) = Contact::add_or_lookup(
                                context,
                                "",
                                &new_addr,
                                Origin::IncomingUnknownFrom,
                            )
                            .await?;
                            context
                                .sql
                                .transaction(|transaction| {
                                    transaction.execute(
                                        "UPDATE chats_contacts
                                         SET remove_timestamp=MAX(add_timestamp+1, ?)
                                         WHERE chat_id=? AND contact_id=?",
                                        (timestamp, chat_id, contact_id),
                                    )?;
                                    transaction.execute(
                                        "INSERT INTO chats_contacts
                                         (chat_id, contact_id, add_timestamp)
                                         VALUES (?1, ?2, ?3)
                                         ON CONFLICT (chat_id, contact_id)
                                         DO UPDATE SET add_timestamp=MAX(remove_timestamp, ?3)",
                                        (chat_id, new_contact_id, timestamp),
                                    )?;
                                    Ok(())
                                })
                                .await?;

                            context.emit_event(EventType::ChatModified(*chat_id));
                        }
                        Err(err) => {
                            warn!(
                                context,
                                "New address {:?} is not valid, not doing AEAP: {:#}.",
                                new_addr,
                                err
                            )
                        }
                    }
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
                None,
            )
            .await?;
        }

        chatlist_events::emit_chatlist_changed(context);
        // update the chats the contact is part of
        chatlist_events::emit_chatlist_items_changed_for_contact(context, contact_id);
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
pub(crate) async fn maybe_do_aeap_transition(
    context: &Context,
    mime_parser: &mut crate::mimeparser::MimeMessage,
) -> Result<()> {
    let Some(peerstate) = &mime_parser.peerstate else {
        return Ok(());
    };

    // If the from addr is different from the peerstate address we know,
    // we may want to do an AEAP transition.
    if !addr_cmp(&peerstate.addr, &mime_parser.from.addr) {
        // Check if it's a chat message; we do this to avoid
        // some accidental transitions if someone writes from multiple
        // addresses with an MUA.
        if !mime_parser.has_chat_version() {
            info!(
                context,
                "Not doing AEAP from {} to {} because the message is not a chat message.",
                &peerstate.addr,
                &mime_parser.from.addr
            );
            return Ok(());
        }

        // Check if the message is encrypted and signed correctly. If it's not encrypted, it's
        // probably from a new contact sharing the same key.
        if mime_parser.signatures.is_empty() {
            info!(
                context,
                "Not doing AEAP from {} to {} because the message is not encrypted and signed.",
                &peerstate.addr,
                &mime_parser.from.addr
            );
            return Ok(());
        }

        // Check if the From: address was also in the signed part of the email.
        // Without this check, an attacker could replay a message from Alice
        // to Bob. Then Bob's device would do an AEAP transition from Alice's
        // to the attacker's address, allowing for easier phishing.
        if !mime_parser.from_is_signed {
            info!(
                context,
                "Not doing AEAP from {} to {} because From: is not signed.",
                &peerstate.addr,
                &mime_parser.from.addr
            );
            return Ok(());
        }

        // DC avoids sending messages with the same timestamp, that's why messages
        // with equal timestamps are ignored here unlike in `Peerstate::apply_header()`.
        if mime_parser.timestamp_sent <= peerstate.last_seen {
            info!(
                context,
                "Not doing AEAP from {} to {} because {} < {}.",
                &peerstate.addr,
                &mime_parser.from.addr,
                mime_parser.timestamp_sent,
                peerstate.last_seen
            );
            return Ok(());
        }

        info!(
            context,
            "Doing AEAP transition from {} to {}.", &peerstate.addr, &mime_parser.from.addr
        );

        let peerstate = mime_parser.peerstate.as_mut().context("no peerstate??")?;
        // Add info messages to chats with this (verified) contact
        //
        peerstate
            .handle_setup_change(
                context,
                mime_parser.timestamp_sent,
                PeerstateChange::Aeap(mime_parser.from.addr.clone()),
            )
            .await?;

        let old_addr = mem::take(&mut peerstate.addr);
        peerstate.addr.clone_from(&mime_parser.from.addr);
        let header = mime_parser.autocrypt_header.as_ref().context(
            "Internal error: Tried to do an AEAP transition without an autocrypt header??",
        )?;
        peerstate.apply_header(context, header, mime_parser.timestamp_sent);

        peerstate
            .save_to_db_ex(&context.sql, Some(&old_addr))
            .await?;
    }

    Ok(())
}

/// Type of the peerstate change.
///
/// Changes to the peerstate are notified to the user via a message
/// explaining the happened change.
enum PeerstateChange {
    /// The contact's public key fingerprint changed, likely because
    /// the contact uses a new device and didn't transfer their key.
    FingerprintChange,
    /// The contact changed their address to the given new address
    /// (Automatic Email Address Porting).
    Aeap(String),
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

        let peerstate = Peerstate {
            addr: addr.into(),
            last_seen: 10,
            last_seen_autocrypt: 11,
            prefer_encrypt: EncryptPreference::Mutual,
            public_key: Some(pub_key.clone()),
            public_key_fingerprint: Some(pub_key.dc_fingerprint()),
            gossip_key: Some(pub_key.clone()),
            gossip_timestamp: 12,
            gossip_key_fingerprint: Some(pub_key.dc_fingerprint()),
            verified_key: Some(pub_key.clone()),
            verified_key_fingerprint: Some(pub_key.dc_fingerprint()),
            verifier: None,
            secondary_verified_key: None,
            secondary_verified_key_fingerprint: None,
            secondary_verifier: None,
            backward_verified_key_id: None,
            fingerprint_changed: false,
        };

        assert!(
            peerstate.save_to_db(&ctx.ctx.sql).await.is_ok(),
            "failed to save to db"
        );

        let peerstate_new = Peerstate::from_addr(&ctx.ctx, addr)
            .await
            .expect("failed to load peerstate from db")
            .expect("no peerstate found in the database");

        assert_eq!(peerstate, peerstate_new);
        let peerstate_new2 = Peerstate::from_fingerprint(&ctx.ctx, &pub_key.dc_fingerprint())
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
            public_key_fingerprint: Some(pub_key.dc_fingerprint()),
            gossip_key: None,
            gossip_timestamp: 12,
            gossip_key_fingerprint: None,
            verified_key: None,
            verified_key_fingerprint: None,
            verifier: None,
            secondary_verified_key: None,
            secondary_verified_key_fingerprint: None,
            secondary_verifier: None,
            backward_verified_key_id: None,
            fingerprint_changed: false,
        };

        assert!(
            peerstate.save_to_db(&ctx.ctx.sql).await.is_ok(),
            "failed to save"
        );
        assert!(
            peerstate.save_to_db(&ctx.ctx.sql).await.is_ok(),
            "double-call with create failed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_peerstate_with_empty_gossip_key_save_to_db() {
        let ctx = crate::test_utils::TestContext::new().await;
        let addr = "hello@mail.com";

        let pub_key = alice_keypair().public;

        let peerstate = Peerstate {
            addr: addr.into(),
            last_seen: 10,
            last_seen_autocrypt: 11,
            prefer_encrypt: EncryptPreference::Mutual,
            public_key: Some(pub_key.clone()),
            public_key_fingerprint: Some(pub_key.dc_fingerprint()),
            gossip_key: None,
            gossip_timestamp: 12,
            gossip_key_fingerprint: None,
            verified_key: None,
            verified_key_fingerprint: None,
            verifier: None,
            secondary_verified_key: None,
            secondary_verified_key_fingerprint: None,
            secondary_verifier: None,
            backward_verified_key_id: None,
            fingerprint_changed: false,
        };

        assert!(
            peerstate.save_to_db(&ctx.ctx.sql).await.is_ok(),
            "failed to save"
        );

        let peerstate_new = Peerstate::from_addr(&ctx.ctx, addr)
            .await
            .expect("failed to load peerstate from db");

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
            .execute("INSERT INTO acpeerstates (addr) VALUES(?)", (addr,))
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
        let ctx = crate::test_utils::TestContext::new().await;

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
            verifier: None,
            secondary_verified_key: None,
            secondary_verified_key_fingerprint: None,
            secondary_verifier: None,
            backward_verified_key_id: None,
            fingerprint_changed: false,
        };

        peerstate.apply_header(&ctx, &header, 100);
        assert_eq!(peerstate.prefer_encrypt, EncryptPreference::Mutual);

        peerstate.degrade_encryption(300);
        assert_eq!(peerstate.prefer_encrypt, EncryptPreference::Reset);

        // This has message time 200, while encryption was degraded at timestamp 300.
        // Because of reordering, header should not be applied.
        peerstate.apply_header(&ctx, &header, 200);
        assert_eq!(peerstate.prefer_encrypt, EncryptPreference::Reset);

        // Same header will be applied in the future.
        peerstate.apply_header(&ctx, &header, 300);
        assert_eq!(peerstate.prefer_encrypt, EncryptPreference::Mutual);
    }
}
