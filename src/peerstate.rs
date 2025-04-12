//! # [Autocrypt Peer State](https://autocrypt.org/level1.html#peer-state-management) module.

use anyhow::{Context as _, Error, Result};
use deltachat_contact_tools::addr_cmp;
use num_traits::FromPrimitive;

use crate::aheader::{Aheader, EncryptPreference};
use crate::chat;
use crate::chatlist::Chatlist;
use crate::context::Context;
use crate::key::{DcKey, Fingerprint, SignedPublicKey};
use crate::message::Message;
use crate::mimeparser::SystemMessage;
use crate::sql::Sql;
use crate::{chatlist_events, stock_str};

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
        };
        for (chat_id, msg_id) in chats.iter() {
            let timestamp_sort = if let Some(msg_id) = msg_id {
                let lastmsg = Message::load_from_db(context, *msg_id).await?;
                lastmsg.timestamp_sort
            } else {
                chat_id.created_timestamp(context).await?
            };

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

/// Type of the peerstate change.
///
/// Changes to the peerstate are notified to the user via a message
/// explaining the happened change.
enum PeerstateChange {
    /// The contact's public key fingerprint changed, likely because
    /// the contact uses a new device and didn't transfer their key.
    FingerprintChange,
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
