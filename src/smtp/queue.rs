//! # SMTP queue module.
use anyhow::{Context as _, Result, bail};

use crate::chat::ChatId;
use crate::context::Context;
use crate::key::{DcKey, SignedPublicKey};
use crate::message::MsgId;
use rusqlite::OptionalExtension as _;

#[derive(Debug, Clone)]
pub(crate) enum Encryption {
    /// Unencrypted message.
    No,

    /// The message is encrypted asymmetrically to public keys.
    Asymmetric {
        /// OpenPGP keys to use for encryption.
        ///
        /// The message is always encrypted to self,
        /// no need to include own key here.
        encryption_pubkeys: Vec<SignedPublicKey>,
    },

    /// Symmetrically encrypted message with a shared secret.
    Symmetric { shared_secret: String },
}

impl Encryption {
    pub(crate) fn is_encrypted(&self) -> bool {
        match self {
            Self::No => false,
            Self::Asymmetric { .. } => true,
            Self::Symmetric { .. } => true,
        }
    }
}

/// Email message queued, but not sent yet.
///
/// It is stored unencrypted to
/// make it possible to change protected headers
/// like the From address and Autocrypt header later.
#[derive(Debug, Clone)]
pub(crate) struct QueuedMail {
    /// Unencrypted queued message.
    ///
    /// This message has both the headers and the body,
    /// but without the From, Autocrypt and Message-ID headers.
    ///
    /// For encrypted messages this is the OpenPGP payload.
    pub(crate) raw_message: Vec<u8>,

    /// Display name to put in the `From:` field.
    ///
    /// Email address is not determined yet here.
    pub(crate) display_name: String,

    /// Message-ID.
    pub(crate) rfc724_mid: String,

    /// Whether the message is encrypted and encryption keys.
    pub(crate) encryption: Encryption,

    /// If true, Autocrypt header should be added before sending.
    pub(crate) should_attach_pubkey: bool,

    /// If true, OpenPGP compression may be used.
    pub(crate) should_compress: bool,

    /// If true, encrypted message should be signed.
    pub(crate) should_sign: bool,

    /// Recipient addresses.
    pub(crate) recipients: Vec<String>,

    /// Addresses the messages was already sent to.
    pub(crate) sent_to: Vec<String>,

    /// If true, own addresses should be added to the list of recipients.
    ///
    /// For unencrypted messages, only the sending addresses should be added.
    /// For encrypted messages, all published addresses should be added.
    pub(crate) bcc_self: bool,
}

/// Side effects that should be applied at the same time
/// as the message is persisted in the queue.
#[derive(Debug, Clone, Default)]
pub struct SideEffects {
    /// ID of the chat side effects should be applied to.
    pub chat_id: ChatId,

    /// Largest timestamp of the location sent in `location.kml` in this message.
    pub last_added_location_timestamp: Option<i64>,

    /// True if the message has the avatar attached.
    ///
    /// Timestamp of the last time avatar was gossiped should be updated.
    pub avatar_is_attached: bool,

    /// A comma-separated string of sync-IDs that are used by the rendered email and must be deleted
    /// from `multi_device_sync` once the message is actually queued for sending.
    pub sync_ids_to_delete: Option<String>,

    /// Subject that was rendered into the message.
    ///
    /// Used to update the subject on the sent message object.
    pub subject: String,
}

/// Email message ready to be queued with the side effects that should be applied at the same time.
pub(crate) type ToBeQueuedMail = (QueuedMail, Option<SideEffects>);

/// Process side effects and store queued mail.
pub(crate) fn enqueue_mail(
    transaction: &mut rusqlite::Transaction<'_>,
    now: i64,
    msg_id: MsgId,
    queued_mail: &QueuedMail,
    side_effects: Option<&SideEffects>,
) -> Result<i64> {
    if let Some(side_effects) = side_effects {
        if let Some(last_added_location_timestamp) = side_effects.last_added_location_timestamp {
            transaction.execute(
                "UPDATE chats SET locations_last_sent=? WHERE id=?;",
                (last_added_location_timestamp, side_effects.chat_id),
            )?;
        }

        if side_effects.avatar_is_attached {
            side_effects
                .chat_id
                .set_selfavatar_timestamp(transaction, now)
                .context("Failed to set selfavatar timestamp")?;
        }

        if let Some(ref sync_ids) = side_effects.sync_ids_to_delete {
            transaction.execute(
                &format!("DELETE FROM multi_device_sync WHERE id IN ({sync_ids})"),
                (),
            )?;
        }
    }

    // Store mail into queue.
    let all_recipients = queued_mail.recipients.join(" ");
    let is_encrypted = queued_mail.encryption.is_encrypted();

    transaction
        .execute(
            "
    INSERT INTO smtp2 (
      display_name,
      rfc724_mid,
      mime,
      should_attach_pubkey,
      should_compress,
      should_sign,
      msg_id,
      recipients,
      bcc_self,
      is_encrypted,
      shared_secret,
      encryption_fingerprints
    )
    VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )
    ",
            (
                &queued_mail.display_name,
                &queued_mail.rfc724_mid,
                &queued_mail.raw_message,
                queued_mail.should_attach_pubkey,
                queued_mail.should_compress,
                queued_mail.should_sign,
                msg_id,
                &all_recipients,
                queued_mail.bcc_self,
                is_encrypted,
                if let Encryption::Symmetric { ref shared_secret } = queued_mail.encryption {
                    shared_secret
                } else {
                    ""
                },
                if let Encryption::Asymmetric {
                    ref encryption_pubkeys,
                } = queued_mail.encryption
                {
                    let res: Vec<String> = encryption_pubkeys
                        .iter()
                        .map(|pubkey| pubkey.dc_fingerprint().hex())
                        .collect();
                    res.join(" ")
                } else {
                    "".to_string()
                },
            ),
        )
        .context("Failed to insert a row into smtp2 table")?;
    let row_id = transaction.last_insert_rowid();
    Ok(row_id)
}

/// Loads the queued mail from `smtp2` table and the list of recipients.
pub(crate) fn load_queued_mail(
    transaction: &mut rusqlite::Transaction<'_>,
    row_id: i64,
) -> Result<QueuedMail> {
    let (mut queued_mail, encryption_fingerprints) = transaction
        .query_row_and_then(
            "
SELECT display_name,
       rfc724_mid,
       mime,
       should_attach_pubkey,
       should_compress,
       should_sign,
       is_encrypted,
       shared_secret,
       encryption_fingerprints,
       recipients,
       sent_to,
       bcc_self
FROM smtp2 WHERE id = ?
",
            (row_id,),
            |row| {
                let display_name: String = row.get(0)?;
                let rfc724_mid: String = row.get(1)?;
                let raw_message: Vec<u8> = row.get(2)?;
                let should_attach_pubkey: bool = row.get(3)?;
                let should_compress: bool = row.get(4)?;
                let should_sign: bool = row.get(5)?;
                let is_encrypted: bool = row.get(6)?;
                let shared_secret: String = row.get(7)?;
                let encryption_fingerprints: String = row.get(8)?;
                let encryption_fingerprints: Vec<String> = if encryption_fingerprints.is_empty() {
                    Vec::new()
                } else {
                    encryption_fingerprints
                        .split(' ')
                        .map(|s| s.to_string())
                        .collect()
                };
                let recipients: String = row.get(9)?;
                let recipients: Vec<String> = if recipients.is_empty() {
                    Vec::new()
                } else {
                    recipients.split(' ').map(|s| s.to_string()).collect()
                };
                debug_assert!(!recipients.iter().any(|s| s.is_empty()));
                let sent_to: String = row.get(10)?;
                let sent_to: Vec<String> = if sent_to.is_empty() {
                    Vec::new()
                } else {
                    sent_to.split(' ').map(|s| s.to_string()).collect()
                };
                let bcc_self: bool = row.get(11)?;

                let encryption = match (
                    is_encrypted,
                    shared_secret.is_empty(),
                    encryption_fingerprints.is_empty(),
                ) {
                    (false, true, true) => Encryption::No,
                    (true, false, true) => Encryption::Symmetric { shared_secret },
                    (true, true, _) => Encryption::Asymmetric {
                        // Public keys are loaded below based on the encryption fingerprints.
                        encryption_pubkeys: Vec::new(),
                    },
                    _ => bail!("Invalid encryption in smtp2 row"),
                };
                Ok::<_, anyhow::Error>((
                    QueuedMail {
                        raw_message,
                        display_name,
                        rfc724_mid,
                        encryption,
                        should_attach_pubkey,
                        should_compress,
                        should_sign,
                        recipients,
                        sent_to,
                        bcc_self,
                    },
                    encryption_fingerprints,
                ))
            },
        )
        .with_context(|| format!("Failed to select row {row_id} from smtp2 table"))?;

    if let Encryption::Asymmetric {
        ref mut encryption_pubkeys,
    } = queued_mail.encryption
    {
        for fingerprint in encryption_fingerprints {
            let public_key_bytes: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT public_key FROM public_keys WHERE fingerprint=?",
                    (fingerprint,),
                    |row| {
                        let bytes: Vec<u8> = row.get(0)?;
                        Ok(bytes)
                    },
                )
                .optional()
                .context("Failed to select public key by fingerprint")?;
            if let Some(public_key_bytes) = public_key_bytes {
                let public_key = SignedPublicKey::from_slice(&public_key_bytes)?;
                encryption_pubkeys.push(public_key);
            }
        }
    }

    Ok(queued_mail)
}

/// Returns true if SMTP queue is empty.
pub(crate) async fn is_empty(context: &Context) -> Result<bool> {
    let sending_finished = !context.sql.exists("SELECT COUNT(*) FROM smtp2", ()).await?;
    Ok(sending_finished)
}
