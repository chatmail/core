//! Helper functions for decryption.
//! The actual decryption is done in the [`crate::pgp`] module.

use std::collections::HashSet;
use std::io::Cursor;

use anyhow::{Context as _, Result, bail};
use mailparse::ParsedMail;
use pgp::composed::Esk;
use pgp::composed::Message;
use pgp::composed::PlainSessionKey;
use pgp::composed::SignedSecretKey;
use pgp::composed::decrypt_session_key_with_password;
use pgp::packet::SymKeyEncryptedSessionKey;
use pgp::types::Password;
use pgp::types::StringToKey;

use crate::chat::ChatId;
use crate::constants::Chattype;
use crate::contact::ContactId;
use crate::context::Context;
use crate::key::self_fingerprint;
use crate::key::{Fingerprint, SignedPublicKey, load_self_secret_keyring};
use crate::token::Namespace;

/// Tries to decrypt the message,
/// returning a tuple of `(decrypted message, fingerprint)`.
///
/// If the message wasn't encrypted, returns `Ok(None)`.
///
/// If the message was asymmetrically encrypted, returns `Ok((decrypted message, None))`.
///
/// If the message was symmetrically encrypted, returns `Ok((decrypted message, Some(fingerprint)))`,
/// where `fingerprint` denotes which contact is allowed to send encrypted with this symmetric secret.
/// If the message is not signed by `fingerprint`, it must be dropped.
///
/// Otherwise, Eve could send a message to Alice
/// encrypted with the symmetric secret of someone else's broadcast channel.
/// If Alice sends an answer (or read receipt),
/// then Eve would know that Alice is in the broadcast channel.
pub(crate) async fn decrypt(
    context: &Context,
    mail: &mailparse::ParsedMail<'_>,
) -> Result<Option<(Message<'static>, Option<String>)>> {
    // `pgp::composed::Message` is huge (>4kb), so, make sure that it is in a Box when held over an await point
    let Some(msg) = get_encrypted_pgp_message_boxed(mail)? else {
        return Ok(None);
    };
    let expected_sender_fingerprint: Option<String>;

    let plain = if let Message::Encrypted { esk, .. } = &*msg
        // We only allow one ESK for symmetrically encrypted messages
        // to avoid dealing with messages that are encrypted to multiple symmetric keys
        // or a mix of symmetric and asymmetric keys:
        && let [Esk::SymKeyEncryptedSessionKey(esk)] = &esk[..]
    {
        check_symmetric_encryption(esk)?;
        let (psk, fingerprint) = decrypt_session_key_symmetrically(context, esk)
            .await
            .context("decrypt_session_key_symmetrically")?;
        expected_sender_fingerprint = fingerprint;

        tokio::task::spawn_blocking(move || -> Result<Message<'_>> {
            let plain = msg
                .decrypt_with_session_key(psk)
                .context("decrypt_with_session_key")?;

            let plain: Message<'static> = plain.decompress()?;
            Ok(plain)
        })
        .await??
    } else {
        // Message is asymmetrically encrypted
        let secret_keys: Vec<SignedSecretKey> = load_self_secret_keyring(context).await?;
        expected_sender_fingerprint = None;

        tokio::task::spawn_blocking(move || -> Result<Message<'_>> {
            let empty_pw = Password::empty();
            let secret_keys: Vec<&SignedSecretKey> = secret_keys.iter().collect();
            let plain = msg
                .decrypt_with_keys(vec![&empty_pw], secret_keys)
                .context("decrypt_with_keys")?;

            let plain: Message<'static> = plain.decompress()?;
            Ok(plain)
        })
        .await??
    };

    Ok(Some((plain, expected_sender_fingerprint)))
}

async fn decrypt_session_key_symmetrically(
    context: &Context,
    esk: &SymKeyEncryptedSessionKey,
) -> Result<(PlainSessionKey, Option<String>)> {
    let self_fp = self_fingerprint(context).await?;
    let query_only = true;
    context
        .sql
        .call(query_only, |conn| {
            // First, try decrypting using AUTH tokens from scanned QR codes, stored in the bobstate,
            // because usually there will only be 1 or 2 of it, so, it should be fast
            let res: Option<(PlainSessionKey, String)> = try_decrypt_with_bobstate(esk, conn)?;
            if let Some((plain_session_key, fingerprint)) = res {
                return Ok((plain_session_key, Some(fingerprint)));
            }

            // Then, try decrypting using broadcast secrets
            let res: Option<(PlainSessionKey, Option<String>)> =
                try_decrypt_with_broadcast_secret(esk, conn)?;
            if let Some((plain_session_key, fingerprint)) = res {
                return Ok((plain_session_key, fingerprint));
            }

            // Finally, try decrypting using own AUTH tokens
            // There can be a lot of AUTH tokens,
            // because a new one is generated every time a QR code is shown
            let res: Option<PlainSessionKey> = try_decrypt_with_auth_token(esk, conn, self_fp)?;
            if let Some(plain_session_key) = res {
                return Ok((plain_session_key, None));
            }

            bail!("Could not find symmetric secret for session key")
        })
        .await
}

fn try_decrypt_with_bobstate(
    esk: &SymKeyEncryptedSessionKey,
    conn: &mut rusqlite::Connection,
) -> Result<Option<(PlainSessionKey, String)>> {
    let mut stmt = conn.prepare("SELECT invite FROM bobstate")?;
    let mut rows = stmt.query(())?;
    while let Some(row) = rows.next()? {
        let invite: crate::securejoin::QrInvite = row.get(0)?;
        let authcode = invite.authcode().to_string();
        let alice_fp = invite.fingerprint().hex();
        let shared_secret = format!("securejoin/{alice_fp}/{authcode}");
        if let Ok(psk) = decrypt_session_key_with_password(esk, &Password::from(shared_secret)) {
            let fingerprint = invite.fingerprint().hex();
            return Ok(Some((psk, fingerprint)));
        }
    }
    Ok(None)
}

fn try_decrypt_with_broadcast_secret(
    esk: &SymKeyEncryptedSessionKey,
    conn: &mut rusqlite::Connection,
) -> Result<Option<(PlainSessionKey, Option<String>)>> {
    let Some((psk, chat_id)) = try_decrypt_with_broadcast_secret_inner(esk, conn)? else {
        return Ok(None);
    };
    let chat_type: Chattype =
        conn.query_one("SELECT type FROM chats WHERE id=?", (chat_id,), |row| {
            row.get(0)
        })?;
    let fp: Option<String> = if chat_type == Chattype::OutBroadcast {
        // An attacker who knows the secret will also know who owns it,
        // and it's easiest code-wise to just return None here.
        // But we could alternatively return the self fingerprint here
        None
    } else if chat_type == Chattype::InBroadcast {
        let contact_id: ContactId = conn
            .query_one(
                "SELECT contact_id FROM chats_contacts WHERE chat_id=? AND contact_id>9",
                (chat_id,),
                |row| row.get(0),
            )
            .context("Find InBroadcast owner")?;
        let fp = conn
            .query_one(
                "SELECT fingerprint FROM contacts WHERE id=?",
                (contact_id,),
                |row| row.get(0),
            )
            .context("Find owner fingerprint")?;
        Some(fp)
    } else {
        bail!("Chat {chat_id} is not a broadcast but {chat_type}")
    };
    Ok(Some((psk, fp)))
}

fn try_decrypt_with_broadcast_secret_inner(
    esk: &SymKeyEncryptedSessionKey,
    conn: &mut rusqlite::Connection,
) -> Result<Option<(PlainSessionKey, ChatId)>> {
    let mut stmt = conn.prepare("SELECT secret, chat_id FROM broadcast_secrets")?;
    let mut rows = stmt.query(())?;
    while let Some(row) = rows.next()? {
        let secret: String = row.get(0)?;
        if let Ok(psk) = decrypt_session_key_with_password(esk, &Password::from(secret)) {
            let chat_id: ChatId = row.get(1)?;
            return Ok(Some((psk, chat_id)));
        }
    }
    Ok(None)
}

fn try_decrypt_with_auth_token(
    esk: &SymKeyEncryptedSessionKey,
    conn: &mut rusqlite::Connection,
    self_fingerprint: &str,
) -> Result<Option<PlainSessionKey>> {
    // ORDER BY id DESC to query the most-recently saved tokens are returned first.
    // This improves performance when Bob scans a QR code that was just created.
    let mut stmt = conn.prepare("SELECT token FROM tokens WHERE namespc=? ORDER BY id DESC")?;
    let mut rows = stmt.query((Namespace::Auth,))?;
    while let Some(row) = rows.next()? {
        let token: String = row.get(0)?;
        let shared_secret = format!("securejoin/{self_fingerprint}/{token}");
        if let Ok(psk) = decrypt_session_key_with_password(esk, &Password::from(shared_secret)) {
            return Ok(Some(psk));
        }
    }
    Ok(None)
}

/// Returns Ok(()) if we want to try symmetrically decrypting the message,
/// and Err with a reason if symmetric decryption should not be tried.
///
/// A DoS attacker could send a message with a lot of encrypted session keys,
/// all of which use a very hard-to-compute string2key algorithm.
/// We would then try to decrypt all of the encrypted session keys
/// with all of the known shared secrets.
/// In order to prevent this, we do not try to symmetrically decrypt messages
/// that use a string2key algorithm other than 'Salted'.
pub(crate) fn check_symmetric_encryption(esk: &SymKeyEncryptedSessionKey) -> Result<()> {
    match esk.s2k() {
        Some(StringToKey::Salted { .. }) => Ok(()),
        _ => bail!("unsupported string2key algorithm"),
    }
}

/// Turns a [`ParsedMail`] into [`pgp::composed::Message`].
/// [`pgp::composed::Message`] is huge (over 4kb),
/// so, it is put on the heap using [`Box`].
pub fn get_encrypted_pgp_message_boxed<'a>(
    mail: &'a ParsedMail<'a>,
) -> Result<Option<Box<Message<'static>>>> {
    let Some(encrypted_data_part) = get_encrypted_mime(mail) else {
        return Ok(None);
    };
    let data = encrypted_data_part.get_body_raw()?;
    let cursor = Cursor::new(data);
    let (msg, _headers) = Message::from_armor(cursor)?;
    Ok(Some(Box::new(msg)))
}

/// Returns a reference to the encrypted payload of a message.
pub fn get_encrypted_mime<'a, 'b>(mail: &'a ParsedMail<'b>) -> Option<&'a ParsedMail<'b>> {
    get_autocrypt_mime(mail)
        .or_else(|| get_mixed_up_mime(mail))
        .or_else(|| get_attachment_mime(mail))
}

/// Returns a reference to the encrypted payload of a ["Mixed
/// Up"][pgpmime-message-mangling] message.
///
/// According to [RFC 3156] encrypted messages should have
/// `multipart/encrypted` MIME type and two parts, but Microsoft
/// Exchange and ProtonMail IMAP/SMTP Bridge are known to mangle this
/// structure by changing the type to `multipart/mixed` and prepending
/// an empty part at the start.
///
/// ProtonMail IMAP/SMTP Bridge prepends a part literally saying
/// "Empty Message", so we don't check its contents at all, checking
/// only for `text/plain` type.
///
/// Returns `None` if the message is not a "Mixed Up" message.
///
/// [RFC 3156]: https://www.rfc-editor.org/info/rfc3156
/// [pgpmime-message-mangling]: https://tools.ietf.org/id/draft-dkg-openpgp-pgpmime-message-mangling-00.html
fn get_mixed_up_mime<'a, 'b>(mail: &'a ParsedMail<'b>) -> Option<&'a ParsedMail<'b>> {
    if mail.ctype.mimetype != "multipart/mixed" {
        return None;
    }
    if let [first_part, second_part, third_part] = &mail.subparts[..] {
        if first_part.ctype.mimetype == "text/plain"
            && second_part.ctype.mimetype == "application/pgp-encrypted"
            && third_part.ctype.mimetype == "application/octet-stream"
        {
            Some(third_part)
        } else {
            None
        }
    } else {
        None
    }
}

/// Returns a reference to the encrypted payload of a message turned into attachment.
///
/// Google Workspace has an option "Append footer" which appends standard footer defined
/// by administrator to all outgoing messages. However, there is no plain text part in
/// encrypted messages sent by Delta Chat, so Google Workspace turns the message into
/// multipart/mixed MIME, where the first part is an empty plaintext part with a footer
/// and the second part is the original encrypted message.
fn get_attachment_mime<'a, 'b>(mail: &'a ParsedMail<'b>) -> Option<&'a ParsedMail<'b>> {
    if mail.ctype.mimetype != "multipart/mixed" {
        return None;
    }
    if let [first_part, second_part] = &mail.subparts[..] {
        if first_part.ctype.mimetype == "text/plain"
            && second_part.ctype.mimetype == "multipart/encrypted"
        {
            get_autocrypt_mime(second_part)
        } else {
            None
        }
    } else {
        None
    }
}

/// Returns a reference to the encrypted payload of a valid PGP/MIME message.
///
/// Returns `None` if the message is not a valid PGP/MIME message.
fn get_autocrypt_mime<'a, 'b>(mail: &'a ParsedMail<'b>) -> Option<&'a ParsedMail<'b>> {
    if mail.ctype.mimetype != "multipart/encrypted" {
        return None;
    }
    if let [first_part, second_part] = &mail.subparts[..] {
        if first_part.ctype.mimetype == "application/pgp-encrypted"
            && second_part.ctype.mimetype == "application/octet-stream"
        {
            Some(second_part)
        } else {
            None
        }
    } else {
        None
    }
}

/// Validates signatures of Multipart/Signed message part, as defined in RFC 1847.
///
/// Returns the signed part and the set of key
/// fingerprints for which there is a valid signature.
///
/// Returns None if the message is not Multipart/Signed or doesn't contain necessary parts.
pub(crate) fn validate_detached_signature<'a, 'b>(
    mail: &'a ParsedMail<'b>,
    public_keyring_for_validate: &[SignedPublicKey],
) -> Option<(&'a ParsedMail<'b>, HashSet<Fingerprint>)> {
    if mail.ctype.mimetype != "multipart/signed" {
        return None;
    }

    if let [first_part, second_part] = &mail.subparts[..] {
        // First part is the content, second part is the signature.
        let content = first_part.raw_bytes;
        let ret_valid_signatures = match second_part.get_body_raw() {
            Ok(signature) => {
                crate::pgp::pk_validate(content, &signature, public_keyring_for_validate)
                    .unwrap_or_default()
            }
            Err(_) => Default::default(),
        };
        Some((first_part, ret_valid_signatures))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receive_imf::receive_imf;
    use crate::test_utils::TestContext;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mixed_up_mime() -> Result<()> {
        // "Mixed Up" mail as received when sending an encrypted
        // message using Delta Chat Desktop via ProtonMail IMAP/SMTP
        // Bridge.
        let mixed_up_mime = include_bytes!("../test-data/message/protonmail-mixed-up.eml");
        let mail = mailparse::parse_mail(mixed_up_mime)?;
        assert!(get_autocrypt_mime(&mail).is_none());
        assert!(get_mixed_up_mime(&mail).is_some());
        assert!(get_attachment_mime(&mail).is_none());

        // Same "Mixed Up" mail repaired by Thunderbird 78.9.0.
        //
        // It added `X-Enigmail-Info: Fixed broken PGP/MIME message`
        // header although the repairing is done by the built-in
        // OpenPGP support, not Enigmail.
        let repaired_mime = include_bytes!("../test-data/message/protonmail-repaired.eml");
        let mail = mailparse::parse_mail(repaired_mime)?;
        assert!(get_autocrypt_mime(&mail).is_some());
        assert!(get_mixed_up_mime(&mail).is_none());
        assert!(get_attachment_mime(&mail).is_none());

        // Another form of "Mixed Up" mail created by Google Workspace,
        // where original message is turned into attachment to empty plaintext message.
        let attachment_mime = include_bytes!("../test-data/message/google-workspace-mixed-up.eml");
        let mail = mailparse::parse_mail(attachment_mime)?;
        assert!(get_autocrypt_mime(&mail).is_none());
        assert!(get_mixed_up_mime(&mail).is_none());
        assert!(get_attachment_mime(&mail).is_some());

        let bob = TestContext::new_bob().await;
        receive_imf(&bob, attachment_mime, false).await?;
        let msg = bob.get_last_msg().await;
        // Subject should be prepended because the attachment doesn't have "Chat-Version".
        assert_eq!(msg.text, "Hello, Bob! – Hello from Thunderbird!");

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mixed_up_mime_long() -> Result<()> {
        // Long "mixed-up" mail as received when sending an encrypted message using Delta Chat
        // Desktop via MS Exchange (actually made with TB though).
        let mixed_up_mime = include_bytes!("../test-data/message/mixed-up-long.eml");
        let bob = TestContext::new_bob().await;
        receive_imf(&bob, mixed_up_mime, false).await?;
        let msg = bob.get_last_msg().await;
        assert!(!msg.get_text().is_empty());
        assert!(msg.has_html());
        assert!(msg.id.get_html(&bob).await?.unwrap().len() > 40000);
        Ok(())
    }
}
