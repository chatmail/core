//! End-to-end decryption support.

use std::collections::HashSet;

use anyhow::Result;
use mailparse::ParsedMail;

use crate::key::{Fingerprint, SignedPublicKey, SignedSecretKey};
use crate::pgp;

/// Tries to decrypt a message, but only if it is structured as an Autocrypt message.
///
/// If successful and the message is encrypted, returns decrypted body.
pub fn try_decrypt<'a>(
    mail: &'a ParsedMail<'a>,
    private_keyring: &'a [SignedSecretKey],
) -> Result<Option<::pgp::composed::Message<'static>>> {
    let Some(encrypted_data_part) = get_encrypted_mime(mail) else {
        return Ok(None);
    };

    let data = encrypted_data_part.get_body_raw()?;
    let msg = pgp::pk_decrypt(data, private_keyring)?;

    Ok(Some(msg))
}

/// Returns a reference to the encrypted payload of a message.
pub(crate) fn get_encrypted_mime<'a, 'b>(mail: &'a ParsedMail<'b>) -> Option<&'a ParsedMail<'b>> {
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
            Ok(signature) => pgp::pk_validate(content, &signature, public_keyring_for_validate)
                .unwrap_or_default(),
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
        assert_eq!(msg.text, "Hello from Thunderbird!");

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
