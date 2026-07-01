//! End-to-end encryption support.

use std::io::Cursor;

use anyhow::Result;
use mail_builder::mime::MimePart;

use crate::aheader::{Aheader, EncryptPreference};
use crate::context::Context;
use crate::key::{SignedPublicKey, load_self_public_key, load_self_secret_key};
use crate::pgp::{self, SeipdVersion};

#[derive(Debug)]
pub struct EncryptHelper {
    pub addr: String,
    pub public_key: SignedPublicKey,
}

impl EncryptHelper {
    pub async fn new(context: &Context) -> Result<EncryptHelper> {
        let addr = context.get_primary_self_addr().await?;
        let public_key = load_self_public_key(context).await?;

        Ok(EncryptHelper { addr, public_key })
    }

    pub fn get_aheader(&self) -> Aheader {
        let public_key = pgp::minimize_autocrypt_certificate(&self.public_key);
        Aheader {
            addr: self.addr.clone(),
            public_key,
            prefer_encrypt: EncryptPreference::Mutual,
            verified: false,
        }
    }

    /// Tries to encrypt the passed in `mail`.
    pub async fn encrypt(
        self,
        context: &Context,
        keyring: Vec<SignedPublicKey>,
        mail_to_encrypt: MimePart<'static>,
        compress: bool,
        seipd_version: SeipdVersion,
    ) -> Result<String> {
        let mut raw_message = Vec::new();
        let cursor = Cursor::new(&mut raw_message);
        mail_to_encrypt.clone().write_part(cursor).ok();

        let ctext = self
            .encrypt_raw(context, keyring, raw_message, compress, seipd_version)
            .await?;
        Ok(ctext)
    }

    pub async fn encrypt_raw(
        self,
        context: &Context,
        keyring: Vec<SignedPublicKey>,
        raw_message: Vec<u8>,
        compress: bool,
        seipd_version: SeipdVersion,
    ) -> Result<String> {
        let sign_key = load_self_secret_key(context).await?;
        let ctext =
            pgp::pk_encrypt(raw_message, keyring, sign_key, compress, seipd_version).await?;

        Ok(ctext)
    }

    /// Symmetrically encrypt the message. This is used for broadcast channels.
    /// `shared secret` is the secret that will be used for symmetric encryption.
    pub async fn encrypt_symmetrically(
        self,
        context: &Context,
        shared_secret: &str,
        mail_to_encrypt: MimePart<'static>,
        compress: bool,
        sign: bool,
    ) -> Result<String> {
        let sign_key = if sign {
            Some(load_self_secret_key(context).await?)
        } else {
            None
        };

        let shared_secret = shared_secret.to_string();
        let mut raw_message = Vec::new();
        let cursor = Cursor::new(&mut raw_message);
        mail_to_encrypt.clone().write_part(cursor).ok();

        let ctext = tokio::task::spawn_blocking(move || {
            pgp::symm_encrypt_message(raw_message, sign_key, shared_secret, compress)
        })
        .await??;

        Ok(ctext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat;
    use crate::chat::send_text_msg;
    use crate::config::Config;
    use crate::message::Message;
    use crate::mimeparser::SystemMessage;
    use crate::receive_imf::receive_imf;
    use crate::test_utils::TestContextManager;

    #[test]
    fn test_mailmime_parse() {
        let plain = b"Chat-Disposition-Notification-To: hello@world.de
Chat-Group-ID: CovhGgau8M-
Chat-Group-Name: Delta Chat Dev
Subject: =?utf-8?Q?Chat=3A?= Delta Chat =?utf-8?Q?Dev=3A?= sidenote for
 =?utf-8?Q?all=3A?= rust core master ...
Content-Type: text/plain; charset=\"utf-8\"; protected-headers=\"v1\"
Content-Transfer-Encoding: quoted-printable

sidenote for all: things are trick atm recomm=
end not to try to run with desktop or ios unless you are ready to hunt bugs

-- =20
Sent with my Delta Chat Messenger: https://delta.chat";
        let mail = mailparse::parse_mail(plain).expect("failed to parse valid message");

        assert_eq!(mail.headers.len(), 6);
        assert!(
            mail.get_body().unwrap().starts_with(
                "sidenote for all: things are trick atm recommend not to try to run with desktop or ios unless you are ready to hunt bugs")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_cannot_send_unencrypted_by_default() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let chat = alice.create_email_chat(bob).await;

        let mut msg = Message::new_text("Hello!".to_string());
        assert!(chat::send_msg(alice, chat.id, &mut msg).await.is_err());
        assert_eq!(
            msg.error().unwrap(),
            "\u{26a0}\u{fe0f} Your email provider example.org requires end-to-end encryption which is not setup yet."
        );
        let info_msg = alice.get_last_msg().await;
        assert_eq!(
            info_msg.get_info_type(),
            SystemMessage::InvalidUnencryptedMail
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_chatmail_can_send_unencrypted() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bob = &tcm.bob().await;
        bob.set_config_bool(Config::IsChatmail, true).await?;
        bob.allow_unencrypted().await?;
        let bob_chat_id = receive_imf(
            bob,
            b"From: alice@example.org\n\
            To: bob@example.net\n\
            Message-ID: <2222@example.org>\n\
            Date: Sun, 22 Mar 3000 22:37:58 +0000\n\
            \n\
            Hello\n",
            false,
        )
        .await?
        .unwrap()
        .chat_id;
        bob_chat_id.accept(bob).await?;
        send_text_msg(bob, bob_chat_id, "hi".to_string()).await?;
        let sent_msg = bob.pop_sent_msg().await;
        let msg = Message::load_from_db(bob, sent_msg.sender_msg_id).await?;
        assert!(!msg.get_showpadlock());
        Ok(())
    }
}
