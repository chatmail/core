//! End-to-end encryption support.

use std::io::Cursor;

use anyhow::Result;
use mail_builder::mime::MimePart;
use num_traits::FromPrimitive;

use crate::aheader::{Aheader, EncryptPreference};
use crate::config::Config;
use crate::context::Context;
use crate::key::{SignedPublicKey, load_self_public_key, load_self_secret_key};
use crate::pgp;

#[derive(Debug)]
pub struct EncryptHelper {
    pub prefer_encrypt: EncryptPreference,
    pub addr: String,
    pub public_key: SignedPublicKey,
}

impl EncryptHelper {
    pub async fn new(context: &Context) -> Result<EncryptHelper> {
        let prefer_encrypt =
            EncryptPreference::from_i32(context.get_config_int(Config::E2eeEnabled).await?)
                .unwrap_or_default();
        let addr = context.get_primary_self_addr().await?;
        let public_key = load_self_public_key(context).await?;

        Ok(EncryptHelper {
            prefer_encrypt,
            addr,
            public_key,
        })
    }

    pub fn get_aheader(&self) -> Aheader {
        let pk = self.public_key.clone();
        let addr = self.addr.to_string();
        Aheader::new(addr, pk, self.prefer_encrypt)
    }

    /// Tries to encrypt the passed in `mail`.
    pub async fn encrypt(
        self,
        context: &Context,
        keyring: Vec<SignedPublicKey>,
        mail_to_encrypt: MimePart<'static>,
        compress: bool,
    ) -> Result<String> {
        let sign_key = load_self_secret_key(context).await?;

        let mut raw_message = Vec::new();
        let cursor = Cursor::new(&mut raw_message);
        mail_to_encrypt.clone().write_part(cursor).ok();

        let ctext = pgp::pk_encrypt(raw_message, keyring, Some(sign_key), compress).await?;

        Ok(ctext)
    }

    /// Signs the passed-in `mail` using the private key from `context`.
    /// Returns the payload and the signature.
    pub async fn sign(self, context: &Context, mail: &MimePart<'static>) -> Result<String> {
        let sign_key = load_self_secret_key(context).await?;
        let mut buffer = Vec::new();
        mail.clone().write_part(&mut buffer)?;
        let signature = pgp::pk_calc_signature(buffer, &sign_key)?;
        Ok(signature)
    }
}

/// Ensures a private key exists for the configured user.
///
/// Normally the private key is generated when the first message is
/// sent but in a few locations there are no such guarantees,
/// e.g. when exporting keys, and calling this function ensures a
/// private key will be present.
// TODO, remove this once deltachat::key::Key no longer exists.
pub async fn ensure_secret_key_exists(context: &Context) -> Result<()> {
    load_self_public_key(context).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::send_text_msg;
    use crate::config::Config;
    use crate::message::Message;
    use crate::receive_imf::receive_imf;
    use crate::test_utils::{TestContext, TestContextManager};

    mod ensure_secret_key_exists {
        use super::*;

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_prexisting() {
            let t = TestContext::new_alice().await;
            assert!(ensure_secret_key_exists(&t).await.is_ok());
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_not_configured() {
            let t = TestContext::new().await;
            assert!(ensure_secret_key_exists(&t).await.is_err());
        }
    }

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
    async fn test_chatmail_can_send_unencrypted() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bob = &tcm.bob().await;
        bob.set_config_bool(Config::IsChatmail, true).await?;
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
