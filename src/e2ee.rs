//! End-to-end encryption support.

use std::collections::BTreeSet;
use std::io::Cursor;

use anyhow::{bail, Result};
use mail_builder::mime::MimePart;
use num_traits::FromPrimitive;

use crate::aheader::{Aheader, EncryptPreference};
use crate::config::Config;
use crate::context::Context;
use crate::key::{load_self_public_key, load_self_secret_key, SignedPublicKey};
use crate::log::warn;
use crate::peerstate::Peerstate;
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

    /// Determines if we can and should encrypt.
    pub(crate) async fn should_encrypt(
        &self,
        context: &Context,
        peerstates: &[(Option<Peerstate>, String)],
    ) -> Result<bool> {
        let is_chatmail = context.is_chatmail().await?;
        for (peerstate, _addr) in peerstates {
            if let Some(peerstate) = peerstate {
                // For chatmail we ignore the encryption preference,
                // because we can either send encrypted or not at all.
                if is_chatmail || peerstate.prefer_encrypt != EncryptPreference::Reset {
                    continue;
                }
            }
            return Ok(false);
        }
        Ok(true)
    }

    /// Constructs a vector of public keys for given peerstates.
    ///
    /// In addition returns the set of recipient addresses
    /// for which there is no key available.
    ///
    /// Returns an error if there are recipients
    /// other than self, but no recipient keys are available.
    pub(crate) fn encryption_keyring(
        &self,
        context: &Context,
        verified: bool,
        peerstates: &[(Option<Peerstate>, String)],
    ) -> Result<(Vec<SignedPublicKey>, BTreeSet<String>)> {
        // Encrypt to self unconditionally,
        // even for a single-device setup.
        let mut keyring = vec![self.public_key.clone()];
        let mut missing_key_addresses = BTreeSet::new();

        if peerstates.is_empty() {
            return Ok((keyring, missing_key_addresses));
        }

        let mut verifier_addresses: Vec<&str> = Vec::new();

        for (peerstate, addr) in peerstates {
            if let Some(peerstate) = peerstate {
                if let Some(key) = peerstate.clone().take_key(verified) {
                    keyring.push(key);
                    verifier_addresses.push(addr);
                } else {
                    warn!(context, "Encryption key for {addr} is missing.");
                    missing_key_addresses.insert(addr.clone());
                }
            } else {
                warn!(context, "Peerstate for {addr} is missing.");
                missing_key_addresses.insert(addr.clone());
            }
        }

        debug_assert!(
            !keyring.is_empty(),
            "At least our own key is in the keyring"
        );
        if keyring.len() <= 1 {
            bail!("No recipient keys are available, cannot encrypt");
        }

        // Encrypt to secondary verified keys
        // if we also encrypt to the introducer ("verifier") of the key.
        if verified {
            for (peerstate, _addr) in peerstates {
                if let Some(peerstate) = peerstate {
                    if let (Some(key), Some(verifier)) = (
                        peerstate.secondary_verified_key.as_ref(),
                        peerstate.secondary_verifier.as_deref(),
                    ) {
                        if verifier_addresses.contains(&verifier) {
                            keyring.push(key.clone());
                        }
                    }
                }
            }
        }

        Ok((keyring, missing_key_addresses))
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
    use crate::key::DcKey;
    use crate::message::{Message, Viewtype};
    use crate::param::Param;
    use crate::receive_imf::receive_imf;
    use crate::test_utils::{bob_keypair, TestContext, TestContextManager};

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
    async fn test_encrypted_no_autocrypt() -> anyhow::Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;

        let chat_alice = alice.create_email_chat(&bob).await.id;
        let chat_bob = bob.create_email_chat(&alice).await.id;

        // Alice sends unencrypted message to Bob
        let mut msg = Message::new(Viewtype::Text);
        let sent = alice.send_msg(chat_alice, &mut msg).await;

        // Bob receives unencrypted message from Alice
        let msg = bob.recv_msg(&sent).await;
        assert!(!msg.get_showpadlock());

        let peerstate_alice = Peerstate::from_addr(&bob.ctx, "alice@example.org")
            .await?
            .expect("no peerstate found in the database");
        assert_eq!(peerstate_alice.prefer_encrypt, EncryptPreference::Mutual);

        // Bob sends empty encrypted message to Alice
        let mut msg = Message::new(Viewtype::Text);
        let sent = bob.send_msg(chat_bob, &mut msg).await;

        // Alice receives an empty encrypted message from Bob.
        // This is also a regression test for previously existing bug
        // that resulted in no padlock on encrypted empty messages.
        let msg = alice.recv_msg(&sent).await;
        assert!(msg.get_showpadlock());

        let peerstate_bob = Peerstate::from_addr(&alice.ctx, "bob@example.net")
            .await?
            .expect("no peerstate found in the database");
        assert_eq!(peerstate_bob.prefer_encrypt, EncryptPreference::Mutual);

        // Now Alice and Bob have established keys.

        // Alice sends encrypted message without Autocrypt header.
        let mut msg = Message::new(Viewtype::Text);
        msg.param.set_int(Param::SkipAutocrypt, 1);
        let sent = alice.send_msg(chat_alice, &mut msg).await;

        let msg = bob.recv_msg(&sent).await;
        assert!(msg.get_showpadlock());
        let peerstate_alice = Peerstate::from_addr(&bob.ctx, "alice@example.org")
            .await?
            .expect("no peerstate found in the database");
        assert_eq!(peerstate_alice.prefer_encrypt, EncryptPreference::Mutual);

        // Alice sends plaintext message with Autocrypt header.
        let mut msg = Message::new(Viewtype::Text);
        msg.force_plaintext();
        let sent = alice.send_msg(chat_alice, &mut msg).await;

        let msg = bob.recv_msg(&sent).await;
        assert!(!msg.get_showpadlock());
        let peerstate_alice = Peerstate::from_addr(&bob.ctx, "alice@example.org")
            .await?
            .expect("no peerstate found in the database");
        assert_eq!(peerstate_alice.prefer_encrypt, EncryptPreference::Mutual);

        // Alice sends plaintext message without Autocrypt header.
        let mut msg = Message::new(Viewtype::Text);
        msg.force_plaintext();
        msg.param.set_int(Param::SkipAutocrypt, 1);
        let sent = alice.send_msg(chat_alice, &mut msg).await;

        let msg = bob.recv_msg(&sent).await;
        assert!(!msg.get_showpadlock());
        let peerstate_alice = Peerstate::from_addr(&bob.ctx, "alice@example.org")
            .await?
            .expect("no peerstate found in the database");
        assert_eq!(peerstate_alice.prefer_encrypt, EncryptPreference::Reset);

        Ok(())
    }

    fn new_peerstates(prefer_encrypt: EncryptPreference) -> Vec<(Option<Peerstate>, String)> {
        let addr = "bob@foo.bar";
        let pub_key = bob_keypair().public;
        let peerstate = Peerstate {
            addr: addr.into(),
            last_seen: 13,
            last_seen_autocrypt: 14,
            prefer_encrypt,
            public_key: Some(pub_key.clone()),
            public_key_fingerprint: Some(pub_key.dc_fingerprint()),
            gossip_key: Some(pub_key.clone()),
            gossip_timestamp: 15,
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
        vec![(Some(peerstate), addr.to_string())]
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_should_encrypt() -> Result<()> {
        let t = TestContext::new_alice().await;
        let encrypt_helper = EncryptHelper::new(&t).await.unwrap();

        let ps = new_peerstates(EncryptPreference::NoPreference);
        assert!(encrypt_helper.should_encrypt(&t, &ps).await?);

        let ps = new_peerstates(EncryptPreference::Reset);
        assert!(!encrypt_helper.should_encrypt(&t, &ps).await?);

        let ps = new_peerstates(EncryptPreference::Mutual);
        assert!(encrypt_helper.should_encrypt(&t, &ps).await?);

        // test with missing peerstate
        let ps = vec![(None, "bob@foo.bar".to_string())];
        assert!(!encrypt_helper.should_encrypt(&t, &ps).await?);
        Ok(())
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
