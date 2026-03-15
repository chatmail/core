use super::*;
use crate::chat::{create_broadcast, load_broadcast_secret};
use crate::constants::DC_CHAT_ID_TRASH;
use crate::key::{load_self_secret_key, self_fingerprint};
use crate::pgp;
use crate::qr::{Qr, check_qr};
use crate::receive_imf::receive_imf;
use crate::securejoin::{get_securejoin_qr, join_securejoin};
use crate::test_utils::{TestContext, TestContextManager};
use anyhow::Result;

/// Tests that the following attack isn't possible:
///
/// Eve is subscribed to a channel and wants to know whether Alice is also subscribed to it.
/// To achieve this, Eve sends a message to Alice
/// encrypted with the symmetric secret of this broadcast channel.
///
/// If Alice sends an answer (or read receipt),
/// then Eve knows that Alice is in the broadcast channel.
///
/// A similar attack would be possible with auth tokens
/// that are also used to symmetrically encrypt messages.
///
/// To defeat this, a message that was unexpectedly
/// encrypted with a symmetric secret must be dropped.
async fn test_shared_secret_decryption_ex(
    recipient_ctx: &TestContext,
    from_addr: &str,
    secret_for_encryption: &str,
    signer_ctx: Option<&TestContext>,
    expected_error: Option<&str>,
) -> Result<()> {
    let plain_body = "Hello, this is a secure message.";
    let plain_text = format!("Content-Type: text/plain; charset=utf-8\r\n\r\n{plain_body}");
    let previous_highest_msg_id = get_highest_msg_id(recipient_ctx).await;

    let signer_key = if let Some(signer_ctx) = signer_ctx {
        Some(load_self_secret_key(signer_ctx).await?)
    } else {
        None
    };
    if let Some(signer_ctx) = signer_ctx {
        // The recipient needs to know the signer's pubkey
        // in order to be able to validate the pubkey:
        recipient_ctx.add_or_lookup_contact(signer_ctx).await;
    }

    let encrypted_msg = pgp::symm_encrypt_message(
        plain_text.as_bytes().to_vec(),
        signer_key,
        secret_for_encryption,
        true,
    )
    .await?;

    let boundary = "boundary123";
    let rcvd_mail = format!(
        "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\n\
         From: {from}\n\
         To: \"hidden-recipients\": ;\n\
         Subject: [...]\n\
         MIME-Version: 1.0\n\
         Message-ID: <12345@example.org>\n\
         \n\
         --{boundary}\n\
         Content-Type: application/pgp-encrypted\n\
         \n\
         Version: 1\n\
         \n\
         --{boundary}\n\
         Content-Type: application/octet-stream; name=\"encrypted.asc\"\n\
         Content-Disposition: inline; filename=\"encrypted.asc\"\n\
         \n\
         {encrypted_msg}\n\
         --{boundary}--\n",
        from = from_addr,
        boundary = boundary,
        encrypted_msg = encrypted_msg
    );

    let rcvd = receive_imf(recipient_ctx, rcvd_mail.as_bytes(), false)
        .await
        .expect("If receive_imf() adds an error here, then Bob may be notified about the error and tell the attacker, leaking that he knows the secret")
        .expect("A trashed message should be created, otherwise we'll unnecessarily download it again");

    if let Some(error_pattern) = expected_error {
        assert!(rcvd.chat_id == DC_CHAT_ID_TRASH);
        assert_eq!(
            previous_highest_msg_id,
            get_highest_msg_id(recipient_ctx).await,
            "receive_imf() must not add any message. Otherwise, Bob may send something about an error to the attacker, leaking that he knows the secret"
        );
        let EventType::Warning(warning) = recipient_ctx
            .evtracker
            .get_matching(|ev| matches!(ev, EventType::Warning(_)))
            .await
        else {
            unreachable!()
        };
        assert!(warning.contains(error_pattern), "Wrong warning: {warning}");
    } else {
        let msg = recipient_ctx.get_last_msg().await;
        assert_eq!(&[msg.id], rcvd.msg_ids.as_slice());
        assert_eq!(msg.text, plain_body);
        assert_eq!(rcvd.chat_id.is_special(), false);
    }

    Ok(())
}

async fn get_highest_msg_id(context: &Context) -> MsgId {
    context
        .sql
        .query_get_value(
            "SELECT MAX(id) FROM msgs WHERE chat_id!=?",
            (DC_CHAT_ID_TRASH,),
        )
        .await
        .unwrap()
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_security_attacker_signature() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await; // Attacker

    let alice_chat_id = create_broadcast(alice, "Channel".to_string()).await?;
    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await?;
    tcm.exec_securejoin_qr(bob, alice, &qr).await;

    let secret = load_broadcast_secret(alice, alice_chat_id).await?.unwrap();

    let charlie_addr = charlie.get_config(Config::Addr).await?.unwrap();

    test_shared_secret_decryption_ex(
        bob,
        &charlie_addr,
        &secret,
        Some(charlie),
        Some("This sender is not allowed to encrypt with this secret key"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_security_no_signature() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_chat_id = create_broadcast(alice, "Channel".to_string()).await?;
    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await?;
    tcm.exec_securejoin_qr(bob, alice, &qr).await;

    let secret = load_broadcast_secret(alice, alice_chat_id).await?.unwrap();

    test_shared_secret_decryption_ex(
        bob,
        "attacker@example.org",
        &secret,
        None,
        Some("Unsigned message is not allowed to be encrypted with this shared secret"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_security_happy_path() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_chat_id = create_broadcast(alice, "Channel".to_string()).await?;
    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await?;
    tcm.exec_securejoin_qr(bob, alice, &qr).await;

    let secret = load_broadcast_secret(alice, alice_chat_id).await?.unwrap();

    let alice_addr = alice
        .get_config(crate::config::Config::Addr)
        .await?
        .unwrap();

    test_shared_secret_decryption_ex(bob, &alice_addr, &secret, Some(alice), None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_qr_code_security() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await; // Attacker

    let qr = get_securejoin_qr(alice, None).await?;
    let Qr::AskVerifyContact { authcode, .. } = check_qr(bob, &qr).await? else {
        unreachable!()
    };
    // Start a securejoin process, but don't finish it:
    join_securejoin(bob, &qr).await?;

    let charlie_addr = charlie.get_config(Config::Addr).await?.unwrap();

    let alice_fp = self_fingerprint(alice).await?;
    let secret_for_encryption = format!("securejoin/{alice_fp}/{authcode}");
    test_shared_secret_decryption_ex(
        bob,
        &charlie_addr,
        &secret_for_encryption,
        Some(charlie),
        Some("This sender is not allowed to encrypt with this secret key"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_qr_code_happy_path() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let qr = get_securejoin_qr(alice, None).await?;
    let Qr::AskVerifyContact { authcode, .. } = check_qr(bob, &qr).await? else {
        unreachable!()
    };
    // Start a securejoin process, but don't finish it:
    join_securejoin(bob, &qr).await?;

    let alice_fp = self_fingerprint(alice).await?;
    let secret_for_encryption = format!("securejoin/{alice_fp}/{authcode}");
    test_shared_secret_decryption_ex(
        bob,
        "alice@example.net",
        &secret_for_encryption,
        Some(alice),
        None,
    )
    .await
}

/// Control: Test that the behavior is the same when the shared secret is unknown
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unknown_secret() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    test_shared_secret_decryption_ex(
        bob,
        "alice@example.net",
        "Some secret unknown to Bob",
        Some(alice),
        Some("Could not find symmetric secret for session key"),
    )
    .await
}
