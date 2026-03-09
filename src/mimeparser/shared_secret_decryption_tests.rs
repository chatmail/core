use super::*;
use crate::chat::{create_broadcast, load_broadcast_secret};
use crate::key::load_self_secret_keyring;
use crate::pgp;
use crate::qr::{Qr, check_qr};
use crate::securejoin::{get_securejoin_qr, join_securejoin};
use crate::test_utils::{TestContext, TestContextManager};
use anyhow::Result;

async fn test_shared_secret_decryption_ex(
    recipient_ctx: &TestContext,
    from_addr: &str,
    secret: &str,
    signer_ctx: Option<&TestContext>,
    expected_error: Option<&str>,
) -> Result<()> {
    let plain_body = "Hello, this is a secure message.";
    let plain_text = format!("Content-Type: text/plain; charset=utf-8\r\n\r\n{plain_body}");

    let signer_key = if let Some(signer_ctx) = signer_ctx {
        Some(load_self_secret_keyring(signer_ctx).await?.remove(0))
    } else {
        None
    };
    if let Some(signer_ctx) = signer_ctx {
        // The recipient needs to know the signer's pubkey
        // in order to be able to validate the pubkey:
        recipient_ctx.add_or_lookup_contact(signer_ctx).await;
    }

    let encrypted_msg =
        pgp::symm_encrypt_message(plain_text.as_bytes().to_vec(), signer_key, secret, true).await?;

    let boundary = "boundary123";
    let rcvd_mail = format!(
        "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\n\
         From: {from}\n\
         To: \"hidden-recipients\": ;\n\
         Subject: [...]\n\
         MIME-Version: 1.0\n\
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

    let res = MimeMessage::from_bytes(recipient_ctx, rcvd_mail.as_bytes()).await;

    if let Some(error_pattern) = expected_error {
        let err_msg = format!("{:#}", res.unwrap_err());
        assert!(
            err_msg.contains(error_pattern),
            "Error '{error_pattern}' not found in '{err_msg}'",
        );
    } else {
        let mime = res.unwrap();
        assert_eq!(mime.parts[0].msg, plain_body);
    }

    Ok(())
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

    let alice_chat_id = crate::chat::create_broadcast(alice, "Channel".to_string()).await?;
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

    let alice_chat_id = crate::chat::create_broadcast(alice, "Channel".to_string()).await?;
    let qr = crate::securejoin::get_securejoin_qr(alice, Some(alice_chat_id)).await?;
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

    let qr = crate::securejoin::get_securejoin_qr(bob, None).await?;
    let Qr::AskVerifyContact { authcode, .. } = check_qr(alice, &qr).await? else {
        unreachable!()
    };
    // Start a securejoin process, but don't finish it:
    join_securejoin(alice, &qr).await?;

    let charlie_addr = charlie.get_config(Config::Addr).await?.unwrap();

    test_shared_secret_decryption_ex(
        alice,
        &charlie_addr,
        &authcode,
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

    let qr = crate::securejoin::get_securejoin_qr(alice, None).await?;
    let Qr::AskVerifyContact { authcode, .. } = check_qr(bob, &qr).await? else {
        unreachable!()
    };
    // Start a securejoin process, but don't finish it:
    join_securejoin(bob, &qr).await?;

    test_shared_secret_decryption_ex(bob, "alice@example.net", &authcode, Some(alice), None).await
}

/// Control: Test that there is a similar error when the shared secret is unknown
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unknown_secret() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    test_shared_secret_decryption_ex(
        bob,
        "alice@example.net",
        "aaaaaa",
        Some(alice),
        Some("error"),
    )
    .await
}
