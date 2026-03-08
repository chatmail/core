use crate::pgp;
use crate::key::{load_self_secret_keyring, Fingerprint};
use crate::test_utils::{TestContextManager, TestContext};
use super::*;
use anyhow::Result;

async fn test_security_ex(
    recipient_ctx: &TestContext,
    from_addr: &str,
    secret: &str,
    signer_ctx: Option<&TestContext>,
    expected_error: Option<&str>,
) -> Result<()> {
    // We add headers to the encrypted part, otherwise it might not be recognized as text.
    let plain_body = "Hello, this is a secure message.";
    let plain_text = format!("Content-Type: text/plain; charset=utf-8\r\n\r\n{plain_body}");
    
    let signer_key = if let Some(ctx) = signer_ctx {
        Some(load_self_secret_keyring(ctx).await?.remove(0))
    } else {
        None
    };

    let encrypted_msg = pgp::symm_encrypt_message(
        plain_text.as_bytes().to_vec(),
        signer_key,
        secret,
        false
    ).await?;

    let boundary = "boundary123";
    let rcvd_mail = format!(
        "From: {from}\n\
         To: recipient@example.net\n\
         Subject: Hi\n\
         MIME-Version: 1.0\n\
         Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\n\
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
        assert!(res.is_err(), "Expected error '{}', but got success", error_pattern);
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains(error_pattern), "Error '{}' not found in '{}'", error_pattern, err_msg);
    } else {
        assert!(res.is_ok(), "Expected success, but got error: {:?}", res.err());
        let mime = res.unwrap();
        assert!(!mime.parts.is_empty(), "No parts found in decrypted message");
        assert_eq!(mime.parts[0].msg, plain_body);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_security_attacker_signature() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let charlie = tcm.charlie().await; // Attacker

    let alice_chat_id = crate::chat::create_broadcast(&alice, "Channel".to_string()).await?;
    let qr = crate::securejoin::get_securejoin_qr(&alice, Some(alice_chat_id)).await?;
    let _bob_chat_id = tcm.exec_securejoin_qr(&bob, &alice, &qr).await;

    let secret: String = alice.sql.query_row(
        "SELECT secret FROM broadcast_secrets WHERE chat_id = ?",
        (alice_chat_id,),
        |row| row.get(0)
    ).await?;

    let charlie_addr = charlie.get_config(crate::config::Config::Addr).await?.unwrap();
    
    test_security_ex(
        &bob,
        &charlie_addr,
        &secret,
        Some(&charlie),
        Some("This sender is not allowed to encrypt with this secret key")
    ).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_security_no_signature() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    let alice_chat_id = crate::chat::create_broadcast(&alice, "Channel".to_string()).await?;
    let qr = crate::securejoin::get_securejoin_qr(&alice, Some(alice_chat_id)).await?;
    let _bob_chat_id = tcm.exec_securejoin_qr(&bob, &alice, &qr).await;

    let secret: String = alice.sql.query_row(
        "SELECT secret FROM broadcast_secrets WHERE chat_id = ?",
        (alice_chat_id,),
        |row| row.get(0)
    ).await?;

    test_security_ex(
        &bob,
        "attacker@example.org",
        &secret,
        None,
        Some("This sender is not allowed to encrypt with this secret key")
    ).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_security_happy_path() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    let alice_chat_id = crate::chat::create_broadcast(&alice, "Channel".to_string()).await?;
    let qr = crate::securejoin::get_securejoin_qr(&alice, Some(alice_chat_id)).await?;
    let _bob_chat_id = tcm.exec_securejoin_qr(&bob, &alice, &qr).await;

    let secret: String = alice.sql.query_row(
        "SELECT secret FROM broadcast_secrets WHERE chat_id = ?",
        (alice_chat_id,),
        |row| row.get(0)
    ).await?;

    let alice_addr = alice.get_config(crate::config::Config::Addr).await?.unwrap();
    
    test_security_ex(
        &bob,
        &alice_addr,
        &secret,
        Some(&alice),
        None
    ).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_qr_code_security_fix() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let charlie = tcm.charlie().await; // Attacker

    // Bob produces a QR code.
    let qr = crate::securejoin::get_securejoin_qr(&bob, None).await?;
    let secret = qr.split("&s=").last().unwrap();
    let bob_fpr = crate::key::self_fingerprint(&bob).await?;
    let bob_fpr: Fingerprint = bob_fpr.parse()?;

    // Alice HAS NOT scanned Bob's QR (to avoid deletion from bobstate),
    // but we manually insert an entry into her bobstate to simulate a stale/ongoing join.
    // We use Bob's real fingerprint as the "expected owner" of the secret.
    let invite = crate::securejoin::QrInvite::Contact {
        contact_id: crate::contact::ContactId::SELF, // Dummy, not used for decryption check
        fingerprint: bob_fpr,
        invitenumber: "123".to_string(),
        authcode: secret.to_string(),
        is_v3: true,
    };

    alice.sql.execute(
        "INSERT INTO bobstate (invite, next_step, chat_id) VALUES (?, ?, ?)",
        (invite, 0, 0)
    ).await?;

    // Charlie (who Alice doesn't know) sends message to Alice using the QR secret.
    let charlie_addr = charlie.get_config(crate::config::Config::Addr).await?.unwrap();
    
    test_security_ex(
        &alice,
        &charlie_addr,
        &secret,
        Some(&charlie),
        Some("This sender is not allowed to encrypt with this secret key")
    ).await
}
