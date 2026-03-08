use crate::chat::{self, ChatId};
use crate::pgp;
use crate::key::{load_self_secret_keyring, Fingerprint};
use crate::test_utils::{TestContextManager};
use crate::constants::Chattype;
use super::*;
use anyhow::Result;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_security_attacker_signature() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let charlie = tcm.charlie().await; // Attacker

    // Alice creates a broadcast channel
    let alice_chat_id = chat::create_broadcast(&alice, "Channel".to_string()).await?;
    
    // Bob joins the channel (SetupContact QR scan)
    let qr = crate::securejoin::get_securejoin_qr(&alice, Some(alice_chat_id)).await?;
    let _bob_chat_id = tcm.exec_securejoin_qr(&bob, &alice, &qr).await;

    // Verify Bob's chat type
    let bob_chat = chat::Chat::load_from_db(&bob, _bob_chat_id).await?;
    println!("Bob's chat ID: {}, type: {:?}", _bob_chat_id, bob_chat.typ);
    assert_eq!(bob_chat.typ, Chattype::InBroadcast);

    // Get the broadcast secret from Alice's db
    let secret: String = alice.sql.query_row(
        "SELECT secret FROM broadcast_secrets WHERE chat_id = ?",
        (alice_chat_id,),
        |row| row.get(0)
    ).await?;

    // Charlie (attacker) also gets the secret and sends a message to Bob, encrypted with it, signed by Charlie.
    let plain_text = "Evil message from Charlie";
    let charlie_secret_key = load_self_secret_keyring(&charlie).await?.remove(0);
    let encrypted_msg = pgp::symm_encrypt_message(
        plain_text.as_bytes().to_vec(),
        Some(charlie_secret_key),
        &secret,
        false
    ).await?;

    // Bob receives the message from Charlie
    let charlie_addr = charlie.get_config(crate::config::Config::Addr).await?.unwrap();
    let boundary = "boundary123";
    let rcvd_mail = format!(
        "From: {from}\n\
         To: bob@example.net\n\
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
        from = charlie_addr,
        boundary = boundary,
        encrypted_msg = encrypted_msg
    );
    
    // Parsing should fail with the specific security error.
    let res = MimeMessage::from_bytes(&bob, rcvd_mail.as_bytes()).await;
    
    match &res {
        Ok(mime) => {
            println!("SUCCESSFULLY parsed (BAD!): {}", mime.parts[0].msg);
            // Check if decryption actually happened
            assert!(!mime.decrypting_failed);
        }
        Err(e) => {
            println!("Got expected error: {}", e);
        }
    }
    
    assert!(res.is_err(), "Expected error for attacker signature, but got success");
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("This sender is not allowed to encrypt with this secret key"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_security_no_signature() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    let alice_chat_id = chat::create_broadcast(&alice, "Channel".to_string()).await?;
    let qr = crate::securejoin::get_securejoin_qr(&alice, Some(alice_chat_id)).await?;
    let _bob_chat_id = tcm.exec_securejoin_qr(&bob, &alice, &qr).await;

    let secret: String = alice.sql.query_row(
        "SELECT secret FROM broadcast_secrets WHERE chat_id = ?",
        (alice_chat_id,),
        |row| row.get(0)
    ).await?;

    // Attacker sends an UNSIGNED message
    let plain_text = "Evil unsigned message";
    let encrypted_msg = pgp::symm_encrypt_message(
        plain_text.as_bytes().to_vec(),
        None, // No signature
        &secret,
        false
    ).await?;

    let boundary = "boundary123";
    let rcvd_mail = format!(
        "From: attacker@example.org\n\
         To: bob@example.net\n\
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
        boundary = boundary,
        encrypted_msg = encrypted_msg
    );
    
    let res = MimeMessage::from_bytes(&bob, rcvd_mail.as_bytes()).await;
    
    assert!(res.is_err(), "Expected error for unsigned message, but got success");
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("This sender is not allowed to encrypt with this secret key"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_security_happy_path() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    let alice_chat_id = chat::create_broadcast(&alice, "Channel".to_string()).await?;
    let qr = crate::securejoin::get_securejoin_qr(&alice, Some(alice_chat_id)).await?;
    let _bob_chat_id = tcm.exec_securejoin_qr(&bob, &alice, &qr).await;

    let secret: String = alice.sql.query_row(
        "SELECT secret FROM broadcast_secrets WHERE chat_id = ?",
        (alice_chat_id,),
        |row| row.get(0)
    ).await?;

    // Alice (owner) sends a message to Bob, encrypted with the broadcast secret, signed by Alice.
    let plain_text = "Hello from Alice";
    let alice_secret_key = load_self_secret_keyring(&alice).await?.remove(0);
    let encrypted_msg = pgp::symm_encrypt_message(
        plain_text.as_bytes().to_vec(),
        Some(alice_secret_key),
        &secret,
        false
    ).await?;

    let alice_addr = alice.get_config(crate::config::Config::Addr).await?.unwrap();
    let boundary = "boundary123";
    let rcvd_mail = format!(
        "From: {from}\n\
         To: bob@example.net\n\
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
        from = alice_addr,
        boundary = boundary,
        encrypted_msg = encrypted_msg
    );
    
    // Parsing should succeed.
    let res = MimeMessage::from_bytes(&bob, rcvd_mail.as_bytes()).await;
    assert!(res.is_ok(), "Happy path failed: {:?}", res.err());
    let mime = res.unwrap();
    assert_eq!(mime.parts[0].msg, plain_text);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_qr_code_security_fix() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let charlie = tcm.charlie().await; // Attacker

    // Bob produces a QR code for Alice to scan
    let qr = crate::securejoin::get_securejoin_qr(&bob, None).await?;
    let secret = qr.split("&s=").last().unwrap();
    
    // Alice scans Bob's QR
    let _alice_chat_with_bob = crate::securejoin::join_securejoin(&alice, &qr).await?;

    // Charlie sends message to Alice
    let plain_text = "Evil message to Alice";
    let charlie_secret_key = load_self_secret_keyring(&charlie).await?.remove(0);
    let encrypted_msg = pgp::symm_encrypt_message(
        plain_text.as_bytes().to_vec(),
        Some(charlie_secret_key),
        &secret,
        false
    ).await?;

    let charlie_addr = charlie.get_config(crate::config::Config::Addr).await?.unwrap();
    let boundary = "boundary123";
    let rcvd_mail = format!(
        "From: {from}\n\
         To: alice@example.org\n\
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
        from = charlie_addr,
        boundary = boundary,
        encrypted_msg = encrypted_msg
    );
    
    let res = MimeMessage::from_bytes(&alice, rcvd_mail.as_bytes()).await;
    
    assert!(res.is_err(), "Expected error for QR code secret abuse, but got success");
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("This sender is not allowed to encrypt with this secret key"));

    Ok(())
}
