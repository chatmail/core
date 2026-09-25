use std::sync::LazyLock;
use tokio::sync::OnceCell;

use super::*;
use crate::transport::add_pseudo_transport;
use crate::{
    config::Config,
    decrypt,
    key::{load_self_public_key, self_fingerprint, store_self_keypair},
    mimefactory::{part_to_bytes, wrap_encrypted_part},
    test_utils::{TestContext, TestContextManager, alice_keypair, bob_keypair},
    token,
};
use chrono::{TimeZone as _, Utc};
use pgp::composed::{Esk, Message};
use pgp::packet::PublicKeyEncryptedSessionKey;

async fn decrypt_bytes(
    bytes: Vec<u8>,
    private_keys_for_decryption: &[SignedSecretKey],
    auth_tokens_for_decryption: &[String],
) -> Result<pgp::composed::Message<'static>> {
    let t = &TestContext::new().await;
    add_pseudo_transport(t, "alice@example.org")
        .await
        .expect("Failed to add pseudo transport");
    t.set_config(Config::ConfiguredAddr, Some("alice@example.org"))
        .await
        .expect("Failed to configure address");

    for secret in auth_tokens_for_decryption {
        token::save(t, token::Namespace::Auth, None, secret, 0).await?;
    }
    let [secret_key] = private_keys_for_decryption else {
        panic!("Only one private key is allowed anymore");
    };
    store_self_keypair(t, secret_key).await?;

    let mime_message = wrap_encrypted_part(bytes.try_into().unwrap());
    let rendered = part_to_bytes(mime_message);
    let parsed = mailparse::parse_mail(&rendered)?;
    let (decrypted, _fp) = decrypt::decrypt(t, &parsed).await?.unwrap();
    Ok(decrypted)
}

async fn pk_decrypt_and_validate<'a>(
    ctext: &'a [u8],
    private_keys_for_decryption: &'a [SignedSecretKey],
    public_keys_for_validation: &[SignedPublicKey],
) -> Result<(
    pgp::composed::Message<'static>,
    HashMap<Fingerprint, Vec<Fingerprint>>,
    Vec<u8>,
)> {
    let mut msg = decrypt_bytes(ctext.to_vec(), private_keys_for_decryption, &[]).await?;
    let content = msg.as_data_vec()?;
    let ret_signature_fingerprints = valid_signature_fingerprints(&msg, public_keys_for_validation);

    Ok((msg, ret_signature_fingerprints, content))
}

#[test]
fn test_create_keypair() {
    let keypair0 = create_keypair(EmailAddress::new("foo@bar.de").unwrap()).unwrap();
    let keypair1 = create_keypair(EmailAddress::new("two@zwo.de").unwrap()).unwrap();
    assert_ne!(keypair0.public_key(), keypair1.public_key());
}

/// [SignedSecretKey] and [SignedPublicKey] objects
/// to use in tests.
struct TestKeys {
    alice_secret: SignedSecretKey,
    alice_public: SignedPublicKey,
    bob_secret: SignedSecretKey,
    bob_public: SignedPublicKey,
}

impl TestKeys {
    fn new() -> TestKeys {
        let alice = alice_keypair();
        let bob = bob_keypair();
        TestKeys {
            alice_secret: alice.clone(),
            alice_public: alice.to_public_key(),
            bob_secret: bob.clone(),
            bob_public: bob.to_public_key(),
        }
    }
}

/// The original text of [CTEXT_SIGNED]
static CLEARTEXT: &[u8] = b"This is a test";

/// Initialised [TestKeys] for tests.
static KEYS: LazyLock<TestKeys> = LazyLock::new(TestKeys::new);

static CTEXT_SIGNED: OnceCell<String> = OnceCell::const_new();

/// A ciphertext encrypted to Alice & Bob, signed by Alice.
async fn ctext_signed() -> &'static String {
    CTEXT_SIGNED
        .get_or_init(|| async {
            let keyring = vec![KEYS.alice_public.clone(), KEYS.bob_public.clone()];
            let compress = true;

            pk_encrypt(
                CLEARTEXT.to_vec(),
                keyring,
                Some(&KEYS.alice_secret),
                compress,
                SeipdVersion::V2,
            )
            .unwrap()
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_encrypt_signed() {
    assert!(!ctext_signed().await.is_empty());
    assert!(
        ctext_signed()
            .await
            .starts_with("-----BEGIN PGP MESSAGE-----")
    );
}

/// Tests that a message encrypted without a signing key has no signature,
/// and therefore no intended recipient fingerprints naming the other recipients.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_encrypt_unsigned() {
    let keyring = vec![KEYS.alice_public.clone(), KEYS.bob_public.clone()];
    let compress = true;
    let ctext = pk_encrypt(
        CLEARTEXT.to_vec(),
        keyring,
        None,
        compress,
        SeipdVersion::V2,
    )
    .unwrap();

    let decrypt_keyring = vec![KEYS.bob_secret.clone()];
    let sig_check_keyring = vec![KEYS.alice_public.clone()];
    let (msg, valid_signatures, content) =
        pk_decrypt_and_validate(ctext.as_bytes(), &decrypt_keyring, &sig_check_keyring)
            .await
            .unwrap();
    assert_eq!(content, CLEARTEXT);
    assert!(!msg.is_signed());
    assert_eq!(valid_signatures.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decrypt_signed() {
    // Check decrypting as Alice
    let decrypt_keyring = vec![KEYS.alice_secret.clone()];
    let sig_check_keyring = vec![KEYS.alice_public.clone()];
    let (_msg, valid_signatures, content) = pk_decrypt_and_validate(
        ctext_signed().await.as_bytes(),
        &decrypt_keyring,
        &sig_check_keyring,
    )
    .await
    .unwrap();
    assert_eq!(content, CLEARTEXT);
    assert_eq!(valid_signatures.len(), 1);
    for recipient_fps in valid_signatures.values() {
        assert_eq!(recipient_fps.len(), 2);
    }

    // Check decrypting as Bob
    let decrypt_keyring = vec![KEYS.bob_secret.clone()];
    let sig_check_keyring = vec![KEYS.alice_public.clone()];
    let (_msg, valid_signatures, content) = pk_decrypt_and_validate(
        ctext_signed().await.as_bytes(),
        &decrypt_keyring,
        &sig_check_keyring,
    )
    .await
    .unwrap();
    assert_eq!(content, CLEARTEXT);
    assert_eq!(valid_signatures.len(), 1);
    for recipient_fps in valid_signatures.values() {
        assert_eq!(recipient_fps.len(), 2);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decrypt_no_sig_check() {
    let keyring = vec![KEYS.alice_secret.clone()];
    let (_msg, valid_signatures, content) =
        pk_decrypt_and_validate(ctext_signed().await.as_bytes(), &keyring, &[])
            .await
            .unwrap();
    assert_eq!(content, CLEARTEXT);
    assert_eq!(valid_signatures.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decrypt_signed_no_key() {
    // The validation does not have the public key of the signer.
    let decrypt_keyring = vec![KEYS.bob_secret.clone()];
    let sig_check_keyring = vec![KEYS.bob_public.clone()];
    let (_msg, valid_signatures, content) = pk_decrypt_and_validate(
        ctext_signed().await.as_bytes(),
        &decrypt_keyring,
        &sig_check_keyring,
    )
    .await
    .unwrap();
    assert_eq!(content, CLEARTEXT);
    assert_eq!(valid_signatures.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decrypt_unsigned() {
    let decrypt_keyring = vec![KEYS.bob_secret.clone()];
    let ctext_unsigned = include_bytes!("../../test-data/message/ctext_unsigned.asc");
    let (_msg, valid_signatures, content) =
        pk_decrypt_and_validate(ctext_unsigned, &decrypt_keyring, &[])
            .await
            .unwrap();
    assert_eq!(content, CLEARTEXT);
    assert_eq!(valid_signatures.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dont_decrypt_expensive_message_happy_path() -> Result<()> {
    let s2k = StringToKey::Salted {
        hash_alg: HashAlgorithm::default(),
        salt: [1; 8],
    };

    test_dont_decrypt_expensive_message_ext(s2k, false, None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dont_decrypt_expensive_message_bad_s2k() -> Result<()> {
    let s2k = StringToKey::new_default(&mut thread_rng()); // Default is IteratedAndSalted

    test_dont_decrypt_expensive_message_ext(s2k, false, Some("unsupported string2key algorithm"))
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dont_decrypt_expensive_message_multiple_secrets() -> Result<()> {
    let s2k = StringToKey::Salted {
        hash_alg: HashAlgorithm::default(),
        salt: [1; 8],
    };

    // This error message is actually not great,
    // but grepping for it will lead to the correct code
    test_dont_decrypt_expensive_message_ext(s2k, true, Some("decrypt_the_ring: missing key")).await
}

/// Test that we don't try to decrypt a message
/// that is symmetrically encrypted
/// with an expensive string2key algorithm
/// or multiple shared secrets.
/// This is to prevent possible DOS attacks on the app.
async fn test_dont_decrypt_expensive_message_ext(
    s2k: StringToKey,
    encrypt_twice: bool,
    expected_error_msg: Option<&str>,
) -> Result<()> {
    let mut tcm = TestContextManager::new();
    let bob = &tcm.bob().await;

    let plain = Vec::from(b"this is the secret message");
    let shared_secret = "shared secret";
    let bob_fp = self_fingerprint(bob).await?;

    let shared_secret_pw = Password::from(format!("securejoin/{bob_fp}/{shared_secret}"));
    let msg = MessageBuilder::from_bytes("", plain);
    let mut rng = thread_rng();

    let mut msg = msg.seipd_v2(
        &mut rng,
        SymmetricKeyAlgorithm::AES128,
        AeadAlgorithm::Ocb,
        ChunkSize::C8KiB,
    );
    msg.encrypt_with_password(&mut rng, s2k.clone(), &shared_secret_pw)?;
    if encrypt_twice {
        msg.encrypt_with_password(&mut rng, s2k, &shared_secret_pw)?;
    }

    let ctext = msg.to_armored_string(&mut rng, Default::default())?;

    // Trying to decrypt it should fail with a helpful error message:

    let bob_private_keyring = crate::key::load_self_secret_keyring(bob).await?;
    let res = decrypt_bytes(
        ctext.into(),
        &bob_private_keyring,
        &[shared_secret.to_string()],
    )
    .await;

    if let Some(expected_error_msg) = expected_error_msg {
        assert_eq!(format!("{:#}", res.unwrap_err()), expected_error_msg);
    } else {
        res.unwrap();
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decryption_error_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let plain = Vec::from(b"this is the secret message");
    let pk_for_encryption = load_self_public_key(alice).await?;

    // Encrypt a message, but only to self, not to Bob:
    let compress = true;
    let ctext = pk_encrypt(
        plain,
        vec![pk_for_encryption],
        Some(&KEYS.alice_secret),
        compress,
        SeipdVersion::V2,
    )?;

    // Trying to decrypt it should fail with an OK error message:
    let bob_private_keyring = crate::key::load_self_secret_keyring(bob).await?;
    let error = decrypt_bytes(ctext.into(), &bob_private_keyring, &[])
        .await
        .unwrap_err();

    assert_eq!(format!("{error:#}"), "decrypt_the_ring: missing key");

    Ok(())
}

/// Tests that recipient key IDs and fingerprints
/// are omitted or replaced with wildcards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_anonymous_recipients() -> Result<()> {
    let ctext = ctext_signed().await.as_bytes();
    let cursor = Cursor::new(ctext);
    let (msg, _headers) = Message::from_armor(cursor)?;

    let Message::Encrypted { esk, .. } = msg else {
        unreachable!();
    };

    for encrypted_session_key in esk {
        let Esk::PublicKeyEncryptedSessionKey(pkesk) = encrypted_session_key else {
            unreachable!()
        };

        match pkesk {
            PublicKeyEncryptedSessionKey::V3 { id, .. } => {
                assert!(id.is_wildcard());
            }
            PublicKeyEncryptedSessionKey::V6 { fingerprint, .. } => {
                assert!(fingerprint.is_none());
            }
            PublicKeyEncryptedSessionKey::Other { .. } => unreachable!(),
        }
    }
    Ok(())
}

#[test]
fn test_merge_openpgp_certificates() {
    let alice = alice_keypair().to_public_key();
    let bob = bob_keypair().to_public_key();

    // Merging certificate with itself does not change it.
    assert_eq!(
        merge_openpgp_certificates(alice.clone(), alice.clone()).unwrap(),
        alice
    );
    assert_eq!(
        merge_openpgp_certificates(bob.clone(), bob.clone()).unwrap(),
        bob
    );

    // Cannot merge certificates with different primary key.
    assert!(merge_openpgp_certificates(alice.clone(), bob.clone()).is_err());
    assert!(merge_openpgp_certificates(bob, alice).is_err());
}

/// Test PQC support.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pqc() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let pqc = &tcm.pqc().await;

    let pqc_received_message = tcm.send_recv_accept(alice, pqc, "Hi!").await;
    let pqc_chat_id = pqc_received_message.chat_id;
    let pqc_sent = pqc.send_text(pqc_chat_id, "Hello back!").await;

    let alice_rcvd = alice.recv_msg(&pqc_sent).await;
    assert_eq!(alice_rcvd.text, "Hello back!");

    Ok(())
}

/// Tests securejoin with inviter using PQC key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_securejoin_pqc_inviter() {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let pqc = &tcm.pqc().await;

    tcm.execute_securejoin(pqc, alice).await;
}

/// Tests securejoin with joiner using PQC key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_securejoin_pqc_joiner() {
    let mut tcm = TestContextManager::new();
    let pqc = &tcm.pqc().await;
    let bob = &tcm.bob().await;

    tcm.execute_securejoin(bob, pqc).await;
}

/// Tests that public subkey selection for encryption respects key flags and prefers expring subkeys.
///
/// Non-encryption subkeys such as RSA subkey for authentication are ignored.
#[test]
fn test_select_pk_for_encryption() {
    // Public key generated with GnuPG 2.4.9 with the following subkeys:
    // 1. Auth-only RSA subkey (92E762B9084CA740).
    // 2. Expired Curve25519 encryption subkey with 1-day expiration (C8F382BD0F35C49E)
    // 3. Ed25519 signing subkey (F177AC3118F923CC).
    // 4. Curve25519 encryption subkey with fingerprint (36188C6FFC8E267B)
    // 5. Curve25519 encryption subkey with 1 year expiration, valid in the beginning of 2008, with key ID 9223FCEE7546CDE7
    // 6. Curve25519 encryption subkey with no expiration (FD2C0567967223D8).
    // Primary key is an Ed25519 not expiring key.
    // Key 4 is the one that should be selected.

    // Subkey 4 fingerprint.
    let expected_fallback_fingerprint = "cdeb3ba3999bf7880f0ee1f536188c6ffc8e267b";

    // Subkey 5 fingerprint, should be preferred to fallback when not expired.
    let expected_expiring_fingerprint = "5133fab157c4a46ca41f6dc39223fcee7546cde7";

    let alice_tpk_asc = "
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=AXAi
-----END PGP PUBLIC KEY BLOCK-----
    ";

    let alice_tpk = SignedPublicKey::from_asc(alice_tpk_asc).unwrap();
    let now = pgp::types::Timestamp::now();
    let encryption_subkey = select_pk_for_encryption(now.as_secs(), &alice_tpk).unwrap();
    assert_eq!(
        encryption_subkey.fingerprint().to_string().as_str(),
        expected_fallback_fingerprint
    );

    // If we pass 1199149200 as the `now` argument, which was in the beginning of 2008,
    // then the expiring subkey is not yet expired and should be used.
    let encryption_subkey = select_pk_for_encryption(1199149200, &alice_tpk).unwrap();
    assert_eq!(
        encryption_subkey.fingerprint().to_string().as_str(),
        expected_expiring_fingerprint
    );
}

/// Tests that key selection fails if there is only an expired subkey.
#[test]
fn test_select_only_expired_subkey() {
    let alice_tpk_asc = "
    -----BEGIN PGP PUBLIC KEY BLOCK-----

mDMERvfcPBYJKwYBBAHaRw8BAQdAUz6AZXIRE8T04Vh8RReFiP3tEV8UfSs2EiYs
8b8i4ce0GUFsaWNlIDxhbGljZUBleGFtcGxlLm9yZz6IkAQTFgoAOBYhBNRG3w/A
qWyPitBaqkGLyqDx3CaUBQJG99w8AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheA
AAoJEEGLyqDx3CaUMjIA/Rq9/iORLP360s6EsIDe9qSmlmSCggtivafH+uVBWa0X
AP0Wb+kailDwISq2O9Ef/jceZw7ozyzDLeDskKpCYiL3A7g4BEb33DwSCisGAQQB
l1UBBQEBB0BXhbrks9iskW1GfT3B022W3KhJCgz8gw81z9lAWv7OZgMBCAeIfgQY
FgoAJhYhBNRG3w/AqWyPitBaqkGLyqDx3CaUBQJG99w8AhsMBQkB4TOAAAoJEEGL
yqDx3CaU6/YA/jaYJsZMXvu5grrMq1wq3Z/yzGXd15zeWp+alY/6UYxoAQCmSrBC
SOtE3ODLZN9tC3F7k1N9clme1cHXyUiH3EliBQ==
=zWPq
-----END PGP PUBLIC KEY BLOCK-----
";

    let alice_tpk = SignedPublicKey::from_asc(alice_tpk_asc).unwrap();
    let now = pgp::types::Timestamp::now();

    assert_eq!(select_pk_for_encryption(now.as_secs(), &alice_tpk), None);
}

/// Tests that the key with the closest expiration date is selected.
#[test]
fn test_expiring_subkey_selection() {
    // The key has the following keys:
    // 1. Primary non-expiring Ed25519 key created on 2025-01-01
    // 2. Non-expiring subkey CE5FC3FD479E41F08069DCE6F6CAD4ADB9AF47F1 created on 2025-01-01
    // 3. Subkey 10493EF4DBA7EE4D55C826A7634684D9BFEEB890 created on 2026-06-01 and expiring on 2026-07-01
    // 4. Subkey 477650C13FA4842BAF2831BC41C2D560BE27B38D created on 2026-06-01 and expiring on 2026-06-15
    // 5. Subkey AB92F4AFD46DDD7D31FB05151BE08A8089F67CA2 created on 2026-06-08 and expiring on 2026-06-22
    let alice_tpk_asc = "
    -----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZ3SFgBYJKwYBBAHaRw8BAQdAOrjYsxkYNvVtjbZwvglXk94Rd8S3F0YlIgcQ
SSp45ni0GUFsaWNlIDxhbGljZUBleGFtcGxlLm9yZz6IkAQTFgoAOBYhBGV3iWZU
bA6WJh3MR00wvB0X57PiBQJndIWAAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheA
AAoJEE0wvB0X57PiAr0A/0qzulPRXZR1+D1fUeW6/C3BRP+8qRZTlOvF0XEnxPOV
AQD7oePZ/QI6AuDMFmnJ5HQJ6cQSSOp/FwyucD8yiAoABrg4BGd0hYASCisGAQQB
l1UBBQEBB0DBBk+BdzyTu3Hys6dewzd0L5AFeYMRIOC99XosMBLZYwMBCAeIeAQY
FgoAIBYhBGV3iWZUbA6WJh3MR00wvB0X57PiBQJndIWAAhsMAAoJEE0wvB0X57Pi
BxYA+gOtDVtb9p9vVaKyAuYCG7LdJ63Bqu0OtrVxmZEQvHQbAQDJmJX/yOX5QSkh
cRtM1qoiY7OUjcT8ERnaoAcw2suFBLg4BGocy4ASCisGAQQBl1UBBQEBB0AgEDSA
muuqS2iyi7aZeV608Xx2qdVqYKjREgiC3cu4YQMBCAeIfgQYFgoAJhYhBGV3iWZU
bA6WJh3MR00wvB0X57PiBQJqHMuAAhsMBQkAJ40AAAoJEE0wvB0X57Pi9KgA/2vW
4yNU1EF/WRCKmr87mJtmYR5Xf9Jps54Tv4BexNGgAQDxxx9lKvwW4U9/8UkrSF28
HrGdWES4wAa9N9HvJzuOD7g4BGocy4ASCisGAQQBl1UBBQEBB0CK1TifDqKtFzks
4E8gNmF90OkIYVriZxdY3QFSwowILQMBCAeIfgQYFgoAJhYhBGV3iWZUbA6WJh3M
R00wvB0X57PiBQJqHMuAAhsMBQkAEnUAAAoJEE0wvB0X57PiZ+UA/0+s3fM/8OOb
8Ft21QMFM/7Ce1P/ovKgkxsYWjk8q7zYAP9HYm/vcWBGzQw08mn3X26UFB9UfCF3
qc1yyltDEeERDrg4BGomBgASCisGAQQBl1UBBQEBB0AvGvgG8Wkwx/KklkUHdLuC
UKKSqTp4xsjocWXJs69rSwMBCAeIfgQYFgoAJhYhBGV3iWZUbA6WJh3MR00wvB0X
57PiBQJqJgYAAhsMBQkAEnUAAAoJEE0wvB0X57PibzQA/A0qT23pcdenNJJ5QZN/
ecs08p2pbiipv+adPeojVGZIAP47Pyr8Hj0o3qhrEhhFZkIhTxxDxS/jAsq2v4UG
JGp8Ag==
=RzZZ
-----END PGP PUBLIC KEY BLOCK-----
";

    let alice_tpk = SignedPublicKey::from_asc(alice_tpk_asc).unwrap();

    // Two-week subkey that was generated earlier is selected
    // because it expires earlier, on 2026-06-15.
    {
        let ts = u32::try_from(
            Utc.with_ymd_and_hms(2026, 6, 9, 0, 0, 0)
                .unwrap()
                .timestamp(),
        )
        .unwrap();
        let subkey = select_pk_for_encryption(ts, &alice_tpk).unwrap();
        assert_eq!(
            subkey.fingerprint().to_string().as_str(),
            "477650c13fa4842baf2831bc41c2d560be27b38d",
        );
    }

    // Now both 477650C13FA4842BAF2831BC41C2D560BE27B38D expires
    // and we switch to another subkey that expires on 2026-06-22.
    {
        let ts = u32::try_from(
            Utc.with_ymd_and_hms(2026, 6, 16, 0, 0, 0)
                .unwrap()
                .timestamp(),
        )
        .unwrap();
        let subkey = select_pk_for_encryption(ts, &alice_tpk).unwrap();
        assert_eq!(
            subkey.fingerprint().to_string().as_str(),
            "ab92f4afd46ddd7d31fb05151be08a8089f67ca2",
        );
    }

    // Now both two-week subkeys have expired and we switch to expiring subkey that expires on 2026-07-01.
    {
        let ts = u32::try_from(
            Utc.with_ymd_and_hms(2026, 6, 23, 0, 0, 0)
                .unwrap()
                .timestamp(),
        )
        .unwrap();
        let subkey = select_pk_for_encryption(ts, &alice_tpk).unwrap();
        assert_eq!(
            subkey.fingerprint().to_string().as_str(),
            "10493ef4dba7ee4d55c826a7634684d9bfeeb890",
        );
    }

    // All expiring subkeys are expired, switching to non-expiring subkey.
    {
        let ts = u32::try_from(
            Utc.with_ymd_and_hms(2026, 7, 2, 0, 0, 0)
                .unwrap()
                .timestamp(),
        )
        .unwrap();
        let subkey = select_pk_for_encryption(ts, &alice_tpk).unwrap();
        assert_eq!(
            subkey.fingerprint().to_string().as_str(),
            "ce5fc3fd479e41f08069dce6f6cad4adb9af47f1",
        );
    }
}
