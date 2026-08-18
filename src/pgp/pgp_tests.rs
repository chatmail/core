use std::sync::LazyLock;
use tokio::sync::OnceCell;

use super::*;
use crate::{
    config::Config,
    decrypt,
    key::{load_self_public_key, self_fingerprint, store_self_keypair},
    mimefactory::{part_to_bytes, wrap_encrypted_part},
    test_utils::{TestContext, TestContextManager, alice_keypair, bob_keypair},
    token,
};
use pgp::composed::{Esk, Message};
use pgp::packet::PublicKeyEncryptedSessionKey;

async fn decrypt_bytes(
    bytes: Vec<u8>,
    private_keys_for_decryption: &[SignedSecretKey],
    auth_tokens_for_decryption: &[String],
) -> Result<pgp::composed::Message<'static>> {
    let t = &TestContext::new().await;
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
                KEYS.alice_secret.clone(),
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
        KEYS.alice_secret.clone(),
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
    assert!(merge_openpgp_certificates(bob.clone(), alice.clone()).is_err());
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
