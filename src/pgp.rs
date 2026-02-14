//! OpenPGP helper module using [rPGP facilities](https://github.com/rpgp/rpgp).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, Cursor};

use anyhow::{Context as _, Result, bail};
use deltachat_contact_tools::EmailAddress;
use pgp::armor::BlockType;
use pgp::composed::{
    ArmorOptions, DecryptionOptions, Deserializable, DetachedSignature, EncryptionCaps,
    KeyType as PgpKeyType, Message, MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey,
    SignedPublicSubKey, SignedSecretKey, SubkeyParamsBuilder, SubpacketConfig, TheRing,
};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{
    CompressionAlgorithm, KeyDetails, KeyVersion, Password, SigningKey as _, StringToKey,
};
use rand_old::{Rng as _, thread_rng};
use tokio::runtime::Handle;

use crate::key::{DcKey, Fingerprint};

#[cfg(test)]
pub(crate) const HEADER_AUTOCRYPT: &str = "autocrypt-prefer-encrypt";

pub(crate) const HEADER_SETUPCODE: &str = "passphrase-begin";

/// Preferred symmetric encryption algorithm.
const SYMMETRIC_KEY_ALGORITHM: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES128;

/// Split data from PGP Armored Data as defined in <https://tools.ietf.org/html/rfc4880#section-6.2>.
///
/// Returns (type, headers, base64 encoded body).
pub fn split_armored_data(buf: &[u8]) -> Result<(BlockType, BTreeMap<String, String>, Vec<u8>)> {
    use std::io::Read;

    let cursor = Cursor::new(buf);
    let mut dearmor = pgp::armor::Dearmor::new(cursor);

    let mut bytes = Vec::with_capacity(buf.len());

    dearmor.read_to_end(&mut bytes)?;
    let typ = dearmor.typ.context("failed to parse type")?;

    // normalize headers
    let headers = dearmor
        .headers
        .into_iter()
        .map(|(key, values)| {
            (
                key.trim().to_lowercase(),
                values
                    .last()
                    .map_or_else(String::new, |s| s.trim().to_string()),
            )
        })
        .collect();

    Ok((typ, headers, bytes))
}

/// A PGP keypair.
///
/// This has it's own struct to be able to keep the public and secret
/// keys together as they are one unit.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeyPair {
    /// Public key.
    pub public: SignedPublicKey,

    /// Secret key.
    pub secret: SignedSecretKey,
}

impl KeyPair {
    /// Creates new keypair from a secret key.
    ///
    /// Public key is split off the secret key.
    pub fn new(secret: SignedSecretKey) -> Result<Self> {
        let public = secret.to_public_key();
        Ok(Self { public, secret })
    }
}

/// Create a new key pair.
///
/// Both secret and public key consist of signing primary key and encryption subkey
/// as [described in the Autocrypt standard](https://autocrypt.org/level1.html#openpgp-based-key-data).
pub(crate) fn create_keypair(addr: EmailAddress) -> Result<KeyPair> {
    let signing_key_type = PgpKeyType::Ed25519Legacy;
    let encryption_key_type = PgpKeyType::ECDH(ECCCurve::Curve25519);

    let user_id = format!("<{addr}>");
    let key_params = SecretKeyParamsBuilder::default()
        .key_type(signing_key_type)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(user_id)
        .passphrase(None)
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha224,
        ])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::ZIP,
        ])
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(encryption_key_type)
                .can_encrypt(EncryptionCaps::All)
                .passphrase(None)
                .build()
                .context("failed to build subkey parameters")?,
        )
        .build()
        .context("failed to build key parameters")?;

    let mut rng = thread_rng();
    let secret_key = key_params
        .generate(&mut rng)
        .context("Failed to generate the key")?;
    secret_key
        .verify_bindings()
        .context("Invalid secret key generated")?;

    let key_pair = KeyPair::new(secret_key)?;
    key_pair
        .public
        .verify_bindings()
        .context("Invalid public key generated")?;
    Ok(key_pair)
}

/// Selects a subkey of the public key to use for encryption.
///
/// Returns `None` if the public key cannot be used for encryption.
///
/// TODO: take key flags and expiration dates into account
fn select_pk_for_encryption(key: &SignedPublicKey) -> Option<&SignedPublicSubKey> {
    key.public_subkeys
        .iter()
        .find(|subkey| subkey.algorithm().can_encrypt())
}

/// Version of SEIPD packet to use.
///
/// See
/// <https://www.rfc-editor.org/rfc/rfc9580#name-avoiding-ciphertext-malleab>
/// for the discussion on when v2 SEIPD should be used.
#[derive(Debug)]
pub enum SeipdVersion {
    /// Use v1 SEIPD, for compatibility.
    V1,

    /// Use v2 SEIPD when we know that v2 SEIPD is supported.
    V2,
}

/// Encrypts `plain` text using `public_keys_for_encryption`
/// and signs it using `private_key_for_signing`.
#[expect(clippy::arithmetic_side_effects)]
pub async fn pk_encrypt(
    plain: Vec<u8>,
    public_keys_for_encryption: Vec<SignedPublicKey>,
    private_key_for_signing: SignedSecretKey,
    compress: bool,
    anonymous_recipients: bool,
    seipd_version: SeipdVersion,
) -> Result<String> {
    Handle::current()
        .spawn_blocking(move || {
            let mut rng = thread_rng();

            let pkeys = public_keys_for_encryption
                .iter()
                .filter_map(select_pk_for_encryption);
            let subpkts = {
                let mut hashed = Vec::with_capacity(1 + public_keys_for_encryption.len() + 1);
                hashed.push(Subpacket::critical(SubpacketData::SignatureCreationTime(
                    pgp::types::Timestamp::now(),
                ))?);
                // Test "elena" uses old Delta Chat.
                let skip = private_key_for_signing.dc_fingerprint().hex()
                    == "B86586B6DEF437D674BFAFC02A6B2EBC633B9E82";
                for key in &public_keys_for_encryption {
                    if skip {
                        break;
                    }
                    let data = SubpacketData::IntendedRecipientFingerprint(key.fingerprint());
                    let subpkt = match private_key_for_signing.version() < KeyVersion::V6 {
                        true => Subpacket::regular(data)?,
                        false => Subpacket::critical(data)?,
                    };
                    hashed.push(subpkt);
                }
                hashed.push(Subpacket::regular(SubpacketData::IssuerFingerprint(
                    private_key_for_signing.fingerprint(),
                ))?);
                let mut unhashed = vec![];
                if private_key_for_signing.version() <= KeyVersion::V4 {
                    unhashed.push(Subpacket::regular(SubpacketData::IssuerKeyId(
                        private_key_for_signing.legacy_key_id(),
                    ))?);
                }
                SubpacketConfig::UserDefined { hashed, unhashed }
            };

            let msg = MessageBuilder::from_bytes("", plain);
            let encoded_msg = match seipd_version {
                SeipdVersion::V1 => {
                    let mut msg = msg.seipd_v1(&mut rng, SYMMETRIC_KEY_ALGORITHM);

                    for pkey in pkeys {
                        if anonymous_recipients {
                            msg.encrypt_to_key_anonymous(&mut rng, &pkey)?;
                        } else {
                            msg.encrypt_to_key(&mut rng, &pkey)?;
                        }
                    }

                    let hash_algorithm = private_key_for_signing.hash_alg();
                    msg.sign_with_subpackets(
                        &*private_key_for_signing,
                        Password::empty(),
                        hash_algorithm,
                        subpkts,
                    );
                    if compress {
                        msg.compression(CompressionAlgorithm::ZLIB);
                    }

                    msg.to_armored_string(&mut rng, Default::default())?
                }
                SeipdVersion::V2 => {
                    let mut msg = msg.seipd_v2(
                        &mut rng,
                        SYMMETRIC_KEY_ALGORITHM,
                        AeadAlgorithm::Ocb,
                        ChunkSize::C8KiB,
                    );

                    for pkey in pkeys {
                        if anonymous_recipients {
                            msg.encrypt_to_key_anonymous(&mut rng, &pkey)?;
                        } else {
                            msg.encrypt_to_key(&mut rng, &pkey)?;
                        }
                    }

                    let hash_algorithm = private_key_for_signing.hash_alg();
                    msg.sign_with_subpackets(
                        &*private_key_for_signing,
                        Password::empty(),
                        hash_algorithm,
                        subpkts,
                    );
                    if compress {
                        msg.compression(CompressionAlgorithm::ZLIB);
                    }

                    msg.to_armored_string(&mut rng, Default::default())?
                }
            };

            Ok(encoded_msg)
        })
        .await?
}

/// Produces a detached signature for `plain` text using `private_key_for_signing`.
pub fn pk_calc_signature(
    plain: Vec<u8>,
    private_key_for_signing: &SignedSecretKey,
) -> Result<String> {
    let rng = thread_rng();

    let mut config = SignatureConfig::from_key(
        rng,
        &private_key_for_signing.primary_key,
        SignatureType::Binary,
    )?;

    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            private_key_for_signing.fingerprint(),
        ))?,
        Subpacket::critical(SubpacketData::SignatureCreationTime(
            pgp::types::Timestamp::now(),
        ))?,
    ];
    config.unhashed_subpackets = vec![];
    if private_key_for_signing.version() <= KeyVersion::V4 {
        config
            .unhashed_subpackets
            .push(Subpacket::regular(SubpacketData::IssuerKeyId(
                private_key_for_signing.legacy_key_id(),
            ))?);
    }

    let signature = config.sign(
        &private_key_for_signing.primary_key,
        &Password::empty(),
        plain.as_slice(),
    )?;

    let sig = DetachedSignature::new(signature);

    Ok(sig.to_armored_string(ArmorOptions::default())?)
}

/// Decrypts the message:
/// - with keys from the private key keyring (passed in `private_keys_for_decryption`)
///   if the message was asymmetrically encrypted,
/// - with a shared secret/password (passed in `shared_secrets`),
///   if the message was symmetrically encrypted.
///
/// Returns the decrypted and decompressed message.
pub fn decrypt(
    ctext: Vec<u8>,
    private_keys_for_decryption: &[SignedSecretKey],
    mut shared_secrets: &[String],
) -> Result<pgp::composed::Message<'static>> {
    let cursor = Cursor::new(ctext);
    let (msg, _headers) = Message::from_armor(cursor)?;

    let skeys: Vec<&SignedSecretKey> = private_keys_for_decryption.iter().collect();
    let empty_pw = Password::empty();

    let decrypt_options = DecryptionOptions::new();
    let symmetric_encryption_res = check_symmetric_encryption(&msg);
    if symmetric_encryption_res.is_err() {
        shared_secrets = &[];
    }

    // We always try out all passwords here,
    // but benchmarking (see `benches/decrypting.rs`)
    // showed that the performance impact is negligible.
    // We can improve this in the future if necessary.
    let message_password: Vec<Password> = shared_secrets
        .iter()
        .map(|p| Password::from(p.as_str()))
        .collect();
    let message_password: Vec<&Password> = message_password.iter().collect();

    let ring = TheRing {
        secret_keys: skeys,
        key_passwords: vec![&empty_pw],
        message_password,
        session_keys: vec![],
        decrypt_options,
    };

    let res = msg.decrypt_the_ring(ring, true);

    let (msg, _ring_result) = match res {
        Ok(it) => it,
        Err(err) => {
            if let Err(reason) = symmetric_encryption_res {
                bail!("{err:#} (Note: symmetric decryption was not tried: {reason})")
            } else {
                bail!("{err:#}");
            }
        }
    };

    // remove one layer of compression
    let msg = msg.decompress()?;

    Ok(msg)
}

/// Returns Ok(()) if we want to try symmetrically decrypting the message,
/// and Err with a reason if symmetric decryption should not be tried.
///
/// A DOS attacker could send a message with a lot of encrypted session keys,
/// all of which use a very hard-to-compute string2key algorithm.
/// We would then try to decrypt all of the encrypted session keys
/// with all of the known shared secrets.
/// In order to prevent this, we do not try to symmetrically decrypt messages
/// that use a string2key algorithm other than 'Salted'.
fn check_symmetric_encryption(msg: &Message<'_>) -> std::result::Result<(), &'static str> {
    let Message::Encrypted { esk, .. } = msg else {
        return Err("not encrypted");
    };

    if esk.len() > 1 {
        return Err("too many esks");
    }

    let [pgp::composed::Esk::SymKeyEncryptedSessionKey(esk)] = &esk[..] else {
        return Err("not symmetrically encrypted");
    };

    match esk.s2k() {
        Some(StringToKey::Salted { .. }) => Ok(()),
        _ => Err("unsupported string2key algorithm"),
    }
}

/// Returns fingerprints
/// of all keys from the `public_keys_for_validation` keyring that
/// have valid signatures in `msg` and corresponding intended recipient fingerprints
/// (<https://www.rfc-editor.org/rfc/rfc9580.html#name-intended-recipient-fingerpr>) if any.
///
/// If the message is wrongly signed, returns an empty map.
pub fn valid_signature_fingerprints(
    msg: &pgp::composed::Message,
    public_keys_for_validation: &[SignedPublicKey],
) -> HashMap<Fingerprint, Vec<Fingerprint>> {
    let mut ret_signature_fingerprints = HashMap::new();
    if msg.is_signed() {
        for pkey in public_keys_for_validation {
            if let Ok(signature) = msg.verify(&pkey.primary_key) {
                let fp = pkey.dc_fingerprint();
                let mut recipient_fps = Vec::new();
                if let Some(cfg) = signature.config() {
                    for subpkt in &cfg.hashed_subpackets {
                        if let SubpacketData::IntendedRecipientFingerprint(fp) = &subpkt.data {
                            recipient_fps.push(fp.clone().into());
                        }
                    }
                }
                ret_signature_fingerprints.insert(fp, recipient_fps);
            }
        }
    }
    ret_signature_fingerprints
}

/// Validates detached signature.
pub fn pk_validate(
    content: &[u8],
    signature: &[u8],
    public_keys_for_validation: &[SignedPublicKey],
) -> Result<HashSet<Fingerprint>> {
    let mut ret: HashSet<Fingerprint> = Default::default();

    let detached_signature = DetachedSignature::from_armor_single(Cursor::new(signature))?.0;

    for pkey in public_keys_for_validation {
        if detached_signature.verify(pkey, content).is_ok() {
            let fp = pkey.dc_fingerprint();
            ret.insert(fp);
        }
    }
    Ok(ret)
}

/// Symmetric encryption for the autocrypt setup message (ASM).
pub async fn symm_encrypt_autocrypt_setup(passphrase: &str, plain: Vec<u8>) -> Result<String> {
    let passphrase = Password::from(passphrase.to_string());

    tokio::task::spawn_blocking(move || {
        let mut rng = thread_rng();
        let s2k = StringToKey::new_default(&mut rng);
        let builder = MessageBuilder::from_bytes("", plain);
        let mut builder = builder.seipd_v1(&mut rng, SYMMETRIC_KEY_ALGORITHM);
        builder.encrypt_with_password(s2k, &passphrase)?;

        let encoded_msg = builder.to_armored_string(&mut rng, Default::default())?;

        Ok(encoded_msg)
    })
    .await?
}

/// Symmetrically encrypt the message.
/// This is used for broadcast channels and for version 2 of the Securejoin protocol.
/// `shared secret` is the secret that will be used for symmetric encryption.
pub async fn symm_encrypt_message(
    plain: Vec<u8>,
    private_key_for_signing: SignedSecretKey,
    shared_secret: &str,
    compress: bool,
) -> Result<String> {
    let shared_secret = Password::from(shared_secret.to_string());

    tokio::task::spawn_blocking(move || {
        let msg = MessageBuilder::from_bytes("", plain);
        let mut rng = thread_rng();
        let mut salt = [0u8; 8];
        rng.fill(&mut salt[..]);
        let s2k = StringToKey::Salted {
            hash_alg: HashAlgorithm::default(),
            salt,
        };
        let mut msg = msg.seipd_v2(
            &mut rng,
            SYMMETRIC_KEY_ALGORITHM,
            AeadAlgorithm::Ocb,
            ChunkSize::C8KiB,
        );
        msg.encrypt_with_password(&mut rng, s2k, &shared_secret)?;

        let hash_algorithm = private_key_for_signing.hash_alg();
        msg.sign(&*private_key_for_signing, Password::empty(), hash_algorithm);
        if compress {
            msg.compression(CompressionAlgorithm::ZLIB);
        }

        let encoded_msg = msg.to_armored_string(&mut rng, Default::default())?;

        Ok(encoded_msg)
    })
    .await?
}

/// Symmetric decryption.
pub async fn symm_decrypt<T: BufRead + std::fmt::Debug + 'static + Send>(
    passphrase: &str,
    ctext: T,
) -> Result<Vec<u8>> {
    let passphrase = passphrase.to_string();
    tokio::task::spawn_blocking(move || {
        let (enc_msg, _) = Message::from_armor(ctext)?;
        let password = Password::from(passphrase);

        let msg = enc_msg.decrypt_with_password(&password)?;
        let res = msg.decompress()?.as_data_vec()?;
        Ok(res)
    })
    .await?
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;
    use tokio::sync::OnceCell;

    use super::*;
    use crate::{
        key::{load_self_public_key, load_self_secret_key},
        test_utils::{TestContextManager, alice_keypair, bob_keypair},
    };
    use pgp::composed::Esk;
    use pgp::packet::PublicKeyEncryptedSessionKey;

    #[expect(clippy::type_complexity)]
    fn pk_decrypt_and_validate<'a>(
        ctext: &'a [u8],
        private_keys_for_decryption: &'a [SignedSecretKey],
        public_keys_for_validation: &[SignedPublicKey],
    ) -> Result<(
        pgp::composed::Message<'static>,
        HashMap<Fingerprint, Vec<Fingerprint>>,
        Vec<u8>,
    )> {
        let mut msg = decrypt(ctext.to_vec(), private_keys_for_decryption, &[])?;
        let content = msg.as_data_vec()?;
        let ret_signature_fingerprints =
            valid_signature_fingerprints(&msg, public_keys_for_validation);

        Ok((msg, ret_signature_fingerprints, content))
    }

    #[test]
    fn test_split_armored_data_1() {
        let (typ, _headers, base64) = split_armored_data(
            b"-----BEGIN PGP MESSAGE-----\nNoVal:\n\naGVsbG8gd29ybGQ=\n-----END PGP MESSAGE-----",
        )
        .unwrap();

        assert_eq!(typ, BlockType::Message);
        assert!(!base64.is_empty());
        assert_eq!(
            std::string::String::from_utf8(base64).unwrap(),
            "hello world"
        );
    }

    #[test]
    fn test_split_armored_data_2() {
        let (typ, headers, base64) = split_armored_data(
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nAutocrypt-Prefer-Encrypt: mutual \n\naGVsbG8gd29ybGQ=\n-----END PGP PRIVATE KEY BLOCK-----"
        )
            .unwrap();

        assert_eq!(typ, BlockType::PrivateKey);
        assert!(!base64.is_empty());
        assert_eq!(headers.get(HEADER_AUTOCRYPT), Some(&"mutual".to_string()));
    }

    #[test]
    fn test_create_keypair() {
        let keypair0 = create_keypair(EmailAddress::new("foo@bar.de").unwrap()).unwrap();
        let keypair1 = create_keypair(EmailAddress::new("two@zwo.de").unwrap()).unwrap();
        assert_ne!(keypair0.public, keypair1.public);
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
                alice_secret: alice.secret.clone(),
                alice_public: alice.public,
                bob_secret: bob.secret.clone(),
                bob_public: bob.public,
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
        let anonymous_recipients = true;
        CTEXT_SIGNED
            .get_or_init(|| async {
                let keyring = vec![KEYS.alice_public.clone(), KEYS.bob_public.clone()];
                let compress = true;

                pk_encrypt(
                    CLEARTEXT.to_vec(),
                    keyring,
                    KEYS.alice_secret.clone(),
                    compress,
                    anonymous_recipients,
                    SeipdVersion::V2,
                )
                .await
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
            pk_decrypt_and_validate(ctext_signed().await.as_bytes(), &keyring, &[]).unwrap();
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
        .unwrap();
        assert_eq!(content, CLEARTEXT);
        assert_eq!(valid_signatures.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decrypt_unsigned() {
        let decrypt_keyring = vec![KEYS.bob_secret.clone()];
        let ctext_unsigned = include_bytes!("../test-data/message/ctext_unsigned.asc");
        let (_msg, valid_signatures, content) =
            pk_decrypt_and_validate(ctext_unsigned, &decrypt_keyring, &[]).unwrap();
        assert_eq!(content, CLEARTEXT);
        assert_eq!(valid_signatures.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_encrypt_decrypt_broadcast() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;

        let plain = Vec::from(b"this is the secret message");
        let shared_secret = "shared secret";
        let ctext = symm_encrypt_message(
            plain.clone(),
            load_self_secret_key(alice).await?,
            shared_secret,
            true,
        )
        .await?;

        let bob_private_keyring = crate::key::load_self_secret_keyring(bob).await?;
        let mut decrypted = decrypt(
            ctext.into(),
            &bob_private_keyring,
            &[shared_secret.to_string()],
        )?;

        assert_eq!(decrypted.as_data_vec()?, plain);

        Ok(())
    }

    /// Test that we don't try to decrypt a message
    /// that is symmetrically encrypted
    /// with an expensive string2key algorithm
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dont_decrypt_expensive_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bob = &tcm.bob().await;

        let plain = Vec::from(b"this is the secret message");
        let shared_secret = "shared secret";

        // Create a symmetrically encrypted message
        // with an IteratedAndSalted string2key algorithm:

        let shared_secret_pw = Password::from(shared_secret.to_string());
        let msg = MessageBuilder::from_bytes("", plain);
        let mut rng = thread_rng();
        let s2k = StringToKey::new_default(&mut rng); // Default is IteratedAndSalted

        let mut msg = msg.seipd_v2(
            &mut rng,
            SymmetricKeyAlgorithm::AES128,
            AeadAlgorithm::Ocb,
            ChunkSize::C8KiB,
        );
        msg.encrypt_with_password(&mut rng, s2k, &shared_secret_pw)?;

        let ctext = msg.to_armored_string(&mut rng, Default::default())?;

        // Trying to decrypt it should fail with a helpful error message:

        let bob_private_keyring = crate::key::load_self_secret_keyring(bob).await?;
        let error = decrypt(
            ctext.into(),
            &bob_private_keyring,
            &[shared_secret.to_string()],
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "missing key (Note: symmetric decryption was not tried: unsupported string2key algorithm)"
        );

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
        let ctext = pk_encrypt(
            plain,
            vec![pk_for_encryption],
            KEYS.alice_secret.clone(),
            true,
            true,
            SeipdVersion::V2,
        )
        .await?;

        // Trying to decrypt it should fail with an OK error message:
        let bob_private_keyring = crate::key::load_self_secret_keyring(bob).await?;
        let error = decrypt(ctext.into(), &bob_private_keyring, &[]).unwrap_err();

        assert_eq!(
            error.to_string(),
            "missing key (Note: symmetric decryption was not tried: not symmetrically encrypted)"
        );

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
}
