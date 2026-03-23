//! OpenPGP helper module using [rPGP facilities](https://github.com/rpgp/rpgp).

use std::collections::{HashMap, HashSet};
use std::io::Cursor;

use anyhow::{Context as _, Result, ensure};
use deltachat_contact_tools::{EmailAddress, may_be_valid_addr};
use pgp::composed::{
    ArmorOptions, Deserializable, DetachedSignature, EncryptionCaps, KeyType as PgpKeyType,
    MessageBuilder, SecretKeyParamsBuilder, SignedKeyDetails, SignedPublicKey, SignedPublicSubKey,
    SignedSecretKey, SubkeyParamsBuilder, SubpacketConfig,
};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{
    CompressionAlgorithm, Imprint, KeyDetails, KeyVersion, Password, SignedUser, SigningKey as _,
    StringToKey,
};
use rand_old::{Rng as _, thread_rng};
use sha2::Sha256;
use tokio::runtime::Handle;

use crate::key::{DcKey, Fingerprint};

/// Preferred symmetric encryption algorithm.
const SYMMETRIC_KEY_ALGORITHM: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES128;

/// Create a new key pair.
///
/// Both secret and public key consist of signing primary key and encryption subkey
/// as [described in the Autocrypt standard](https://autocrypt.org/level1.html#openpgp-based-key-data).
pub(crate) fn create_keypair(addr: EmailAddress) -> Result<SignedSecretKey> {
    let signing_key_type = PgpKeyType::Ed25519Legacy;
    let encryption_key_type = PgpKeyType::ECDH(ECCCurve::Curve25519);

    let user_id = format!("<{addr}>");
    let key_params = SecretKeyParamsBuilder::default()
        .key_type(signing_key_type)
        .can_certify(true)
        .can_sign(true)
        .feature_seipd_v2(true)
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

    Ok(secret_key)
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
                for key in &public_keys_for_encryption {
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
                        msg.encrypt_to_key_anonymous(&mut rng, &pkey)?;
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
                        msg.encrypt_to_key_anonymous(&mut rng, &pkey)?;
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

/// Symmetrically encrypt the message.
/// This is used for broadcast channels and for version 2 of the Securejoin protocol.
/// `shared secret` is the secret that will be used for symmetric encryption.
pub async fn symm_encrypt_message(
    plain: Vec<u8>,
    private_key_for_signing: Option<SignedSecretKey>,
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

        if let Some(private_key_for_signing) = private_key_for_signing.as_deref() {
            let hash_algorithm = private_key_for_signing.hash_alg();
            msg.sign(private_key_for_signing, Password::empty(), hash_algorithm);
        }
        if compress {
            msg.compression(CompressionAlgorithm::ZLIB);
        }

        let encoded_msg = msg.to_armored_string(&mut rng, Default::default())?;

        Ok(encoded_msg)
    })
    .await?
}

/// Merges and minimizes OpenPGP certificates.
///
/// Keeps at most one direct key signature and
/// at most one User ID with exactly one signature.
///
/// See <https://openpgp.dev/book/adv/certificates.html#merging>
/// and <https://openpgp.dev/book/adv/certificates.html#certificate-minimization>.
///
/// `new_certificate` does not necessarily contain newer data.
/// It may come not directly from the key owner,
/// e.g. via protected Autocrypt header or protected attachment
/// in a signed message, but from Autocrypt-Gossip header or a vCard.
/// Gossiped key may be older than the one we have
/// or even have some packets maliciously dropped
/// (for example, all encryption subkeys dropped)
/// or restored from some older version of the certificate.
pub fn merge_openpgp_certificates(
    old_certificate: SignedPublicKey,
    new_certificate: SignedPublicKey,
) -> Result<SignedPublicKey> {
    old_certificate
        .verify_bindings()
        .context("First key cannot be verified")?;
    new_certificate
        .verify_bindings()
        .context("Second key cannot be verified")?;

    // Decompose certificates.
    let SignedPublicKey {
        primary_key: old_primary_key,
        details: old_details,
        public_subkeys: old_public_subkeys,
    } = old_certificate;
    let SignedPublicKey {
        primary_key: new_primary_key,
        details: new_details,
        public_subkeys: _new_public_subkeys,
    } = new_certificate;

    // Public keys may be serialized differently, e.g. using old and new packet type,
    // so we compare imprints instead of comparing the keys
    // directly with `old_primary_key == new_primary_key`.
    // Imprints, like fingerprints, are calculated over normalized packets.
    // On error we print fingerprints as this is what is used in the database
    // and what most tools show.
    let old_imprint = old_primary_key.imprint::<Sha256>()?;
    let new_imprint = new_primary_key.imprint::<Sha256>()?;
    ensure!(
        old_imprint == new_imprint,
        "Cannot merge certificates with different primary keys {} and {}",
        old_primary_key.fingerprint(),
        new_primary_key.fingerprint()
    );

    // Decompose old and the new key details.
    //
    // Revocation signatures are currently ignored so we do not store them.
    //
    // User attributes are thrown away on purpose,
    // the only defined in RFC 9580 attribute is the Image Attribute
    // (<https://www.rfc-editor.org/rfc/rfc9580.html#section-5.12.1>
    // which we do not use and do not want to gossip.
    let SignedKeyDetails {
        revocation_signatures: _old_revocation_signatures,
        direct_signatures: old_direct_signatures,
        users: old_users,
        user_attributes: _old_user_attributes,
    } = old_details;
    let SignedKeyDetails {
        revocation_signatures: _new_revocation_signatures,
        direct_signatures: new_direct_signatures,
        users: new_users,
        user_attributes: _new_user_attributes,
    } = new_details;

    // Select at most one direct key signature, the newest one.
    let best_direct_key_signature: Option<Signature> = old_direct_signatures
        .into_iter()
        .chain(new_direct_signatures)
        .filter(|x: &Signature| x.verify_key(&old_primary_key).is_ok())
        .max_by_key(|x: &Signature|
            // Converting to seconds because `Ord` is not derived for `Timestamp`:
            // <https://github.com/rpgp/rpgp/issues/737>
            x.created().map_or(0, |ts| ts.as_secs()));
    let direct_signatures: Vec<Signature> = best_direct_key_signature.into_iter().collect();

    // Select at most one User ID.
    //
    // We prefer User IDs marked as primary,
    // but will select non-primary otherwise
    // because sometimes keys have no primary User ID,
    // such as Alice's key in `test-data/key/alice-secret.asc`.
    let best_user: Option<SignedUser> = old_users
        .into_iter()
        .chain(new_users.clone())
        .filter_map(|SignedUser { id, signatures }| {
            // Select the best signature for each User ID.
            // If User ID has no valid signatures, it is filtered out.
            let best_user_signature: Option<Signature> = signatures
                .into_iter()
                .filter(|signature: &Signature| {
                    signature
                        .verify_certification(&old_primary_key, pgp::types::Tag::UserId, &id)
                        .is_ok()
                })
                .max_by_key(|signature: &Signature| {
                    signature.created().map_or(0, |ts| ts.as_secs())
                });
            best_user_signature.map(|signature| (id, signature))
        })
        .max_by_key(|(_id, signature)| signature.created().map_or(0, |ts| ts.as_secs()))
        .map(|(id, signature)| SignedUser {
            id,
            signatures: vec![signature],
        });
    let users: Vec<SignedUser> = best_user.into_iter().collect();

    let public_subkeys = old_public_subkeys;

    Ok(SignedPublicKey {
        primary_key: old_primary_key,
        details: SignedKeyDetails {
            revocation_signatures: vec![],
            direct_signatures,
            users,
            user_attributes: vec![],
        },
        public_subkeys,
    })
}

/// Returns relays addresses from the public key signature.
///
/// Not more than 3 relays are returned for each key.
pub(crate) fn addresses_from_public_key(public_key: &SignedPublicKey) -> Option<Vec<String>> {
    for signature in &public_key.details.direct_signatures {
        // The signature should be verified already when importing the key,
        // but we double-check here.
        let signature_is_valid = signature.verify_key(&public_key.primary_key).is_ok();
        debug_assert!(signature_is_valid);
        if signature_is_valid {
            for notation in signature.notations() {
                if notation.name == "relays@chatmail.at"
                    && let Ok(value) = str::from_utf8(&notation.value)
                {
                    return Some(
                        value
                            .split(",")
                            .map(|s| s.to_string())
                            .filter(|s| may_be_valid_addr(s))
                            .take(3)
                            .collect(),
                    );
                }
            }
        }
    }
    None
}

/// Returns true if public key advertises SEIPDv2 feature.
pub(crate) fn pubkey_supports_seipdv2(public_key: &SignedPublicKey) -> bool {
    // If any Direct Key Signature or any User ID signature has SEIPDv2 feature,
    // assume that recipient can handle SEIPDv2.
    //
    // Third-party User ID signatures are dropped during certificate merging.
    // We don't check if the User ID is primary User ID.
    // Primary User ID is preferred during merging
    // and if some key has only non-primary User ID
    // it is acceptable. It is anyway unlikely that SEIPDv2
    // is advertised in a key without DKS or primary User ID.
    public_key
        .details
        .direct_signatures
        .iter()
        .chain(
            public_key
                .details
                .users
                .iter()
                .flat_map(|user| user.signatures.iter()),
        )
        .any(|signature| {
            signature
                .features()
                .is_some_and(|features| features.seipd_v2())
        })
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;
    use tokio::sync::OnceCell;

    use super::*;
    use crate::{
        config::Config,
        decrypt,
        key::{load_self_public_key, self_fingerprint, store_self_keypair},
        mimefactory::{render_outer_message, wrap_encrypted_part},
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
        let rendered = render_outer_message(vec![], mime_message);
        let parsed = mailparse::parse_mail(rendered.as_bytes())?;
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
        let ret_signature_fingerprints =
            valid_signature_fingerprints(&msg, public_keys_for_validation);

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
        let ctext_unsigned = include_bytes!("../test-data/message/ctext_unsigned.asc");
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

        test_dont_decrypt_expensive_message_ex(s2k, false, None).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dont_decrypt_expensive_message_bad_s2k() -> Result<()> {
        let s2k = StringToKey::new_default(&mut thread_rng()); // Default is IteratedAndSalted

        test_dont_decrypt_expensive_message_ex(s2k, false, Some("unsupported string2key algorithm"))
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
        test_dont_decrypt_expensive_message_ex(s2k, true, Some("decrypt_with_keys: missing key"))
            .await
    }

    /// Test that we don't try to decrypt a message
    /// that is symmetrically encrypted
    /// with an expensive string2key algorithm
    /// or multiple shared secrets.
    /// This is to prevent possible DOS attacks on the app.
    async fn test_dont_decrypt_expensive_message_ex(
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
        )
        .await?;

        // Trying to decrypt it should fail with an OK error message:
        let bob_private_keyring = crate::key::load_self_secret_keyring(bob).await?;
        let error = decrypt_bytes(ctext.into(), &bob_private_keyring, &[])
            .await
            .unwrap_err();

        assert_eq!(format!("{error:#}"), "decrypt_with_keys: missing key");

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
}
