//! Autocrypt2 implementation.
use anyhow::Context as _;
use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use anyhow::format_err;
use hkdf::Hkdf;
use pgp::composed::SignedKeyDetails;
use pgp::composed::SignedSecretKey;
use pgp::composed::SignedSecretSubKey;
use pgp::crypto::aead::AeadAlgorithm;
use pgp::crypto::ed25519;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::ml_kem768_x25519;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::Features;
use pgp::packet::KeyFlags;
use pgp::packet::PacketTrait as _;
use pgp::packet::PubKeyInner;
use pgp::packet::PublicKey;
use pgp::packet::PublicSubkey;
use pgp::packet::SecretKey;
use pgp::packet::SecretSubkey;
use pgp::packet::SignatureConfig;
use pgp::packet::SignatureType;
use pgp::packet::Subpacket;
use pgp::packet::SubpacketData;
use pgp::ser::Serialize as _;
use pgp::types::Duration as PgpDuration;
use pgp::types::Ed25519PublicParams;
use pgp::types::KeyDetails;
use pgp::types::KeyVersion;
use pgp::types::MlKem768X25519PublicParams;
use pgp::types::Password;
use pgp::types::PlainSecretParams;
use pgp::types::PublicParams;
use pgp::types::SecretParams;
use pgp::types::Timestamp;
use rand_old::thread_rng;
use sha2::Digest;
use sha2::Sha512;

/// Creates an Autocrypt 2 TSK.
///
/// <https://datatracker.ietf.org/doc/draft-autocrypt-openpgp-v2-cert/>
pub(crate) fn create_autocrypt2_keypair(now: Timestamp) -> Result<SignedSecretKey> {
    let mut rng = thread_rng();

    // Fake zero timestamp for primary key and fallback key creation.
    // We do not want to leak the key creation date to contacts.
    // This is not to be used for rotating subkey timestamps.
    let zero_timestamp = Timestamp::from_secs(0);

    let public_key_algorithm = PublicKeyAlgorithm::Ed25519;

    let primary_key_packet = {
        let ed25519_secret = ed25519::SecretKey::generate(&mut rng, ed25519::Mode::Ed25519);
        let public_params = PublicParams::Ed25519(Ed25519PublicParams::from(&ed25519_secret));
        let secret_params = SecretParams::Plain(PlainSecretParams::Ed25519(ed25519_secret));

        let pubkey_inner = PubKeyInner::new(
            KeyVersion::V6,
            public_key_algorithm,
            zero_timestamp,
            None,
            public_params,
        )?;
        let pubkey = PublicKey::from_inner(pubkey_inner)?;
        SecretKey::new(pubkey, secret_params)?
    };

    let details = {
        let mut signature_config =
            SignatureConfig::from_key(&mut rng, &primary_key_packet, SignatureType::Key)?;
        let mut keyflags = KeyFlags::default();
        keyflags.set_certify(true);
        keyflags.set_sign(true);

        let mut features = Features::default();
        features.set_seipd_v1(true);
        features.set_seipd_v2(true);

        signature_config.hashed_subpackets = vec![
            Subpacket::critical(SubpacketData::SignatureCreationTime(now))?,
            Subpacket::regular(SubpacketData::KeyFlags(keyflags))?,
            Subpacket::regular(SubpacketData::Features(features))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                primary_key_packet.fingerprint(),
            ))?,
            Subpacket::regular(SubpacketData::PreferredAeadAlgorithms(smallvec![(
                SymmetricKeyAlgorithm::AES256,
                AeadAlgorithm::Ocb
            )]))?,
        ];

        let signature = signature_config.sign_key(
            &primary_key_packet,
            &Password::empty(),
            &primary_key_packet.public_key(),
        )?;

        SignedKeyDetails {
            revocation_signatures: vec![],
            direct_signatures: vec![signature],
            users: vec![],
            user_attributes: vec![],
        }
    };

    let fallback_subkey_packet = {
        let ml_kem_secret = ml_kem768_x25519::SecretKey::generate(&mut rng);
        let public_params =
            PublicParams::MlKem768X25519(MlKem768X25519PublicParams::from(&ml_kem_secret));
        let secret_params = SecretParams::Plain(PlainSecretParams::MlKem768X25519(ml_kem_secret));

        let pubkey_inner = PubKeyInner::new(
            KeyVersion::V6,
            PublicKeyAlgorithm::MlKem768X25519,
            zero_timestamp,
            None,
            public_params,
        )?;
        let public_subkey = PublicSubkey::from_inner(pubkey_inner)?;
        SecretSubkey::new(public_subkey, secret_params)?
    };

    let signed_fallback_subkey = {
        let mut keyflags = KeyFlags::default();
        keyflags.set_encrypt_storage(true);
        keyflags.set_encrypt_comms(true);

        let mut signature_config = SignatureConfig::v6(
            &mut rng,
            SignatureType::SubkeyBinding,
            public_key_algorithm,
            HashAlgorithm::Sha256,
        )?;
        signature_config.hashed_subpackets = vec![
            Subpacket::critical(SubpacketData::SignatureCreationTime(zero_timestamp))?,
            Subpacket::critical(SubpacketData::KeyFlags(keyflags))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                primary_key_packet.fingerprint(),
            ))?,
        ];
        let signature = signature_config.sign_subkey_binding(
            &primary_key_packet,
            primary_key_packet.public_key(),
            &Password::empty(),
            fallback_subkey_packet.public_key(),
        )?;
        SignedSecretSubKey {
            key: fallback_subkey_packet,
            signatures: vec![signature],
        }
    };

    let rotating_subkey_packet = {
        let ml_kem_secret = ml_kem768_x25519::SecretKey::generate(&mut rng);
        let public_params =
            PublicParams::MlKem768X25519(MlKem768X25519PublicParams::from(&ml_kem_secret));
        let secret_params = SecretParams::Plain(PlainSecretParams::MlKem768X25519(ml_kem_secret));

        let mut keyflags = KeyFlags::default();
        keyflags.set_encrypt_comms(true);

        let pubkey_inner = PubKeyInner::new(
            KeyVersion::V6,
            PublicKeyAlgorithm::MlKem768X25519,
            now,
            None,
            public_params,
        )?;
        let public_subkey = PublicSubkey::from_inner(pubkey_inner)?;
        SecretSubkey::new(public_subkey, secret_params)?
    };

    let signed_rotating_subkey = {
        let mut keyflags = KeyFlags::default();
        keyflags.set_encrypt_comms(true);

        let mut signature_config = SignatureConfig::v6(
            &mut rng,
            SignatureType::SubkeyBinding,
            public_key_algorithm,
            HashAlgorithm::Sha256,
        )?;

        // Expiration duration is 10 days according to
        // <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-02.html#section-2.2-2.6.2.2.1>
        let expiration_duration = PgpDuration::from_secs(864000);
        signature_config.hashed_subpackets = vec![
            Subpacket::critical(SubpacketData::SignatureCreationTime(now))?,
            Subpacket::critical(SubpacketData::KeyFlags(keyflags))?,
            // XXX: marking expiration as critical
            // even though reference implementation does not:
            // <https://codeberg.org/autocrypt2/autocrypt-v2-cert/issues/53>
            Subpacket::critical(SubpacketData::KeyExpirationTime(expiration_duration))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                primary_key_packet.fingerprint(),
            ))?,
        ];
        let signature = signature_config.sign_subkey_binding(
            &primary_key_packet,
            primary_key_packet.public_key(),
            &Password::empty(),
            rotating_subkey_packet.public_key(),
        )?;
        SignedSecretSubKey {
            key: rotating_subkey_packet,
            signatures: vec![signature],
        }
    };

    let secret_key = SignedSecretKey {
        primary_key: primary_key_packet,
        details,
        public_subkeys: Vec::new(),
        secret_subkeys: vec![signed_fallback_subkey, signed_rotating_subkey],
    };

    secret_key
        .verify_bindings()
        .context("Invalid Autocrypt2 key generated")?;

    Ok(secret_key)
}

/// Returns true if TSK is an Autocrypt 2 TSK.
///
/// <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-02.html#name-identification-by-tsk-struc>
fn is_autocrypt2_tsk(tsk: &SignedSecretKey) -> bool {
    if tsk.primary_key.version() != KeyVersion::V6
        || tsk.primary_key.algorithm() != PublicKeyAlgorithm::Ed25519
    {
        return false;
    }

    // Direct key signature.
    let [direct_key_signature] = &tsk.details.direct_signatures[..] else {
        return false;
    };

    let Some(features) = direct_key_signature.features() else {
        return false;
    };
    // SEIPDv2 feature is required according to
    // <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-02.html#section-2.2-2.2.2.4.1>
    if !features.seipd_v2() {
        return false;
    }

    // Primary key must have certification (0x01) and signing (0x02) flags.
    let dks_key_flags = direct_key_signature.key_flags();
    if !dks_key_flags.certify() || !dks_key_flags.sign() {
        return false;
    }

    // No expiration:
    // <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-02.html#section-2.2-2.2.2.6.1>
    // No key expiration (<https://www.rfc-editor.org/rfc/rfc9580.html#name-key-expiration-time>)
    // and no signature expiration (<https://docs.rs/pgp/latest/pgp/packet/struct.Signature.html#method.signature_expiration_time>).
    //
    // XXX: spec should say explicitly that both key expiration and signature expiration should not be there
    if direct_key_signature
        .key_expiration_time()
        .is_some_and(|duration| duration.as_secs() != 0)
        || direct_key_signature
            .signature_expiration_time()
            .is_some_and(|duration| duration.as_secs() != 0)
    {
        return false;
    }

    if !(tsk.details.revocation_signatures.is_empty()
        && tsk.details.users.is_empty()
        && tsk.details.user_attributes.is_empty())
    {
        return false;
    }

    if !tsk.public_subkeys.is_empty() {
        return false;
    }

    // TODO: check all rotating subkeys
    // Subkeys may overlap, as long as subkey is not expired, it does not need to be deleted.
    let [ref fallback_subkey, .., ref rotating_subkey] = tsk.secret_subkeys[..] else {
        return false;
    };

    let [ref fallback_subkey_signature] = fallback_subkey.signatures[..] else {
        return false;
    };
    let fallback_subkey_flags = fallback_subkey_signature.key_flags();
    if !fallback_subkey_flags.encrypt_comms() || !fallback_subkey_flags.encrypt_storage() {
        return false;
    }

    if fallback_subkey_signature
        .key_expiration_time()
        .is_some_and(|duration| duration.as_secs() != 0)
    {
        return false;
    }

    let [ref rotating_subkey_signature] = rotating_subkey.signatures[..] else {
        return false;
    };
    let rotating_subkey_flags = rotating_subkey_signature.key_flags();
    // Rotating subkey can be used to encrypt communications, but not storage:
    // <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-02.html#section-2.2-2.6.2.3.1>
    if !rotating_subkey_flags.encrypt_comms() || rotating_subkey_flags.encrypt_storage() {
        return false;
    }

    if rotating_subkey_signature
        .key_expiration_time()
        .is_none_or(|duration| duration.as_secs() == 0)
    {
        return false;
    }

    true
}

fn normalize_x25519_scalar(m: &mut [u8]) {
    // From decodeScalar25519 in <https://www.rfc-editor.org/info/rfc7748/#section-5>
    m[0] &= 248;
    m[31] &= 127;
    m[31] |= 64;
}

/// Generates new rotating subkey from a previous one.
///
/// <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-02.html#section-4.1.1>
fn ratchet(mut tsk: SignedSecretKey) -> Result<SignedSecretKey> {
    // Extract the last rotating subkey.
    // Other rotating subkeys do not matter.
    // This corresponds to
    // <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-02.html#section-4.1.1-6.2.1>
    let [ref _fallback_subkey, .., ref rotating_subkey] = tsk.secret_subkeys[..] else {
        bail!("Cannot extract last rotating subkey");
    };
    let [ref rotating_subkey_signature] = rotating_subkey.signatures[..] else {
        bail!("Rotating subkey must have exactly one signature");
    };
    let rotating_subkey_flags = rotating_subkey_signature.key_flags();
    // We do not search for the latest-expiring subkey
    // with the ability to encrypt communications.
    // It must be the last one by convention.
    // TODO: write TSK structure explicitly in the specification.
    let max_rd: u32 = rotating_subkey_signature
        .key_expiration_time()
        .context("Last subkey is not expiring")?
        .as_secs();
    let min_rd: u32 = max_rd / 2;
    ensure!(
        rotating_subkey_flags.encrypt_comms(),
        "Last rotating subkey cannot be used to encrypt communications"
    );

    let start: u32 = rotating_subkey
        .created_at()
        .as_secs()
        .checked_add(min_rd)
        .context("Overflow while adding min_rd")?;
    let mut salt = Vec::from(start.to_be_bytes());
    rotating_subkey
        .public_key()
        .to_writer_with_header(&mut salt)
        .context("Failed to serialize rotating subkey")?;
    debug_assert_eq!(
        salt.len(),
        4 + rotating_subkey.public_key().write_len_with_header()
    );

    let SecretParams::Plain(PlainSecretParams::MlKem768X25519(old_ml_kem768_x25519_secret_key)) =
        rotating_subkey.secret_params()
    else {
        bail!("Cannot extract ML-KEM-768 + X25519 secret key");
    };
    let mut ikm = Vec::with_capacity(old_ml_kem768_x25519_secret_key.write_len());
    old_ml_kem768_x25519_secret_key
        .to_writer(&mut ikm)
        .context("Failed to serialize IKM")?;

    // <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-02.html#section-4.1.1-6.6.1>
    normalize_x25519_scalar(&mut ikm);
    debug_assert_eq!(ikm.len(), 96);

    let info = {
        let mut info = b"Autocrypt_v2_ratchet".to_vec();
        tsk.primary_key
            .public_key()
            .to_writer_with_header(&mut info)
            .context("Failed to serialize primary key")?;
        info.extend_from_slice(&max_rd.to_be_bytes());
        info
    };

    let hkdf = Hkdf::<Sha512>::new(Some(&salt), &ikm);
    let mut ks = [0u8; 160];
    hkdf.expand(&info, &mut ks)
        .map_err(|_err: hkdf::InvalidLength| {
            format_err!("HKDF-Expand failed because of invalid output length")
        })?;

    let new_ml_kem768_x25519_secret_key = {
        let mut new_x25519 = [0u8; 32];
        let mut new_ml_kem = [0u8; 64];
        new_x25519.copy_from_slice(&ks[64..96]);
        new_ml_kem.copy_from_slice(&ks[96..160]);
        normalize_x25519_scalar(&mut new_x25519[..]);

        ml_kem768_x25519::SecretKey::try_from_bytes(new_x25519, new_ml_kem)?
    };
    let new_rotating_subkey = {
        let public_params = PublicParams::MlKem768X25519(MlKem768X25519PublicParams::from(
            &new_ml_kem768_x25519_secret_key,
        ));
        let secret_params = SecretParams::Plain(PlainSecretParams::MlKem768X25519(
            new_ml_kem768_x25519_secret_key,
        ));

        let pubkey_inner = PubKeyInner::new(
            KeyVersion::V6,
            PublicKeyAlgorithm::MlKem768X25519,
            Timestamp::from_secs(start),
            None,
            public_params,
        )?;
        let public_subkey = PublicSubkey::from_inner(pubkey_inner)?;
        SecretSubkey::new(public_subkey, secret_params)?
    };

    let new_signed_rotating_subkey = {
        let mut keyflags = KeyFlags::default();
        keyflags.set_encrypt_comms(true);

        let digest = Sha512::digest(&ks[0..64]);
        let bssalt = digest[0..16].to_vec();

        let mut signature_config = SignatureConfig::v6_with_salt(
            SignatureType::SubkeyBinding,
            tsk.primary_key.algorithm(),
            HashAlgorithm::Sha256,
            bssalt,
        );

        // FIXME
        let expiration_duration = PgpDuration::from_secs(864000);
        signature_config.hashed_subpackets = vec![
            Subpacket::critical(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                start,
            )))?,
            Subpacket::critical(SubpacketData::KeyFlags(keyflags))?,
            // XXX: marking expiration as critical
            // even though reference implementation does not:
            // <https://codeberg.org/autocrypt2/autocrypt-v2-cert/issues/53>
            Subpacket::critical(SubpacketData::KeyExpirationTime(expiration_duration))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                tsk.primary_key.public_key().fingerprint(),
            ))?,
        ];
        let signature = signature_config.sign_subkey_binding(
            &tsk.primary_key,
            tsk.primary_key.public_key(),
            &Password::empty(),
            new_rotating_subkey.public_key(),
        )?;
        SignedSecretSubKey {
            key: new_rotating_subkey,
            signatures: vec![signature],
        }
    };

    tsk.secret_subkeys.push(new_signed_rotating_subkey);
    Ok(tsk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key;
    use crate::pgp::DcKey;
    use crate::test_utils;

    /// Tests creating Autocrypt 2 TSK and detecting it.
    #[test]
    fn test_create_autocrypt2_keypair() {
        let now = Timestamp::now();
        let keypair = create_autocrypt2_keypair(now).unwrap();
        assert!(is_autocrypt2_tsk(&keypair));

        // Test that Autocrypt 2 TSK can be serialized and deserialized.
        let secret_key_bytes = DcKey::to_bytes(&keypair);
        let signed_secret_key = SignedSecretKey::from_slice(&secret_key_bytes)
            .expect("Cannot deserialize Autocrypt2 TSK");

        assert!(is_autocrypt2_tsk(&signed_secret_key));
    }

    /// Tests that the key does not leak creation timestamp.
    #[test]
    fn test_tsk_timestamps() {
        let now = Timestamp::now();
        let tsk = create_autocrypt2_keypair(now).unwrap();

        // Primary key creation timestamp is zero.
        assert_eq!(tsk.primary_key.created_at().as_secs(), 0);

        // Primary key direct key signature timestamp is zero.
        let [ref direct_signature] = tsk.details.direct_signatures[..] else {
            panic!("Autocrypt 2 TSK must have exactly one direct key signature");
        };

        // Direct key signature is a real key creation timestamp
        // and should not be zero.
        // <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-02.html#section-2.2-2.2.2.1.1>
        // This timestamp from TSK should not leak into the public key however
        // as we recreate the signature every time relay list is changed:
        let created_timestamp = direct_signature.created().unwrap();
        assert_ne!(created_timestamp.as_secs(), 0);

        let fallback_subkey = tsk
            .secret_subkeys
            .first()
            .expect("Fallback subkey not found");

        // Fallback subkey creation timestamp should be zero.
        // We will not be able to change this timestamp and it should not leak
        // the profile creation timestamp.
        assert_eq!(fallback_subkey.key.created_at().as_secs(), 0);

        // Fallback subkey binding signature timestamp must match
        // the direct key signature timestamp.
        // TODO: it should be recreated each time Direct Key Signature is recreated.
        let [ref fallback_subkey_signature] = fallback_subkey.signatures[..] else {
            panic!("Fallback subkey does not have exactly one binding signature");
        };
    }

    /// Tests that Autocrypt 2 TSK detection is not triggered for existing non-AC2 test keys.
    #[test]
    fn test_is_autocrypt2_tsk_no_false_positives() {
        assert!(!is_autocrypt2_tsk(&test_utils::alice_keypair()));
        assert!(!is_autocrypt2_tsk(&test_utils::bob_keypair()));
        assert!(!is_autocrypt2_tsk(&test_utils::charlie_keypair()));
        assert!(!is_autocrypt2_tsk(&test_utils::dom_keypair()));
        assert!(!is_autocrypt2_tsk(&test_utils::elena_keypair()));
        assert!(!is_autocrypt2_tsk(&test_utils::pqc_keypair()));
    }

    #[test]
    fn test_ratchet() {
        let now = Timestamp::now();
        let tsk = create_autocrypt2_keypair(now).unwrap();
        assert!(is_autocrypt2_tsk(&tsk));

        let new_tsk = ratchet(tsk).expect("Ratchet failed");
        assert!(is_autocrypt2_tsk(&new_tsk));
    }

    #[test]
    fn test_autocrypt2_key_selection() {
        let now = Timestamp::now();
        let tsk = create_autocrypt2_keypair(now).unwrap();

        let public_key = key::secret_key_to_public_key(
            tsk.clone(),
            now.as_secs(),
            "alice@example.org",
            "alice@example.org",
        )
        .expect("Failed to convert secret key to public key");

        // For Autocrypt 2 certificate rotating key should be selected for encryption.
        let pk_for_encryption =
            crate::pgp::select_pk_for_encryption(now.as_secs(), &public_key).unwrap();
        let [ref pk_for_encryption_signature] = pk_for_encryption.signatures[..] else {
            panic!("Selected public key has multiple signatures");
        };
        let key_flags = pk_for_encryption_signature.key_flags();
        assert!(key_flags.encrypt_comms());
        assert!(!key_flags.encrypt_storage());
    }
}
