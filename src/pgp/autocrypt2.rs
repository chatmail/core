//! Autocrypt2 implementation.
use crate::key;
use crate::key::DcKey;
use crate::log::warn;
use crate::tools;
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
use pgp::types::Timestamp as PgpTimestamp;
use rand_old::thread_rng;
use sha2::{Digest as _, Sha512};
use std::ops::Deref;

use crate::config::Config;
use crate::context::Context;
use crate::ensure_and_debug_assert;
use crate::key::load_self_secret_key;

/// Well-known timestamp for primary key and fallback encryption subkey key as specified in
/// <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-03.html#name-fixed-creation-timestamp>
const WELL_KNOWN_TIMESTAMP: u32 = 1782863999;

/// Autocrypt2 TSK.
///
/// Must contain an OpenPGP TSK of Autocrypt 2 structure inside.
#[derive(Debug, PartialEq, Eq)]
pub struct Autocrypt2Tsk(SignedSecretKey);

impl Autocrypt2Tsk {
    /// Creates an Autocrypt 2 TSK.
    ///
    /// <https://datatracker.ietf.org/doc/draft-autocrypt-openpgp-v2-cert/>
    pub fn new(now: PgpTimestamp) -> Result<Self> {
        let mut rng = thread_rng();

        let well_known_timestamp = PgpTimestamp::from_secs(WELL_KNOWN_TIMESTAMP);

        let public_key_algorithm = PublicKeyAlgorithm::Ed25519;

        let primary_key_packet = {
            let ed25519_secret = ed25519::SecretKey::generate(&mut rng, ed25519::Mode::Ed25519);
            let public_params = PublicParams::Ed25519(Ed25519PublicParams::from(&ed25519_secret));
            let secret_params = SecretParams::Plain(PlainSecretParams::Ed25519(ed25519_secret));

            let pubkey_inner = PubKeyInner::new(
                KeyVersion::V6,
                public_key_algorithm,
                well_known_timestamp,
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
            features.set_seipd_v1(false);
            features.set_seipd_v2(true);

            signature_config.hashed_subpackets = vec![
                Subpacket::critical(SubpacketData::SignatureCreationTime(well_known_timestamp))?,
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
            let secret_params =
                SecretParams::Plain(PlainSecretParams::MlKem768X25519(ml_kem_secret));

            let pubkey_inner = PubKeyInner::new(
                KeyVersion::V6,
                PublicKeyAlgorithm::MlKem768X25519,
                well_known_timestamp,
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
                Subpacket::critical(SubpacketData::SignatureCreationTime(well_known_timestamp))?,
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
            let secret_params =
                SecretParams::Plain(PlainSecretParams::MlKem768X25519(ml_kem_secret));

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
                Subpacket::critical(SubpacketData::KeyExpirationTime(expiration_duration))?,
                Subpacket::critical(SubpacketData::KeyFlags(keyflags))?,
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
        ensure_and_debug_assert!(
            is_autocrypt2_tsk(&secret_key),
            "Must generate Autocrypt 2 TSK"
        );

        Ok(Self(secret_key))
    }

    /// Returns inner OpenPGP TSK.
    pub fn into_inner(self) -> SignedSecretKey {
        self.0
    }

    /// Generates new rotating subkey from a previous one.
    ///
    /// <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-02.html#section-4.1.1>
    ///
    /// Old rotating subkeys are not deleted by this function.
    fn maybe_ratchet(&mut self, now: PgpTimestamp) -> Result<Option<SignedSecretSubKey>> {
        // Extract the last rotating subkey.
        // Other rotating subkeys do not matter.
        // This corresponds to
        // <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-02.html#section-4.1.1-6.2.1>
        let [ref _fallback_subkey, .., ref rotating_subkey] = self.0.secret_subkeys[..] else {
            bail!("Cannot extract last rotating subkey");
        };
        ratchet_subkey(rotating_subkey, &self.0.primary_key, now)
    }

    /// Generate subkeys until the last subkey covers the current timestamp.
    ///
    /// This function must be called before trying to decrypt messages with this TSK,
    /// to make sure we don't fail to decrypt messages.
    pub(crate) fn ratchet_until(&mut self, now: PgpTimestamp) -> Result<()> {
        for _ in self.0.secret_subkeys.len()..100 {
            if let Some(subkey) = self.maybe_ratchet(now)? {
                self.0.secret_subkeys.push(subkey);
            } else {
                break;
            }
        }
        debug_assert!(is_autocrypt2_tsk(&self.0));
        Ok(())
    }

    /// Rotates subkey to exactly the `now` timestamp.
    ///
    /// This destroys all other subkeys and is meant to be used
    /// after importing a backup.
    pub(crate) fn ratchet_to(&mut self, now: PgpTimestamp) -> Result<()> {
        let [ref _fallback_subkey, ref mut rotating_subkey, ..] = self.0.secret_subkeys[..] else {
            bail!("Must have at least two subkeys");
        };
        while let Some(new_subkey) = ratchet_subkey(rotating_subkey, &self.0.primary_key, now)? {
            *rotating_subkey = new_subkey;
        }
        self.0.secret_subkeys.truncate(2);
        debug_assert!(is_autocrypt2_tsk(&self.0));
        Ok(())
    }

    /// Removes all but the first rotating subkeys.
    ///
    /// Newer rotating subkeys can always be derived again
    /// from the first rotating subkey.
    fn truncate(&mut self) {
        self.0.secret_subkeys.truncate(2);
        debug_assert!(is_autocrypt2_tsk(&self.0));
    }

    /// Destroys old secret key 10 days after expiration.
    ///
    /// <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-03.html#key-destruction-timing>
    ///
    /// Returns true if any subkey was deleted.
    fn maybe_destroy_old_subkey(&mut self, now: PgpTimestamp) -> bool {
        // Never remove the last rotating subkey.
        if self.0.secret_subkeys.len() < 3 {
            return false;
        }
        let Some(subkey) = self.0.secret_subkeys.get(1) else {
            return false;
        };
        let Some(signature) = subkey.signatures.first() else {
            return false;
        };
        let Some(expiration_time) = signature
            .key_expiration_time()
            .filter(|duration| duration.as_secs() > 0)
        else {
            return false;
        };
        if now.as_secs()
            <= subkey
                .created_at()
                .as_secs()
                .saturating_add(expiration_time.as_secs().saturating_add(10 * 24 * 3600))
        {
            return false;
        }
        self.0.secret_subkeys.remove(1);
        debug_assert!(is_autocrypt2_tsk(&self.0));
        true
    }
}

// We don't implement DerefMut so it is not possible
// to accidentally break Autocrypt 2 TSK structure.
impl Deref for Autocrypt2Tsk {
    type Target = SignedSecretKey;

    fn deref(&self) -> &SignedSecretKey {
        &self.0
    }
}

impl TryFrom<SignedSecretKey> for Autocrypt2Tsk {
    type Error = SignedSecretKey;

    fn try_from(tsk: SignedSecretKey) -> Result<Self, SignedSecretKey> {
        if is_autocrypt2_tsk(&tsk) {
            Ok(Self(tsk))
        } else {
            Err(tsk)
        }
    }
}

/// Returns true if TSK is an Autocrypt 2 TSK.
///
/// <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-03.html#name-identification-by-tsk-struc>
fn is_autocrypt2_tsk(tsk: &SignedSecretKey) -> bool {
    if tsk.verify_bindings().is_err() {
        return false;
    }

    if tsk.primary_key.version() != KeyVersion::V6
        || tsk.primary_key.algorithm() != PublicKeyAlgorithm::Ed25519
        || tsk.primary_key.created_at().as_secs() != WELL_KNOWN_TIMESTAMP
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

    // SEIPDv1 is not enabled in example Autocrypt 2 certificates.
    if features.seipd_v1() {
        return false;
    }

    // Primary key must have certification (0x01) and signing (0x02) flags.
    let dks_key_flags = direct_key_signature.key_flags();
    if !dks_key_flags.certify() || !dks_key_flags.sign() {
        return false;
    }

    // No expiration:
    // <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-03.html#section-2.3-2.2.2.6.1>
    // No key expiration (<https://www.rfc-editor.org/rfc/rfc9580.html#name-key-expiration-time>)
    // and no signature expiration (<https://docs.rs/pgp/latest/pgp/packet/struct.Signature.html#method.signature_expiration_time>).
    //
    // XXX <https://codeberg.org/autocrypt2/autocrypt-v2-cert/issues/64>
    if direct_key_signature
        .key_expiration_time()
        .is_some_and(|duration| duration.as_secs() > 0)
        || direct_key_signature
            .signature_expiration_time()
            .is_some_and(|duration| duration.as_secs() > 0)
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

    let Some((fallback_subkey, rotating_subkeys)) = tsk.secret_subkeys.split_first() else {
        return false;
    };

    if fallback_subkey.created_at().as_secs() != WELL_KNOWN_TIMESTAMP {
        return false;
    }

    if fallback_subkey.algorithm() != PublicKeyAlgorithm::MlKem768X25519 {
        return false;
    }

    let [ref fallback_subkey_signature] = fallback_subkey.signatures[..] else {
        return false;
    };
    let fallback_subkey_flags = fallback_subkey_signature.key_flags();
    if !fallback_subkey_flags.encrypt_comms() || !fallback_subkey_flags.encrypt_storage() {
        return false;
    }

    if fallback_subkey_signature
        .key_expiration_time()
        .is_some_and(|duration| duration.as_secs() > 0)
    {
        return false;
    }

    // There must be at least one rotating subkey.
    //
    // There is also a discussion about requiring two subkeys:
    // <https://codeberg.org/autocrypt2/autocrypt-v2-cert/issues/62>
    if rotating_subkeys.is_empty() {
        return false;
    }

    // Subkeys may overlap, as long as subkey is not expired, it does not need to be deleted.
    for rotating_subkey in rotating_subkeys {
        if rotating_subkey.algorithm() != PublicKeyAlgorithm::MlKem768X25519 {
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

        // We only support max_rd equal to 864000.
        // Other values are not tested, so better just use the key without rotation.
        if rotating_subkey_signature
            .key_expiration_time()
            .is_none_or(|duration| duration.as_secs() != 864000)
        {
            return false;
        }
    }

    true
}

fn normalize_x25519_scalar(m: &mut [u8]) -> Result<()> {
    // From decodeScalar25519 in <https://www.rfc-editor.org/info/rfc7748/#section-5>
    *m.get_mut(0).context("Indexing failed")? &= 248;
    *m.get_mut(31).context("Indexing failed")? &= 127;
    *m.get_mut(31).context("Indexing failed")? |= 64;
    Ok(())
}

fn ratchet_subkey(
    rotating_subkey: &SignedSecretSubKey,
    primary_key: &SecretKey,
    now: PgpTimestamp,
) -> Result<Option<SignedSecretSubKey>> {
    let [ref rotating_subkey_signature] = rotating_subkey.signatures[..] else {
        bail!("Rotating subkey must have exactly one signature");
    };
    let rotating_subkey_flags = rotating_subkey_signature.key_flags();
    // We do not search for the latest-expiring subkey
    // with the ability to encrypt communications.
    // It must be the last one by convention.
    let max_rd: u32 = rotating_subkey_signature
        .key_expiration_time()
        .filter(|duration| duration.as_secs() > 0)
        .context("Last subkey is not expiring")?
        .as_secs();
    debug_assert_eq!(max_rd, 864000);
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

    // If start == now, don't exit, i.e. generate a new key.
    // This is important mainly to avoid flaky tests
    // when the key is generated, exact number of days is added
    // and key rotation is tested.
    // It should not matter whether one more second has passed or not.
    if start > now.as_secs() {
        return Ok(None);
    }

    let mut salt = Vec::from(start.to_be_bytes());
    rotating_subkey
        .public_key()
        .to_writer_with_header(&mut salt)
        .context("Failed to serialize rotating subkey")?;
    debug_assert_eq!(
        Some(salt.len()),
        rotating_subkey
            .public_key()
            .write_len_with_header()
            .checked_add(4)
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
    normalize_x25519_scalar(&mut ikm)?;
    debug_assert_eq!(ikm.len(), 96);

    let info = {
        let mut info = b"Autocrypt_v2_ratchet".to_vec();
        primary_key
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
        normalize_x25519_scalar(&mut new_x25519[..])?;

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
            PgpTimestamp::from_secs(start),
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
        let bssalt = digest.get(0..16).context("SHA-512 is too short")?.to_vec();

        let mut signature_config = SignatureConfig::v6_with_salt(
            SignatureType::SubkeyBinding,
            primary_key.algorithm(),
            HashAlgorithm::Sha256,
            bssalt,
        );

        let expiration_duration = PgpDuration::from_secs(max_rd);
        signature_config.hashed_subpackets = vec![
            Subpacket::critical(SubpacketData::SignatureCreationTime(
                PgpTimestamp::from_secs(start),
            ))?,
            Subpacket::critical(SubpacketData::KeyExpirationTime(expiration_duration))?,
            Subpacket::critical(SubpacketData::KeyFlags(keyflags))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                primary_key.public_key().fingerprint(),
            ))?,
        ];
        let signature = signature_config.sign_subkey_binding(
            primary_key,
            primary_key.public_key(),
            &Password::empty(),
            new_rotating_subkey.public_key(),
        )?;
        SignedSecretSubKey {
            key: new_rotating_subkey,
            signatures: vec![signature],
        }
    };

    Ok(Some(new_signed_rotating_subkey))
}

/// Ratchet the key all the way to the current timestamp.
///
/// Unlike [housekeeping] this may skip many keys at once
/// as this function is meant for backups.
pub async fn ratchet_after_import(context: &Context, now: PgpTimestamp) -> Result<()> {
    if key::self_fingerprint_opt(context).await?.is_none() {
        // Unexpected that backup has no key,
        // but we don't need to do anything in this case.
        return Ok(());
    }

    let tsk = load_self_secret_key(context).await?;
    let Ok(mut autocrypt2_tsk) = Autocrypt2Tsk::try_from(tsk) else {
        // Legacy non-Autocrypt 2 key, do nothing.
        return Ok(());
    };

    autocrypt2_tsk.ratchet_to(now)?;

    save_autocrypt2_tsk(context, autocrypt2_tsk).await?;

    Ok(())
}

async fn save_autocrypt2_tsk(context: &Context, autocrypt2_tsk: Autocrypt2Tsk) -> Result<()> {
    // We must never store the TSK if due to a bug it becomes not recognizable as Autocrypt 2 TSK anymore.
    // TODO: maybe add a device message if this ever happens
    let signed_secret_key = autocrypt2_tsk.into_inner();
    ensure_and_debug_assert!(
        is_autocrypt2_tsk(&signed_secret_key),
        "Autocrypt 2 TSK became unrecognizable after housekeeping"
    );

    let signed_public_key = signed_secret_key.to_public_key();
    let public_key = DcKey::to_bytes(&signed_public_key);
    let secret_key = DcKey::to_bytes(&signed_secret_key);

    context
        .sql
        .execute(
            "UPDATE keypairs
             SET public_key=?, private_key=?
             WHERE id=(SELECT value FROM config WHERE keyname='key_id')",
            (public_key, secret_key),
        )
        .await?;

    Ok(())
}

/// Generates new and removes old secret subkeys as needed.
///
/// We only remove at most one secret per run
/// to avoid irreversibly ratcheting the key forward
/// if the user has clock set to the future.
pub async fn housekeeping(context: &Context, now: PgpTimestamp) -> Result<()> {
    if key::self_fingerprint_opt(context).await?.is_none() {
        return Ok(());
    }

    let last_ac2_housekeeping = context
        .get_config_i64(Config::LastAutocrypt2Housekeeping)
        .await?;

    // Delete at most one key per day.
    // This should not be larger than the rate at which we generate the keys,
    // which is one key per 5 days.
    //
    // This prevents ratcheting the key forward immediately
    // if the user sets the clock into far future.
    if i64::from(now.as_secs()) >= last_ac2_housekeeping {
        if i64::from(now.as_secs()) <= last_ac2_housekeeping.saturating_add(24 * 3600) {
            return Ok(());
        }
    } else {
        warn!(
            context,
            "Housekeeping timestamp {last_ac2_housekeeping} is in the future compared to {}, ignoring it.",
            now.as_secs()
        );
    }

    // FIXME: use `now` instead of time()?
    context
        .set_config(
            Config::LastAutocrypt2Housekeeping,
            Some(&tools::time().to_string()),
        )
        .await?;

    let tsk = load_self_secret_key(context).await?;
    let Ok(mut autocrypt2_tsk) = Autocrypt2Tsk::try_from(tsk) else {
        // Legacy non-Autocrypt 2 key, do nothing.
        return Ok(());
    };

    // Generate new subkeys so we can delete old ones.
    autocrypt2_tsk.ratchet_until(now)?;
    let modified = autocrypt2_tsk.maybe_destroy_old_subkey(now);
    autocrypt2_tsk.truncate();

    if !modified {
        return Ok(());
    }

    save_autocrypt2_tsk(context, autocrypt2_tsk).await?;

    Ok(())
}

#[cfg(test)]
mod autocrypt2_tests;
