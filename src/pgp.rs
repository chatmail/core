//! OpenPGP helper module using [rPGP facilities](https://github.com/rpgp/rpgp).

use std::cmp::Ordering;
use std::collections::btree_map::Entry as BTreeMapEntry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Cursor;

use anyhow::{Context as _, Result, ensure};
use deltachat_contact_tools::{EmailAddress, may_be_valid_addr};
use pgp::composed::{
    Deserializable, DetachedSignature, EncryptionCaps, KeyType as PgpKeyType, MessageBuilder,
    SecretKeyParamsBuilder, SignedKeyDetails, SignedPublicKey, SignedPublicSubKey, SignedSecretKey,
    SubkeyParamsBuilder, SubpacketConfig,
};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Signature, SignatureType, Subpacket, SubpacketData};
use pgp::types::{
    CompressionAlgorithm, Imprint, KeyDetails, KeyVersion, Password, SignedUser, SigningKey as _,
    StringToKey,
};
use rand_old::{Rng as _, thread_rng};
use sha2::Sha256;

use crate::configure::MAX_RELAYS;
use crate::key::{DcKey, Fingerprint};

pub(crate) mod autocrypt2;

/// Preferred symmetric encryption algorithm.
const SYMMETRIC_KEY_ALGORITHM: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES128;

/// Create a new key pair.
///
/// Both secret and public key consist of signing primary key and encryption subkey
/// as [described in the Autocrypt standard](https://autocrypt.org/level1.html#openpgp-based-key-data).
pub(crate) fn create_keypair(addr: EmailAddress) -> Result<SignedSecretKey> {
    let signing_key_type = PgpKeyType::Ed25519Legacy;
    let encryption_key_type = PgpKeyType::ECDH(ECCCurve::Curve25519Legacy);

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
/// The key is selected according to
/// <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-03.html#section-4.3-4>.
/// If multiple keys are available, the one that will expire sooner is selected.
///
/// Returns `None` if the public key cannot be used for encryption.
fn select_pk_for_encryption(now: u32, key: &SignedPublicKey) -> Option<&SignedPublicSubKey> {
    key.public_subkeys
        .iter()
        .filter(|subkey| subkey.algorithm().can_encrypt())
        .filter_map(|subkey| {
            let signature = subkey.signatures.first()?;

            let key_flags = signature.key_flags();
            if !key_flags.encrypt_comms() {
                return None;
            }

            if let Some(expiration_duration) = signature
                .key_expiration_time()
                .filter(|duration| duration.as_secs() != 0)
                && now
                    > subkey
                        .created_at()
                        .as_secs()
                        .saturating_add(expiration_duration.as_secs())
            {
                // Key is expired.
                return None;
            }
            Some((subkey, signature))
        })
        .min_by(|(subkey1, signature1), (subkey2, signature2)| {
            match (
                signature1
                    .key_expiration_time()
                    .filter(|duration| duration.as_secs() != 0),
                signature2
                    .key_expiration_time()
                    .filter(|duration| duration.as_secs() != 0),
            ) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(expiration1), Some(expiration2)) => (subkey1
                    .created_at()
                    .as_secs()
                    .saturating_add(expiration1.as_secs()))
                .cmp(
                    &(subkey2
                        .created_at()
                        .as_secs()
                        .saturating_add(expiration2.as_secs())),
                ),
            }
        })
        .map(|(subkey, _signature)| subkey)
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

/// Returns the subpackets for a signature over a message
/// encrypted to `public_keys_for_encryption`.
#[expect(clippy::arithmetic_side_effects)]
fn signature_subpackets(
    private_key_for_signing: &SignedSecretKey,
    public_keys_for_encryption: &[SignedPublicKey],
) -> Result<SubpacketConfig> {
    let mut hashed = Vec::with_capacity(1 + public_keys_for_encryption.len() + 1);
    hashed.push(Subpacket::critical(SubpacketData::SignatureCreationTime(
        pgp::types::Timestamp::now(),
    ))?);
    for key in public_keys_for_encryption {
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
    Ok(SubpacketConfig::UserDefined { hashed, unhashed })
}

/// Encrypts `plain` text using `public_keys_for_encryption`,
/// signing it with `private_key_for_signing` if there is one.
///
/// An unsigned message carries no intended recipient fingerprints,
/// so its recipients do not learn who else received it.
pub fn pk_encrypt(
    plain: Vec<u8>,
    public_keys_for_encryption: Vec<SignedPublicKey>,
    private_key_for_signing: Option<&SignedSecretKey>,
    compress: bool,
    seipd_version: SeipdVersion,
) -> Result<String> {
    tokio::task::block_in_place(|| {
        let mut rng = thread_rng();
        let now = pgp::types::Timestamp::now();

        let pkeys = public_keys_for_encryption
            .iter()
            .filter_map(|key| select_pk_for_encryption(now.as_secs(), key));

        let msg = MessageBuilder::from_bytes("", plain);
        let encoded_msg = match seipd_version {
            SeipdVersion::V1 => {
                let mut msg = msg.seipd_v1(&mut rng, SYMMETRIC_KEY_ALGORITHM);

                for pkey in pkeys {
                    msg.encrypt_to_key_anonymous(&mut rng, &pkey)?;
                }

                if let Some(secret_key) = private_key_for_signing {
                    let subpkts = signature_subpackets(secret_key, &public_keys_for_encryption)?;
                    let hash_algorithm = secret_key.hash_alg();
                    msg.sign_with_subpackets(
                        &**secret_key,
                        Password::empty(),
                        hash_algorithm,
                        subpkts,
                    );
                }
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

                if let Some(secret_key) = private_key_for_signing {
                    let subpkts = signature_subpackets(secret_key, &public_keys_for_encryption)?;
                    let hash_algorithm = secret_key.hash_alg();
                    msg.sign_with_subpackets(
                        &**secret_key,
                        Password::empty(),
                        hash_algorithm,
                        subpkts,
                    );
                }
                if compress {
                    msg.compression(CompressionAlgorithm::ZLIB);
                }

                msg.to_armored_string(&mut rng, Default::default())?
            }
        };

        Ok(encoded_msg)
    })
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
pub fn symm_encrypt_message(
    plain: Vec<u8>,
    private_key_for_signing: Option<&SignedSecretKey>,
    shared_secret: String,
    compress: bool,
) -> Result<String> {
    tokio::task::block_in_place(|| {
        let shared_secret = Password::from(shared_secret);

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

        if let Some(private_key_for_signing) = private_key_for_signing {
            let hash_algorithm = private_key_for_signing.hash_alg();
            msg.sign(
                &**private_key_for_signing,
                Password::empty(),
                hash_algorithm,
            );
        }
        if compress {
            msg.compression(CompressionAlgorithm::ZLIB);
        }

        let encoded_msg = msg.to_armored_string(&mut rng, Default::default())?;

        Ok(encoded_msg)
    })
}

/// Minimizes the signatures of a subkey.
///
/// Keeps at most one subkey binding signature
/// and at most one revocation signature,
/// preferring the newest signatures.
///
/// Subkey binding signature is kept
/// even if the revocation signature exists
/// because according to
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-openpgp-version-6-certifica>
/// "Every subkey MUST have at least one Subkey Binding signature."
/// Distributing subkey with only a revocation signature
/// is not allowed according to the standard,
/// so we keep a subkey binding signature next to it
/// for interoperability.
///
/// This function does not check if the signatures are valid.
/// Such properties should be validated when importing OpenPGP certificates.
fn minimize_subpacket_signatures(signatures: Vec<Signature>) -> Vec<Signature> {
    let mut newest_revocation_signature: Option<Signature> = None;
    let mut newest_binding_signature: Option<Signature> = None;
    for signature in signatures {
        let Some(config) = signature.config() else {
            // Skip unknown signatures.
            continue;
        };
        match config.typ {
            SignatureType::SubkeyBinding => {
                if newest_binding_signature
                    .as_ref()
                    .is_none_or(|s| s.created() < signature.created())
                {
                    newest_binding_signature = Some(signature)
                }
            }
            SignatureType::SubkeyRevocation => {
                if newest_revocation_signature
                    .as_ref()
                    .is_none_or(|s| s.created() < signature.created())
                {
                    newest_revocation_signature = Some(signature)
                }
            }
            _ => continue,
        }
    }
    newest_revocation_signature
        .into_iter()
        .chain(newest_binding_signature)
        .collect()
}

/// Minimizes OpenPGP certificate for Autocrypt and Autocrypt-Gossip headers.
pub fn minimize_autocrypt_certificate(certificate: &SignedPublicKey) -> SignedPublicKey {
    let primary_key = certificate.primary_key.clone();
    let details = certificate.details.clone();

    // Select the newest non-expiring subkey and the newest expiring subkey.
    let fallback_subkey = certificate
        .public_subkeys
        .iter()
        .filter(|subkey| {
            subkey
                .signatures
                .iter()
                .find(|signature| {
                    signature
                        .config()
                        .is_some_and(|config| config.typ == SignatureType::SubkeyBinding)
                })
                .is_some_and(|signature| signature.key_expiration_time().is_none())
        })
        .max_by_key(|subkey| {
            subkey
                .signatures
                .iter()
                .find(|signature| {
                    signature
                        .config()
                        .is_some_and(|config| config.typ == SignatureType::SubkeyBinding)
                })
                .map(|signature| signature.created().unwrap_or(subkey.created_at()))
        });
    let rotating_subkey = certificate
        .public_subkeys
        .iter()
        .filter(|subkey| {
            subkey
                .signatures
                .iter()
                .find(|signature| {
                    signature
                        .config()
                        .is_some_and(|config| config.typ == SignatureType::SubkeyBinding)
                })
                .is_some_and(|signature| signature.key_expiration_time().is_some())
        })
        .max_by_key(|subkey| {
            subkey
                .signatures
                .iter()
                .find(|signature| {
                    signature
                        .config()
                        .is_some_and(|config| config.typ == SignatureType::SubkeyBinding)
                })
                .map(|signature| signature.created().unwrap_or(subkey.created_at()))
        });
    let public_subkeys: Vec<_> = fallback_subkey
        .into_iter()
        .chain(rotating_subkey)
        .cloned()
        .collect();

    // We do not want to ever gossip more than two subkeys
    // to save the traffic.
    debug_assert!(public_subkeys.len() <= 2);

    SignedPublicKey {
        primary_key,
        details,
        public_subkeys,
    }
}

/// Merges two OpenPGP subkeys.
fn merge_openpgp_subkey(old_subkey: &mut SignedPublicSubKey, new_subkey: SignedPublicSubKey) {
    debug_assert_eq!(old_subkey.fingerprint(), new_subkey.fingerprint());
    old_subkey.signatures = minimize_subpacket_signatures(
        std::mem::take(&mut old_subkey.signatures)
            .into_iter()
            .chain(new_subkey.signatures)
            .collect(),
    );
}

/// Merges OpenPGP subkey vectors.
pub fn merge_openpgp_subkeys(
    subkeys: impl IntoIterator<Item = SignedPublicSubKey>,
) -> Result<Vec<SignedPublicSubKey>> {
    let mut merged_subkeys: BTreeMap<_, SignedPublicSubKey> = BTreeMap::new();
    for subkey in subkeys {
        let imprint = subkey.imprint::<Sha256>()?;
        match merged_subkeys.entry(imprint) {
            BTreeMapEntry::Vacant(entry) => {
                entry.insert(subkey);
            }
            BTreeMapEntry::Occupied(entry) => {
                merge_openpgp_subkey(entry.into_mut(), subkey);
            }
        }
    }
    Ok(merged_subkeys.into_values().collect())
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
        public_subkeys: new_public_subkeys,
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
        .max_by_key(|x: &Signature| x.created());
    let direct_signatures: Vec<Signature> = best_direct_key_signature.into_iter().collect();

    // Select at most one User ID.
    //
    // We prefer User IDs marked as primary,
    // but will select non-primary otherwise
    // because sometimes keys have no primary User ID,
    // such as Alice's key in `test-data/key/alice-secret.asc`.
    let best_user: Option<SignedUser> = old_users
        .into_iter()
        .chain(new_users)
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
                .max_by_key(|signature: &Signature| signature.created());
            best_user_signature.map(|signature| (id, signature))
        })
        .max_by_key(|(_id, signature)| signature.created())
        .map(|(id, signature)| SignedUser {
            id,
            signatures: vec![signature],
        });
    let users: Vec<SignedUser> = best_user.into_iter().collect();

    let (fallback_subkeys, mut rotating_subkeys): (Vec<_>, Vec<_>) =
        merge_openpgp_subkeys(old_public_subkeys.into_iter().chain(new_public_subkeys))?
            .into_iter()
            .filter_map(|subkey| {
                // Select the newest subkey binding signature.
                //
                // There is at most one subkey binding signature at this point
                // because older subkey binding signatures are removed during merging.
                let signature = subkey.signatures.iter().find(|signature| {
                    signature
                        .config()
                        .is_some_and(|config| config.typ == SignatureType::SubkeyBinding)
                })?;

                let created_at_secs = signature.created().unwrap_or(subkey.created_at()).as_secs();
                let expires_at_secs: Option<u32> = signature
                    .key_expiration_time()
                    .map(|duration| duration.as_secs())
                    .filter(|duration_secs| *duration_secs != 0)
                    .map(|duration_secs| {
                        subkey.created_at().as_secs().saturating_add(duration_secs)
                    });

                Some((subkey, created_at_secs, expires_at_secs))
            })
            .partition(|(_subkey, _created_at_secs, expires_at_secs)| expires_at_secs.is_none());
    let fallback_subkey: Option<SignedPublicSubKey> = fallback_subkeys
        .into_iter()
        .max_by_key(|(_subkey, created_at_secs, _)| *created_at_secs)
        .map(|(subkey, _, _)| subkey);

    rotating_subkeys
        .sort_by_key(|(_subkey, created_at_secs, _)| std::cmp::Reverse(*created_at_secs));

    // Put the fallback subkey first so it is gossiped first.
    //
    // We want to always gossip non-expiring key first
    // for older versions that always encrypted to the first subkey.
    //
    // Keep 10 newest rotating subkeys to avoid storing indefinitely growing number of subkeys locally.
    let public_subkeys = fallback_subkey
        .into_iter()
        .chain(
            rotating_subkeys
                .into_iter()
                .take(10)
                .map(|(subkey, _, _)| subkey),
        )
        .collect();

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
/// Not more than [`MAX_RELAYS`] relays are returned for each key.
/// This is the same constant as the maximum number of relays
/// the user is allowed to have in the key.
/// If the constant is changed in the future,
/// the client with the lower constant value
/// will ignore some relays advertised in the key,
/// but still send to the first [`MAX_RELAYS`].
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
                            .take(MAX_RELAYS)
                            .collect(),
                    );
                }
            }
        }
    }
    None
}

/// Returns the addresses to reach the owner of `public_key`,
/// falling back to `addr` if the key carries no relay list.
pub(crate) fn relay_addrs(public_key: &SignedPublicKey, addr: &str) -> Vec<String> {
    addresses_from_public_key(public_key).unwrap_or_else(|| {
        if addr.is_empty() {
            vec![]
        } else {
            vec![addr.to_string()]
        }
    })
}

/// Returns true if the key can be encrypted to, i.e. has an encryption subkey.
pub(crate) fn pubkey_can_encrypt(public_key: &SignedPublicKey) -> bool {
    let now = pgp::types::Timestamp::now();
    select_pk_for_encryption(now.as_secs(), public_key).is_some()
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
mod pgp_tests;
