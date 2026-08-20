//! OpenPGP helper module using [rPGP facilities](https://github.com/rpgp/rpgp).

use std::collections::{HashMap, HashSet};
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
use pgp::packet::{Signature, Subpacket, SubpacketData};
use pgp::types::{
    CompressionAlgorithm, Imprint, KeyDetails, KeyVersion, Password, SignedUser, SigningKey as _,
    StringToKey,
};
use rand_old::{Rng as _, thread_rng};
use sha2::Sha256;

use crate::configure::MAX_RELAYS;
use crate::key::{DcKey, Fingerprint};

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
pub fn pk_encrypt(
    plain: Vec<u8>,
    public_keys_for_encryption: Vec<SignedPublicKey>,
    private_key_for_signing: SignedSecretKey,
    compress: bool,
    seipd_version: SeipdVersion,
) -> Result<String> {
    tokio::task::block_in_place(|| {
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
    private_key_for_signing: Option<SignedSecretKey>,
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
                .max_by_key(|signature: &Signature| signature.created());
            best_user_signature.map(|signature| (id, signature))
        })
        .max_by_key(|(_id, signature)| signature.created())
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
/// Not more than [`MAX_RELAYS`] relays are returned for each key.
/// This is the same constant as the maximum number of published relays
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
    addresses_from_public_key(public_key).unwrap_or_else(|| vec![addr.to_string()])
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
