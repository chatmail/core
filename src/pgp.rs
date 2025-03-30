//! OpenPGP helper module using [rPGP facilities](https://github.com/rpgp/rpgp).

use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead, Cursor};

use anyhow::{Context as _, Result};
use deltachat_contact_tools::EmailAddress;
use pgp::armor::BlockType;
use pgp::composed::{
    Deserializable, KeyType as PgpKeyType, Message, MessageBuilder, SecretKeyParamsBuilder,
    SignedPublicKey, SignedPublicSubKey, SignedSecretKey, StandaloneSignature, SubkeyParamsBuilder,
    TheRing,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{
    CompressionAlgorithm, KeyDetails, Password, PublicKeyTrait, SignatureBytes, StringToKey,
};
use rand::thread_rng;
use tokio::runtime::Handle;

use crate::key::{DcKey, Fingerprint};

#[cfg(test)]
pub(crate) const HEADER_AUTOCRYPT: &str = "autocrypt-prefer-encrypt";

pub const HEADER_SETUPCODE: &str = "passphrase-begin";

/// Preferred symmetric encryption algorithm.
const SYMMETRIC_KEY_ALGORITHM: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES128;

/// Preferred cryptographic hash.
const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha256;

/// A wrapper for rPGP public key types
#[derive(Debug)]
enum SignedPublicKeyOrSubkey<'a> {
    Key(&'a SignedPublicKey),
    Subkey(&'a SignedPublicSubKey),
}

impl KeyDetails for SignedPublicKeyOrSubkey<'_> {
    fn version(&self) -> pgp::types::KeyVersion {
        match self {
            Self::Key(k) => k.version(),
            Self::Subkey(k) => k.version(),
        }
    }

    fn fingerprint(&self) -> pgp::types::Fingerprint {
        match self {
            Self::Key(k) => k.fingerprint(),
            Self::Subkey(k) => k.fingerprint(),
        }
    }

    fn key_id(&self) -> pgp::types::KeyId {
        match self {
            Self::Key(k) => k.key_id(),
            Self::Subkey(k) => k.key_id(),
        }
    }

    fn algorithm(&self) -> pgp::crypto::public_key::PublicKeyAlgorithm {
        match self {
            Self::Key(k) => k.algorithm(),
            Self::Subkey(k) => k.algorithm(),
        }
    }
}

impl PublicKeyTrait for SignedPublicKeyOrSubkey<'_> {
    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        match self {
            Self::Key(k) => k.created_at(),
            Self::Subkey(k) => k.created_at(),
        }
    }

    fn expiration(&self) -> Option<u16> {
        match self {
            Self::Key(k) => k.expiration(),
            Self::Subkey(k) => k.expiration(),
        }
    }

    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> pgp::errors::Result<()> {
        match self {
            Self::Key(k) => k.verify_signature(hash, data, sig),
            Self::Subkey(k) => k.verify_signature(hash, data, sig),
        }
    }

    fn public_params(&self) -> &pgp::types::PublicParams {
        match self {
            Self::Key(k) => k.public_params(),
            Self::Subkey(k) => k.public_params(),
        }
    }
}

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
        use crate::key::DcSecretKey;

        let public = secret.split_public_key()?;
        Ok(Self { public, secret })
    }
}

/// Create a new key pair.
///
/// Both secret and public key consist of signing primary key and encryption subkey
/// as [described in the Autocrypt standard](https://autocrypt.org/level1.html#openpgp-based-key-data).
pub(crate) fn create_keypair(addr: EmailAddress) -> Result<KeyPair> {
    let signing_key_type = PgpKeyType::EdDSALegacy;
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
                .can_encrypt(true)
                .passphrase(None)
                .build()
                .context("failed to build subkey parameters")?,
        )
        .build()
        .context("failed to build key parameters")?;

    let mut rng = thread_rng();
    let secret_key = key_params
        .generate(&mut rng)
        .context("failed to generate the key")?
        .sign(&mut rng, &Password::empty())
        .context("failed to sign secret key")?;
    secret_key
        .verify()
        .context("invalid secret key generated")?;

    let key_pair = KeyPair::new(secret_key)?;
    key_pair
        .public
        .verify()
        .context("invalid public key generated")?;
    Ok(key_pair)
}

/// Select public key or subkey to use for encryption.
///
/// First, tries to use subkeys. If none of the subkeys are suitable
/// for encryption, tries to use primary key. Returns `None` if the public
/// key cannot be used for encryption.
///
/// TODO: take key flags and expiration dates into account
fn select_pk_for_encryption(key: &SignedPublicKey) -> Option<SignedPublicKeyOrSubkey> {
    key.public_subkeys
        .iter()
        .find(|subkey| subkey.is_encryption_key())
        .map_or_else(
            || {
                // No usable subkey found, try primary key
                if key.is_encryption_key() {
                    Some(SignedPublicKeyOrSubkey::Key(key))
                } else {
                    None
                }
            },
            |subkey| Some(SignedPublicKeyOrSubkey::Subkey(subkey)),
        )
}

/// Encrypts `plain` text using `public_keys_for_encryption`
/// and signs it using `private_key_for_signing`.
pub async fn pk_encrypt(
    plain: &[u8],
    public_keys_for_encryption: Vec<SignedPublicKey>,
    private_key_for_signing: Option<SignedSecretKey>,
    compress: bool,
) -> Result<String> {
    let lit_msg = MessageBuilder::from_bytes("", plain);

    Handle::current()
        .spawn_blocking(move || {
            let pkeys: Vec<SignedPublicKeyOrSubkey> = public_keys_for_encryption
                .iter()
                .filter_map(select_pk_for_encryption)
                .collect();

            let mut rng = thread_rng();

            let encrypted_msg = if let Some(ref skey) = private_key_for_signing {
                let signed_msg = lit_msg.sign(&**skey, Password::empty(), HASH_ALGORITHM);
                let compressed_msg = if compress {
                    signed_msg.compression(CompressionAlgorithm::ZLIB)
                } else {
                    signed_msg
                };
                let mut msg = compressed_msg.seipd_v1(&mut rng, SYMMETRIC_KEY_ALGORITHM);
                for pkey in &pkeys {
                    msg = msg.encrypt_to_key(&mut rng, &*pkey)?;
                }
                msg
            } else {
                let mut msg = lit_msg.seipd_v1(&mut rng, SYMMETRIC_KEY_ALGORITHM);
                for pkey in &pkeys {
                    msg = msg.encrypt_to_key(&mut rng, &*pkey)?;
                }
                msg
            };

            let encoded_msg = encrypted_msg.to_armored_string(&mut rng, Default::default())?;

            Ok(encoded_msg)
        })
        .await?
}

/// Signs `plain` text using `private_key_for_signing`.
pub fn pk_calc_signature(
    plain: Vec<u8>,
    private_key_for_signing: &SignedSecretKey,
) -> Result<String> {
    let mut rng = thread_rng();
    let signature = MessageBuilder::from_bytes("", plain)
        .sign(
            &**private_key_for_signing,
            Password::empty(),
            HASH_ALGORITHM,
        )
        .to_armored_string(&mut rng, Default::default())?;

    Ok(signature)
}

/// Decrypts the message with keys from the private key keyring.
///
/// Receiver private keys are provided in
/// `private_keys_for_decryption`.
pub fn pk_decrypt(
    ctext: Vec<u8>,
    private_keys_for_decryption: &[SignedSecretKey],
) -> Result<pgp::composed::Message<'static>> {
    let cursor = Cursor::new(ctext);
    let (msg, _headers) = Message::from_armor(cursor)?;

    let skeys: Vec<&SignedSecretKey> = private_keys_for_decryption.iter().collect();

    let ring = TheRing {
        secret_keys: skeys,
        key_passwords: vec![],
        message_password: vec![],
        session_keys: vec![],
        allow_legacy: false,
    };
    let (msg, _key_ids) = msg.decrypt_the_ring(ring, true)?;

    // get_content() will decompress the message if needed,
    // but this avoids decompressing it again to check signatures
    let msg = msg.decompress()?;

    Ok(msg)
}

/// Returns fingerprints
/// of all keys from the `public_keys_for_validation` keyring that
/// have valid signatures there.
///
/// If the message is wrongly signed, HashSet will be empty.
pub fn valid_signature_fingerprints(
    msg: &pgp::composed::Message,
    public_keys_for_validation: &[SignedPublicKey],
) -> Result<HashSet<Fingerprint>> {
    let mut ret_signature_fingerprints: HashSet<Fingerprint> = Default::default();
    if let signed_msg @ pgp::composed::Message::Signed { .. } = msg {
        for pkey in public_keys_for_validation {
            if signed_msg.verify(&pkey.primary_key).is_ok() {
                let fp = pkey.dc_fingerprint();
                ret_signature_fingerprints.insert(fp);
            }
        }
    }
    Ok(ret_signature_fingerprints)
}

/// Validates detached signature.
pub fn pk_validate(
    content: &[u8],
    signature: &[u8],
    public_keys_for_validation: &[SignedPublicKey],
) -> Result<HashSet<Fingerprint>> {
    let mut ret: HashSet<Fingerprint> = Default::default();

    let standalone_signature = StandaloneSignature::from_armor_single(Cursor::new(signature))?.0;

    for pkey in public_keys_for_validation {
        if standalone_signature.verify(pkey, content).is_ok() {
            let fp = pkey.dc_fingerprint();
            ret.insert(fp);
        }
    }
    Ok(ret)
}

/// Symmetric encryption.
pub async fn symm_encrypt(passphrase: &str, plain: &[u8]) -> Result<String> {
    let lit_msg = MessageBuilder::from_bytes("", plain);
    let passphrase = Password::from(passphrase.to_string());

    tokio::task::spawn_blocking(move || {
        let mut rng = thread_rng();
        let s2k = StringToKey::new_default(&mut rng);
        let msg = lit_msg
            .seipd_v1(&mut rng, SYMMETRIC_KEY_ALGORITHM)
            .encrypt_with_password(s2k, &passphrase)?;

        let encoded_msg = msg.to_armored_string(&mut rng, Default::default())?;

        Ok(encoded_msg)
    })
    .await?
}

/// Symmetric decryption.
pub async fn symm_decrypt<'a, T: BufRead + std::fmt::Debug + 'a>(
    passphrase: &str,
    ctext: T,
) -> Result<Vec<u8>> {
    let (enc_msg, _) = Message::from_armor(ctext)?;

    let passphrase = passphrase.to_string();
    tokio::task::spawn_blocking(move || {
        let msg = enc_msg.decrypt_with_password(&Password::empty())?;
        let res = msg.decompress()?.as_data_vec()?;
        Ok(res)
    })
    .await?
}

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;
    use tokio::sync::OnceCell;

    use super::*;
    use crate::test_utils::{alice_keypair, bob_keypair};

    fn pk_decrypt_and_validate<'a>(
        ctext: &'a [u8],
        private_keys_for_decryption: &'a [SignedSecretKey],
        public_keys_for_validation: &[SignedPublicKey],
    ) -> Result<(pgp::composed::Message<'static>, HashSet<Fingerprint>)> {
        let msg = pk_decrypt(ctext.to_vec(), private_keys_for_decryption)?;
        let ret_signature_fingerprints =
            valid_signature_fingerprints(&msg, public_keys_for_validation)?;

        Ok((msg, ret_signature_fingerprints))
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
    static KEYS: Lazy<TestKeys> = Lazy::new(TestKeys::new);

    static CTEXT_SIGNED: OnceCell<String> = OnceCell::const_new();
    static CTEXT_UNSIGNED: OnceCell<String> = OnceCell::const_new();

    /// A ciphertext encrypted to Alice & Bob, signed by Alice.
    async fn ctext_signed() -> &'static String {
        CTEXT_SIGNED
            .get_or_init(|| async {
                let keyring = vec![KEYS.alice_public.clone(), KEYS.bob_public.clone()];
                let compress = true;

                pk_encrypt(
                    CLEARTEXT,
                    keyring,
                    Some(KEYS.alice_secret.clone()),
                    compress,
                )
                .await
                .unwrap()
            })
            .await
    }

    /// A ciphertext encrypted to Alice & Bob, not signed.
    async fn ctext_unsigned() -> &'static String {
        CTEXT_UNSIGNED
            .get_or_init(|| async {
                let keyring = vec![KEYS.alice_public.clone(), KEYS.bob_public.clone()];
                let compress = true;

                pk_encrypt(CLEARTEXT, keyring, None, compress)
                    .await
                    .unwrap()
            })
            .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_encrypt_signed() {
        assert!(!ctext_signed().await.is_empty());
        assert!(ctext_signed()
            .await
            .starts_with("-----BEGIN PGP MESSAGE-----"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_encrypt_unsigned() {
        assert!(!ctext_unsigned().await.is_empty());
        assert!(ctext_unsigned()
            .await
            .starts_with("-----BEGIN PGP MESSAGE-----"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decrypt_singed() {
        // Check decrypting as Alice
        let decrypt_keyring = vec![KEYS.alice_secret.clone()];
        let sig_check_keyring = vec![KEYS.alice_public.clone()];
        let (msg, valid_signatures) = pk_decrypt_and_validate(
            ctext_signed().await.as_bytes(),
            &decrypt_keyring,
            &sig_check_keyring,
        )
        .unwrap();
        assert_eq!(msg.decompress().unwrap().as_data_vec().unwrap(), CLEARTEXT);
        assert_eq!(valid_signatures.len(), 1);

        // Check decrypting as Bob
        let decrypt_keyring = vec![KEYS.bob_secret.clone()];
        let sig_check_keyring = vec![KEYS.alice_public.clone()];
        let (msg, valid_signatures) = pk_decrypt_and_validate(
            ctext_signed().await.as_bytes(),
            &decrypt_keyring,
            &sig_check_keyring,
        )
        .unwrap();
        assert_eq!(msg.decompress().unwrap().as_data_vec().unwrap(), CLEARTEXT);
        assert_eq!(valid_signatures.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decrypt_no_sig_check() {
        let keyring = vec![KEYS.alice_secret.clone()];
        let (msg, valid_signatures) =
            pk_decrypt_and_validate(ctext_signed().await.as_bytes(), &keyring, &[]).unwrap();
        assert_eq!(msg.decompress().unwrap().as_data_vec().unwrap(), CLEARTEXT);
        assert_eq!(valid_signatures.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decrypt_signed_no_key() {
        // The validation does not have the public key of the signer.
        let decrypt_keyring = vec![KEYS.bob_secret.clone()];
        let sig_check_keyring = vec![KEYS.bob_public.clone()];
        let (msg, valid_signatures) = pk_decrypt_and_validate(
            ctext_signed().await.as_bytes(),
            &decrypt_keyring,
            &sig_check_keyring,
        )
        .unwrap();
        assert_eq!(msg.decompress().unwrap().as_data_vec().unwrap(), CLEARTEXT);
        assert_eq!(valid_signatures.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decrypt_unsigned() {
        let decrypt_keyring = vec![KEYS.bob_secret.clone()];
        let (msg, valid_signatures) =
            pk_decrypt_and_validate(ctext_unsigned().await.as_bytes(), &decrypt_keyring, &[])
                .unwrap();
        assert_eq!(msg.decompress().unwrap().as_data_vec().unwrap(), CLEARTEXT);
        assert_eq!(valid_signatures.len(), 0);
    }
}
