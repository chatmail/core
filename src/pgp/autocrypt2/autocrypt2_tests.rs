use super::Autocrypt2Tsk;
use crate::config::Config;
use crate::imex;
use crate::imex::ImexMode;
use crate::key;
use crate::pgp::DcKey;
use crate::pgp::pgp_time;
use crate::test_utils;
use crate::test_utils::TestContextManager;
use crate::tools::SystemTime;
use anyhow::Result;
use pgp::composed::SignedSecretKey;
use pgp::types::KeyDetails as _;
use pgp::types::Timestamp as PgpTimestamp;
use pretty_assertions::assert_eq;
use std::time::Duration;

/// Tests creating Autocrypt 2 TSK and detecting it.
#[test]
fn test_create_autocrypt2_keypair() {
    let now = pgp_time();
    let keypair = Autocrypt2Tsk::new(now).unwrap();
    assert!(super::is_autocrypt2_tsk(&keypair.0));

    // Test that Autocrypt 2 TSK can be serialized and deserialized.
    let secret_key_bytes = DcKey::to_bytes(&keypair.0);
    let signed_secret_key =
        SignedSecretKey::from_slice(&secret_key_bytes).expect("Cannot deserialize Autocrypt2 TSK");

    assert!(super::is_autocrypt2_tsk(&signed_secret_key));
}

/// Tests that the key does not leak creation timestamp.
#[test]
fn test_tsk_timestamps() {
    let now = pgp_time();
    let tsk = Autocrypt2Tsk::new(now).unwrap();

    assert_eq!(
        tsk.primary_key.created_at().as_secs(),
        super::WELL_KNOWN_TIMESTAMP
    );

    // Primary key direct key signature timestamp is zero.
    let [ref direct_signature] = tsk.details.direct_signatures[..] else {
        panic!("Autocrypt 2 TSK must have exactly one direct key signature");
    };

    // Direct key signature may be larger than well known timestamp
    // <https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-03.html#section-2.3-2.2.2.1.1>
    // We use well known timestamp even here to not store the profile creation timestamp locally.
    // This timestamp from TSK does not leak into the certificate however
    // as we recreate the signature every time relay list is changed.
    let created_timestamp = direct_signature.created().unwrap();
    assert_eq!(created_timestamp.as_secs(), super::WELL_KNOWN_TIMESTAMP);

    let fallback_subkey = tsk
        .secret_subkeys
        .first()
        .expect("Fallback subkey not found");

    // We will not be able to change this timestamp after key creation
    // and it should not leak the profile creation timestamp.
    assert_eq!(
        fallback_subkey.key.created_at().as_secs(),
        super::WELL_KNOWN_TIMESTAMP
    );

    // Fallback subkey binding signature timestamp.
    let [ref fallback_subkey_signature] = fallback_subkey.signatures[..] else {
        panic!("Fallback subkey does not have exactly one binding signature");
    };
    assert_eq!(
        fallback_subkey_signature.created().unwrap().as_secs(),
        super::WELL_KNOWN_TIMESTAMP
    );
}

/// Tests that Autocrypt 2 TSK detection is not triggered for existing non-AC2 test keys.
#[test]
fn test_is_autocrypt2_tsk_no_false_positives() {
    use super::is_autocrypt2_tsk;

    assert!(!is_autocrypt2_tsk(&test_utils::alice_keypair()));
    assert!(!is_autocrypt2_tsk(&test_utils::bob_keypair()));
    assert!(!is_autocrypt2_tsk(&test_utils::charlie_keypair()));
    assert!(!is_autocrypt2_tsk(&test_utils::dom_keypair()));
    assert!(!is_autocrypt2_tsk(&test_utils::elena_keypair()));
    assert!(!is_autocrypt2_tsk(&test_utils::pqc_keypair()));
}

#[test]
fn test_autocrypt2_key_selection() {
    let now = pgp_time();
    let tsk = Autocrypt2Tsk::new(now).unwrap();

    let public_key = key::secret_key_to_public_key(
        tsk.clone(),
        now.as_secs(),
        "alice@example.org",
        "alice@example.org",
    )
    .expect("Failed to convert secret key to public key");

    // For Autocrypt 2 certificate rotating key should be selected for encryption.
    let pk_for_encryption = crate::pgp::select_pk_for_encryption(now, &public_key).unwrap();
    let [ref pk_for_encryption_signature] = pk_for_encryption.signatures[..] else {
        panic!("Selected public key has multiple signatures");
    };
    let key_flags = pk_for_encryption_signature.key_flags();
    assert!(key_flags.encrypt_comms());
    assert!(!key_flags.encrypt_storage());
}

/// Tests that by default Autocrypt 2 keys are generated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_autocrypt2_key_generation() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.unconfigured().await;
    alice.configure_addr("alice@example.org").await;
    assert!(alice.get_config_bool(Config::Autocrypt2).await?);
    let tsk = key::load_self_secret_key(alice).await?;
    assert!(super::is_autocrypt2_tsk(&tsk));
    Ok(())
}

/// Tests that Autocrypt 1 keys are generated if Autocrypt2 config is disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_legacy_key_generation() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.unconfigured().await;
    alice.configure_addr("alice@example.org").await;
    alice.set_config_bool(Config::Autocrypt2, false).await?;
    let tsk = key::load_self_secret_key(alice).await?;
    assert!(!super::is_autocrypt2_tsk(&tsk));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_autocrypt2_key_deletion() -> Result<()> {
    let _n = test_utils::TimeShiftFalsePositiveNote;

    let mut tcm = TestContextManager::new();
    let alice = &tcm.unconfigured().await;
    alice.configure_addr("alice@example.org").await;

    let tsk_start = key::load_self_secret_key(alice).await?;
    assert_eq!(tsk_start.secret_subkeys.len(), 4);
    SystemTime::shift(Duration::from_secs(60));
    let tsk_start = key::load_self_secret_key(alice).await?;
    assert_eq!(tsk_start.secret_subkeys.len(), 4);

    let public_key_start = key::load_self_public_key(alice).await?;
    assert_eq!(public_key_start.public_subkeys.len(), 2);

    super::housekeeping(alice, pgp_time()).await?;

    for _ in 0..50 {
        let tsk_before = key::load_self_secret_key(alice).await?;

        SystemTime::shift(Duration::from_secs(24 * 5 * 3600));

        super::housekeeping(alice, pgp_time()).await?;
        let tsk_after = key::load_self_secret_key(alice).await?;

        assert_ne!(tsk_before, tsk_after);
    }

    let tsk = key::load_self_secret_key(alice).await?;
    assert_eq!(tsk.secret_subkeys.len(), 7);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_autocrypt2_spec() -> Result<()> {
    let initial_keypair =
        key::SignedSecretKey::from_asc(include_str!("../../../test-data/autocrypt2/initial.key"))
            .unwrap();
    assert!(super::is_autocrypt2_tsk(&initial_keypair));
    let mut autocrypt2_tsk = Autocrypt2Tsk::try_from(initial_keypair).unwrap();
    assert_eq!(autocrypt2_tsk.secret_subkeys.len(), 2);

    let new_subkey_added_keypair = key::SignedSecretKey::from_asc(include_str!(
        "../../../test-data/autocrypt2/new-subkey-added.key"
    ))
    .unwrap();
    let new_autocrypt2_tsk = Autocrypt2Tsk::try_from(new_subkey_added_keypair).unwrap();
    assert_eq!(new_autocrypt2_tsk.secret_subkeys.len(), 3);

    assert_ne!(autocrypt2_tsk, new_autocrypt2_tsk);

    // Unix timestamp 1783359225 is 2026-07-06T17:33:45Z
    autocrypt2_tsk.ratchet_until(PgpTimestamp::from_secs(1783359225 - 1))?;
    assert_eq!(autocrypt2_tsk.secret_subkeys.len(), 2);

    autocrypt2_tsk.ratchet_until(PgpTimestamp::from_secs(1783359225))?;
    assert_eq!(autocrypt2_tsk.secret_subkeys.len(), 3);

    assert_eq!(autocrypt2_tsk, new_autocrypt2_tsk);

    let old_subkey_removed_keypair = key::SignedSecretKey::from_asc(include_str!(
        "../../../test-data/autocrypt2/old-subkey-removed.key"
    ))
    .unwrap();
    let old_subkey_removed_autocrypt2_tsk =
        Autocrypt2Tsk::try_from(old_subkey_removed_keypair).unwrap();

    // Unix timestamp 1784655225 is 2026-07-21T17:33:45Z
    let is_removed = autocrypt2_tsk.maybe_destroy_old_subkey(PgpTimestamp::from_secs(1784655225));
    assert!(!is_removed);

    let is_removed =
        autocrypt2_tsk.maybe_destroy_old_subkey(PgpTimestamp::from_secs(1784655225 + 1));
    assert!(is_removed);
    assert_eq!(autocrypt2_tsk, old_subkey_removed_autocrypt2_tsk);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_autocrypt2_import_export() -> Result<()> {
    let _n = test_utils::TimeShiftFalsePositiveNote;

    let backup_dir = tempfile::tempdir().unwrap();

    let mut tcm = TestContextManager::new();
    let alice = &tcm.unconfigured().await;
    alice.configure_addr("alice@example.org").await;

    let tsk_before = key::load_self_secret_key(alice).await?;

    imex::imex(alice, ImexMode::ExportBackup, backup_dir.path(), None).await?;

    for _ in 1..200 {
        SystemTime::shift(Duration::from_secs(5 * 24 * 3600));
        super::housekeeping(alice, pgp_time()).await?;
    }

    let alice2 = &tcm.unconfigured().await;
    let backup = imex::has_backup(alice2, backup_dir.path()).await?;
    imex::imex(alice2, ImexMode::ImportBackup, backup.as_ref(), None).await?;

    let tsk_after = key::load_self_secret_key(alice).await?;
    assert_eq!(tsk_after.secret_subkeys.len(), 8);

    assert_ne!(tsk_after, tsk_before);

    let tsk2 = key::load_self_secret_key(alice2).await?;
    assert_eq!(tsk2.secret_subkeys.len(), 4);

    Ok(())
}
