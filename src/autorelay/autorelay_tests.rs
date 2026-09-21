use std::time::Duration;

use super::*;
use crate::EventType;
use crate::test_utils::{TestContext, TestContextManager};
use crate::tools::SystemTime;

/// Tests that the default relays are candidates without a row in the table.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_triable_relay_candidates_defaults() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let t = &tcm.unconfigured().await;
    let now = time();

    assert!(DEFAULT_RELAY_CANDIDATES.is_sorted());
    let mut candidates = triable_relay_candidates(t, now).await?;
    candidates.sort();
    assert_eq!(candidates, DEFAULT_RELAY_CANDIDATES);

    let tried = DEFAULT_RELAY_CANDIDATES[0];
    save_relay_candidates(t, &[tried], now).await?;
    let candidates = triable_relay_candidates(t, now).await?;
    assert_eq!(candidates.len(), DEFAULT_RELAY_CANDIDATES.len() - 1);
    assert!(!candidates.contains(&tried.to_string()));

    Ok(())
}

/// Tests that a transport is added on a candidate from the given addresses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_transport_from_candidates() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let t = &tcm.unconfigured().await;
    mark_defaults_tried(t, time()).await?;
    let addrs_from_qr = [
        "alice@example.org".to_string(),
        "bob@example.org".to_string(),
    ];
    let skip_network = true;
    add_relay_candidates(t, &addrs_from_qr).await?;
    add_transport_from_candidates(t, skip_network).await?;

    let transports = t.list_transports().await?;
    assert_eq!(transports.len(), 1);
    assert!(transports[0].addr.ends_with("@example.org"));
    let untried = untried_relay_candidates(t).await?;
    assert_eq!(untried, ["example.org"]);
    assert!(configure_progress_emitted(t).await);

    Ok(())
}

/// Tests correct add_transport_from_candidates error handling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_transport_from_candidates_failure() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let t = &tcm.unconfigured().await;
    mark_defaults_tried(t, time()).await?;
    save_relay_candidates(t, &["bad host", "worse host"], 0).await?;

    let skip_network = true;
    let err = add_transport_from_candidates(t, skip_network)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("Bad email-address"));
    assert!(!t.is_configured().await?);
    let untried = untried_relay_candidates(t).await?;
    assert_eq!(untried, ["bad host", "worse host"]);
    t.assert_warns_or_errors(&[
        "Failed to add relay bad host",
        "Failed to add relay worse host",
    ])
    .await;

    Ok(())
}

async fn untried_relay_candidates(t: &TestContext) -> Result<Vec<String>> {
    t.sql
        .query_map_vec(
            "SELECT host FROM relay_candidates WHERE last_tried=0 ORDER BY host",
            (),
            |row| Ok(row.get(0)?),
        )
        .await
}

async fn save_relay_candidates(t: &TestContext, hosts: &[&str], last_tried: i64) -> Result<()> {
    t.sql
        .transaction(|tx| {
            for host in hosts {
                save_relay_candidate(tx, host, last_tried)?;
            }
            Ok(())
        })
        .await
}

/// Keeps the default relays out of `triable_relay_candidates()`.
async fn mark_defaults_tried(t: &TestContext, now: i64) -> Result<()> {
    save_relay_candidates(t, DEFAULT_RELAY_CANDIDATES, now).await
}

/// Consumes emitted events, telling whether a configure progress is among them.
async fn configure_progress_emitted(t: &TestContext) -> bool {
    t.evtracker
        .get_matching_opt(t, |evt| matches!(evt, EventType::ConfigureProgress { .. }))
        .await
        .is_some()
}

/// Tests that saving a candidate overwrites its stored timestamp.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_save_relay_candidate() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let t = &tcm.unconfigured().await;
    let now = time();

    for last_tried in [0, now, 0] {
        t.sql
            .transaction(|tx| save_relay_candidate(tx, "relay.example", last_tried))
            .await?;
        let stored: Option<i64> = t
            .sql
            .query_get_value(
                "SELECT last_tried FROM relay_candidates WHERE host=?",
                ("relay.example",),
            )
            .await?;
        assert_eq!(stored, Some(last_tried));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_triable_relay_candidates_single() -> Result<()> {
    let t = &TestContext::new_alice().await;
    enable_config(t).await;
    let now = time();

    mark_defaults_tried(t, now).await?;

    save_relay_candidates(t, &["never_tried.example", "example.org"], 0).await?;
    save_relay_candidates(t, &["recent.example"], now).await?;

    let candidates = triable_relay_candidates(t, now).await?;

    assert_eq!(candidates, vec!["never_tried.example".to_string()]);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_triable_relay_candidates_multiple() -> Result<()> {
    let t = &TestContext::new().await;
    enable_config(t).await;
    let now = time();

    mark_defaults_tried(t, now).await?;
    save_relay_candidates(t, &["a.example", "b.example", "c.example"], 0).await?;

    let mut candidates = triable_relay_candidates(t, now).await?;
    candidates.sort();

    assert_eq!(
        candidates,
        vec![
            "a.example".to_string(),
            "b.example".to_string(),
            "c.example".to_string()
        ]
    );
    Ok(())
}

async fn assert_autorelay_does_nothing(t: &TestContext) {
    let transports_before = t.count_transports().await.unwrap();
    let config_before = t.get_config_i64(Config::LastAutorelay).await.unwrap();

    let skip_network = false; // No need to skip network, nothing is supposed to happen
    let relay_added = maybe_add_additional_relays_inner(t, skip_network)
        .await
        .unwrap();
    assert_eq!(relay_added, false);

    let config_after = t.get_config_i64(Config::LastAutorelay).await.unwrap();
    let transports_after = t.count_transports().await.unwrap();

    assert_eq!(config_after, config_before);
    assert_eq!(transports_before, transports_after);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_relays_mutex_held() -> Result<()> {
    let t = &TestContext::new().await;
    enable_config(t).await;

    // Hold the housekeeping mutex ourselves, simulating another task
    // already running housekeeping or relay management.
    let _lock = t.background_task_mutex.lock().await;

    assert_autorelay_does_nothing(t).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_relays_debounce() -> Result<()> {
    let t = &TestContext::new_alice().await;
    enable_config(t).await;
    let some_seconds_ago = time() - 10;

    // Pretend automatic relay management just ran.
    t.set_config_internal(Config::LastAutorelay, Some(&some_seconds_ago.to_string()))
        .await?;

    assert_autorelay_does_nothing(t).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_relays_disabled() {
    // By default, automatic relay management is disabled:
    let t = &TestContext::new_alice().await;
    assert_autorelay_does_nothing(t).await;
}

/// Runs maybe_add_additional_relays_inner(), then deletes one of the transports.
/// Even after AUTOMATIC_ADDITION_DEBOUNCE_SECONDS,
/// running automatic transport management again should not add back a transport.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_relays_does_nothing_after_finishing_once() -> Result<()> {
    let t = &TestContext::new_alice().await;
    enable_config(t).await;

    let skip_network = true;
    let relay_added = maybe_add_additional_relays_inner(t, skip_network).await?;
    assert!(relay_added);

    let transports = t.list_transports().await?;
    t.delete_transport(&transports.last().unwrap().addr).await?;

    SystemTime::shift(Duration::from_secs(
        AUTOMATIC_ADDITION_DEBOUNCE_SECONDS as u64 + 1,
    ));

    let transports_count = t.count_transports().await?;
    assert_eq!(transports_count, NUM_TRANSPORTS_TARGET - 1);

    assert!(t.get_config_bool(Config::AutorelayFinished).await?);
    assert_autorelay_does_nothing(t).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_relays_add_one() -> Result<()> {
    let t = &TestContext::new_alice().await;
    enable_config(t).await;
    let now = time();

    mark_defaults_tried(t, now).await?;
    save_relay_candidates(t, &["relay.example"], 0).await?;

    let transports_before = t.count_transports().await?;

    let skip_network = true;
    let relay_added = maybe_add_additional_relays_inner(t, skip_network).await?;
    assert!(relay_added);

    let config_after = t.get_config_i64(Config::LastAutorelay).await?;
    assert!(config_after >= now);

    let transports_after = t.count_transports().await?;
    assert_eq!(transports_after, transports_before + 1);
    assert!(!configure_progress_emitted(t).await);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_relays_add_multiple() -> Result<()> {
    let t = &TestContext::new_alice().await;
    enable_config(t).await;
    let now = time();

    mark_defaults_tried(t, now).await?;
    save_relay_candidates(t, &["a.example", "b.example", "c.example", "d.example"], 0).await?;

    let skip_network = true;
    let relay_added = maybe_add_additional_relays_inner(t, skip_network).await?;
    assert!(relay_added);

    let config_after = t.get_config_i64(Config::LastAutorelay).await?;
    assert!(config_after >= now);

    let transports_after = t.count_transports().await?;
    assert_eq!(transports_after, NUM_TRANSPORTS_TARGET);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_relays_failure() -> Result<()> {
    let t = &TestContext::new_alice().await;
    enable_config(t).await;
    let now = time();

    mark_defaults_tried(t, now).await?;
    for i in 1..10 {
        save_relay_candidates(t, &[format!("{i}.invalid.example").as_str()], 0).await?;
    }

    let transports_before = t.count_transports().await?;

    // Don't skip network, since we want the relay addition to fail
    let skip_network = false;
    let relay_added = maybe_add_additional_relays_inner(t, skip_network).await?;
    assert_eq!(relay_added, false);

    // The config is still updated:
    let config_after = t.get_config_i64(Config::LastAutorelay).await?;
    assert!(config_after >= now);

    let transports_after = t.count_transports().await?;
    assert_eq!(transports_after, transports_before);

    // Some of the candidates should have an updated last_tried:
    assert!(
        t.sql
            .exists(
                "SELECT COUNT(*) FROM relay_candidates WHERE last_tried>=?",
                (now,)
            )
            .await?
    );

    // ...but not all, because there might be many relay candidates
    // and we don't want to try all of them in a single call:
    assert_eq!(triable_relay_candidates(t, now).await?.is_empty(), false);

    t.assert_warns_or_errors(&[
        "DNS lookup with memory cache failure",
        "Could not find DNS resolutions",
    ])
    .await;

    Ok(())
}

async fn enable_config(context: &Context) {
    context
        .set_config_bool(Config::Autorelay, true)
        .await
        .unwrap();
}
