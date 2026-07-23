use super::*;
use crate::test_utils::TestContext;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_load_relay_candidates_single() -> Result<()> {
    let t = &TestContext::new_alice().await;
    enable_config(t).await;
    let now = time();

    t.sql.execute("DELETE FROM relay_candidates", ()).await?;

    // This host should be returned by load_relay_candidates():
    t.sql
        .execute(
            "INSERT INTO relay_candidates (host, last_tried) VALUES (?, ?)",
            ("never_tried.example", 0),
        )
        .await?;

    // This host was recently tried and should not be returned:
    t.sql
        .execute(
            "INSERT INTO relay_candidates (host, last_tried) VALUES (?, ?)",
            ("recent.example", now),
        )
        .await?;

    // This host is already in use (alice@example.org) and should not be returned:
    t.sql
        .execute(
            "INSERT INTO relay_candidates (host, last_tried) VALUES (?, ?)",
            ("example.org", 0),
        )
        .await?;

    let candidates = load_relay_candidates(t, now).await?;

    assert_eq!(candidates, vec!["never_tried.example".to_string()]);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_load_relay_candidates_multiple() -> Result<()> {
    let t = &TestContext::new().await;
    enable_config(t).await;
    let now = time();

    t.sql.execute("DELETE FROM relay_candidates", ()).await?;
    for host in ["a.example", "b.example", "c.example"] {
        t.sql
            .execute(
                "INSERT INTO relay_candidates (host, last_tried) VALUES (?, ?)",
                (host, 0),
            )
            .await?;
    }

    let mut candidates = load_relay_candidates(t, now).await?;
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

async fn assert_automatic_relay_management_does_nothing(t: &TestContext) {
    let transports_before = t.count_transports().await.unwrap();
    let config_before = t
        .get_config_i64(Config::LastAutomaticRelayManagement)
        .await
        .unwrap();

    let skip_network = false; // No need to skip network, nothing is supposed to happen
    maybe_add_additional_relays_inner(t, skip_network)
        .await
        .unwrap();

    let config_after = t
        .get_config_i64(Config::LastAutomaticRelayManagement)
        .await
        .unwrap();
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

    assert_automatic_relay_management_does_nothing(t).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_relays_debounce() -> Result<()> {
    let t = &TestContext::new_alice().await;
    enable_config(t).await;
    let some_seconds_ago = time() - 10;

    // Pretend automatic relay management just ran.
    t.set_config_internal(
        Config::LastAutomaticRelayManagement,
        Some(&some_seconds_ago.to_string()),
    )
    .await?;

    assert_automatic_relay_management_does_nothing(t).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_relays_disabled() {
    // By default, automatic relay management is disabled:
    let t = &TestContext::new_alice().await;
    assert_automatic_relay_management_does_nothing(t).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_relays_add_one() -> Result<()> {
    let t = &TestContext::new_alice().await;
    enable_config(t).await;
    let now = time();

    t.sql.execute("DELETE FROM relay_candidates", ()).await?;
    t.sql
        .execute(
            "INSERT INTO relay_candidates (host, last_tried) VALUES (?, ?)",
            ("relay.example", 0),
        )
        .await?;

    let transports_before = t.count_transports().await?;

    let skip_network = true;
    maybe_add_additional_relays_inner(t, skip_network).await?;

    let config_after = t
        .get_config_i64(Config::LastAutomaticRelayManagement)
        .await?;
    assert!(config_after >= now);

    let transports_after = t.count_transports().await?;
    assert_eq!(transports_after, transports_before + 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_relays_add_multiple() -> Result<()> {
    let t = &TestContext::new_alice().await;
    enable_config(t).await;
    let now = time();

    t.sql.execute("DELETE FROM relay_candidates", ()).await?;
    for host in ["a.example", "b.example", "c.example", "d.example"] {
        t.sql
            .execute(
                "INSERT INTO relay_candidates (host, last_tried) VALUES (?, ?)",
                (host, 0),
            )
            .await?;
    }

    let skip_network = true;
    maybe_add_additional_relays_inner(t, skip_network).await?;

    let config_after = t
        .get_config_i64(Config::LastAutomaticRelayManagement)
        .await?;
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

    t.sql.execute("DELETE FROM relay_candidates", ()).await?;
    for i in 1..10 {
        t.sql
            .execute(
                "INSERT INTO relay_candidates (host, last_tried) VALUES (?, ?)",
                (format!("{i}.invalid.example"), 0),
            )
            .await?;
    }

    let transports_before = t.count_transports().await?;

    // Don't skip network, since we want the relay addition to fail
    let skip_network = false;
    maybe_add_additional_relays_inner(t, skip_network).await?;

    // The config is still updated:
    let config_after = t
        .get_config_i64(Config::LastAutomaticRelayManagement)
        .await?;
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
    assert_eq!(load_relay_candidates(t, now).await?.is_empty(), false);

    Ok(())
}

async fn enable_config(context: &Context) {
    context
        .set_config_bool(Config::AutomaticRelayManagement, true)
        .await
        .unwrap();
}
