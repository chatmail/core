use super::*;
use crate::test_utils::TestContext;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_load_transport_candidates_single() -> Result<()> {
    let t = TestContext::new_alice().await;
    let now = time();

    t.sql.execute("DELETE FROM relay_candidates", ()).await?;

    // This domain should be returned by load_transport_candidates():
    t.sql
        .execute(
            "INSERT INTO relay_candidates (domain, last_tried) VALUES (?, ?)",
            ("never_tried.example", 0),
        )
        .await?;

    // This domain was recently tried and should not be returned:
    t.sql
        .execute(
            "INSERT INTO relay_candidates (domain, last_tried) VALUES (?, ?)",
            ("recent.example", now),
        )
        .await?;

    // This domain is already in use (alice@example.org) and should not be returned:
    t.sql
        .execute(
            "INSERT INTO relay_candidates (domain, last_tried) VALUES (?, ?)",
            ("example.org", 0),
        )
        .await?;

    let candidates = load_transport_candidates(&t, now).await?;

    assert_eq!(candidates, vec!["never_tried.example".to_string()]);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_load_transport_candidates_multiple() -> Result<()> {
    let t = TestContext::new().await;
    let now = time();

    t.sql.execute("DELETE FROM relay_candidates", ()).await?;
    for domain in ["a.example", "b.example", "c.example"] {
        t.sql
            .execute(
                "INSERT INTO relay_candidates (domain, last_tried) VALUES (?, ?)",
                (domain, 0),
            )
            .await?;
    }

    let mut candidates = load_transport_candidates(&t, now).await?;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_transports_mutex_held() -> Result<()> {
    let t = TestContext::new().await;

    // Hold the housekeeping mutex ourselves, simulating another task
    // already running housekeeping or transport management.
    let _lock = t.housekeeping_mutex.lock().await;

    let transports_before = t.count_transports().await?;

    maybe_add_additional_transports_inner(&t, false).await?;
    maybe_add_additional_transports_inner(&t, false).await?;

    let config_after = t
        .get_config_i64(Config::LastAutomaticTransportManagement)
        .await?;
    let transports_after = t.count_transports().await?;

    assert_eq!(0, config_after); // Assert the config still has the default value (0)
    assert_eq!(transports_before, transports_after);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_transports_debounce() -> Result<()> {
    let t = TestContext::new_alice().await;
    let some_seconds_ago = time() - 10;

    // Pretend automatic transport management just ran.
    t.set_config_internal(
        Config::LastAutomaticTransportManagement,
        Some(&some_seconds_ago.to_string()),
    )
    .await?;

    let transports_before = t.count_transports().await?;

    maybe_add_additional_transports_inner(&t, false).await?;

    let config_after = t
        .get_config_i64(Config::LastAutomaticTransportManagement)
        .await?;
    let transports_after = t.count_transports().await?;

    assert_eq!(config_after, some_seconds_ago);
    assert_eq!(transports_before, transports_after);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_add_additional_transports_add_one() -> Result<()> {
    let t = TestContext::new_alice().await;
    let now = time();

    t.sql.execute("DELETE FROM relay_candidates", ()).await?;
    t.sql
        .execute(
            "INSERT INTO relay_candidates (domain, last_tried) VALUES (?, ?)",
            ("relay.example", 0),
        )
        .await?;

    let transports_before = t.count_transports().await?;

    maybe_add_additional_transports_inner(&t, true).await?;

    let config_after = t
        .get_config_i64(Config::LastAutomaticTransportManagement)
        .await?;
    assert!(config_after >= now);

    let transports_after = t.count_transports().await?;
    assert_eq!(transports_after, transports_before + 1);

    Ok(())
}
