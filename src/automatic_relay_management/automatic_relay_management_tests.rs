use std::time::Duration;

use anyhow::Context as _;

use super::*;
use crate::imap::prefetch_should_download;
use crate::test_utils::{TestContext, TestContextManager};
use crate::tools::SystemTime;
use crate::transport::add_pseudo_transport;

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
    let relay_added = maybe_add_additional_relays_inner(t, skip_network)
        .await
        .unwrap();
    assert_eq!(relay_added, false);

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
    t.delete_transport(&transports.last().unwrap().param.addr)
        .await?;

    SystemTime::shift(Duration::from_secs(
        AUTOMATIC_ADDITION_DEBOUNCE_SECONDS as u64 + 1,
    ));

    let transports_count = t.count_transports().await?;
    assert_eq!(transports_count, NUM_TRANSPORTS_TARGET - 1);

    assert!(
        t.get_config_bool(Config::AutomaticRelayManagementFinished)
            .await?
    );
    assert_automatic_relay_management_does_nothing(t).await;

    Ok(())
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
    let relay_added = maybe_add_additional_relays_inner(t, skip_network).await?;
    assert!(relay_added);

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
    let relay_added = maybe_add_additional_relays_inner(t, skip_network).await?;
    assert!(relay_added);

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
    let relay_added = maybe_add_additional_relays_inner(t, skip_network).await?;
    assert_eq!(relay_added, false);

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

    t.assert_warns_or_errors(&[
        "DNS lookup with memory cache failure",
        "Could not find DNS resolutions",
    ])
    .await;

    Ok(())
}

async fn enable_config(context: &Context) {
    context
        .set_config_bool(Config::AutomaticRelayManagement, true)
        .await
        .unwrap();
}

/// Tests that `record_message_sent_via_transport()`,
/// `record_message_sent_via_transport_by_msg_id()` and `prefetch_should_download()`
/// correctly populate the `transport_knowledge_by_contacts` table,
/// and that `output_debug_transport_knowledge()`
/// turns that table into a human-readable device message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_transport_knowledge() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    bob.set_config(Config::Displayname, Some("Bob")).await?;
    let charlie = &tcm.charlie().await;
    charlie
        .set_config(Config::Displayname, Some("Charlie"))
        .await?;
    let dom = &tcm.dom().await;
    dom.set_config(Config::Displayname, Some("Dom")).await?;
    let fiona = &tcm.fiona().await;
    fiona.set_config(Config::Displayname, Some("Fiona")).await?;

    add_pseudo_transport(alice, "transport-a@example.org").await?;
    add_pseudo_transport(alice, "transport-b@example.org").await?;
    let transport_a: u32 = alice
        .sql
        .query_get_value(
            "SELECT id FROM transports WHERE addr=?",
            ("transport-a@example.org",),
        )
        .await?
        .context("transport A not found")?;
    let transport_b: u32 = alice
        .sql
        .query_get_value(
            "SELECT id FROM transports WHERE addr=?",
            ("transport-b@example.org",),
        )
        .await?
        .context("transport B not found")?;

    // Fiona is only reachable via transport A, recorded directly
    // via `record_message_sent_via_transport()`.
    let fiona_id = alice.add_or_lookup_contact_id(fiona).await;
    record_message_sent_via_transport(alice, fiona_id, transport_a).await?;

    // Bob is only reachable via transport B, recorded indirectly
    // via `record_message_sent_via_transport_by_msg_id()`.
    let bob_id = alice.add_or_lookup_contact_id(bob).await;
    alice
        .sql
        .execute(
            "INSERT INTO msgs (rfc724_mid, from_id) VALUES (?, ?)",
            ("bob-message@localhost", bob_id),
        )
        .await?;
    let bob_msg_id: MsgId = alice
        .sql
        .query_get_value(
            "SELECT id FROM msgs WHERE rfc724_mid=?",
            ("bob-message@localhost",),
        )
        .await?
        .context("Bob's message not found")?;
    record_message_sent_via_transport_by_msg_id(alice, bob_msg_id, transport_b).await?;

    // Charlie is reachable via both transports, so she should not show up as
    // "at risk" for either of them. His usage of transport A is recorded
    // directly, his usage of transport B is recorded by simulating that an
    // already-fetched message of him is prefetched again (as happens e.g.
    // when the same message is visible on two transports).
    let charlie_id = alice.add_or_lookup_contact_id(charlie).await;
    record_message_sent_via_transport(alice, charlie_id, transport_a).await?;
    alice
        .sql
        .execute(
            "INSERT INTO msgs (rfc724_mid, from_id) VALUES (?, ?)",
            ("charlie-message@localhost", charlie_id),
        )
        .await?;
    let download = prefetch_should_download(
        alice,
        &[],
        "charlie-message@localhost",
        std::iter::empty(),
        transport_b,
    )
    .await?;
    // The message was already fetched, so it should not be downloaded again
    assert_eq!(download, false);

    // Dom never sent us anything on any transport, so it's unclear how they
    // can reach us.
    let _dom_id = alice.add_or_lookup_contact_id(dom).await;

    let mut recorded: Vec<(ContactId, u32)> = alice
        .sql
        .query_map_vec(
            "SELECT contact_id, transport_id FROM transport_knowledge_by_contacts",
            (),
            |row| {
                let contact_id: ContactId = row.get(0)?;
                let transport_id: u32 = row.get(1)?;
                Ok((contact_id, transport_id))
            },
        )
        .await?;
    recorded.sort();
    let mut expected = vec![
        (fiona_id, transport_a),
        (bob_id, transport_b),
        (charlie_id, transport_a),
        (charlie_id, transport_b),
    ];
    expected.sort();
    assert_eq!(recorded, expected);

    let actual = get_debug_transport_knowledge(alice).await?;
    assert_eq!(
        actual,
        "=== Usage of transports by contacts ===
These contacts fail to reach you if you remove transport alice@example.org:

These contacts fail to reach you if you remove transport transport-a@example.org:
Fiona
These contacts fail to reach you if you remove transport transport-b@example.org:
Bob
These contacts likely can't reach you anymore:

For these contacts, it's unclear how they can reach you:
Dom",
        "Transport usage output didn't match, actual output was:\n{actual}\n"
    );

    alice.delete_transport("transport-a@example.org").await?;

    let actual = get_debug_transport_knowledge(alice).await?;
    assert_eq!(
        actual,
        "=== Usage of transports by contacts ===
These contacts fail to reach you if you remove transport alice@example.org:

These contacts fail to reach you if you remove transport transport-b@example.org:
Bob
Charlie
These contacts likely can't reach you anymore:
Fiona
For these contacts, it's unclear how they can reach you:
Dom",
        "Transport usage output didn't match, actual output was:\n{actual}\n"
    );

    Ok(())
}
