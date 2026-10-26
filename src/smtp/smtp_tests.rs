use anyhow::Result;

use super::sorted_transport_ids;
use crate::test_utils::TestContextManager;
use crate::transport;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_candidates() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let t = &tcm.unconfigured().await;

    transport::add_pseudo_transport(t, "foo@example.net").await?;
    transport::add_pseudo_transport(t, "bar@example.net").await?;
    transport::add_pseudo_transport(t, "baz@example.net").await?;

    // By default first added transport is used first.
    assert_eq!(sorted_transport_ids(t).await?, [1, 2, 3]);

    super::record_success(t, 3).await?;
    assert_eq!(sorted_transport_ids(t).await?, [3, 1, 2]);

    super::record_success(t, 2).await?;
    assert_eq!(sorted_transport_ids(t).await?, [2, 3, 1]);

    super::record_success(t, 3).await?;
    assert_eq!(sorted_transport_ids(t).await?, [3, 2, 1]);

    super::record_failure(t, 3).await?;
    assert_eq!(sorted_transport_ids(t).await?, [2, 1, 3]);

    // New transport is added before all failing transports.
    transport::add_pseudo_transport(t, "qux@example.net").await?;
    assert_eq!(sorted_transport_ids(t).await?, [2, 1, 4, 3]);

    super::record_success(t, 4).await?;
    assert_eq!(sorted_transport_ids(t).await?, [4, 2, 1, 3]);

    super::record_failure(t, 4).await?;
    assert_eq!(sorted_transport_ids(t).await?, [2, 1, 3, 4]);
    super::record_failure(t, 3).await?;
    assert_eq!(sorted_transport_ids(t).await?, [2, 1, 4, 3]);
    super::record_failure(t, 2).await?;
    assert_eq!(sorted_transport_ids(t).await?, [1, 4, 3, 2]);

    Ok(())
}
