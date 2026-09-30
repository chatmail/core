use anyhow::Result;

use crate::test_utils::TestContextManager;
use crate::transport;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_candidates() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let t = &tcm.unconfigured().await;

    transport::add_pseudo_transport(t, "foo@example.net").await?;
    transport::add_pseudo_transport(t, "bar@example.net").await?;
    transport::add_pseudo_transport(t, "baz@example.net").await?;

    let transports = super::sorted_transports(t).await?;
    let [
        (transport_id1, ref transport1),
        (transport_id2, ref transport2),
        (transport_id3, ref transport3),
    ] = transports[..]
    else {
        panic!("Unexpected number of transports");
    };

    // By default first added transport is used first.
    assert_eq!(transport1.addr, "foo@example.net");
    assert_eq!(transport2.addr, "bar@example.net");
    assert_eq!(transport3.addr, "baz@example.net");

    super::record_success(t, transport_id3).await?;
    let transports2 = super::sorted_transports(t).await?;
    assert_eq!(transports2[0].0, transport_id3);
    assert_eq!(transports2[1].0, transport_id1);
    assert_eq!(transports2[2].0, transport_id2);

    super::record_success(t, transport_id2).await?;
    let transports3 = super::sorted_transports(t).await?;
    assert_eq!(transports3[0].0, transport_id2);
    assert_eq!(transports3[1].0, transport_id3);
    assert_eq!(transports3[2].0, transport_id1);

    super::record_success(t, transport_id3).await?;
    let transports4 = super::sorted_transports(t).await?;
    assert_eq!(transports4[0].0, transport_id3);
    assert_eq!(transports4[1].0, transport_id2);
    assert_eq!(transports4[2].0, transport_id1);

    Ok(())
}
