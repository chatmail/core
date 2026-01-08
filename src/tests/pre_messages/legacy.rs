//! Test that downloading old stub messages still works
use anyhow::Result;

use crate::download::DownloadState;
use crate::receive_imf::receive_imf_from_inbox;
use crate::test_utils::TestContext;

// The code for downloading stub messages stays
// during the transition perios to pre-messages
// so people can still download their files shortly after they updated.
// After there are a few release with pre-message rolled out,
// we will remove the ability to download stub messages and replace the following test
// so it checks that it doesn't crash or that the messages are replaced by sth.
// like "download failed/expired, please ask sender to send it again"
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_download_stub_message() -> Result<()> {
    let t = TestContext::new_alice().await;

    let header = "Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
             From: bob@example.com\n\
             To: alice@example.org\n\
             Subject: foo\n\
             Message-ID: <Mr.12345678901@example.com>\n\
             Chat-Version: 1.0\n\
             Date: Sun, 22 Mar 2020 22:37:57 +0000\
             Content-Type: text/plain";

    t.sql
        .execute(
            r#"INSERT INTO chats VALUES(
                    11001,100,'bob@example.com',0,'',2,'',
                    replace('C=1763151754\nt=foo','\n',char(10)),0,0,0,0,0,1763151754,0,NULL,0,'');
                "#,
            (),
        )
        .await?;
    t.sql.execute(r#"INSERT INTO msgs VALUES(
                11001,'Mr.12345678901@example.com','',0,
                11001,11001,1,1763151754,10,10,1,0,
                '[97.66 KiB message]','','',0,1763151754,1763151754,0,X'',
                '','',1,0,'',0,0,0,'foo',10,replace('Hop: From: userid; Date: Mon, 4 Dec 2006 13:51:39 +0000\n\nDKIM Results: Passed=true','\n',char(10)),1,NULL,0,'');
        "#, ()).await?;
    let msg = t.get_last_msg().await;
    assert_eq!(msg.download_state(), DownloadState::Available);
    assert_eq!(msg.get_subject(), "foo");
    assert!(msg.get_text().contains("[97.66 KiB message]"));

    receive_imf_from_inbox(
        &t,
        "Mr.12345678901@example.com",
        format!("{header}\n\n100k text...").as_bytes(),
        false,
    )
    .await?;
    let msg = t.get_last_msg().await;
    assert_eq!(msg.download_state(), DownloadState::Done);
    assert_eq!(msg.get_subject(), "foo");
    assert_eq!(msg.get_text(), "100k text...");

    Ok(())
}
