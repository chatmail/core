use crate::smtp::{send_smtp_chunks, SendResult, SmtpSender};
use crate::test_utils::TestContextManager;
use crate::context::Context;
use anyhow::Result;
use futures::future::{BoxFuture, FutureExt};

/// Result the mock should return on the designated call.
enum MockFailure {
    Transient,
    Permanent,
}

struct MockSmtpSender {
    call_count: usize,
    fail_on_call: Option<(usize, MockFailure)>,
}

impl SmtpSender for MockSmtpSender {
    fn send_chunk<'a>(
        &'a mut self,
        _context: &'a Context,
        _recipients: &'a [async_smtp::EmailAddress],
        _body: &'a str,
    ) -> BoxFuture<'a, SendResult> {
        self.call_count += 1;
        let count = self.call_count;
        let fail_on = self.fail_on_call.as_ref().map(|(n, _)| *n);
        let is_permanent = matches!(
            self.fail_on_call,
            Some((_, MockFailure::Permanent))
        );
        async move {
            if fail_on == Some(count) {
                if is_permanent {
                    return SendResult::Failure(
                        anyhow::format_err!("permanent error"),
                    );
                }
                return SendResult::Retry;
            }
            SendResult::Success
        }
        .boxed()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_smtp_chunks() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;

    let recipients: Vec<_> = ["r1@ex.org", "r2@ex.org", "r3@ex.org", "r4@ex.org", "r5@ex.org"]
        .iter()
        .map(|a| async_smtp::EmailAddress::new(a.to_string()).unwrap())
        .collect();

    // All chunks succeed.
    let mut sender = MockSmtpSender { call_count: 0, fail_on_call: None };
    let (status, processed) =
        send_smtp_chunks(&alice.ctx, &recipients, "body", 2, &mut sender).await;
    assert!(matches!(status, SendResult::Success));
    assert_eq!(processed, 5);
    assert_eq!(sender.call_count, 3); // chunks: [2, 2, 1]

    // Second chunk gets a transient error, only first chunk's recipients are processed.
    let mut sender =
        MockSmtpSender { call_count: 0, fail_on_call: Some((2, MockFailure::Transient)) };
    let (status, processed) =
        send_smtp_chunks(&alice.ctx, &recipients, "body", 2, &mut sender).await;
    assert!(matches!(status, SendResult::Retry));
    assert_eq!(processed, 2);
    assert_eq!(sender.call_count, 2);

    // Last chunk gets a transient error, first two chunks' recipients are processed.
    let mut sender =
        MockSmtpSender { call_count: 0, fail_on_call: Some((3, MockFailure::Transient)) };
    let (status, processed) =
        send_smtp_chunks(&alice.ctx, &recipients, "body", 2, &mut sender).await;
    assert!(matches!(status, SendResult::Retry));
    assert_eq!(processed, 4);
    assert_eq!(sender.call_count, 3);

    // Second chunk gets a permanent error; processed includes the failed chunk.
    let mut sender =
        MockSmtpSender { call_count: 0, fail_on_call: Some((2, MockFailure::Permanent)) };
    let (status, processed) =
        send_smtp_chunks(&alice.ctx, &recipients, "body", 2, &mut sender).await;
    assert!(matches!(status, SendResult::Failure(_)));
    assert_eq!(processed, 4);
    assert_eq!(sender.call_count, 2);

    // Last chunk gets a permanent error; processed includes the failed chunk.
    let mut sender =
        MockSmtpSender { call_count: 0, fail_on_call: Some((3, MockFailure::Permanent)) };
    let (status, processed) =
        send_smtp_chunks(&alice.ctx, &recipients, "body", 2, &mut sender).await;
    assert!(matches!(status, SendResult::Failure(_)));
    assert_eq!(processed, 6); // capped at (i+1)*chunk_size, may exceed len
    assert_eq!(sender.call_count, 3);

    Ok(())
}
