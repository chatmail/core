use super::*;
use crate::test_utils::TestContext;

#[test]
fn test_connect_prefers_login_error() {
    let connection_error = format_err!("All connection attempts failed");
    let login_error = format_err!("Cannot login, please check the password");

    let error = select_connect_error(Some(connection_error), Some(login_error));

    assert_eq!(error.to_string(), "Cannot login, please check the password");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_uid_next_validity() {
    let t = TestContext::new_alice().await;
    assert_eq!(get_uid_next(&t.ctx, 1, "Inbox").await.unwrap(), 0);
    assert_eq!(get_uidvalidity(&t.ctx, 1, "Inbox").await.unwrap(), 0);

    set_uidvalidity(&t.ctx, 1, "Inbox", 7).await.unwrap();
    assert_eq!(get_uidvalidity(&t.ctx, 1, "Inbox").await.unwrap(), 7);
    assert_eq!(get_uid_next(&t.ctx, 1, "Inbox").await.unwrap(), 0);

    // For another transport there is still no UIDVALIDITY set.
    assert_eq!(get_uidvalidity(&t.ctx, 2, "Inbox").await.unwrap(), 0);

    set_uid_next(&t.ctx, 1, "Inbox", 5).await.unwrap();
    set_uidvalidity(&t.ctx, 1, "Inbox", 6).await.unwrap();
    assert_eq!(get_uid_next(&t.ctx, 1, "Inbox").await.unwrap(), 5);
    assert_eq!(get_uidvalidity(&t.ctx, 1, "Inbox").await.unwrap(), 6);

    assert_eq!(get_uid_next(&t.ctx, 2, "Inbox").await.unwrap(), 0);
    assert_eq!(get_uidvalidity(&t.ctx, 2, "Inbox").await.unwrap(), 0);
}

#[test]
fn test_build_sequence_sets() {
    assert_eq!(build_sequence_sets(&[]).unwrap(), vec![]);

    let cases = vec![
        (vec![1], "1"),
        (vec![3291], "3291"),
        (vec![1, 3, 5, 7, 9, 11], "1,3,5,7,9,11"),
        (vec![1, 2, 3], "1:3"),
        (vec![1, 4, 5, 6], "1,4:6"),
        ((1..=500).collect(), "1:500"),
        (vec![3, 4, 8, 9, 10, 11, 39, 50, 2], "3:4,8:11,39,50,2"),
    ];
    for (input, s) in cases {
        assert_eq!(
            build_sequence_sets(&input).unwrap(),
            vec![(input, s.into())]
        );
    }

    let has_number = |(uids, s): &(Vec<u32>, String), number| {
        uids.contains(&number) && s.split(',').any(|n| n.parse::<u32>().unwrap() == number)
    };

    let numbers: Vec<_> = (2..=500).step_by(2).collect();
    let result = build_sequence_sets(&numbers).unwrap();
    for (_, set) in &result {
        assert!(set.len() < 1010);
        assert!(!set.ends_with(','));
        assert!(!set.starts_with(','));
    }
    assert!(result.len() == 1); // these UIDs fit in one set
    for &number in &numbers {
        assert!(result.iter().any(|r| has_number(r, number)));
    }

    let numbers: Vec<_> = (1..=1000).step_by(3).collect();
    let result = build_sequence_sets(&numbers).unwrap();
    for (_, set) in &result {
        assert!(set.len() < 1010);
        assert!(!set.ends_with(','));
        assert!(!set.starts_with(','));
    }
    let (last_uids, last_str) = result.last().unwrap();
    assert_eq!(
        last_uids.get((last_uids.len() - 2)..).unwrap(),
        &[997, 1000]
    );
    assert!(last_str.ends_with("997,1000"));
    assert!(result.len() == 2); // This time we need 2 sets
    for &number in &numbers {
        assert!(result.iter().any(|r| has_number(r, number)));
    }

    let numbers: Vec<_> = (30000000..=30002500).step_by(4).collect();
    let result = build_sequence_sets(&numbers).unwrap();
    for (_, set) in &result {
        assert!(set.len() < 1010);
        assert!(!set.ends_with(','));
        assert!(!set.starts_with(','));
    }
    assert_eq!(result.len(), 6);
    for &number in &numbers {
        assert!(result.iter().any(|r| has_number(r, number)));
    }
}

#[test]
fn test_uid_grouper() {
    // Input: sequence of (rowid: i64, uid: u32, target: String)
    // Output: sequence of (target: String, rowid_set: Vec<i64>, uid_set: String)
    let grouper = UidGrouper::from([(1, 2, "INBOX".to_string())]);
    let res: Vec<(String, Vec<i64>, String)> = grouper.into_iter().collect();
    assert_eq!(res, vec![("INBOX".to_string(), vec![1], "2".to_string())]);

    let grouper = UidGrouper::from([(1, 2, "INBOX".to_string()), (2, 3, "INBOX".to_string())]);
    let res: Vec<(String, Vec<i64>, String)> = grouper.into_iter().collect();
    assert_eq!(
        res,
        vec![("INBOX".to_string(), vec![1, 2], "2:3".to_string())]
    );

    let grouper = UidGrouper::from([
        (1, 2, "INBOX".to_string()),
        (2, 2, "INBOX".to_string()),
        (3, 3, "INBOX".to_string()),
    ]);
    let res: Vec<(String, Vec<i64>, String)> = grouper.into_iter().collect();
    assert_eq!(
        res,
        vec![("INBOX".to_string(), vec![1, 2, 3], "2:3".to_string())]
    );
}
