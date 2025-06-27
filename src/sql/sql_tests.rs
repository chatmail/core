use super::*;
use crate::{EventType, test_utils::TestContext};

#[test]
fn test_maybe_add_file() {
    let mut files = Default::default();
    maybe_add_file(&mut files, "$BLOBDIR/hello");
    maybe_add_file(&mut files, "$BLOBDIR/world.txt");
    maybe_add_file(&mut files, "world2.txt");
    maybe_add_file(&mut files, "$BLOBDIR");

    assert!(files.contains("hello"));
    assert!(files.contains("world.txt"));
    assert!(!files.contains("world2.txt"));
    assert!(!files.contains("$BLOBDIR"));
}

#[test]
fn test_is_file_in_use() {
    let mut files = Default::default();
    maybe_add_file(&mut files, "$BLOBDIR/hello");
    maybe_add_file(&mut files, "$BLOBDIR/world.txt");
    maybe_add_file(&mut files, "world2.txt");

    assert!(is_file_in_use(&files, None, "hello"));
    assert!(!is_file_in_use(&files, Some(".txt"), "hello"));
    assert!(is_file_in_use(&files, Some("-suffix"), "world.txt-suffix"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_table_exists() {
    let t = TestContext::new().await;
    assert!(t.ctx.sql.table_exists("msgs").await.unwrap());
    assert!(!t.ctx.sql.table_exists("foobar").await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_col_exists() {
    let t = TestContext::new().await;
    assert!(t.ctx.sql.col_exists("msgs", "mime_modified").await.unwrap());
    assert!(!t.ctx.sql.col_exists("msgs", "foobar").await.unwrap());
    assert!(!t.ctx.sql.col_exists("foobar", "foobar").await.unwrap());
}

/// Tests that auto_vacuum is enabled for new databases.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_auto_vacuum() -> Result<()> {
    let t = TestContext::new().await;

    let query_only = true;
    let auto_vacuum = t
        .sql
        .call(query_only, |conn| {
            let auto_vacuum = conn.pragma_query_value(None, "auto_vacuum", |row| {
                let auto_vacuum: i32 = row.get(0)?;
                Ok(auto_vacuum)
            })?;
            Ok(auto_vacuum)
        })
        .await?;

    // auto_vacuum=2 is the same as auto_vacuum=INCREMENTAL
    assert_eq!(auto_vacuum, 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_housekeeping_db_closed() {
    let t = TestContext::new().await;

    let avatar_src = t.dir.path().join("avatar.png");
    let avatar_bytes = include_bytes!("../../test-data/image/avatar64x64.png");
    tokio::fs::write(&avatar_src, avatar_bytes).await.unwrap();
    t.set_config(Config::Selfavatar, Some(avatar_src.to_str().unwrap()))
        .await
        .unwrap();

    let event_source = t.get_event_emitter();

    let a = t.get_config(Config::Selfavatar).await.unwrap().unwrap();
    assert_eq!(avatar_bytes, &tokio::fs::read(&a).await.unwrap()[..]);

    t.sql.close().await;
    housekeeping(&t).await.unwrap(); // housekeeping should emit warnings but not fail
    t.sql.open(&t, "".to_string()).await.unwrap();

    let a = t.get_config(Config::Selfavatar).await.unwrap().unwrap();
    assert_eq!(avatar_bytes, &tokio::fs::read(&a).await.unwrap()[..]);

    while let Ok(event) = event_source.try_recv() {
        match event.typ {
            EventType::Info(s) => assert!(
                !s.contains("Keeping new unreferenced file"),
                "File {s} was almost deleted, only reason it was kept is that it was created recently (as the tests don't run for a long time)"
            ),
            EventType::Error(s) => panic!("{}", s),
            _ => {}
        }
    }
}

/// Regression test for a bug where housekeeping deleted drafts since their
/// `hidden` flag is set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_housekeeping_dont_delete_drafts() {
    let t = TestContext::new_alice().await;

    let chat = t.create_chat_with_contact("bob", "bob@example.com").await;
    let mut new_draft = Message::new_text("This is my draft".to_string());
    chat.id.set_draft(&t, Some(&mut new_draft)).await.unwrap();

    housekeeping(&t).await.unwrap();

    let loaded_draft = chat.id.get_draft(&t).await.unwrap();
    assert_eq!(loaded_draft.unwrap().text, "This is my draft");
}

/// Tests that `housekeeping` deletes the blobs backup dir which is created normally by
/// `imex::import_backup`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_housekeeping_delete_blobs_backup_dir() {
    let t = TestContext::new_alice().await;
    let dir = t.get_blobdir().join(BLOBS_BACKUP_NAME);
    tokio::fs::create_dir(&dir).await.unwrap();
    tokio::fs::write(dir.join("f"), "").await.unwrap();
    housekeeping(&t).await.unwrap();
    tokio::fs::create_dir(&dir).await.unwrap();
}

/// Regression test.
///
/// Previously the code checking for existence of `config` table
/// checked it with `PRAGMA table_info("config")` but did not
/// drain `SqlitePool.fetch` result, only using the first row
/// returned. As a result, prepared statement for `PRAGMA` was not
/// finalized early enough, leaving reader connection in a broken
/// state after reopening the database, when `config` table
/// existed and `PRAGMA` returned non-empty result.
///
/// Statements were not finalized due to a bug in sqlx:
/// <https://github.com/launchbadge/sqlx/issues/1147>
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_db_reopen() -> Result<()> {
    use tempfile::tempdir;

    // The context is used only for logging.
    let t = TestContext::new().await;

    // Create a separate empty database for testing.
    let dir = tempdir()?;
    let dbfile = dir.path().join("testdb.sqlite");
    let sql = Sql::new(dbfile);

    // Create database with all the tables.
    sql.open(&t, "".to_string()).await.unwrap();
    sql.close().await;

    // Reopen the database
    sql.open(&t, "".to_string()).await?;
    sql.execute(
        "INSERT INTO config (keyname, value) VALUES (?, ?);",
        ("foo", "bar"),
    )
    .await?;

    let value: Option<String> = sql
        .query_get_value("SELECT value FROM config WHERE keyname=?;", ("foo",))
        .await?;
    assert_eq!(value.unwrap(), "bar");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_migration_flags() -> Result<()> {
    let t = TestContext::new().await;
    t.evtracker.get_info_contains("Opened database").await;

    // as migrations::run() was already executed on context creation,
    // another call should not result in any action needed.
    // this test catches some bugs where dbversion was forgotten to be persisted.
    let (update_icons, disable_server_delete, recode_avatar) = migrations::run(&t, &t.sql).await?;
    assert!(!update_icons);
    assert!(!disable_server_delete);
    assert!(!recode_avatar);

    info!(&t, "test_migration_flags: XXX END MARKER");

    loop {
        let evt = t
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::Info(_)))
            .await;
        match evt {
            EventType::Info(msg) => {
                assert!(
                    !msg.contains("[migration]"),
                    "Migrations were run twice, you probably forgot to update the db version"
                );
                if msg.contains("test_migration_flags: XXX END MARKER") {
                    break;
                }
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_check_passphrase() -> Result<()> {
    use tempfile::tempdir;

    // The context is used only for logging.
    let t = TestContext::new().await;

    // Create a separate empty database for testing.
    let dir = tempdir()?;
    let dbfile = dir.path().join("testdb.sqlite");
    let sql = Sql::new(dbfile.clone());

    sql.check_passphrase("foo".to_string()).await?;
    sql.open(&t, "foo".to_string())
        .await
        .context("failed to open the database first time")?;
    sql.close().await;

    // Reopen the database
    let sql = Sql::new(dbfile);

    // Test that we can't open encrypted database without a passphrase.
    assert!(sql.open(&t, "".to_string()).await.is_err());

    // Now open the database with passpharse, it should succeed.
    sql.check_passphrase("foo".to_string()).await?;
    sql.open(&t, "foo".to_string())
        .await
        .context("failed to open the database second time")?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sql_change_passphrase() -> Result<()> {
    use tempfile::tempdir;

    // The context is used only for logging.
    let t = TestContext::new().await;

    // Create a separate empty database for testing.
    let dir = tempdir()?;
    let dbfile = dir.path().join("testdb.sqlite");
    let sql = Sql::new(dbfile.clone());

    sql.open(&t, "foo".to_string())
        .await
        .context("failed to open the database first time")?;
    sql.close().await;

    // Change the passphrase from "foo" to "bar".
    let sql = Sql::new(dbfile.clone());
    sql.open(&t, "foo".to_string())
        .await
        .context("failed to open the database second time")?;
    sql.change_passphrase("bar".to_string())
        .await
        .context("failed to change passphrase")?;

    // Test that at least two connections are still working.
    // This ensures that not only the connection which changed the password is working,
    // but other connections as well.
    {
        let lock = sql.pool.read().await;
        let pool = lock.as_ref().unwrap();
        let query_only = true;
        let conn1 = pool.get(query_only).await?;
        let conn2 = pool.get(query_only).await?;
        conn1
            .query_row("SELECT count(*) FROM sqlite_master", [], |_row| Ok(()))
            .unwrap();
        conn2
            .query_row("SELECT count(*) FROM sqlite_master", [], |_row| Ok(()))
            .unwrap();
    }

    sql.close().await;

    let sql = Sql::new(dbfile);

    // Test that old passphrase is not working.
    assert!(sql.open(&t, "foo".to_string()).await.is_err());

    // Open the database with the new passphrase.
    sql.check_passphrase("bar".to_string()).await?;
    sql.open(&t, "bar".to_string())
        .await
        .context("failed to open the database third time")?;
    sql.close().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_query_only() -> Result<()> {
    let t = TestContext::new().await;

    // `query_row` does not acquire write lock
    // and operates on read-only connection.
    // Using it to `INSERT` should fail.
    let res = t
        .sql
        .query_row(
            "INSERT INTO config (keyname, value) VALUES (?, ?) RETURNING 1",
            ("xyz", "ijk"),
            |row| {
                let res: u32 = row.get(0)?;
                Ok(res)
            },
        )
        .await;
    assert!(res.is_err());

    // If you want to `INSERT` and get value via `RETURNING`,
    // use `call_write` or `transaction`.

    let res: Result<u32> = t
        .sql
        .call_write(|conn| {
            let val = conn.query_row(
                "INSERT INTO config (keyname, value) VALUES (?, ?) RETURNING 2",
                ("foo", "bar"),
                |row| {
                    let res: u32 = row.get(0)?;
                    Ok(res)
                },
            )?;
            Ok(val)
        })
        .await;
    assert_eq!(res.unwrap(), 2);

    let res = t
        .sql
        .transaction(|t| {
            let val = t.query_row(
                "INSERT INTO config (keyname, value) VALUES (?, ?) RETURNING 3",
                ("abc", "def"),
                |row| {
                    let res: u32 = row.get(0)?;
                    Ok(res)
                },
            )?;
            Ok(val)
        })
        .await;
    assert_eq!(res.unwrap(), 3);

    Ok(())
}

/// Tests that incremental_vacuum does not fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_incremental_vacuum() -> Result<()> {
    let t = TestContext::new().await;

    incremental_vacuum(&t).await?;

    Ok(())
}
