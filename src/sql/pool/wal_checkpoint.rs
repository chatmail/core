//! # WAL checkpointing for SQLite connection pool.

use anyhow::{Result, ensure};
use std::sync::Arc;
use std::time::Duration;

use crate::sql::Sql;
use crate::tools::{Time, time_elapsed};

use super::Pool;

/// Information about WAL checkpointing call for logging.
#[derive(Debug)]
pub(crate) struct WalCheckpointStats {
    /// Duration of the whole WAL checkpointing.
    pub total_duration: Duration,

    /// Duration for which WAL checkpointing blocked the writers.
    pub writers_blocked_duration: Duration,

    /// Duration for which WAL checkpointing blocked the readers.
    pub readers_blocked_duration: Duration,

    /// Number of pages in WAL before truncating.
    pub pages_total: i64,

    /// Number of checkpointed WAL pages.
    ///
    /// It should be the same as `pages_total`
    /// unless there are external connections to the database
    /// that are not in the pool.
    pub pages_checkpointed: i64,
}

/// Runs a checkpoint operation in TRUNCATE mode, so the WAL file is truncated to 0 bytes.
pub(super) async fn wal_checkpoint(pool: &Pool) -> Result<WalCheckpointStats> {
    let t_start = Time::now();

    // Do as much work as possible without blocking anybody.
    let query_only = true;
    let conn = pool.get(query_only).await?;
    tokio::task::block_in_place(|| {
        // Execute some transaction causing the WAL file to be opened so that the
        // `wal_checkpoint()` can proceed, otherwise it fails when called the first time,
        // see https://sqlite.org/forum/forumpost/7512d76a05268fc8.
        conn.query_row("PRAGMA table_list", [], |_| Ok(()))?;
        conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()))
    })?;

    // Kick out writers. `write_mutex` should be locked before taking an `InnerPool.semaphore`
    // permit to avoid ABBA deadlocks, so drop `conn` which holds a semaphore permit.
    drop(conn);
    let _write_lock = Arc::clone(&pool.inner.write_mutex).lock_owned().await;
    let t_writers_blocked = Time::now();
    let conn = pool.get(query_only).await?;
    // Ensure that all readers use the most recent database snapshot (are at the end of WAL) so
    // that `wal_checkpoint(FULL)` isn't blocked. We could use `PASSIVE` as well, but it's
    // documented poorly, https://www.sqlite.org/pragma.html#pragma_wal_checkpoint and
    // https://www.sqlite.org/c3ref/wal_checkpoint_v2.html don't tell how it interacts with new
    // readers.
    let mut read_conns = Vec::with_capacity(Sql::N_DB_CONNECTIONS - 1);
    for _ in 0..(Sql::N_DB_CONNECTIONS - 1) {
        read_conns.push(pool.get(query_only).await?);
    }
    read_conns.clear();
    // Checkpoint the remaining WAL pages without blocking readers.
    let (pages_total, pages_checkpointed) = tokio::task::block_in_place(|| {
        conn.query_row("PRAGMA table_list", [], |_| Ok(()))?;
        conn.query_row("PRAGMA wal_checkpoint(FULL)", [], |row| {
            let pages_total: i64 = row.get(1)?;
            let pages_checkpointed: i64 = row.get(2)?;
            Ok((pages_total, pages_checkpointed))
        })
    })?;
    // Kick out readers to avoid blocking/SQLITE_BUSY.
    for _ in 0..(Sql::N_DB_CONNECTIONS - 1) {
        read_conns.push(pool.get(query_only).await?);
    }
    let t_readers_blocked = Time::now();
    tokio::task::block_in_place(|| {
        let blocked = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            let blocked: i64 = row.get(0)?;
            Ok(blocked)
        })?;
        ensure!(blocked == 0);
        Ok(())
    })?;
    Ok(WalCheckpointStats {
        total_duration: time_elapsed(&t_start),
        writers_blocked_duration: time_elapsed(&t_writers_blocked),
        readers_blocked_duration: time_elapsed(&t_readers_blocked),
        pages_total,
        pages_checkpointed,
    })
}
