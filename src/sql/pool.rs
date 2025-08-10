//! # SQLite connection pool.
//!
//! The connection pool holds a number of SQLite connections and allows to allocate them.
//! When allocated connection is dropped, underlying connection is returned back to the pool.
//!
//! The pool is organized as a stack. It always allocates the most recently used connection.
//! Each SQLite connection has its own page cache, so allocating recently used connections
//! improves the performance compared to, for example, organizing the pool as a queue
//! and returning the least recently used connection each time.
//!
//! Pool returns at most one write connection (with `PRAGMA query_only=0`).
//! This ensures that there never are multiple write transactions at once.
//!
//! Doing the locking ourselves instead of relying on SQLite has these reasons:
//!
//! - SQLite's locking mechanism is non-async, blocking a thread
//! - SQLite's locking mechanism just sleeps in a loop, which is really inefficient
//!
//! ---
//!
//! More considerations on alternatives to the current approach:
//!
//! We use [DEFERRED](https://www.sqlite.org/lang_transaction.html#deferred_immediate_and_exclusive_transactions) transactions.
//!
//! In order to never get concurrency issues, we could make all transactions IMMEDIATE,
//! but this would mean that there can never be two simultaneous transactions.
//!
//! Read transactions can simply be made DEFERRED to run in parallel w/o any drawbacks.
//!
//! DEFERRED write transactions without doing the locking ourselves would have these drawbacks:
//!
//! 1. As mentioned above, SQLite's locking mechanism is non-async and sleeps in a loop.
//! 2. If there are other write transactions, we block the db connection until
//!    upgraded. If some reader comes then, it has to get the next, less used connection with a
//!    worse per-connection page cache (SQLite allows one write and any number of reads in parallel).
//! 3. If a transaction is blocked for more than `busy_timeout`, it fails with SQLITE_BUSY.
//! 4. If upon a successful upgrade to a write transaction the db has been modified,
//!    the transaction has to be rolled back and retried, which means extra work in terms of
//!    CPU/battery.
//!
//! The only pro of making write transactions DEFERRED w/o the external locking would be some
//! parallelism between them.
//!
//! Another option would be to make write transactions IMMEDIATE, also
//! w/o the external locking. But then cons 1. - 3. above would still be valid.

use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Weak};

use anyhow::{Context, Result};
use rusqlite::Connection;
use tokio::sync::{Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};

/// Inner connection pool.
#[derive(Debug)]
struct InnerPool {
    /// Available connections.
    connections: parking_lot::Mutex<Vec<Connection>>,

    /// Counts the number of available connections.
    semaphore: Arc<Semaphore>,

    /// Write mutex.
    ///
    /// This mutex ensures there is at most
    /// one write connection with `query_only=0`.
    ///
    /// This mutex is locked when write connection
    /// is outside the pool.
    pub(crate) write_mutex: Arc<Mutex<()>>,
}

impl InnerPool {
    /// Puts a connection into the pool.
    ///
    /// The connection could be new or returned back.
    fn put(&self, connection: Connection) {
        let mut connections = self.connections.lock();
        connections.push(connection);
        drop(connections);
    }

    /// Retrieves a connection from the pool.
    ///
    /// Sets `query_only` pragma to the provided value
    /// to prevent accidental misuse of connection
    /// for writing when reading is intended.
    /// Only pass `query_only=false` if you want
    /// to use the connection for writing.
    pub async fn get(self: Arc<Self>, query_only: bool) -> Result<PooledConnection> {
        if query_only {
            let permit = self.semaphore.clone().acquire_owned().await?;
            let conn = {
                let mut connections = self.connections.lock();
                connections
                    .pop()
                    .context("Got a permit when there are no connections in the pool")?
            };
            let conn = PooledConnection {
                pool: Arc::downgrade(&self),
                conn: Some(conn),
                _permit: permit,
                _write_mutex_guard: None,
            };
            conn.pragma_update(None, "query_only", "1")?;
            Ok(conn)
        } else {
            // We get write guard first to avoid taking a permit
            // and not using it, blocking a reader from getting a connection
            // while being ourselves blocked by another wrtier.
            let write_mutex_guard = Arc::clone(&self.write_mutex).lock_owned().await;

            // We may still have to wait for a connection
            // to be returned by some reader.
            let permit = self.semaphore.clone().acquire_owned().await?;
            let conn = {
                let mut connections = self.connections.lock();
                connections.pop().context(
                    "Got a permit and write lock when there are no connections in the pool",
                )?
            };
            let conn = PooledConnection {
                pool: Arc::downgrade(&self),
                conn: Some(conn),
                _permit: permit,
                _write_mutex_guard: Some(write_mutex_guard),
            };
            conn.pragma_update(None, "query_only", "0")?;
            Ok(conn)
        }
    }
}

/// Pooled connection.
pub struct PooledConnection {
    /// Weak reference to the pool used to return the connection back.
    pool: Weak<InnerPool>,

    /// Only `None` right after moving the connection back to the pool.
    conn: Option<Connection>,

    /// Semaphore permit, dropped after returning the connection to the pool.
    _permit: OwnedSemaphorePermit,

    /// Write mutex guard.
    ///
    /// `None` for read-only connections with `PRAGMA query_only=1`.
    _write_mutex_guard: Option<OwnedMutexGuard<()>>,
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        // Put the connection back unless the pool is already dropped.
        if let Some(pool) = self.pool.upgrade() {
            if let Some(conn) = self.conn.take() {
                pool.put(conn);
            }
        }
    }
}

impl Deref for PooledConnection {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.conn.as_ref().unwrap()
    }
}

impl DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().unwrap()
    }
}

/// Connection pool.
#[derive(Clone, Debug)]
pub struct Pool {
    /// Reference to the actual connection pool.
    inner: Arc<InnerPool>,
}

impl Pool {
    /// Creates a new connection pool.
    pub fn new(connections: Vec<Connection>) -> Self {
        let semaphore = Arc::new(Semaphore::new(connections.len()));
        let inner = Arc::new(InnerPool {
            connections: parking_lot::Mutex::new(connections),
            semaphore,
            write_mutex: Default::default(),
        });
        Pool { inner }
    }

    pub async fn get(&self, query_only: bool) -> Result<PooledConnection> {
        Arc::clone(&self.inner).get(query_only).await
    }

    /// Returns a mutex guard guaranteeing that there are no concurrent write connections.
    ///
    /// NB: Make sure you're not holding all connections when calling this, otherwise it deadlocks
    /// if there is a concurrent writer waiting for available connection.
    pub(crate) async fn write_lock(&self) -> OwnedMutexGuard<()> {
        Arc::clone(&self.inner.write_mutex).lock_owned().await
    }
}
