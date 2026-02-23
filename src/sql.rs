//! # SQLite wrapper.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use rusqlite::{Connection, OpenFlags, Row, config::DbConfig, types::ValueRef};
use tokio::sync::RwLock;

use crate::blob::BlobObject;
use crate::chat::add_device_msg;
use crate::config::Config;
use crate::constants::DC_CHAT_ID_TRASH;
use crate::context::Context;
use crate::debug_logging::set_debug_logging_xdc;
use crate::ephemeral::start_ephemeral_timers;
use crate::imex::BLOBS_BACKUP_NAME;
use crate::location::delete_orphaned_poi_locations;
use crate::log::{LogExt, warn};
use crate::message::Message;
use crate::message::MsgId;
use crate::net::dns::prune_dns_cache;
use crate::net::http::http_cache_cleanup;
use crate::net::prune_connection_history;
use crate::param::{Param, Params};
use crate::stock_str;
use crate::tools::{SystemTime, Time, delete_file, time, time_elapsed};

/// Extension to [`rusqlite::ToSql`] trait
/// which also includes [`Send`] and [`Sync`].
pub trait ToSql: rusqlite::ToSql + Send + Sync {}

impl<T: rusqlite::ToSql + Send + Sync> ToSql for T {}

/// Constructs a slice of trait object references `&dyn ToSql`.
///
/// One of the uses is passing more than 16 parameters
/// to a query, because [`rusqlite::Params`] is only implemented
/// for tuples of up to 16 elements.
#[macro_export]
macro_rules! params_slice {
    ($($param:expr),+) => {
        [$(&$param as &dyn $crate::sql::ToSql),+]
    };
}

mod migrations;
mod pool;

use pool::Pool;

/// A wrapper around the underlying Sqlite3 object.
#[derive(Debug)]
pub struct Sql {
    /// Database file path
    pub(crate) dbfile: PathBuf,

    /// SQL connection pool.
    pool: RwLock<Option<Pool>>,

    /// None if the database is not open, true if it is open with passphrase and false if it is
    /// open without a passphrase.
    is_encrypted: RwLock<Option<bool>>,

    /// Cache of `config` table.
    pub(crate) config_cache: RwLock<HashMap<String, Option<String>>>,
}

impl Sql {
    /// Creates new SQL database.
    pub fn new(dbfile: PathBuf) -> Sql {
        Self {
            dbfile,
            pool: Default::default(),
            is_encrypted: Default::default(),
            config_cache: Default::default(),
        }
    }

    /// Tests SQLCipher passphrase.
    ///
    /// Returns true if passphrase is correct, i.e. the database is new or can be unlocked with
    /// this passphrase, and false if the database is already encrypted with another passphrase or
    /// corrupted.
    ///
    /// Fails if database is already open.
    pub async fn check_passphrase(&self, passphrase: String) -> Result<bool> {
        if self.is_open().await {
            bail!("Database is already opened.");
        }

        // Hold the lock to prevent other thread from opening the database.
        let _lock = self.pool.write().await;

        // Test that the key is correct using a single connection.
        let connection = Connection::open(&self.dbfile)?;
        if !passphrase.is_empty() {
            connection
                .pragma_update(None, "key", &passphrase)
                .context("Failed to set PRAGMA key")?;
        }
        let key_is_correct = connection
            .query_row("SELECT count(*) FROM sqlite_master", [], |_row| Ok(()))
            .is_ok();

        Ok(key_is_correct)
    }

    /// Checks if there is currently a connection to the underlying Sqlite database.
    pub async fn is_open(&self) -> bool {
        self.pool.read().await.is_some()
    }

    /// Returns true if the database is encrypted.
    ///
    /// If database is not open, returns `None`.
    pub(crate) async fn is_encrypted(&self) -> Option<bool> {
        *self.is_encrypted.read().await
    }

    /// Closes all underlying Sqlite connections.
    pub(crate) async fn close(&self) {
        let _ = self.pool.write().await.take();
        // drop closes the connection
    }

    /// Imports the database from a separate file with the given passphrase.
    pub(crate) async fn import(&self, path: &Path, passphrase: String) -> Result<()> {
        let path_str = path
            .to_str()
            .with_context(|| format!("path {path:?} is not valid unicode"))?
            .to_string();

        // Keep `config_cache` locked all the time the db is imported so that nobody can use invalid
        // values from there. And clear it immediately so as not to forget in case of errors.
        let mut config_cache = self.config_cache.write().await;
        config_cache.clear();

        let query_only = false;
        self.call(query_only, move |conn| {
            // Check that backup passphrase is correct before resetting our database.
            conn.execute("ATTACH DATABASE ? AS backup KEY ?", (path_str, passphrase))
                .context("failed to attach backup database")?;
            let res = conn
                .query_row("SELECT count(*) FROM sqlite_master", [], |_row| Ok(()))
                .context("backup passphrase is not correct");

            // Reset the database without reopening it. We don't want to reopen the database because we
            // don't have main database passphrase at this point.
            // See <https://sqlite.org/c3ref/c_dbconfig_enable_fkey.html> for documentation.
            // Without resetting import may fail due to existing tables.
            res.and_then(|_| {
                conn.set_db_config(DbConfig::SQLITE_DBCONFIG_RESET_DATABASE, true)
                    .context("failed to set SQLITE_DBCONFIG_RESET_DATABASE")
            })
            .and_then(|_| {
                conn.execute("VACUUM", [])
                    .context("failed to vacuum the database")
            })
            .and(
                conn.set_db_config(DbConfig::SQLITE_DBCONFIG_RESET_DATABASE, false)
                    .context("failed to unset SQLITE_DBCONFIG_RESET_DATABASE"),
            )
            .and_then(|_| {
                conn.query_row("SELECT sqlcipher_export('main', 'backup')", [], |_row| {
                    Ok(())
                })
                .context("failed to import from attached backup database")
            })
            .and(
                conn.execute("DETACH DATABASE backup", [])
                    .context("failed to detach backup database"),
            )?;
            Ok(())
        })
        .await
    }

    const N_DB_CONNECTIONS: usize = 3;

    /// Creates a new connection pool.
    fn new_pool(dbfile: &Path, passphrase: String) -> Result<Pool> {
        let mut connections = Vec::with_capacity(Self::N_DB_CONNECTIONS);
        for _ in 0..Self::N_DB_CONNECTIONS {
            let connection = new_connection(dbfile, &passphrase)?;
            connections.push(connection);
        }

        let pool = Pool::new(connections);
        Ok(pool)
    }

    async fn try_open(&self, context: &Context, dbfile: &Path, passphrase: String) -> Result<()> {
        *self.pool.write().await = Some(Self::new_pool(dbfile, passphrase.to_string())?);

        if let Err(e) = self.run_migrations(context).await {
            error!(context, "Running migrations failed: {e:#}");
            // Emiting an error event probably doesn't work
            // because we are in the process of opening the context,
            // so there is no event emitter yet.
            // So, try to report the error in other ways:
            eprintln!("Running migrations failed: {e:#}");
            context.set_migration_error(&format!("Updating Delta Chat failed. Please send this message to the Delta Chat developers, either at delta@merlinux.eu or at https://support.delta.chat.\n\n{e:#}"));
            // We can't simply close the db for two reasons:
            // a. backup export would fail
            // b. The UI would think that the account is unconfigured (because `is_configured()` fails)
            // and remove the account when the user presses "Back"
        }

        Ok(())
    }

    /// Updates SQL schema to the latest version.
    pub async fn run_migrations(&self, context: &Context) -> Result<()> {
        // (1) update low-level database structure.
        // this should be done before updates that use high-level objects that
        // rely themselves on the low-level structure.

        let recode_avatar = migrations::run(context, self)
            .await
            .context("failed to run migrations")?;

        // (2) updates that require high-level objects
        // the structure is complete now and all objects are usable

        if recode_avatar && let Some(avatar) = context.get_config(Config::Selfavatar).await? {
            let mut blob = BlobObject::from_path(context, Path::new(&avatar))?;
            match blob.recode_to_avatar_size(context).await {
                Ok(()) => {
                    if let Some(path) = blob.to_abs_path().to_str() {
                        context
                            .set_config_internal(Config::Selfavatar, Some(path))
                            .await?;
                    } else {
                        warn!(context, "Setting selfavatar failed: non-UTF-8 filename");
                    }
                }
                Err(e) => {
                    warn!(context, "Migrations can't recode avatar, removing. {:#}", e);
                    context
                        .set_config_internal(Config::Selfavatar, None)
                        .await?
                }
            }
        }

        Ok(())
    }

    /// Opens the provided database and runs any necessary migrations.
    /// If a database is already open, this will return an error.
    pub async fn open(&self, context: &Context, passphrase: String) -> Result<()> {
        if self.is_open().await {
            error!(
                context,
                "Cannot open, database \"{:?}\" already opened.", self.dbfile,
            );
            bail!("SQL database is already opened.");
        }

        let passphrase_nonempty = !passphrase.is_empty();
        self.try_open(context, &self.dbfile, passphrase).await?;
        info!(context, "Opened database {:?}.", self.dbfile);
        *self.is_encrypted.write().await = Some(passphrase_nonempty);

        // setup debug logging if there is an entry containing its id
        if let Some(xdc_id) = self
            .get_raw_config_u32(Config::DebugLogging.as_ref())
            .await?
        {
            set_debug_logging_xdc(context, Some(MsgId::new(xdc_id))).await?;
        }
        Ok(())
    }

    /// Changes the passphrase of encrypted database.
    ///
    /// The database must already be encrypted and the passphrase cannot be empty.
    /// It is impossible to turn encrypted database into unencrypted
    /// and vice versa this way, use import/export for this.
    pub async fn change_passphrase(&self, passphrase: String) -> Result<()> {
        let mut lock = self.pool.write().await;

        let pool = lock.take().context("SQL connection pool is not open")?;
        let query_only = false;
        let conn = pool.get(query_only).await?;
        if !passphrase.is_empty() {
            conn.pragma_update(None, "rekey", passphrase.clone())
                .context("Failed to set PRAGMA rekey")?;
        }
        drop(pool);

        *lock = Some(Self::new_pool(&self.dbfile, passphrase.to_string())?);

        Ok(())
    }

    /// Allocates a connection and calls `function` with the connection.
    ///
    /// If `query_only` is true, allocates read-only connection,
    /// otherwise allocates write connection.
    ///
    /// Returns the result of the function.
    async fn call<'a, F, R>(&'a self, query_only: bool, function: F) -> Result<R>
    where
        F: 'a + FnOnce(&mut Connection) -> Result<R> + Send,
        R: Send + 'static,
    {
        let lock = self.pool.read().await;
        let pool = lock.as_ref().context("no SQL connection")?;
        let mut conn = pool.get(query_only).await?;
        let res = tokio::task::block_in_place(move || function(&mut conn))?;
        Ok(res)
    }

    /// Allocates a connection and calls given function, assuming it does write queries, with the
    /// connection.
    ///
    /// Returns the result of the function.
    pub async fn call_write<'a, F, R>(&'a self, function: F) -> Result<R>
    where
        F: 'a + FnOnce(&mut Connection) -> Result<R> + Send,
        R: Send + 'static,
    {
        let query_only = false;
        self.call(query_only, function).await
    }

    /// Execute `query` assuming it is a write query, returning the number of affected rows.
    pub async fn execute(
        &self,
        query: &str,
        params: impl rusqlite::Params + Send,
    ) -> Result<usize> {
        self.call_write(move |conn| {
            let res = conn.execute(query, params)?;
            Ok(res)
        })
        .await
    }

    /// Executes the given query, returning the last inserted row ID.
    pub async fn insert(&self, query: &str, params: impl rusqlite::Params + Send) -> Result<i64> {
        self.call_write(move |conn| {
            conn.execute(query, params)?;
            Ok(conn.last_insert_rowid())
        })
        .await
    }

    /// Prepares and executes the statement and maps a function over the resulting rows.
    /// Then executes the second function over the returned iterator and returns the
    /// result of that function.
    pub async fn query_map<T, F, G, H>(
        &self,
        sql: &str,
        params: impl rusqlite::Params + Send,
        f: F,
        g: G,
    ) -> Result<H>
    where
        F: Send + FnMut(&rusqlite::Row) -> Result<T>,
        G: Send + FnOnce(rusqlite::AndThenRows<F>) -> Result<H>,
        H: Send + 'static,
    {
        let query_only = true;
        self.call(query_only, move |conn| {
            let mut stmt = conn.prepare(sql)?;
            let res = stmt.query_and_then(params, f)?;
            g(res)
        })
        .await
    }

    /// Prepares and executes the statement and maps a function over the resulting rows.
    ///
    /// Collects the resulting rows into a generic structure.
    pub async fn query_map_collect<T, C, F>(
        &self,
        sql: &str,
        params: impl rusqlite::Params + Send,
        f: F,
    ) -> Result<C>
    where
        T: Send + 'static,
        C: Send + 'static + std::iter::FromIterator<T>,
        F: Send + FnMut(&rusqlite::Row) -> Result<T>,
    {
        self.query_map(sql, params, f, |rows| {
            rows.collect::<std::result::Result<C, _>>()
        })
        .await
    }

    /// Prepares and executes the statement and maps a function over the resulting rows.
    ///
    /// Collects the resulting rows into a `Vec`.
    pub async fn query_map_vec<T, F>(
        &self,
        sql: &str,
        params: impl rusqlite::Params + Send,
        f: F,
    ) -> Result<Vec<T>>
    where
        T: Send + 'static,
        F: Send + FnMut(&rusqlite::Row) -> Result<T>,
    {
        self.query_map_collect(sql, params, f).await
    }

    /// Used for executing `SELECT COUNT` statements only. Returns the resulting count.
    pub async fn count(&self, query: &str, params: impl rusqlite::Params + Send) -> Result<usize> {
        let count: isize = self.query_row(query, params, |row| row.get(0)).await?;
        Ok(usize::try_from(count)?)
    }

    /// Used for executing `SELECT COUNT` statements only. Returns `true`, if the count is at least
    /// one, `false` otherwise.
    pub async fn exists(&self, sql: &str, params: impl rusqlite::Params + Send) -> Result<bool> {
        let count = self.count(sql, params).await?;
        Ok(count > 0)
    }

    /// Execute a query which is expected to return one row.
    pub async fn query_row<T, F>(
        &self,
        query: &str,
        params: impl rusqlite::Params + Send,
        f: F,
    ) -> Result<T>
    where
        F: FnOnce(&rusqlite::Row) -> rusqlite::Result<T> + Send,
        T: Send + 'static,
    {
        let query_only = true;
        self.call(query_only, move |conn| {
            let res = conn.query_row(query, params, f)?;
            Ok(res)
        })
        .await
    }

    /// Execute the function inside a transaction assuming that it does writes.
    ///
    /// If the function returns an error, the transaction will be rolled back. If it does not return an
    /// error, the transaction will be committed.
    pub async fn transaction<G, H>(&self, callback: G) -> Result<H>
    where
        H: Send + 'static,
        G: Send + FnOnce(&mut rusqlite::Transaction<'_>) -> Result<H>,
    {
        let query_only = false;
        self.transaction_ex(query_only, callback).await
    }

    /// Execute the function inside a transaction.
    ///
    /// * `query_only` - Whether the function only executes read statements (queries) and can be run
    ///   in parallel with other transactions. NB: Creating and modifying temporary tables are also
    ///   allowed with `query_only`, temporary tables aren't visible in other connections, but you
    ///   need to pass `PRAGMA query_only=0;` to SQLite before that:
    ///   ```text
    ///   pragma_update(None, "query_only", "0")
    ///   ```
    ///   Also temporary tables need to be dropped because the connection is returned to the pool
    ///   then.
    ///
    /// If the function returns an error, the transaction will be rolled back. If it does not return
    /// an error, the transaction will be committed.
    pub async fn transaction_ex<G, H>(&self, query_only: bool, callback: G) -> Result<H>
    where
        H: Send + 'static,
        G: Send + FnOnce(&mut rusqlite::Transaction<'_>) -> Result<H>,
    {
        self.call(query_only, move |conn| {
            let mut transaction = conn.transaction()?;
            let ret = callback(&mut transaction);

            match ret {
                Ok(ret) => {
                    transaction.commit()?;
                    Ok(ret)
                }
                Err(err) => {
                    transaction.rollback()?;
                    Err(err)
                }
            }
        })
        .await
    }

    /// Query the database if the requested table already exists.
    pub async fn table_exists(&self, name: &str) -> Result<bool> {
        let query_only = true;
        self.call(query_only, move |conn| {
            let mut exists = false;
            conn.pragma(None, "table_info", name.to_string(), |_row| {
                // will only be executed if the info was found
                exists = true;
                Ok(())
            })?;

            Ok(exists)
        })
        .await
    }

    /// Check if a column exists in a given table.
    pub async fn col_exists(&self, table_name: &str, col_name: &str) -> Result<bool> {
        let query_only = true;
        self.call(query_only, move |conn| {
            let mut exists = false;
            // `PRAGMA table_info` returns one row per column,
            // each row containing 0=cid, 1=name, 2=type, 3=notnull, 4=dflt_value
            conn.pragma(None, "table_info", table_name.to_string(), |row| {
                let curr_name: String = row.get(1)?;
                if col_name == curr_name {
                    exists = true;
                }
                Ok(())
            })?;

            Ok(exists)
        })
        .await
    }

    /// Execute a query which is expected to return zero or one row.
    pub async fn query_row_optional<T, F>(
        &self,
        sql: &str,
        params: impl rusqlite::Params + Send,
        f: F,
    ) -> Result<Option<T>>
    where
        F: Send + FnOnce(&rusqlite::Row) -> rusqlite::Result<T>,
        T: Send + 'static,
    {
        let query_only = true;
        self.call(query_only, move |conn| {
            match conn.query_row(sql.as_ref(), params, f) {
                Ok(res) => Ok(Some(res)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(err) => Err(err.into()),
            }
        })
        .await
    }

    /// Executes a query which is expected to return one row and one
    /// column. If the query does not return any rows, returns `Ok(None)`.
    pub async fn query_get_value<T>(
        &self,
        query: &str,
        params: impl rusqlite::Params + Send,
    ) -> Result<Option<T>>
    where
        T: rusqlite::types::FromSql + Send + 'static,
    {
        self.query_row_optional(query, params, |row| row.get::<_, T>(0))
            .await
    }

    /// Set private configuration options.
    ///
    /// Setting `None` deletes the value.  On failure an error message
    /// will already have been logged.
    pub async fn set_raw_config(&self, key: &str, value: Option<&str>) -> Result<()> {
        let mut lock = self.config_cache.write().await;
        if let Some(value) = value {
            self.execute(
                "INSERT OR REPLACE INTO config (keyname, value) VALUES (?, ?)",
                (key, value),
            )
            .await?;
        } else {
            self.execute("DELETE FROM config WHERE keyname=?", (key,))
                .await?;
        }
        lock.insert(key.to_string(), value.map(|s| s.to_string()));
        drop(lock);

        Ok(())
    }

    /// Get configuration options from the database.
    pub async fn get_raw_config(&self, key: &str) -> Result<Option<String>> {
        let lock = self.config_cache.read().await;
        let cached = lock.get(key).cloned();
        drop(lock);

        if let Some(c) = cached {
            return Ok(c);
        }

        let mut lock = self.config_cache.write().await;
        let value = self
            .query_get_value("SELECT value FROM config WHERE keyname=?", (key,))
            .await
            .context(format!("failed to fetch raw config: {key}"))?;
        lock.insert(key.to_string(), value.clone());
        drop(lock);

        Ok(value)
    }

    /// Removes the `key`'s value from the cache.
    pub(crate) async fn uncache_raw_config(&self, key: &str) {
        let mut lock = self.config_cache.write().await;
        lock.remove(key);
    }

    /// Sets configuration for the given key to 32-bit signed integer value.
    pub async fn set_raw_config_int(&self, key: &str, value: i32) -> Result<()> {
        self.set_raw_config(key, Some(&format!("{value}"))).await
    }

    /// Returns 32-bit signed integer configuration value for the given key.
    pub async fn get_raw_config_int(&self, key: &str) -> Result<Option<i32>> {
        self.get_raw_config(key)
            .await
            .map(|s| s.and_then(|s| s.parse().ok()))
    }

    /// Returns 32-bit unsigned integer configuration value for the given key.
    pub async fn get_raw_config_u32(&self, key: &str) -> Result<Option<u32>> {
        self.get_raw_config(key)
            .await
            .map(|s| s.and_then(|s| s.parse().ok()))
    }

    /// Returns boolean configuration value for the given key.
    pub async fn get_raw_config_bool(&self, key: &str) -> Result<bool> {
        // Not the most obvious way to encode bool as string, but it is matter
        // of backward compatibility.
        let res = self.get_raw_config_int(key).await?;
        Ok(res.unwrap_or_default() > 0)
    }

    /// Sets configuration for the given key to boolean value.
    pub async fn set_raw_config_bool(&self, key: &str, value: bool) -> Result<()> {
        let value = if value { Some("1") } else { None };
        self.set_raw_config(key, value).await
    }

    /// Sets configuration for the given key to 64-bit signed integer value.
    pub async fn set_raw_config_int64(&self, key: &str, value: i64) -> Result<()> {
        self.set_raw_config(key, Some(&format!("{value}"))).await
    }

    /// Returns 64-bit signed integer configuration value for the given key.
    pub async fn get_raw_config_int64(&self, key: &str) -> Result<Option<i64>> {
        self.get_raw_config(key)
            .await
            .map(|s| s.and_then(|r| r.parse().ok()))
    }

    /// Returns configuration cache.
    #[cfg(feature = "internals")]
    pub fn config_cache(&self) -> &RwLock<HashMap<String, Option<String>>> {
        &self.config_cache
    }

    /// Runs a checkpoint operation in TRUNCATE mode, so the WAL file is truncated to 0 bytes.
    pub(crate) async fn wal_checkpoint(context: &Context) -> Result<()> {
        let t_start = Time::now();
        let lock = context.sql.pool.read().await;
        let Some(pool) = lock.as_ref() else {
            // No db connections, nothing to checkpoint.
            return Ok(());
        };

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

        // Kick out writers.
        const _: () = assert!(Sql::N_DB_CONNECTIONS > 1, "Deadlock possible");
        let _write_lock = pool.write_lock().await;
        let t_writers_blocked = Time::now();
        // Ensure that all readers use the most recent database snapshot (are at the end of WAL) so
        // that `wal_checkpoint(FULL)` isn't blocked. We could use `PASSIVE` as well, but it's
        // documented poorly, https://www.sqlite.org/pragma.html#pragma_wal_checkpoint and
        // https://www.sqlite.org/c3ref/wal_checkpoint_v2.html don't tell how it interacts with new
        // readers.
        let mut read_conns = Vec::with_capacity(Self::N_DB_CONNECTIONS - 1);
        for _ in 0..(Self::N_DB_CONNECTIONS - 1) {
            read_conns.push(pool.get(query_only).await?);
        }
        read_conns.clear();
        // Checkpoint the remaining WAL pages without blocking readers.
        let (pages_total, pages_checkpointed) = tokio::task::block_in_place(|| {
            conn.query_row("PRAGMA wal_checkpoint(FULL)", [], |row| {
                let pages_total: i64 = row.get(1)?;
                let pages_checkpointed: i64 = row.get(2)?;
                Ok((pages_total, pages_checkpointed))
            })
        })?;
        if pages_checkpointed < pages_total {
            warn!(
                context,
                "Cannot checkpoint whole WAL. Pages total: {pages_total}, checkpointed: {pages_checkpointed}. Make sure there are no external connections running transactions.",
            );
        }
        // Kick out readers to avoid blocking/SQLITE_BUSY.
        for _ in 0..(Self::N_DB_CONNECTIONS - 1) {
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
        info!(
            context,
            "wal_checkpoint: Total time: {:?}. Writers blocked for: {:?}. Readers blocked for: {:?}.",
            time_elapsed(&t_start),
            time_elapsed(&t_writers_blocked),
            time_elapsed(&t_readers_blocked),
        );
        Ok(())
    }
}

/// Creates a new SQLite connection.
///
/// `path` is the database path.
///
/// `passphrase` is the SQLCipher database passphrase.
/// Empty string if database is not encrypted.
fn new_connection(path: &Path, passphrase: &str) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE;
    let conn = Connection::open_with_flags(path, flags)?;
    conn.execute_batch(
        "PRAGMA cipher_memory_security = OFF; -- Too slow on Android
         PRAGMA secure_delete=on;
         PRAGMA soft_heap_limit = 8388608; -- 8 MiB limit, same as set in Android SQLiteDatabase.
         PRAGMA foreign_keys=on;
         ",
    )?;

    // Avoid SQLITE_IOERR_GETTEMPPATH errors on Android and maybe other systems.
    // Downside is more RAM consumption esp. on VACUUM.
    // Therefore, on systems known to have working default (using files), stay with that.
    if cfg!(not(target_os = "ios")) {
        conn.pragma_update(None, "temp_store", "memory")?;
    }

    // Fail immediately when the database is busy,
    // except for iOS. On iOS we don't have
    // `accounts.lock` lockfile and the database
    // is used by two processes:
    // main process and the notification extension.
    // Due to a bug they both may run at the same time
    // and try to write to the database.
    // As a workaround, we wait up to 1 minute and retry
    // instead of failing immediately and
    // possibly missing a message.
    if cfg!(target_os = "ios") {
        conn.busy_timeout(Duration::new(60, 0))?;
    } else {
        conn.busy_timeout(Duration::ZERO)?;
    }

    if !passphrase.is_empty() {
        conn.pragma_update(None, "key", passphrase)?;
    }
    // Try to enable auto_vacuum. This will only be
    // applied if the database is new or after successful
    // VACUUM, which usually happens before backup export.
    // When auto_vacuum is INCREMENTAL, it is possible to
    // use PRAGMA incremental_vacuum to return unused
    // database pages to the filesystem.
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL".to_string())?;

    conn.pragma_update(None, "journal_mode", "WAL".to_string())?;
    // Default synchronous=FULL is much slower. NORMAL is sufficient for WAL mode.
    conn.pragma_update(None, "synchronous", "NORMAL".to_string())?;

    Ok(conn)
}

// Tries to clear the freelist to free some space on the disk.
//
// This only works if auto_vacuum is enabled.
#[expect(clippy::arithmetic_side_effects)]
async fn incremental_vacuum(context: &Context) -> Result<()> {
    context
        .sql
        .call_write(move |conn| {
            let mut stmt = conn
                .prepare("PRAGMA incremental_vacuum")
                .context("Failed to prepare incremental_vacuum statement")?;

            // It is important to step the statement until it returns no more rows.
            // Otherwise it will not free as many pages as it can:
            // <https://stackoverflow.com/questions/53746807/sqlite-incremental-vacuum-removing-only-one-free-page>.
            let mut rows = stmt
                .query(())
                .context("Failed to run incremental_vacuum statement")?;
            let mut row_count = 0;
            while let Some(_row) = rows
                .next()
                .context("Failed to step incremental_vacuum statement")?
            {
                row_count += 1;
            }
            info!(context, "Incremental vacuum freed {row_count} pages.");
            Ok(())
        })
        .await
}

/// Cleanup the account to restore some storage and optimize the database.
pub async fn housekeeping(context: &Context) -> Result<()> {
    // Setting `Config::LastHousekeeping` at the beginning avoids endless loops when things do not
    // work out for whatever reason or are interrupted by the OS.
    if let Err(e) = context
        .set_config_internal(Config::LastHousekeeping, Some(&time().to_string()))
        .await
    {
        warn!(context, "Can't set config: {e:#}.");
    }

    http_cache_cleanup(context)
        .await
        .context("Failed to cleanup HTTP cache")
        .log_err(context)
        .ok();
    migrations::msgs_to_key_contacts(context)
        .await
        .context("migrations::msgs_to_key_contacts")
        .log_err(context)
        .ok();

    if let Err(err) = remove_unused_files(context).await {
        warn!(
            context,
            "Housekeeping: cannot remove unused files: {:#}.", err
        );
    }

    if let Err(err) = start_ephemeral_timers(context).await {
        warn!(
            context,
            "Housekeeping: cannot start ephemeral timers: {:#}.", err
        );
    }

    if let Err(err) = prune_tombstones(&context.sql).await {
        warn!(
            context,
            "Housekeeping: Cannot prune message tombstones: {:#}.", err
        );
    }

    maybe_add_mvbox_move_deprecation_message(context)
        .await
        .context("maybe_add_mvbox_move_deprecation_message")
        .log_err(context)
        .ok();

    if let Err(err) = incremental_vacuum(context).await {
        warn!(context, "Failed to run incremental vacuum: {err:#}.");
    }
    // Work around possible checkpoint starvations (there were cases reported when a WAL file is
    // bigger than 200M) and also make sure we truncate the WAL periodically. Auto-checkponting does
    // not normally truncate the WAL (unless the `journal_size_limit` pragma is set), see
    // https://www.sqlite.org/wal.html.
    if let Err(err) = Sql::wal_checkpoint(context).await {
        warn!(context, "wal_checkpoint() failed: {err:#}.");
        debug_assert!(false);
    }

    context
        .sql
        .execute(
            "DELETE FROM msgs_mdns WHERE msg_id NOT IN \
            (SELECT id FROM msgs WHERE chat_id!=?)",
            (DC_CHAT_ID_TRASH,),
        )
        .await
        .context("failed to remove old MDNs")
        .log_err(context)
        .ok();

    context
        .sql
        .execute(
            "DELETE FROM msgs_status_updates WHERE msg_id NOT IN \
            (SELECT id FROM msgs WHERE chat_id!=?)",
            (DC_CHAT_ID_TRASH,),
        )
        .await
        .context("failed to remove old webxdc status updates")
        .log_err(context)
        .ok();

    prune_connection_history(context)
        .await
        .context("Failed to prune connection history")
        .log_err(context)
        .ok();
    prune_dns_cache(context)
        .await
        .context("Failed to prune DNS cache")
        .log_err(context)
        .ok();

    // Delete POI locations
    // which don't have corresponding message.
    delete_orphaned_poi_locations(context)
        .await
        .context("Failed to delete orphaned POI locations")
        .log_err(context)
        .ok();

    info!(context, "Housekeeping done.");
    Ok(())
}

/// Adds device message about `mvbox_move` config deprecation
/// if the user has it enabled.
async fn maybe_add_mvbox_move_deprecation_message(context: &Context) -> Result<()> {
    if !context.get_config_bool(Config::OnlyFetchMvbox).await?
        && context.get_config_bool(Config::MvboxMove).await?
    {
        let mut msg = Message::new_text(stock_str::mvbox_move_deprecation(context).await);
        add_device_msg(context, Some("mvbox_move_deprecation"), Some(&mut msg)).await?;
    }
    Ok(())
}

/// Get the value of a column `idx` of the `row` as `Vec<u8>`.
pub fn row_get_vec(row: &Row, idx: usize) -> rusqlite::Result<Vec<u8>> {
    row.get(idx).or_else(|err| match row.get_ref(idx)? {
        ValueRef::Null => Ok(Vec::new()),
        ValueRef::Text(text) => Ok(text.to_vec()),
        ValueRef::Blob(blob) => Ok(blob.to_vec()),
        ValueRef::Integer(_) | ValueRef::Real(_) => Err(err),
    })
}

/// Enumerates used files in the blobdir and removes unused ones.
#[expect(clippy::arithmetic_side_effects)]
pub async fn remove_unused_files(context: &Context) -> Result<()> {
    let mut files_in_use = HashSet::new();
    let mut unreferenced_count = 0;

    info!(context, "Start housekeeping...");
    maybe_add_from_param(
        &context.sql,
        &mut files_in_use,
        "SELECT param FROM msgs  WHERE chat_id!=3   AND type!=10;",
        Param::File,
    )
    .await?;
    maybe_add_from_param(
        &context.sql,
        &mut files_in_use,
        "SELECT param FROM chats;",
        Param::ProfileImage,
    )
    .await?;
    maybe_add_from_param(
        &context.sql,
        &mut files_in_use,
        "SELECT param FROM contacts;",
        Param::ProfileImage,
    )
    .await?;

    context
        .sql
        .query_map(
            "SELECT value FROM config;",
            (),
            |row| {
                let row: String = row.get(0)?;
                Ok(row)
            },
            |rows| {
                for row in rows {
                    maybe_add_file(&mut files_in_use, &row?);
                }
                Ok(())
            },
        )
        .await
        .context("housekeeping: failed to SELECT value FROM config")?;

    context
        .sql
        .query_map(
            "SELECT blobname FROM http_cache",
            (),
            |row| {
                let row: String = row.get(0)?;
                Ok(row)
            },
            |rows| {
                for row in rows {
                    maybe_add_file(&mut files_in_use, &row?);
                }
                Ok(())
            },
        )
        .await
        .context("Failed to SELECT blobname FROM http_cache")?;

    info!(context, "{} files in use.", files_in_use.len());
    /* go through directories and delete unused files */
    let blobdir = context.get_blobdir();
    for p in [&blobdir.join(BLOBS_BACKUP_NAME), blobdir] {
        match tokio::fs::read_dir(p).await {
            Ok(mut dir_handle) => {
                /* avoid deletion of files that are just created to build a message object */
                let diff = std::time::Duration::from_secs(60 * 60);
                let keep_files_newer_than = SystemTime::now()
                    .checked_sub(diff)
                    .unwrap_or(SystemTime::UNIX_EPOCH);

                while let Ok(Some(entry)) = dir_handle.next_entry().await {
                    let name_f = entry.file_name();
                    let name_s = name_f.to_string_lossy();

                    if p == blobdir
                        && (is_file_in_use(&files_in_use, None, &name_s)
                            || is_file_in_use(&files_in_use, Some(".waveform"), &name_s)
                            || is_file_in_use(&files_in_use, Some("-preview.jpg"), &name_s))
                    {
                        continue;
                    }

                    let stats = match tokio::fs::metadata(entry.path()).await {
                        Err(err) => {
                            warn!(
                                context,
                                "Cannot get metadata for {}: {:#}.",
                                entry.path().display(),
                                err
                            );
                            continue;
                        }
                        Ok(stats) => stats,
                    };

                    if stats.is_dir() {
                        if let Err(e) = tokio::fs::remove_dir(entry.path()).await {
                            // The dir could be created not by a user, but by a desktop
                            // environment f.e. So, no warning.
                            info!(
                                context,
                                "Housekeeping: Cannot rmdir {}: {:#}.",
                                entry.path().display(),
                                e
                            );
                        }
                        continue;
                    }

                    unreferenced_count += 1;
                    let recently_created = stats.created().is_ok_and(|t| t > keep_files_newer_than);
                    let recently_modified =
                        stats.modified().is_ok_and(|t| t > keep_files_newer_than);
                    let recently_accessed =
                        stats.accessed().is_ok_and(|t| t > keep_files_newer_than);

                    if p == blobdir && (recently_created || recently_modified || recently_accessed)
                    {
                        info!(
                            context,
                            "Housekeeping: Keeping new unreferenced file #{}: {:?}.",
                            unreferenced_count,
                            entry.file_name(),
                        );
                        continue;
                    }

                    info!(
                        context,
                        "Housekeeping: Deleting unreferenced file #{}: {:?}.",
                        unreferenced_count,
                        entry.file_name()
                    );
                    let path = entry.path();
                    if let Err(err) = delete_file(context, &path).await {
                        error!(
                            context,
                            "Failed to delete unused file {}: {:#}.",
                            path.display(),
                            err
                        );
                    }
                }
            }
            Err(err) => {
                if !p.ends_with(BLOBS_BACKUP_NAME) {
                    warn!(
                        context,
                        "Housekeeping: Cannot read dir {}: {:#}.",
                        p.display(),
                        err
                    );
                }
            }
        }
    }

    Ok(())
}

fn is_file_in_use(files_in_use: &HashSet<String>, namespc_opt: Option<&str>, name: &str) -> bool {
    let name_to_check = if let Some(namespc) = namespc_opt {
        let Some(name) = name.strip_suffix(namespc) else {
            return false;
        };
        name
    } else {
        name
    };
    files_in_use.contains(name_to_check)
}

fn maybe_add_file(files_in_use: &mut HashSet<String>, file: &str) {
    if let Some(file) = file.strip_prefix("$BLOBDIR/") {
        files_in_use.insert(file.to_string());
    }
}

async fn maybe_add_from_param(
    sql: &Sql,
    files_in_use: &mut HashSet<String>,
    query: &str,
    param_id: Param,
) -> Result<()> {
    sql.query_map(
        query,
        (),
        |row| {
            let row: String = row.get(0)?;
            Ok(row)
        },
        |rows| {
            for row in rows {
                let param: Params = row?.parse().unwrap_or_default();
                if let Some(file) = param.get(param_id) {
                    maybe_add_file(files_in_use, file);
                }
            }
            Ok(())
        },
    )
    .await
    .context(format!("housekeeping: failed to add_from_param {query}"))?;

    Ok(())
}

/// Removes from the database stale locally deleted messages that also don't
/// have a server UID.
async fn prune_tombstones(sql: &Sql) -> Result<()> {
    // Keep tombstones for the last two days to prevent redownloading locally deleted messages.
    let timestamp_max = time().saturating_sub(2 * 24 * 3600);
    sql.execute(
        "DELETE FROM msgs
         WHERE chat_id=?
         AND timestamp<=?
         AND NOT EXISTS (
         SELECT * FROM imap WHERE msgs.rfc724_mid=rfc724_mid AND target!=''
         )",
        (DC_CHAT_ID_TRASH, timestamp_max),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod sql_tests;
