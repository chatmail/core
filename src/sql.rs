//! # SQLite wrapper

use async_std::sync::RwLock;

use std::collections::HashSet;
use std::convert::TryFrom;
use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use async_std::prelude::*;
use rusqlite::OpenFlags;

use crate::chat::{add_device_msg, update_device_icon, update_saved_messages_icon};
use crate::config::Config;
use crate::constants::{Viewtype, DC_CHAT_ID_TRASH};
use crate::context::Context;
use crate::dc_tools::{dc_delete_file, time};
use crate::ephemeral::start_ephemeral_timers;
use crate::message::Message;
use crate::param::{Param, Params};
use crate::peerstate::Peerstate;
use crate::stock_str;

#[macro_export]
macro_rules! paramsv {
    () => {
        Vec::new()
    };
    ($($param:expr),+ $(,)?) => {
        vec![$(&$param as &dyn $crate::ToSql),+]
    };
}

mod error;
mod migrations;

pub use self::error::*;

/// A wrapper around the underlying Sqlite3 object.
#[derive(Debug)]
pub struct Sql {
    pool: RwLock<Option<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>>,
}

impl Default for Sql {
    fn default() -> Self {
        Self {
            pool: RwLock::new(None),
        }
    }
}

impl Sql {
    pub fn new() -> Sql {
        Self::default()
    }

    /// Checks if there is currently a connection to the underlying Sqlite database.
    pub async fn is_open(&self) -> bool {
        self.pool.read().await.is_some()
    }

    /// Closes all underlying Sqlite connections.
    pub async fn close(&self) {
        let _ = self.pool.write().await.take();
        // drop closes the connection
    }

    pub fn new_pool(
        dbfile: &Path,
        readonly: bool,
    ) -> anyhow::Result<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>> {
        let mut open_flags = OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if readonly {
            open_flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        } else {
            open_flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            open_flags.insert(OpenFlags::SQLITE_OPEN_CREATE);
        }

        // this actually creates min_idle database handles just now.
        // therefore, with_init() must not try to modify the database as otherwise
        // we easily get busy-errors (eg. table-creation, journal_mode etc. should be done on only one handle)
        let mgr = r2d2_sqlite::SqliteConnectionManager::file(dbfile)
            .with_flags(open_flags)
            .with_init(|c| {
                c.execute_batch(&format!(
                    "PRAGMA secure_delete=on;
                     PRAGMA busy_timeout = {};
                     PRAGMA temp_store=memory; -- Avoid SQLITE_IOERR_GETTEMPPATH errors on Android
                     ",
                    Duration::from_secs(10).as_millis()
                ))?;
                Ok(())
            });

        let pool = r2d2::Pool::builder()
            .min_idle(Some(2))
            .max_size(10)
            .connection_timeout(Duration::from_secs(60))
            .build(mgr)
            .map_err(Error::ConnectionPool)?;
        Ok(pool)
    }

    /// Opens the provided database and runs any necessary migrations.
    /// If a database is already open, this will return an error.
    pub async fn open(
        &self,
        context: &Context,
        dbfile: impl AsRef<Path>,
        readonly: bool,
    ) -> anyhow::Result<()> {
        if self.is_open().await {
            error!(
                context,
                "Cannot open, database \"{:?}\" already opened.",
                dbfile.as_ref(),
            );
            return Err(Error::SqlAlreadyOpen.into());
        }

        *self.pool.write().await = Some(Self::new_pool(dbfile.as_ref(), readonly)?);

        if !readonly {
            // journal_mode is persisted, it is sufficient to change it only for one handle.
            self.with_conn(move |conn| {
                conn.pragma_update(None, "journal_mode", &"WAL".to_string())?;
                Ok(())
            })
            .await?;

            // (1) update low-level database structure.
            // this should be done before updates that use high-level objects that
            // rely themselves on the low-level structure.

            let (recalc_fingerprints, update_icons, disable_server_delete) =
                migrations::run(context, self).await?;

            // (2) updates that require high-level objects
            // the structure is complete now and all objects are usable

            if recalc_fingerprints {
                info!(context, "[migration] recalc fingerprints");
                let addrs = self
                    .query_map(
                        "SELECT addr FROM acpeerstates;",
                        paramsv![],
                        |row| row.get::<_, String>(0),
                        |addrs| {
                            addrs
                                .collect::<std::result::Result<Vec<_>, _>>()
                                .map_err(Into::into)
                        },
                    )
                    .await?;
                for addr in &addrs {
                    if let Some(ref mut peerstate) = Peerstate::from_addr(context, addr).await? {
                        peerstate.recalc_fingerprint();
                        peerstate.save_to_db(self, false).await?;
                    }
                }
            }

            if update_icons {
                update_saved_messages_icon(context).await?;
                update_device_icon(context).await?;
            }

            if disable_server_delete {
                // We now always watch all folders and delete messages there if delete_server is enabled.
                // So, for people who have delete_server enabled, disable it and add a hint to the devicechat:
                if context.get_config_delete_server_after().await?.is_some() {
                    let mut msg = Message::new(Viewtype::Text);
                    msg.text = Some(stock_str::delete_server_turned_off(context).await);
                    add_device_msg(context, None, Some(&mut msg)).await?;
                    context
                        .set_config(Config::DeleteServerAfter, Some("0"))
                        .await?;
                }
            }
        }

        info!(context, "Opened {:?}.", dbfile.as_ref());

        Ok(())
    }

    /// Execute the given query, returning the number of affected rows.
    pub async fn execute(
        &self,
        query: impl AsRef<str>,
        params: Vec<&dyn crate::ToSql>,
    ) -> Result<usize> {
        let conn = self.get_conn().await?;
        let res = conn.execute(query.as_ref(), params)?;
        Ok(res)
    }

    /// Executes the given query, returning the last inserted row ID.
    pub async fn insert(
        &self,
        query: impl AsRef<str>,
        params: Vec<&dyn crate::ToSql>,
    ) -> anyhow::Result<usize> {
        let conn = self.get_conn().await?;
        conn.execute(query.as_ref(), params)?;
        Ok(usize::try_from(conn.last_insert_rowid())?)
    }

    /// Prepares and executes the statement and maps a function over the resulting rows.
    /// Then executes the second function over the returned iterator and returns the
    /// result of that function.
    pub async fn query_map<T, F, G, H>(
        &self,
        sql: impl AsRef<str>,
        params: Vec<&dyn crate::ToSql>,
        f: F,
        mut g: G,
    ) -> Result<H>
    where
        F: FnMut(&rusqlite::Row) -> rusqlite::Result<T>,
        G: FnMut(rusqlite::MappedRows<F>) -> Result<H>,
    {
        let sql = sql.as_ref();

        let conn = self.get_conn().await?;
        let mut stmt = conn.prepare(sql)?;
        let res = stmt.query_map(&params, f)?;
        g(res)
    }

    pub async fn get_conn(
        &self,
    ) -> Result<r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>> {
        let lock = self.pool.read().await;
        let pool = lock.as_ref().ok_or(Error::SqlNoConnection)?;
        let conn = pool.get()?;

        Ok(conn)
    }

    pub async fn with_conn<G, H>(&self, g: G) -> anyhow::Result<H>
    where
        H: Send + 'static,
        G: Send
            + 'static
            + FnOnce(
                r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>,
            ) -> anyhow::Result<H>,
    {
        let lock = self.pool.read().await;
        let pool = lock.as_ref().ok_or(Error::SqlNoConnection)?;
        let conn = pool.get()?;

        g(conn)
    }

    pub async fn with_conn_async<G, H, Fut>(&self, mut g: G) -> Result<H>
    where
        G: FnMut(r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>) -> Fut,
        Fut: Future<Output = Result<H>> + Send,
    {
        let lock = self.pool.read().await;
        let pool = lock.as_ref().ok_or(Error::SqlNoConnection)?;

        let conn = pool.get()?;
        g(conn).await
    }

    /// Used for executing `SELECT COUNT` statements only. Returns the resulting count.
    pub async fn count(
        &self,
        query: impl AsRef<str>,
        params: Vec<&dyn crate::ToSql>,
    ) -> anyhow::Result<usize> {
        let count: isize = self.query_row(query, params, |row| row.get(0)).await?;
        Ok(usize::try_from(count)?)
    }

    /// Used for executing `SELECT COUNT` statements only. Returns `true`, if the count is at least
    /// one, `false` otherwise.
    pub async fn exists(&self, sql: &str, params: Vec<&dyn crate::ToSql>) -> Result<bool> {
        let count = self.count(sql, params).await?;
        Ok(count > 0)
    }

    /// Execute a query which is expected to return one row.
    pub async fn query_row<T, F>(
        &self,
        query: impl AsRef<str>,
        params: Vec<&dyn crate::ToSql>,
        f: F,
    ) -> Result<T>
    where
        F: FnOnce(&rusqlite::Row) -> rusqlite::Result<T>,
    {
        let conn = self.get_conn().await?;
        let res = conn.query_row(query.as_ref(), params, f)?;
        Ok(res)
    }

    /// Execute the function inside a transaction.
    ///
    /// If the function returns an error, the transaction will be rolled back. If it does not return an
    /// error, the transaction will be committed.
    pub async fn transaction<G, H>(&self, callback: G) -> anyhow::Result<H>
    where
        H: Send + 'static,
        G: Send + 'static + FnOnce(&mut rusqlite::Transaction<'_>) -> anyhow::Result<H>,
    {
        self.with_conn(move |mut conn| {
            let conn2 = &mut conn;
            let mut transaction = conn2.transaction()?;
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
    pub async fn table_exists(&self, name: impl AsRef<str>) -> anyhow::Result<bool> {
        let name = name.as_ref().to_string();
        self.with_conn(move |conn| {
            let mut exists = false;
            conn.pragma(None, "table_info", &name, |_row| {
                // will only be executed if the info was found
                exists = true;
                Ok(())
            })?;

            Ok(exists)
        })
        .await
    }

    /// Check if a column exists in a given table.
    pub async fn col_exists(
        &self,
        table_name: impl AsRef<str>,
        col_name: impl AsRef<str>,
    ) -> anyhow::Result<bool> {
        let table_name = table_name.as_ref().to_string();
        let col_name = col_name.as_ref().to_string();
        self.with_conn(move |conn| {
            let mut exists = false;
            // `PRAGMA table_info` returns one row per column,
            // each row containing 0=cid, 1=name, 2=type, 3=notnull, 4=dflt_value
            conn.pragma(None, "table_info", &table_name, |row| {
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
        sql: impl AsRef<str>,
        params: Vec<&dyn crate::ToSql>,
        f: F,
    ) -> anyhow::Result<Option<T>>
    where
        F: FnOnce(&rusqlite::Row) -> rusqlite::Result<T>,
    {
        let res = match self.query_row(sql, params, f).await {
            Ok(res) => Ok(Some(res)),
            Err(Error::Sql(rusqlite::Error::QueryReturnedNoRows)) => Ok(None),
            Err(Error::Sql(rusqlite::Error::InvalidColumnType(
                _,
                _,
                rusqlite::types::Type::Null,
            ))) => Ok(None),
            Err(err) => Err(err),
        }?;
        Ok(res)
    }

    /// Executes a query which is expected to return one row and one
    /// column. If the query does not return a value or returns SQL
    /// `NULL`, returns `Ok(None)`.
    pub async fn query_get_value<T>(
        &self,
        query: &str,
        params: Vec<&dyn crate::ToSql>,
    ) -> anyhow::Result<Option<T>>
    where
        T: rusqlite::types::FromSql,
    {
        self.query_row_optional(query, params, |row| row.get::<_, T>(0))
            .await
    }

    /// Set private configuration options.
    ///
    /// Setting `None` deletes the value.  On failure an error message
    /// will already have been logged.
    pub async fn set_raw_config(&self, key: impl AsRef<str>, value: Option<&str>) -> Result<()> {
        if !self.is_open().await {
            return Err(Error::SqlNoConnection);
        }

        let key = key.as_ref();
        if let Some(value) = value {
            let exists = self
                .exists(
                    "SELECT COUNT(*) FROM config WHERE keyname=?;",
                    paramsv![key],
                )
                .await?;

            if exists {
                self.execute(
                    "UPDATE config SET value=? WHERE keyname=?;",
                    paramsv![(*value).to_string(), key.to_string()],
                )
                .await?;
            } else {
                self.execute(
                    "INSERT INTO config (keyname, value) VALUES (?, ?);",
                    paramsv![key.to_string(), (*value).to_string()],
                )
                .await?;
            }
        } else {
            self.execute("DELETE FROM config WHERE keyname=?;", paramsv![key])
                .await?;
        }

        Ok(())
    }

    /// Get configuration options from the database.
    pub async fn get_raw_config(&self, key: impl AsRef<str>) -> Result<Option<String>> {
        if !self.is_open().await || key.as_ref().is_empty() {
            return Err(Error::SqlNoConnection);
        }
        let value = self
            .query_get_value(
                "SELECT value FROM config WHERE keyname=?;",
                paramsv![key.as_ref().to_string()],
            )
            .await
            .context(format!("failed to fetch raw config: {}", key.as_ref()))?;

        Ok(value)
    }

    pub async fn set_raw_config_int(&self, key: impl AsRef<str>, value: i32) -> Result<()> {
        self.set_raw_config(key, Some(&format!("{}", value))).await
    }

    pub async fn get_raw_config_int(&self, key: impl AsRef<str>) -> Result<Option<i32>> {
        self.get_raw_config(key)
            .await
            .map(|s| s.and_then(|s| s.parse().ok()))
    }

    pub async fn get_raw_config_bool(&self, key: impl AsRef<str>) -> Result<bool> {
        // Not the most obvious way to encode bool as string, but it is matter
        // of backward compatibility.
        let res = self.get_raw_config_int(key).await?;
        Ok(res.unwrap_or_default() > 0)
    }

    pub async fn set_raw_config_bool<T>(&self, key: T, value: bool) -> Result<()>
    where
        T: AsRef<str>,
    {
        let value = if value { Some("1") } else { None };
        self.set_raw_config(key, value).await
    }

    pub async fn set_raw_config_int64(&self, key: impl AsRef<str>, value: i64) -> Result<()> {
        self.set_raw_config(key, Some(&format!("{}", value))).await
    }

    pub async fn get_raw_config_int64(&self, key: impl AsRef<str>) -> Result<Option<i64>> {
        self.get_raw_config(key)
            .await
            .map(|s| s.and_then(|r| r.parse().ok()))
    }
}

pub async fn housekeeping(context: &Context) -> Result<()> {
    if let Err(err) = crate::ephemeral::delete_expired_messages(context).await {
        warn!(context, "Failed to delete expired messages: {}", err);
    }

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
        "SELECT param FROM jobs;",
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
            paramsv![],
            |row| row.get::<_, String>(0),
            |rows| {
                for row in rows {
                    maybe_add_file(&mut files_in_use, row?);
                }
                Ok(())
            },
        )
        .await
        .context("housekeeping: failed to SELECT value FROM config")?;

    info!(context, "{} files in use.", files_in_use.len(),);
    /* go through directory and delete unused files */
    let p = context.get_blobdir();
    match async_std::fs::read_dir(p).await {
        Ok(mut dir_handle) => {
            /* avoid deletion of files that are just created to build a message object */
            let diff = std::time::Duration::from_secs(60 * 60);
            let keep_files_newer_than = std::time::SystemTime::now().checked_sub(diff).unwrap();

            while let Some(entry) = dir_handle.next().await {
                if entry.is_err() {
                    break;
                }
                let entry = entry.unwrap();
                let name_f = entry.file_name();
                let name_s = name_f.to_string_lossy();

                if is_file_in_use(&files_in_use, None, &name_s)
                    || is_file_in_use(&files_in_use, Some(".increation"), &name_s)
                    || is_file_in_use(&files_in_use, Some(".waveform"), &name_s)
                    || is_file_in_use(&files_in_use, Some("-preview.jpg"), &name_s)
                {
                    continue;
                }

                unreferenced_count += 1;

                if let Ok(stats) = async_std::fs::metadata(entry.path()).await {
                    let recently_created =
                        stats.created().is_ok() && stats.created().unwrap() > keep_files_newer_than;
                    let recently_modified = stats.modified().is_ok()
                        && stats.modified().unwrap() > keep_files_newer_than;
                    let recently_accessed = stats.accessed().is_ok()
                        && stats.accessed().unwrap() > keep_files_newer_than;

                    if recently_created || recently_modified || recently_accessed {
                        info!(
                            context,
                            "Housekeeping: Keeping new unreferenced file #{}: {:?}",
                            unreferenced_count,
                            entry.file_name(),
                        );
                        continue;
                    }
                }
                info!(
                    context,
                    "Housekeeping: Deleting unreferenced file #{}: {:?}",
                    unreferenced_count,
                    entry.file_name()
                );
                let path = entry.path();
                dc_delete_file(context, path).await;
            }
        }
        Err(err) => {
            warn!(
                context,
                "Housekeeping: Cannot open {}. ({})",
                context.get_blobdir().display(),
                err
            );
        }
    }

    if let Err(err) = start_ephemeral_timers(context).await {
        warn!(
            context,
            "Housekeeping: cannot start ephemeral timers: {}", err
        );
    }

    if let Err(err) = prune_tombstones(&context.sql).await {
        warn!(
            context,
            "Housekeeping: Cannot prune message tombstones: {}", err
        );
    }

    if let Err(e) = context
        .set_config(Config::LastHousekeeping, Some(&time().to_string()))
        .await
    {
        warn!(context, "Can't set config: {}", e);
    }

    info!(context, "Housekeeping done.");
    Ok(())
}

#[allow(clippy::indexing_slicing)]
fn is_file_in_use(files_in_use: &HashSet<String>, namespc_opt: Option<&str>, name: &str) -> bool {
    let name_to_check = if let Some(namespc) = namespc_opt {
        let name_len = name.len();
        let namespc_len = namespc.len();
        if name_len <= namespc_len || !name.ends_with(namespc) {
            return false;
        }
        &name[..name_len - namespc_len]
    } else {
        name
    };
    files_in_use.contains(name_to_check)
}

fn maybe_add_file(files_in_use: &mut HashSet<String>, file: impl AsRef<str>) {
    if let Some(file) = file.as_ref().strip_prefix("$BLOBDIR/") {
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
        paramsv![],
        |row| row.get::<_, String>(0),
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
    .context(format!("housekeeping: failed to add_from_param {}", query))?;

    Ok(())
}

/// Removes from the database locally deleted messages that also don't
/// have a server UID.
async fn prune_tombstones(sql: &Sql) -> Result<()> {
    sql.execute(
        "DELETE FROM msgs \
         WHERE (chat_id = ? OR hidden) \
         AND server_uid = 0",
        paramsv![DC_CHAT_ID_TRASH],
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use async_std::fs::File;

    use crate::config::Config;
    use crate::{test_utils::TestContext, Event, EventType};

    use super::*;

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

    #[async_std::test]
    async fn test_table_exists() {
        let t = TestContext::new().await;
        assert!(t.ctx.sql.table_exists("msgs").await.unwrap());
        assert!(!t.ctx.sql.table_exists("foobar").await.unwrap());
    }

    #[async_std::test]
    async fn test_col_exists() {
        let t = TestContext::new().await;
        assert!(t.ctx.sql.col_exists("msgs", "mime_modified").await.unwrap());
        assert!(!t.ctx.sql.col_exists("msgs", "foobar").await.unwrap());
        assert!(!t.ctx.sql.col_exists("foobar", "foobar").await.unwrap());
    }

    #[async_std::test]
    async fn test_housekeeping_db_closed() {
        let t = TestContext::new().await;

        let avatar_src = t.dir.path().join("avatar.png");
        let avatar_bytes = include_bytes!("../test-data/image/avatar64x64.png");
        File::create(&avatar_src)
            .await
            .unwrap()
            .write_all(avatar_bytes)
            .await
            .unwrap();
        t.set_config(Config::Selfavatar, Some(avatar_src.to_str().unwrap()))
            .await
            .unwrap();

        t.add_event_sink(move |event: Event| async move {
            match event.typ {
                EventType::Info(s) => assert!(
                    !s.contains("Keeping new unreferenced file"),
                    "File {} was almost deleted, only reason it was kept is that it was created recently (as the tests don't run for a long time)",
                    s
                ),
                EventType::Error(s) => panic!("{}", s),
                _ => {}
            }
        })
        .await;

        let a = t.get_config(Config::Selfavatar).await.unwrap().unwrap();
        assert_eq!(avatar_bytes, &async_std::fs::read(&a).await.unwrap()[..]);

        t.sql.close().await;
        housekeeping(&t).await.unwrap_err(); // housekeeping should fail as the db is closed
        t.sql.open(&t, &t.get_dbfile(), false).await.unwrap();

        let a = t.get_config(Config::Selfavatar).await.unwrap().unwrap();
        assert_eq!(avatar_bytes, &async_std::fs::read(&a).await.unwrap()[..]);
    }
}
