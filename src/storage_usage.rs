//! Module to collect and display Disk Space Usage of a Profile.
use crate::{context::Context, message::MsgId};
use anyhow::Result;
use humansize::{BINARY, format_size};
use walkdir::WalkDir;

/// Storage Usage Report
/// Useful for debugging space usage problems in the deltachat database.
#[derive(Debug)]
pub struct StorageUsage {
    /// Total database size, subtract this from the backup size to estimate size of all blobs
    pub db_size: u64,
    /// size and row count of the 10 biggest tables
    pub largest_tables: Vec<(String, u64, Option<u64>)>,
    /// count and total size of status updates
    /// for the 10 webxdc apps with the most size usage in status updates
    pub largest_webxdc_data: Vec<(MsgId, u64, u64)>,
    /// Total size of all files in the blobdir
    pub blobdir_size: u64,
}

impl std::fmt::Display for StorageUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Storage Usage:")?;
        let blobdir_size = format_size(self.blobdir_size, BINARY);
        writeln!(f, "[Blob Directory Size]: {blobdir_size}")?;
        let human_db_size = format_size(self.db_size, BINARY);
        writeln!(f, "[Database Size]: {human_db_size}")?;
        writeln!(f, "[Largest Tables]:")?;
        for (name, size, row_count) in &self.largest_tables {
            let human_table_size = format_size(*size, BINARY);
            writeln!(
                f,
                "   {name:<20} {human_table_size:>10}, {row_count:>6} rows",
                name = format!("{name}:"),
                row_count = row_count.map(|c| c.to_string()).unwrap_or("?".to_owned())
            )?;
        }
        writeln!(f, "[Webxdc With Biggest Status Update Space Usage]:")?;
        for (msg_id, size, update_count) in &self.largest_webxdc_data {
            let human_size = format_size(*size, BINARY);
            writeln!(
                f,
                "   {msg_id:<8} {human_size:>10} across {update_count:>5} updates",
                msg_id = format!("{msg_id}:")
            )?;
        }
        Ok(())
    }
}

/// Get storage usage information for the Context's database
#[expect(clippy::arithmetic_side_effects)]
pub async fn get_storage_usage(ctx: &Context) -> Result<StorageUsage> {
    let context_clone = ctx.clone();
    let blobdir_size =
        tokio::task::spawn_blocking(move || get_blobdir_storage_usage(&context_clone));

    let page_size: u64 = ctx
        .sql
        .query_get_value("PRAGMA page_size", ())
        .await?
        .unwrap_or_default();
    let page_count: u64 = ctx
        .sql
        .query_get_value("PRAGMA page_count", ())
        .await?
        .unwrap_or_default();

    let mut largest_tables = ctx
        .sql
        .query_map_vec(
            "SELECT name,
                SUM(pgsize) AS size
                FROM dbstat
                WHERE name IN (SELECT name FROM sqlite_master WHERE type='table')
                GROUP BY name ORDER BY size DESC LIMIT 10",
            (),
            |row| {
                let name: String = row.get(0)?;
                let size: u64 = row.get(1)?;
                Ok((name, size, None))
            },
        )
        .await?;

    for row in &mut largest_tables {
        let name = &row.0;
        let row_count: Result<Option<u64>> = ctx
            .sql
            // SECURITY: the table name comes from the db, not from the user
            .query_get_value(&format!("SELECT COUNT(*) FROM {name}"), ())
            .await;
        row.2 = row_count.unwrap_or_default();
    }

    let largest_webxdc_data = ctx
        .sql
        .query_map_vec(
            "SELECT msg_id, SUM(length(update_item)) as size, COUNT(*) as update_count
                 FROM msgs_status_updates
                 GROUP BY msg_id ORDER BY size DESC LIMIT 10",
            (),
            |row| {
                let msg_id: MsgId = row.get(0)?;
                let size: u64 = row.get(1)?;
                let count: u64 = row.get(2)?;

                Ok((msg_id, size, count))
            },
        )
        .await?;

    let blobdir_size = blobdir_size.await?;

    Ok(StorageUsage {
        db_size: page_size * page_count,
        largest_tables,
        largest_webxdc_data,
        blobdir_size,
    })
}

/// Returns storage usage of the blob directory
#[expect(clippy::arithmetic_side_effects)]
pub fn get_blobdir_storage_usage(ctx: &Context) -> u64 {
    WalkDir::new(ctx.get_blobdir())
        .max_depth(2)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.metadata().ok())
        .filter(|metadata| metadata.is_file())
        .fold(0, |acc, m| acc + m.len())
}
