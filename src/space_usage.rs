//! Module to collect and display Disk Space Usage of a Profile.
use crate::context::Context;
use anyhow::Result;
use humansize::{BINARY, format_size};

/// Space Usage Report
/// Useful for debugging space usage problems in the deltachat database.
#[derive(Debug)]
pub struct SpaceUsage {
    /// Total database size, subtract this from the backup size to estimate size of all blobs
    pub db_size: usize,
    /// size and row count of the 10 biggest tables
    pub largest_tables: Vec<(String, usize, Option<usize>)>,
    /// count and total size of status updates
    /// for the 10 webxdc apps with the most size usage in status updates
    pub largest_webxdc_data: Vec<(usize, usize, usize)>,
}

impl std::fmt::Display for SpaceUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut report = String::from("SpaceUsage:\n");
        let human_db_size = format_size(self.db_size, BINARY);
        report += &format!("[Database Size]: {human_db_size}\n");
        report += "[Largest Tables]:\n";
        for (name, size, row_count) in &self.largest_tables {
            let human_table_size = format_size(*size, BINARY);
            report += &format!(
                "   {name:<20} {human_table_size:>10}, {row_count:>6} rows\n",
                name = format!("{name}:"),
                row_count = row_count.map(|c| c.to_string()).unwrap_or("?".to_owned())
            );
        }
        report += "[Webxdc With Biggest Status Update Space Usage]:\n";
        for (msg_id, size, update_count) in &self.largest_webxdc_data {
            let human_size = format_size(*size, BINARY);
            report += &format!(
                "   {msg_id:<5} {human_size} across {update_count} updates\n",
                msg_id = format!("{msg_id}:")
            );
        }
        write!(f, "{report}")
    }
}

impl Context {
    /// Get space usage information for the Context's database
    /// used in Context.get_info()
    pub async fn get_space_usage(&self) -> Result<SpaceUsage> {
        // currently this is shown in system info, so needs to be fast,
        // that's why we donot count size of all blobs for now
        let page_size: usize = self
            .sql
            .query_get_value("PRAGMA page_size", ())
            .await?
            .unwrap_or_default();
        let page_count: usize = self
            .sql
            .query_get_value("PRAGMA page_count", ())
            .await?
            .unwrap_or_default();

        let mut largest_tables = Vec::new();

        // check if https://sqlite.org/dbstat.html is enabled
        if self
            .sql
            .query_map("SELECT * FROM dbstat LIMIT 1", (), |_| Ok(()), |_| Ok(()))
            .await
            .is_ok()
        {
            let biggest_tables = self
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
                        let size: usize = row.get(1)?;
                        Ok((name, size))
                    },
                )
                .await?;

            for (name, size) in biggest_tables {
                let row_count: Result<Option<usize>> = self
                    .sql
                    // SAFETY: the table name comes from the db, not from the user
                    .query_get_value(&format!("SELECT COUNT(*) FROM {name}"), ())
                    .await;
                largest_tables.push((name, size, row_count.unwrap_or_default()));
            }
        } else {
            error!(self, "used sqlite version does not support dbstat");
        }

        let largest_webxdc_data = self
            .sql
            .query_map_vec(
                "SELECT msg_id, SUM(length(update_item)) as size, COUNT(*) as update_count
                 FROM msgs_status_updates
                 GROUP BY msg_id ORDER BY size DESC LIMIT 10",
                (),
                |row| {
                    let msg_id: usize = row.get(0)?;
                    let size: usize = row.get(1)?;
                    let count: usize = row.get(2)?;

                    Ok((msg_id, size, count))
                },
            )
            .await?;

        Ok(SpaceUsage {
            db_size: page_size * page_count,
            largest_tables,
            largest_webxdc_data,
        })
    }
}
