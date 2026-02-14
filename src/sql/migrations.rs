//! Migrations module.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use deltachat_contact_tools::EmailAddress;
use deltachat_contact_tools::addr_cmp;
use pgp::composed::SignedPublicKey;
use rusqlite::OptionalExtension;

use crate::config::Config;
use crate::configure::EnteredLoginParam;
use crate::constants::ShowEmails;
use crate::context::Context;
use crate::key::DcKey;
use crate::log::warn;
use crate::message::MsgId;
use crate::provider::get_provider_info;
use crate::sql::Sql;
use crate::tools::{Time, inc_and_check, time_elapsed};
use crate::transport::ConfiguredLoginParam;

const DBVERSION: i32 = 68;
const VERSION_CFG: &str = "dbversion";
const TABLES: &str = include_str!("./tables.sql");

#[cfg(test)]
tokio::task_local! {
    static STOP_MIGRATIONS_AT: i32;
}

#[expect(clippy::arithmetic_side_effects)]
pub async fn run(context: &Context, sql: &Sql) -> Result<bool> {
    let mut exists_before_update = false;
    let mut dbversion_before_update = DBVERSION;

    if !sql
        .table_exists("config")
        .await
        .context("failed to check if config table exists")?
    {
        sql.transaction(move |transaction| {
            transaction.execute_batch(TABLES)?;

            // set raw config inside the transaction
            transaction.execute(
                "INSERT INTO config (keyname, value) VALUES (?, ?);",
                (VERSION_CFG, format!("{dbversion_before_update}")),
            )?;
            Ok(())
        })
        .await
        .context("Creating tables failed")?;

        let mut lock = context.sql.config_cache.write().await;
        lock.insert(
            VERSION_CFG.to_string(),
            Some(format!("{dbversion_before_update}")),
        );
        drop(lock);
    } else {
        exists_before_update = true;
        dbversion_before_update = sql
            .get_raw_config_int(VERSION_CFG)
            .await?
            .unwrap_or_default();
    }

    let dbversion = dbversion_before_update;
    let mut recode_avatar = false;

    if dbversion < 1 {
        sql.execute_migration(
            r#"
CREATE TABLE leftgrps ( id INTEGER PRIMARY KEY, grpid TEXT DEFAULT '');
CREATE INDEX leftgrps_index1 ON leftgrps (grpid);"#,
            1,
        )
        .await?;
    }
    if dbversion < 2 {
        sql.execute_migration(
            "ALTER TABLE contacts ADD COLUMN authname TEXT DEFAULT '';",
            2,
        )
        .await?;
    }
    if dbversion < 7 {
        sql.execute_migration(
            "CREATE TABLE keypairs (\
                 id INTEGER PRIMARY KEY, \
                 addr TEXT DEFAULT '' COLLATE NOCASE, \
                 is_default INTEGER DEFAULT 0, \
                 private_key, \
                 public_key, \
                 created INTEGER DEFAULT 0);",
            7,
        )
        .await?;
    }
    if dbversion < 10 {
        sql.execute_migration(
            "CREATE TABLE acpeerstates (\
                 id INTEGER PRIMARY KEY, \
                 addr TEXT DEFAULT '' COLLATE NOCASE, \
                 last_seen INTEGER DEFAULT 0, \
                 last_seen_autocrypt INTEGER DEFAULT 0, \
                 public_key, \
                 prefer_encrypted INTEGER DEFAULT 0); \
              CREATE INDEX acpeerstates_index1 ON acpeerstates (addr);",
            10,
        )
        .await?;
    }
    if dbversion < 12 {
        sql.execute_migration(
            r#"
CREATE TABLE msgs_mdns ( msg_id INTEGER,  contact_id INTEGER);
CREATE INDEX msgs_mdns_index1 ON msgs_mdns (msg_id);"#,
            12,
        )
        .await?;
    }
    if dbversion < 17 {
        sql.execute_migration(
            r#"
ALTER TABLE chats ADD COLUMN archived INTEGER DEFAULT 0;
CREATE INDEX chats_index2 ON chats (archived);
ALTER TABLE msgs ADD COLUMN starred INTEGER DEFAULT 0;
CREATE INDEX msgs_index5 ON msgs (starred);"#,
            17,
        )
        .await?;
    }
    if dbversion < 18 {
        sql.execute_migration(
            r#"
ALTER TABLE acpeerstates ADD COLUMN gossip_timestamp INTEGER DEFAULT 0;
ALTER TABLE acpeerstates ADD COLUMN gossip_key;"#,
            18,
        )
        .await?;
    }
    if dbversion < 27 {
        // chat.id=1 and chat.id=2 are the old deaddrops,
        // the current ones are defined by chats.blocked=2
        sql.execute_migration(
            r#"
DELETE FROM msgs WHERE chat_id=1 OR chat_id=2;
CREATE INDEX chats_contacts_index2 ON chats_contacts (contact_id);
ALTER TABLE msgs ADD COLUMN timestamp_sent INTEGER DEFAULT 0;
ALTER TABLE msgs ADD COLUMN timestamp_rcvd INTEGER DEFAULT 0;"#,
            27,
        )
        .await?;
    }
    if dbversion < 34 {
        sql.execute_migration(
            r#"
ALTER TABLE msgs ADD COLUMN hidden INTEGER DEFAULT 0;
ALTER TABLE msgs_mdns ADD COLUMN timestamp_sent INTEGER DEFAULT 0;
ALTER TABLE acpeerstates ADD COLUMN public_key_fingerprint TEXT DEFAULT '';
ALTER TABLE acpeerstates ADD COLUMN gossip_key_fingerprint TEXT DEFAULT '';
CREATE INDEX acpeerstates_index3 ON acpeerstates (public_key_fingerprint);
CREATE INDEX acpeerstates_index4 ON acpeerstates (gossip_key_fingerprint);"#,
            34,
        )
        .await?;
    }
    if dbversion < 39 {
        sql.execute_migration(
            r#"
CREATE TABLE tokens ( 
  id INTEGER PRIMARY KEY, 
  namespc INTEGER DEFAULT 0, 
  foreign_id INTEGER DEFAULT 0, 
  token TEXT DEFAULT '', 
  timestamp INTEGER DEFAULT 0
);
ALTER TABLE acpeerstates ADD COLUMN verified_key;
ALTER TABLE acpeerstates ADD COLUMN verified_key_fingerprint TEXT DEFAULT '';
CREATE INDEX acpeerstates_index5 ON acpeerstates (verified_key_fingerprint);"#,
            39,
        )
        .await?;
    }
    if dbversion < 40 {
        sql.execute_migration("ALTER TABLE jobs ADD COLUMN thread INTEGER DEFAULT 0;", 40)
            .await?;
    }
    if dbversion < 44 {
        sql.execute_migration("ALTER TABLE msgs ADD COLUMN mime_headers TEXT;", 44)
            .await?;
    }
    if dbversion < 46 {
        sql.execute_migration(
            r#"
ALTER TABLE msgs ADD COLUMN mime_in_reply_to TEXT;
ALTER TABLE msgs ADD COLUMN mime_references TEXT;"#,
            46,
        )
        .await?;
    }
    if dbversion < 47 {
        sql.execute_migration("ALTER TABLE jobs ADD COLUMN tries INTEGER DEFAULT 0;", 47)
            .await?;
    }
    if dbversion < 48 {
        // NOTE: move_state is not used anymore
        sql.execute_migration(
            "ALTER TABLE msgs ADD COLUMN move_state INTEGER DEFAULT 1;",
            48,
        )
        .await?;
    }
    if dbversion < 49 {
        sql.execute_migration(
            "ALTER TABLE chats ADD COLUMN gossiped_timestamp INTEGER DEFAULT 0;",
            49,
        )
        .await?;
    }
    if dbversion < 50 {
        // installations <= 0.100.1 used DC_SHOW_EMAILS_ALL implicitly;
        // keep this default and use DC_SHOW_EMAILS_NO
        // only for new installations
        if exists_before_update {
            sql.set_raw_config_int("show_emails", ShowEmails::All as i32)
                .await?;
        }
        sql.set_db_version(50).await?;
    }
    if dbversion < 53 {
        // the messages containing _only_ locations
        // are also added to the database as _hidden_.
        sql.execute_migration(
            r#"
CREATE TABLE locations ( 
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  latitude REAL DEFAULT 0.0, 
  longitude REAL DEFAULT 0.0, 
  accuracy REAL DEFAULT 0.0, 
  timestamp INTEGER DEFAULT 0, 
  chat_id INTEGER DEFAULT 0, 
  from_id INTEGER DEFAULT 0
);"
CREATE INDEX locations_index1 ON locations (from_id);
CREATE INDEX locations_index2 ON locations (timestamp);
ALTER TABLE chats ADD COLUMN locations_send_begin INTEGER DEFAULT 0;
ALTER TABLE chats ADD COLUMN locations_send_until INTEGER DEFAULT 0;
ALTER TABLE chats ADD COLUMN locations_last_sent INTEGER DEFAULT 0;
CREATE INDEX chats_index3 ON chats (locations_send_until);"#,
            53,
        )
        .await?;
    }
    if dbversion < 54 {
        sql.execute_migration(
            r#"
ALTER TABLE msgs ADD COLUMN location_id INTEGER DEFAULT 0;
CREATE INDEX msgs_index6 ON msgs (location_id);"#,
            54,
        )
        .await?;
    }
    if dbversion < 55 {
        sql.execute_migration(
            "ALTER TABLE locations ADD COLUMN independent INTEGER DEFAULT 0;",
            55,
        )
        .await?;
    }
    if dbversion < 59 {
        // records in the devmsglabels are kept when the message is deleted.
        // so, msg_id may or may not exist.
        sql.execute_migration(
            r#"
CREATE TABLE devmsglabels (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT, msg_id INTEGER DEFAULT 0);
CREATE INDEX devmsglabels_index1 ON devmsglabels (label);"#, 59)
            .await?;
        if exists_before_update && sql.get_raw_config_int("bcc_self").await?.is_none() {
            sql.set_raw_config_int("bcc_self", 1).await?;
        }
    }

    if dbversion < 60 {
        sql.execute_migration(
            "ALTER TABLE chats ADD COLUMN created_timestamp INTEGER DEFAULT 0;",
            60,
        )
        .await?;
    }
    if dbversion < 61 {
        sql.execute_migration(
            "ALTER TABLE contacts ADD COLUMN selfavatar_sent INTEGER DEFAULT 0;",
            61,
        )
        .await?;
    }
    if dbversion < 62 {
        sql.execute_migration(
            "ALTER TABLE chats ADD COLUMN muted_until INTEGER DEFAULT 0;",
            62,
        )
        .await?;
    }
    if dbversion < 63 {
        sql.execute_migration("UPDATE chats SET grpid='' WHERE type=100", 63)
            .await?;
    }
    if dbversion < 64 {
        sql.execute_migration("ALTER TABLE msgs ADD COLUMN error TEXT DEFAULT '';", 64)
            .await?;
    }
    if dbversion < 65 {
        sql.execute_migration(
            r#"
ALTER TABLE chats ADD COLUMN ephemeral_timer INTEGER;
ALTER TABLE msgs ADD COLUMN ephemeral_timer INTEGER DEFAULT 0;
ALTER TABLE msgs ADD COLUMN ephemeral_timestamp INTEGER DEFAULT 0;"#,
            65,
        )
        .await?;
    }
    if dbversion < 66 {
        sql.set_db_version(66).await?;
    }
    if dbversion < 67 {
        for prefix in &["", "configured_"] {
            if let Some(server_flags) = sql
                .get_raw_config_int(&format!("{prefix}server_flags"))
                .await?
            {
                let imap_socket_flags = server_flags & 0x700;
                let key = &format!("{prefix}mail_security");
                match imap_socket_flags {
                    0x100 => sql.set_raw_config_int(key, 2).await?, // STARTTLS
                    0x200 => sql.set_raw_config_int(key, 1).await?, // SSL/TLS
                    0x400 => sql.set_raw_config_int(key, 3).await?, // Plain
                    _ => sql.set_raw_config_int(key, 0).await?,
                }
                let smtp_socket_flags = server_flags & 0x70000;
                let key = &format!("{prefix}send_security");
                match smtp_socket_flags {
                    0x10000 => sql.set_raw_config_int(key, 2).await?, // STARTTLS
                    0x20000 => sql.set_raw_config_int(key, 1).await?, // SSL/TLS
                    0x40000 => sql.set_raw_config_int(key, 3).await?, // Plain
                    _ => sql.set_raw_config_int(key, 0).await?,
                }
            }
        }
        sql.set_db_version(67).await?;
    }
    if dbversion < 68 {
        // the index is used to speed up get_fresh_msg_cnt() (see comment there for more details) and marknoticed_chat()
        sql.execute_migration(
            "CREATE INDEX IF NOT EXISTS msgs_index7 ON msgs (state, hidden, chat_id);",
            68,
        )
        .await?;
    }
    if dbversion < 69 {
        sql.execute_migration(
            r#"
ALTER TABLE chats ADD COLUMN protected INTEGER DEFAULT 0;
-- 120=group, 130=old verified group
UPDATE chats SET protected=1, type=120 WHERE type=130;"#,
            69,
        )
        .await?;
    }

    if dbversion < 71 {
        if let Ok(addr) = context.get_primary_self_addr().await {
            if let Ok(domain) = EmailAddress::new(&addr).map(|email| email.domain) {
                context
                    .set_config_internal(
                        Config::ConfiguredProvider,
                        get_provider_info(&domain).map(|provider| provider.id),
                    )
                    .await?;
            } else {
                warn!(context, "Can't parse configured address: {:?}", addr);
            }
        }

        sql.set_db_version(71).await?;
    }
    if dbversion < 72 && !sql.col_exists("msgs", "mime_modified").await? {
        sql.execute_migration(
            r#"
    ALTER TABLE msgs ADD COLUMN mime_modified INTEGER DEFAULT 0;"#,
            72,
        )
        .await?;
    }
    if dbversion < 73 {
        sql.execute(
            r#"
CREATE TABLE imap_sync (folder TEXT PRIMARY KEY, uidvalidity INTEGER DEFAULT 0, uid_next INTEGER DEFAULT 0);"#,
()
        )
            .await?;
        for c in [
            "configured_inbox_folder",
            "configured_sentbox_folder",
            "configured_mvbox_folder",
        ] {
            if let Some(folder) = context.sql.get_raw_config(c).await? {
                let key = format!("imap.mailbox.{folder}");

                let (uid_validity, last_seen_uid) =
                    if let Some(entry) = context.sql.get_raw_config(&key).await? {
                        // the entry has the format `imap.mailbox.<folder>=<uidvalidity>:<lastseenuid>`
                        let mut parts = entry.split(':');
                        (
                            parts.next().unwrap_or_default().parse().unwrap_or(0),
                            parts.next().unwrap_or_default().parse().unwrap_or(0),
                        )
                    } else {
                        (0, 0)
                    };
                if last_seen_uid > 0 {
                    context
                        .sql
                        .execute(
                            "INSERT INTO imap_sync (folder, uid_next) VALUES (?,?)
                             ON CONFLICT(folder) DO UPDATE SET uid_next=excluded.uid_next",
                            (&folder, last_seen_uid + 1),
                        )
                        .await?;
                    context
                        .sql
                        .execute(
                            "INSERT INTO imap_sync (folder, uidvalidity) VALUES (?,?)
                             ON CONFLICT(folder) DO UPDATE SET uidvalidity=excluded.uidvalidity",
                            (&folder, uid_validity),
                        )
                        .await?;
                }
            }
        }
        sql.set_db_version(73).await?;
    }
    if dbversion < 74 {
        sql.execute_migration("UPDATE contacts SET name='' WHERE name=authname", 74)
            .await?;
    }
    if dbversion < 75 {
        sql.execute_migration(
            "ALTER TABLE contacts ADD COLUMN status TEXT DEFAULT '';",
            75,
        )
        .await?;
    }
    if dbversion < 76 {
        sql.execute_migration("ALTER TABLE msgs ADD COLUMN subject TEXT DEFAULT '';", 76)
            .await?;
    }
    if dbversion < 77 {
        recode_avatar = true;
        sql.set_db_version(77).await?;
    }
    if dbversion < 78 {
        // move requests to "Archived Chats",
        // this way, the app looks familiar after the contact request upgrade.
        sql.execute_migration("UPDATE chats SET archived=1 WHERE blocked=2;", 78)
            .await?;
    }
    if dbversion < 79 {
        sql.execute_migration(
            r#"
        ALTER TABLE msgs ADD COLUMN download_state INTEGER DEFAULT 0;
        "#,
            79,
        )
        .await?;
    }
    if dbversion < 80 {
        sql.execute_migration(
            r#"CREATE TABLE multi_device_sync (
id INTEGER PRIMARY KEY AUTOINCREMENT,
item TEXT DEFAULT '');"#,
            80,
        )
        .await?;
    }
    if dbversion < 81 {
        sql.execute_migration("ALTER TABLE msgs ADD COLUMN hop_info TEXT;", 81)
            .await?;
    }
    if dbversion < 82 {
        sql.execute_migration(
            r#"CREATE TABLE imap (
id INTEGER PRIMARY KEY AUTOINCREMENT,
rfc724_mid TEXT DEFAULT '', -- Message-ID header
folder TEXT DEFAULT '', -- IMAP folder
target TEXT DEFAULT '', -- Destination folder, empty to delete.
uid INTEGER DEFAULT 0, -- UID
uidvalidity INTEGER DEFAULT 0,
UNIQUE (folder, uid, uidvalidity)
);
CREATE INDEX imap_folder ON imap(folder);
CREATE INDEX imap_messageid ON imap(rfc724_mid);

INSERT INTO imap
(rfc724_mid, folder, target, uid, uidvalidity)
SELECT
rfc724_mid,
server_folder AS folder,
server_folder AS target,
server_uid AS uid,
(SELECT uidvalidity FROM imap_sync WHERE folder=server_folder) AS uidvalidity
FROM msgs
WHERE server_uid>0
ON CONFLICT (folder, uid, uidvalidity)
DO UPDATE SET rfc724_mid=excluded.rfc724_mid,
              target=excluded.target;
"#,
            82,
        )
        .await?;
    }
    if dbversion < 83 {
        sql.execute_migration(
            "ALTER TABLE imap_sync
             ADD COLUMN modseq -- Highest modification sequence
             INTEGER DEFAULT 0",
            83,
        )
        .await?;
    }
    if dbversion < 84 {
        sql.execute_migration(
            r#"CREATE TABLE msgs_status_updates (
id INTEGER PRIMARY KEY AUTOINCREMENT,
msg_id INTEGER,
update_item TEXT DEFAULT '',
update_item_read INTEGER DEFAULT 0 -- XXX unused
);
CREATE INDEX msgs_status_updates_index1 ON msgs_status_updates (msg_id);"#,
            84,
        )
        .await?;
    }
    if dbversion < 85 {
        sql.execute_migration(
            r#"CREATE TABLE smtp (
id INTEGER PRIMARY KEY,
rfc724_mid TEXT NOT NULL,          -- Message-ID
mime TEXT NOT NULL,                -- SMTP payload
msg_id INTEGER NOT NULL,           -- ID of the message in `msgs` table
recipients TEXT NOT NULL,          -- List of recipients separated by space
retries INTEGER NOT NULL DEFAULT 0 -- Number of failed attempts to send the message
);
CREATE INDEX smtp_messageid ON imap(rfc724_mid);
"#,
            85,
        )
        .await?;
    }
    if dbversion < 86 {
        sql.execute_migration(
            r#"CREATE TABLE bobstate (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   invite TEXT NOT NULL,
                   next_step INTEGER NOT NULL,
                   chat_id INTEGER NOT NULL
            );"#,
            86,
        )
        .await?;
    }
    if dbversion < 87 {
        // the index is used to speed up delete_expired_messages()
        sql.execute_migration(
            "CREATE INDEX IF NOT EXISTS msgs_index8 ON msgs (ephemeral_timestamp);",
            87,
        )
        .await?;
    }
    if dbversion < 88 {
        sql.execute_migration("DROP TABLE IF EXISTS backup_blobs;", 88)
            .await?;
    }
    if dbversion < 89 {
        sql.execute_migration(
            r#"CREATE TABLE imap_markseen (
              id INTEGER,
              FOREIGN KEY(id) REFERENCES imap(id) ON DELETE CASCADE
            );"#,
            89,
        )
        .await?;
    }
    if dbversion < 90 {
        sql.execute_migration(
            r#"CREATE TABLE smtp_mdns (
              msg_id INTEGER NOT NULL, -- id of the message in msgs table which requested MDN (DEPRECATED 2024-06-21)
              from_id INTEGER NOT NULL, -- id of the contact that sent the message, MDN destination
              rfc724_mid TEXT NOT NULL, -- Message-ID header
              retries INTEGER NOT NULL DEFAULT 0 -- Number of failed attempts to send MDN
            );"#,
            90,
        )
        .await?;
    }
    if dbversion < 91 {
        sql.execute_migration(
            r#"CREATE TABLE smtp_status_updates (
              msg_id INTEGER NOT NULL UNIQUE, -- msg_id of the webxdc instance with pending updates
              first_serial INTEGER NOT NULL, -- id in msgs_status_updates
              last_serial INTEGER NOT NULL, -- id in msgs_status_updates
              descr TEXT NOT NULL -- text to send along with the updates
            );"#,
            91,
        )
        .await?;
    }
    if dbversion < 92 {
        sql.execute_migration(
            r#"CREATE TABLE reactions (
              msg_id INTEGER NOT NULL, -- id of the message reacted to
              contact_id INTEGER NOT NULL, -- id of the contact reacting to the message
              reaction TEXT DEFAULT '' NOT NULL, -- a sequence of emojis separated by spaces
              PRIMARY KEY(msg_id, contact_id),
              FOREIGN KEY(msg_id) REFERENCES msgs(id) ON DELETE CASCADE -- delete reactions when message is deleted
              FOREIGN KEY(contact_id) REFERENCES contacts(id) ON DELETE CASCADE -- delete reactions when contact is deleted
            )"#,
            92
        ).await?;
    }
    if dbversion < 93 {
        // `sending_domains` is now unused, but was not removed for backwards compatibility.
        sql.execute_migration(
            "CREATE TABLE sending_domains(domain TEXT PRIMARY KEY, dkim_works INTEGER DEFAULT 0);",
            93,
        )
        .await?;
    }
    if dbversion < 94 {
        sql.execute_migration(
            // Create new `acpeerstates` table, same as before but with unique constraint.
            //
            // This allows to use `UPSERT` to update existing or insert a new peerstate
            // depending on whether one exists already.
            "CREATE TABLE new_acpeerstates (
             id INTEGER PRIMARY KEY,
             addr TEXT DEFAULT '' COLLATE NOCASE,
             last_seen INTEGER DEFAULT 0,
             last_seen_autocrypt INTEGER DEFAULT 0,
             public_key,
             prefer_encrypted INTEGER DEFAULT 0,
             gossip_timestamp INTEGER DEFAULT 0,
             gossip_key,
             public_key_fingerprint TEXT DEFAULT '',
             gossip_key_fingerprint TEXT DEFAULT '',
             verified_key,
             verified_key_fingerprint TEXT DEFAULT '',
             UNIQUE (addr) -- Only one peerstate per address
             );
            INSERT OR IGNORE INTO new_acpeerstates SELECT
                id, addr, last_seen, last_seen_autocrypt, public_key, prefer_encrypted,
                gossip_timestamp, gossip_key, public_key_fingerprint,
                gossip_key_fingerprint, verified_key, verified_key_fingerprint
            FROM acpeerstates;
            DROP TABLE acpeerstates;
            ALTER TABLE new_acpeerstates RENAME TO acpeerstates;
            CREATE INDEX acpeerstates_index1 ON acpeerstates (addr);
            CREATE INDEX acpeerstates_index3 ON acpeerstates (public_key_fingerprint);
            CREATE INDEX acpeerstates_index4 ON acpeerstates (gossip_key_fingerprint);
            CREATE INDEX acpeerstates_index5 ON acpeerstates (verified_key_fingerprint);
            ",
            94,
        )
        .await?;
    }
    if dbversion < 95 {
        sql.execute_migration(
            "CREATE TABLE new_chats_contacts (chat_id INTEGER, contact_id INTEGER, UNIQUE(chat_id, contact_id));\
            INSERT OR IGNORE INTO new_chats_contacts SELECT chat_id, contact_id FROM chats_contacts;\
            DROP TABLE chats_contacts;\
            ALTER TABLE new_chats_contacts RENAME TO chats_contacts;\
            CREATE INDEX chats_contacts_index1 ON chats_contacts (chat_id);\
            CREATE INDEX chats_contacts_index2 ON chats_contacts (contact_id);",
            95
        ).await?;
    }
    if dbversion < 96 {
        sql.execute_migration(
            "ALTER TABLE acpeerstates ADD COLUMN verifier TEXT DEFAULT '';",
            96,
        )
        .await?;
    }
    if dbversion < 97 {
        sql.execute_migration(
            "CREATE TABLE dns_cache (
               hostname TEXT NOT NULL,
               address TEXT NOT NULL, -- IPv4 or IPv6 address
               timestamp INTEGER NOT NULL,
               UNIQUE (hostname, address)
             )",
            97,
        )
        .await?;
    }
    if dbversion < 98 {
        if exists_before_update && sql.get_raw_config_int("show_emails").await?.is_none() {
            sql.set_raw_config_int("show_emails", ShowEmails::Off as i32)
                .await?;
        }
        sql.set_db_version(98).await?;
    }
    if dbversion < 99 {
        // sql.execute_migration(
        //     "ALTER TABLE msgs DROP COLUMN server_folder;
        //      ALTER TABLE msgs DROP COLUMN server_uid;
        //      ALTER TABLE msgs DROP COLUMN move_state;
        //      ALTER TABLE chats DROP COLUMN draft_timestamp;
        //      ALTER TABLE chats DROP COLUMN draft_txt",
        //     99,
        // )
        // .await?;

        // Reverted above, as it requires to load the whole DB in memory.
        sql.set_db_version(99).await?;
    }
    if dbversion < 100 {
        sql.execute_migration(
            "ALTER TABLE msgs ADD COLUMN mime_compressed INTEGER NOT NULL DEFAULT 0",
            100,
        )
        .await?;
    }
    if dbversion < 101 {
        // Recreate `smtp` table with autoincrement.
        // rfc724_mid index is not recreated, because it is not used.
        sql.execute_migration(
            "DROP TABLE smtp;
             CREATE TABLE smtp (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             rfc724_mid TEXT NOT NULL,          -- Message-ID
             mime TEXT NOT NULL,                -- SMTP payload
             msg_id INTEGER NOT NULL,           -- ID of the message in `msgs` table
             recipients TEXT NOT NULL,          -- List of recipients separated by space
             retries INTEGER NOT NULL DEFAULT 0 -- Number of failed attempts to send the message
            );
            ",
            101,
        )
        .await?;
    }

    if dbversion < 102 {
        sql.execute_migration(
            "CREATE TABLE download (
            msg_id INTEGER NOT NULL -- id of the message stub in msgs table
            )",
            102,
        )
        .await?;
    }

    // Add is_bot column to contacts table with default false.
    if dbversion < 103 {
        sql.execute_migration(
            "ALTER TABLE contacts ADD COLUMN is_bot INTEGER NOT NULL DEFAULT 0",
            103,
        )
        .await?;
    }

    if dbversion < 104 {
        sql.execute_migration(
            "ALTER TABLE acpeerstates
             ADD COLUMN secondary_verified_key;
             ALTER TABLE acpeerstates
             ADD COLUMN secondary_verified_key_fingerprint TEXT DEFAULT '';
             ALTER TABLE acpeerstates
             ADD COLUMN secondary_verifier TEXT DEFAULT ''",
            104,
        )
        .await?;
    }

    if dbversion < 105 {
        // Create UNIQUE uid column and drop unused update_item_read column.
        sql.execute_migration(
            r#"CREATE TABLE new_msgs_status_updates (
id INTEGER PRIMARY KEY AUTOINCREMENT,
msg_id INTEGER,
update_item TEXT DEFAULT '',
uid TEXT UNIQUE
);
INSERT OR IGNORE INTO new_msgs_status_updates SELECT
  id, msg_id, update_item, NULL
FROM msgs_status_updates;
DROP TABLE msgs_status_updates;
ALTER TABLE new_msgs_status_updates RENAME TO msgs_status_updates;
CREATE INDEX msgs_status_updates_index1 ON msgs_status_updates (msg_id);
CREATE INDEX msgs_status_updates_index2 ON msgs_status_updates (uid);
"#,
            105,
        )
        .await?;
    }

    if dbversion < 106 {
        // Recreate `config` table with UNIQUE constraint on `keyname`.
        sql.execute_migration(
            "CREATE TABLE new_config (
               id INTEGER PRIMARY KEY,
               keyname TEXT UNIQUE,
               value TEXT NOT NULL
             );
             INSERT OR IGNORE INTO new_config SELECT
               id, keyname, value
             FROM config;
             DROP TABLE config;
             ALTER TABLE new_config RENAME TO config;
             CREATE INDEX config_index1 ON config (keyname);",
            106,
        )
        .await?;
    }

    if dbversion < 107 {
        sql.execute_migration(
            "CREATE TABLE new_keypairs (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               private_key UNIQUE NOT NULL,
               public_key UNIQUE NOT NULL
             );
             INSERT OR IGNORE INTO new_keypairs SELECT id, private_key, public_key FROM keypairs;

             INSERT OR IGNORE
             INTO config (keyname, value)
             VALUES
             ('key_id', (SELECT id FROM new_keypairs
                         WHERE private_key=
                           (SELECT private_key FROM keypairs
                            WHERE addr=(SELECT value FROM config WHERE keyname='configured_addr')
                            AND is_default=1)));

             -- We do not drop the old `keypairs` table for now,
             -- but move it to `old_keypairs`. We can remove it later
             -- in next migrations. This may be needed for recovery
             -- in case something is wrong with the migration.
             ALTER TABLE keypairs RENAME TO old_keypairs;
             ALTER TABLE new_keypairs RENAME TO keypairs;
             ",
            107,
        )
        .await?;
    }

    if dbversion < 108 {
        let version = 108;
        let chunk_size = context.get_max_smtp_rcpt_to().await?;
        sql.transaction(move |trans| {
            Sql::set_db_version_trans(trans, version)?;
            let id_max =
                trans.query_row("SELECT IFNULL((SELECT MAX(id) FROM smtp), 0)", (), |row| {
                    let id_max: i64 = row.get(0)?;
                    Ok(id_max)
                })?;
            while let Some((id, rfc724_mid, mime, msg_id, recipients, retries)) = trans
                .query_row(
                    "SELECT id, rfc724_mid, mime, msg_id, recipients, retries FROM smtp \
                    WHERE id<=? LIMIT 1",
                    (id_max,),
                    |row| {
                        let id: i64 = row.get(0)?;
                        let rfc724_mid: String = row.get(1)?;
                        let mime: String = row.get(2)?;
                        let msg_id: MsgId = row.get(3)?;
                        let recipients: String = row.get(4)?;
                        let retries: i64 = row.get(5)?;
                        Ok((id, rfc724_mid, mime, msg_id, recipients, retries))
                    },
                )
                .optional()?
            {
                trans.execute("DELETE FROM smtp WHERE id=?", (id,))?;
                let recipients = recipients.split(' ').collect::<Vec<_>>();
                for recipients in recipients.chunks(chunk_size) {
                    let recipients = recipients.join(" ");
                    trans.execute(
                        "INSERT INTO smtp (rfc724_mid, mime, msg_id, recipients, retries) \
                        VALUES (?, ?, ?, ?, ?)",
                        (&rfc724_mid, &mime, msg_id, recipients, retries),
                    )?;
                }
            }
            Ok(())
        })
        .await
        .with_context(|| format!("migration failed for version {version}"))?;

        sql.set_db_version_in_cache(version).await?;
    }

    if dbversion < 109 {
        sql.execute_migration(
            r#"ALTER TABLE acpeerstates
               ADD COLUMN backward_verified_key_id -- What we think the contact has as our verified key
               INTEGER;
               UPDATE acpeerstates
               SET backward_verified_key_id=(SELECT value FROM config WHERE keyname='key_id')
               WHERE verified_key IS NOT NULL
               "#,
            109,
        )
        .await?;
    }

    if dbversion < 110 {
        sql.execute_migration(
            "ALTER TABLE keypairs ADD COLUMN addr TEXT DEFAULT '' COLLATE NOCASE;
            ALTER TABLE keypairs ADD COLUMN is_default INTEGER DEFAULT 0;
            ALTER TABLE keypairs ADD COLUMN created INTEGER DEFAULT 0;
            UPDATE keypairs SET addr=(SELECT value FROM config WHERE keyname='configured_addr'), is_default=1;",
            110,
        )
        .await?;
    }

    if dbversion < 111 {
        sql.execute_migration(
            "CREATE TABLE iroh_gossip_peers (msg_id TEXT not NULL, topic TEXT NOT NULL, public_key TEXT NOT NULL)",
            111,
        )
        .await?;
    }

    if dbversion < 112 {
        sql.execute_migration(
            "DROP TABLE iroh_gossip_peers; CREATE TABLE iroh_gossip_peers (msg_id INTEGER not NULL, topic BLOB NOT NULL, public_key BLOB NOT NULL, relay_server TEXT, UNIQUE (public_key, topic)) STRICT",
            112,
        )
        .await?;
    }

    if dbversion < 113 {
        sql.execute_migration(
            "DROP TABLE iroh_gossip_peers; CREATE TABLE iroh_gossip_peers (msg_id INTEGER not NULL, topic BLOB NOT NULL, public_key BLOB NOT NULL, relay_server TEXT, UNIQUE (topic, public_key), PRIMARY KEY(topic, public_key)) STRICT",
            113,
        )
        .await?;
    }

    if dbversion < 114 {
        sql.execute_migration("CREATE INDEX reactions_index1 ON reactions (msg_id)", 114)
            .await?;
    }

    if dbversion < 115 {
        sql.execute_migration("ALTER TABLE msgs ADD COLUMN txt_normalized TEXT", 115)
            .await?;
    }
    let mut migration_version: i32 = 115;

    inc_and_check(&mut migration_version, 116)?;
    if dbversion < migration_version {
        // Whether the message part doesn't need to be stored on the server. If all parts are marked
        // deleted, a server-side deletion is issued.
        sql.execute_migration(
            "ALTER TABLE msgs ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 117)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "CREATE TABLE connection_history (
                host TEXT NOT NULL, -- server hostname
                port INTEGER NOT NULL, -- server port
                alpn TEXT NOT NULL, -- ALPN such as smtp or imap
                addr TEXT NOT NULL, -- IP address
                timestamp INTEGER NOT NULL, -- timestamp of the most recent successful connection
                UNIQUE (host, port, alpn, addr)
            ) STRICT",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 118)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "CREATE TABLE tokens_new (
                id INTEGER PRIMARY KEY,
                namespc INTEGER DEFAULT 0,
                foreign_key TEXT DEFAULT '',
                token TEXT DEFAULT '',
                timestamp INTEGER DEFAULT 0
            ) STRICT;
            INSERT INTO tokens_new
                SELECT t.id, t.namespc, IFNULL(c.grpid, ''), t.token, t.timestamp
                FROM tokens t LEFT JOIN chats c ON t.foreign_id=c.id;
            DROP TABLE tokens;
            ALTER TABLE tokens_new RENAME TO tokens;",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 119)?;
    if dbversion < migration_version {
        // This table is deprecated sinc 2025-12-25.
        // Sync messages are again sent over SMTP.
        sql.execute_migration(
            "CREATE TABLE imap_send (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mime TEXT NOT NULL, -- Message content
                msg_id INTEGER NOT NULL, -- ID of the message in the `msgs` table
                attempts INTEGER NOT NULL DEFAULT 0 -- Number of failed attempts to send the message
            )",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 120)?;
    if dbversion < migration_version {
        // Core 1.143.0 changed the default for `delete_server_after`
        // to delete immediately (`1`) for chatmail accounts that don't have multidevice
        // and updating to `0` when backup is exported.
        //
        // Since we don't know if existing configurations
        // are multidevice, we set `delete_server_after` for them
        // to the old default of `0`, so only new configurations are
        // affected by the default change.
        //
        // `INSERT OR IGNORE` works
        // because `keyname` was made UNIQUE in migration 106.
        sql.execute_migration(
            "INSERT OR IGNORE INTO config (keyname, value)
             SELECT 'delete_server_after', '0'
             FROM config WHERE keyname='configured'
            ",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 121)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "CREATE INDEX chats_index4 ON chats (name)",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 122)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "ALTER TABLE tokens ADD COLUMN foreign_id INTEGER NOT NULL DEFAULT 0",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 123)?;
    if dbversion < migration_version {
        // Add FOREIGN KEY(msg_id).
        sql.execute_migration(
            "CREATE TABLE new_msgs_status_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id INTEGER,
                update_item TEXT DEFAULT '',
                uid TEXT UNIQUE,
                FOREIGN KEY(msg_id) REFERENCES msgs(id) ON DELETE CASCADE
            );
            INSERT OR IGNORE INTO new_msgs_status_updates SELECT
                id, msg_id, update_item, uid
            FROM msgs_status_updates;
            DROP TABLE msgs_status_updates;
            ALTER TABLE new_msgs_status_updates RENAME TO msgs_status_updates;
            CREATE INDEX msgs_status_updates_index1 ON msgs_status_updates (msg_id);
            CREATE INDEX msgs_status_updates_index2 ON msgs_status_updates (uid);
            ",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 124)?;
    if dbversion < migration_version {
        // Mark Saved Messages chat as protected if it already exists.
        sql.execute_migration(
            "UPDATE chats
             SET protected=1 -- ProtectionStatus::Protected
             WHERE type==100 -- Chattype::Single
             AND EXISTS (
                 SELECT 1 FROM chats_contacts cc
                 WHERE cc.chat_id==chats.id
                 AND cc.contact_id=1
             )
             ",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 125)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "CREATE TABLE http_cache (
                url TEXT PRIMARY KEY,
                expires INTEGER NOT NULL, -- When the cache entry is considered expired, timestamp in seconds.
                blobname TEXT NOT NULL,
                mimetype TEXT NOT NULL DEFAULT '', -- MIME type extracted from Content-Type header.
                encoding TEXT NOT NULL DEFAULT '' -- Encoding from Content-Type header.
            ) STRICT",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 126)?;
    if dbversion < migration_version {
        // Recreate http_cache table with new `stale` column.
        sql.execute_migration(
            "DROP TABLE http_cache;
             CREATE TABLE http_cache (
                url TEXT PRIMARY KEY,
                expires INTEGER NOT NULL, -- When the cache entry is considered expired, timestamp in seconds.
                stale INTEGER NOT NULL, -- When the cache entry is considered stale, timestamp in seconds.
                blobname TEXT NOT NULL,
                mimetype TEXT NOT NULL DEFAULT '', -- MIME type extracted from Content-Type header.
                encoding TEXT NOT NULL DEFAULT '' -- Encoding from Content-Type header.
            ) STRICT",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 127)?;
    if dbversion < migration_version {
        // This is buggy: `delete_server_after` > 1 isn't handled. Migration #129 fixes this.
        sql.execute_migration(
            "INSERT OR IGNORE INTO config (keyname, value)
             SELECT 'bcc_self', '1'
             FROM config WHERE keyname='delete_server_after' AND value='0'
            ",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 128)?;
    if dbversion < migration_version {
        // Add the timestamps of addition and removal.
        //
        // If `add_timestamp >= remove_timestamp`,
        // then the member is currently a member of the chat.
        // Otherwise the member is a past member.
        sql.execute_migration(
            "ALTER TABLE chats_contacts
             ADD COLUMN add_timestamp NOT NULL DEFAULT 0;
             ALTER TABLE chats_contacts
             ADD COLUMN remove_timestamp NOT NULL DEFAULT 0;
            ",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 129)?;
    if dbversion < migration_version {
        // Existing chatmail configurations having `delete_server_after` != "delete at once" should
        // get `bcc_self` enabled, they may be multidevice configurations:
        // - Before migration #127, `delete_server_after` was set to 0 upon a backup export, but
        //   then `bcc_self` is enabled instead (whose default is changed to 0 for chatmail).
        // - The user might set `delete_server_after` to a value other than 0 or 1 when that was
        //   possible in UIs.
        // We don't check `is_chatmail` for simplicity.
        sql.execute_migration(
            "INSERT OR IGNORE INTO config (keyname, value)
             SELECT 'bcc_self', '1'
             FROM config WHERE keyname='delete_server_after' AND value!='1'
            ",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 130)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "
CREATE TABLE gossip_timestamp (
  chat_id INTEGER NOT NULL, 
  fingerprint TEXT NOT NULL, -- Upper-case fingerprint of the key.
  timestamp INTEGER NOT NULL,
  UNIQUE (chat_id, fingerprint)
) STRICT;
CREATE INDEX gossip_timestamp_index ON gossip_timestamp (chat_id, fingerprint);
",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 131)?;
    if dbversion < migration_version {
        let entered_param = EnteredLoginParam::load(context).await?;
        let configured_param = ConfiguredLoginParam::load_legacy(context).await?;

        sql.execute_migration_transaction(
            |transaction| {
                transaction.execute(
                    "CREATE TABLE transports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        addr TEXT NOT NULL,
                        entered_param TEXT NOT NULL,
                        configured_param TEXT NOT NULL,
                        UNIQUE(addr)
                        )",
                    (),
                )?;
                if let Some(configured_param) = configured_param {
                    transaction.execute(
                        "INSERT INTO transports (addr, entered_param, configured_param)
                         VALUES (?, ?, ?)",
                        (
                            configured_param.addr.clone(),
                            serde_json::to_string(&entered_param)?,
                            configured_param.into_json()?,
                        ),
                    )?;
                }

                Ok(())
            },
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 132)?;
    if dbversion < migration_version {
        let start = Time::now();
        sql.execute_migration_transaction(|t| migrate_key_contacts(context, t), migration_version)
            .await?;
        info!(
            context,
            "key-contacts migration took {:?} in total.",
            time_elapsed(&start),
        );
        // Schedule `msgs_to_key_contacts()`.
        context
            .set_config_internal(Config::LastHousekeeping, None)
            .await?;
    }

    inc_and_check(&mut migration_version, 133)?;
    if dbversion < migration_version {
        // Make `ProtectionBroken` chats `Unprotected`. Chats can't break anymore.
        sql.execute_migration(
            "UPDATE chats SET protected=0 WHERE protected!=1",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 134)?; // Migration 134 was removed

    inc_and_check(&mut migration_version, 135)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "CREATE TABLE stats_securejoin_sources(
                source INTEGER PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            ) STRICT;
            CREATE TABLE stats_securejoin_uipaths(
                uipath INTEGER PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            ) STRICT;
            CREATE TABLE stats_securejoin_invites(
                already_existed INTEGER NOT NULL,
                already_verified INTEGER NOT NULL,
                type TEXT NOT NULL
            ) STRICT;
            CREATE TABLE stats_msgs(
                chattype INTEGER PRIMARY KEY,
                verified INTEGER NOT NULL DEFAULT 0,
                unverified_encrypted INTEGER NOT NULL DEFAULT 0,
                unencrypted INTEGER NOT NULL DEFAULT 0,
                only_to_self INTEGER NOT NULL DEFAULT 0,
                last_counted_msg_id INTEGER NOT NULL DEFAULT 0
            ) STRICT;",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 136)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "CREATE TABLE stats_sending_enabled_events(timestamp INTEGER NOT NULL) STRICT;
            CREATE TABLE stats_sending_disabled_events(timestamp INTEGER NOT NULL) STRICT;",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 137)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "DELETE FROM config WHERE keyname IN (
                'configured',
                'configured_imap_certificate_checks',
                'configured_imap_servers',
                'configured_mail_port',
                'configured_mail_pw',
                'configured_mail_security',
                'configured_mail_server',
                'configured_mail_user',
                'configured_send_port',
                'configured_send_pw',
                'configured_send_security',
                'configured_send_server',
                'configured_send_user',
                'configured_server_flags',
                'configured_smtp_certificate_checks',
                'configured_smtp_servers'
            )",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 138)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "CREATE TABLE broadcast_secrets(
                chat_id INTEGER PRIMARY KEY NOT NULL,
                secret TEXT NOT NULL
            ) STRICT",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 139)?;
    if dbversion < migration_version {
        sql.execute_migration_transaction(
            |transaction| {
                if exists_before_update {
                    let is_chatmail = transaction
                        .query_row(
                            "SELECT value FROM config WHERE keyname='is_chatmail'",
                            (),
                            |row| {
                                let value: String = row.get(0)?;
                                Ok(value)
                            },
                        )
                        .optional()?
                        .as_deref()
                        == Some("1");

                    // For non-chatmail accounts
                    // default "bcc_self" was "1".
                    // If it is not in the database,
                    // save the old default explicity
                    // as the new default is "0"
                    // for all accounts.
                    if !is_chatmail {
                        transaction.execute(
                            "INSERT OR IGNORE
                             INTO config (keyname, value)
                             VALUES (?, ?)",
                            ("bcc_self", "1"),
                        )?;
                    }
                }
                Ok(())
            },
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 140)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "
CREATE TABLE new_imap (
id INTEGER PRIMARY KEY AUTOINCREMENT,
transport_id INTEGER NOT NULL, -- ID of the transport in the `transports` table.
rfc724_mid TEXT NOT NULL, -- Message-ID header
folder TEXT NOT NULL, -- IMAP folder
target TEXT NOT NULL, -- Destination folder. Empty string means that the message shall be deleted.
uid INTEGER NOT NULL, -- UID
uidvalidity INTEGER NOT NULL,
UNIQUE (transport_id, folder, uid, uidvalidity)
) STRICT;

INSERT OR IGNORE INTO new_imap SELECT
  id, 1, rfc724_mid, folder, target, uid, uidvalidity
FROM imap;
DROP TABLE imap;
ALTER TABLE new_imap RENAME TO imap;
CREATE INDEX imap_folder ON imap(transport_id, folder);
CREATE INDEX imap_rfc724_mid ON imap(transport_id, rfc724_mid);

CREATE TABLE new_imap_sync (
    transport_id INTEGER NOT NULL, -- ID of the transport in the `transports` table.
    folder TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL DEFAULT 0,
    uid_next INTEGER NOT NULL DEFAULT 0,
    modseq INTEGER NOT NULL DEFAULT 0,
    UNIQUE (transport_id, folder)
) STRICT;
INSERT OR IGNORE INTO new_imap_sync SELECT
    1, folder, uidvalidity, uid_next, modseq
FROM imap_sync;
DROP TABLE imap_sync;
ALTER TABLE new_imap_sync RENAME TO imap_sync;
CREATE INDEX imap_sync_index ON imap_sync(transport_id, folder);
",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 141)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "CREATE INDEX imap_only_rfc724_mid ON imap(rfc724_mid)",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 142)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "ALTER TABLE transports
             ADD COLUMN add_timestamp INTEGER NOT NULL DEFAULT 0;
             CREATE TABLE removed_transports (
                 addr TEXT NOT NULL,
                 remove_timestamp INTEGER NOT NULL,
                 UNIQUE(addr)
             ) STRICT;",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 143)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "
ALTER TABLE chats ADD COLUMN name_normalized TEXT;
ALTER TABLE contacts ADD COLUMN name_normalized TEXT;
                ",
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 144)?;
    if dbversion < migration_version {
        sql.execute_migration_transaction(
            |transaction| {
                let is_chatmail = transaction
                    .query_row(
                        "SELECT value FROM config WHERE keyname='is_chatmail'",
                        (),
                        |row| {
                            let value: String = row.get(0)?;
                            Ok(value)
                        },
                    )
                    .optional()?
                    .as_deref()
                    == Some("1");

                if is_chatmail {
                    transaction.execute_batch(
                        "DELETE FROM config WHERE keyname='only_fetch_mvbox';
                         DELETE FROM config WHERE keyname='show_emails';
                         UPDATE config SET value='0' WHERE keyname='mvbox_move'",
                    )?;
                }
                Ok(())
            },
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 145)?;
    if dbversion < migration_version {
        // `msg_id` in `download` table is not needed anymore,
        // but we still keep it so that it's possible to import a backup into an older DC version,
        // because we don't always release at the same time on all platforms.
        sql.execute_migration(
            "CREATE TABLE download_new (
                rfc724_mid TEXT PRIMARY KEY,
                msg_id INTEGER NOT NULL DEFAULT 0
            ) STRICT;
            INSERT OR IGNORE INTO download_new (rfc724_mid, msg_id)
                SELECT m.rfc724_mid, d.msg_id FROM download d
                LEFT JOIN msgs m ON d.msg_id = m.id
                WHERE m.rfc724_mid IS NOT NULL AND m.rfc724_mid != '';
            DROP TABLE download;
            ALTER TABLE download_new RENAME TO download;
            CREATE TABLE available_post_msgs (
                rfc724_mid TEXT PRIMARY KEY
            ) STRICT;
            ALTER TABLE msgs ADD COLUMN pre_rfc724_mid TEXT DEFAULT '';
            CREATE INDEX msgs_index9 ON msgs (pre_rfc724_mid);",
            migration_version,
        )
        .await?;
    }

    // Copy of migration 144, but inserts a value for `mvbox_move`
    // if it does not exist, because no value is treated as `1`.
    inc_and_check(&mut migration_version, 146)?;
    if dbversion < migration_version {
        sql.execute_migration_transaction(
            |transaction| {
                let is_chatmail = transaction
                    .query_row(
                        "SELECT value FROM config WHERE keyname='is_chatmail'",
                        (),
                        |row| {
                            let value: String = row.get(0)?;
                            Ok(value)
                        },
                    )
                    .optional()?
                    .as_deref()
                    == Some("1");

                if is_chatmail {
                    transaction.execute_batch(
                        "DELETE FROM config WHERE keyname='only_fetch_mvbox';
                         DELETE FROM config WHERE keyname='show_emails';
                         INSERT OR REPLACE INTO config (keyname, value) VALUES ('mvbox_move', '0')",
                    )?;
                }
                Ok(())
            },
            migration_version,
        )
        .await?;
    }

    inc_and_check(&mut migration_version, 147)?;
    if dbversion < migration_version {
        sql.execute_migration(
            "CREATE TABLE chats_descriptions (chat_id INTEGER PRIMARY KEY AUTOINCREMENT, description TEXT NOT NULL DEFAULT '') STRICT;",
            migration_version,
        )
        .await?;
    }

    let new_version = sql
        .get_raw_config_int(VERSION_CFG)
        .await?
        .unwrap_or_default();
    if new_version != dbversion || !exists_before_update {
        let created_db = if exists_before_update {
            ""
        } else {
            "Created new database. "
        };
        info!(context, "{}Migration done from v{}.", created_db, dbversion);
    }
    info!(context, "Database version: v{new_version}.");

    Ok(recode_avatar)
}

fn migrate_key_contacts(
    context: &Context,
    transaction: &mut rusqlite::Transaction<'_>,
) -> std::result::Result<(), anyhow::Error> {
    info!(context, "Starting key-contact transition.");

    // =============================== Step 1: ===============================
    //                              Alter tables
    transaction.execute_batch(
        "ALTER TABLE contacts ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '';

        -- Verifier is an ID of the verifier contact.
        -- 0 if the contact is not verified.
        ALTER TABLE contacts ADD COLUMN verifier INTEGER NOT NULL DEFAULT 0;

        CREATE INDEX contacts_fingerprint_index ON contacts (fingerprint);

        CREATE TABLE public_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint TEXT NOT NULL UNIQUE, -- Upper-case fingerprint of the key.
        public_key BLOB NOT NULL -- Binary key, not ASCII-armored
        ) STRICT;
        CREATE INDEX public_key_index ON public_keys (fingerprint);

        INSERT OR IGNORE INTO public_keys (fingerprint, public_key)
        SELECT public_key_fingerprint, public_key FROM acpeerstates
         WHERE public_key_fingerprint IS NOT NULL AND public_key IS NOT NULL;

        INSERT OR IGNORE INTO public_keys (fingerprint, public_key)
        SELECT gossip_key_fingerprint, gossip_key FROM acpeerstates
         WHERE gossip_key_fingerprint IS NOT NULL AND gossip_key IS NOT NULL;

        INSERT OR IGNORE INTO public_keys (fingerprint, public_key)
        SELECT verified_key_fingerprint, verified_key FROM acpeerstates
         WHERE verified_key_fingerprint IS NOT NULL AND verified_key IS NOT NULL;

        INSERT OR IGNORE INTO public_keys (fingerprint, public_key)
        SELECT secondary_verified_key_fingerprint, secondary_verified_key FROM acpeerstates
         WHERE secondary_verified_key_fingerprint IS NOT NULL AND secondary_verified_key IS NOT NULL;",
    )
    .context("Creating key-contact tables")?;

    let Some(self_addr): Option<String> = transaction
        .query_row(
            "SELECT value FROM config WHERE keyname='configured_addr'",
            (),
            |row| row.get(0),
        )
        .optional()
        .context("Step 0")?
    else {
        info!(
            context,
            "Not yet configured, no need to migrate key-contacts"
        );
        return Ok(());
    };

    // =============================== Step 2: ===============================
    // Create up to 3 new contacts for every contact that has a peerstate:
    // one from the Autocrypt key fingerprint, one from the verified key fingerprint,
    // one from the secondary verified key fingerprint.
    // In the process, build maps from old contact id to new contact id:
    // one that maps to Autocrypt key-contact, one that maps to verified key-contact.
    let mut autocrypt_key_contacts: BTreeMap<u32, u32> = BTreeMap::new();
    let mut autocrypt_key_contacts_with_reset_peerstate: BTreeMap<u32, u32> = BTreeMap::new();
    let mut verified_key_contacts: BTreeMap<u32, u32> = BTreeMap::new();
    {
        // This maps from the verified contact to the original contact id of the verifier.
        // It can't map to the verified key contact id, because at the time of constructing
        // this map, not all key-contacts are in the database.
        let mut verifications: BTreeMap<u32, u32> = BTreeMap::new();

        let mut load_contacts_stmt = transaction
            .prepare(
                "SELECT c.id, c.name, c.addr, c.origin, c.blocked, c.last_seen,
                c.authname, c.param, c.status, c.is_bot, c.selfavatar_sent,
                IFNULL(p.public_key, p.gossip_key),
                p.verified_key, IFNULL(p.verifier, ''),
                p.secondary_verified_key, p.secondary_verifier, p.prefer_encrypted
                FROM contacts c
                INNER JOIN acpeerstates p ON c.addr=p.addr
                WHERE c.id > 9
                ORDER BY p.last_seen DESC",
            )
            .context("Step 2")?;

        let all_address_contacts: rusqlite::Result<Vec<_>> = load_contacts_stmt
            .query_map((), |row| {
                let id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let addr: String = row.get(2)?;
                let origin: i64 = row.get(3)?;
                let blocked: Option<bool> = row.get(4)?;
                let last_seen: i64 = row.get(5)?;
                let authname: String = row.get(6)?;
                let param: String = row.get(7)?;
                let status: Option<String> = row.get(8)?;
                let is_bot: bool = row.get(9)?;
                let selfavatar_sent: i64 = row.get(10)?;
                let autocrypt_key = row
                    .get(11)
                    .ok()
                    .and_then(|blob: Vec<u8>| SignedPublicKey::from_slice(&blob).ok());
                let verified_key = row
                    .get(12)
                    .ok()
                    .and_then(|blob: Vec<u8>| SignedPublicKey::from_slice(&blob).ok());
                let verifier: String = row.get(13)?;
                let secondary_verified_key = row
                    .get(12)
                    .ok()
                    .and_then(|blob: Vec<u8>| SignedPublicKey::from_slice(&blob).ok());
                let secondary_verifier: String = row.get(15)?;
                let prefer_encrypt: u8 = row.get(16)?;
                Ok((
                    id,
                    name,
                    addr,
                    origin,
                    blocked,
                    last_seen,
                    authname,
                    param,
                    status,
                    is_bot,
                    selfavatar_sent,
                    autocrypt_key,
                    verified_key,
                    verifier,
                    secondary_verified_key,
                    secondary_verifier,
                    prefer_encrypt,
                ))
            })
            .context("Step 3")?
            .collect();

        let mut insert_contact_stmt = transaction
            .prepare(
                "INSERT INTO contacts (name, addr, origin, blocked, last_seen,
                authname, param, status, is_bot, selfavatar_sent, fingerprint)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            )
            .context("Step 4")?;
        let mut fingerprint_to_id_stmt = transaction
            .prepare("SELECT id FROM contacts WHERE fingerprint=? AND id>9")
            .context("Step 5")?;
        let mut original_contact_id_from_addr_stmt = transaction
            .prepare("SELECT id FROM contacts WHERE addr=? AND fingerprint='' AND id>9")
            .context("Step 6")?;

        for row in all_address_contacts? {
            let (
                original_id,
                name,
                addr,
                origin,
                blocked,
                last_seen,
                authname,
                param,
                status,
                is_bot,
                selfavatar_sent,
                autocrypt_key,
                verified_key,
                verifier,
                secondary_verified_key,
                secondary_verifier,
                prefer_encrypt,
            ) = row;
            let mut insert_contact = |key: SignedPublicKey| -> Result<u32> {
                let fingerprint = key.dc_fingerprint().hex();
                let existing_contact_id: Option<u32> = fingerprint_to_id_stmt
                    .query_row((&fingerprint,), |row| row.get(0))
                    .optional()
                    .context("Step 7")?;
                if let Some(existing_contact_id) = existing_contact_id {
                    return Ok(existing_contact_id);
                }
                insert_contact_stmt
                    .execute((
                        &name,
                        &addr,
                        origin,
                        blocked,
                        last_seen,
                        &authname,
                        &param,
                        &status,
                        is_bot,
                        selfavatar_sent,
                        fingerprint.clone(),
                    ))
                    .context("Step 8")?;
                let id = transaction
                    .last_insert_rowid()
                    .try_into()
                    .context("Step 9")?;
                info!(
                    context,
                    "Inserted new contact id={id} name='{name}' addr='{addr}' fingerprint={fingerprint}"
                );
                Ok(id)
            };
            let mut original_contact_id_from_addr = |addr: &str, default: u32| -> Result<u32> {
                if addr_cmp(addr, &self_addr) {
                    Ok(1) // ContactId::SELF
                } else if addr.is_empty() {
                    Ok(default)
                } else {
                    Ok(original_contact_id_from_addr_stmt
                        .query_row((addr,), |row| row.get(0))
                        .optional()
                        .with_context(|| format!("Original contact '{addr}' not found"))?
                        .unwrap_or(default))
                }
            };

            let Some(autocrypt_key) = autocrypt_key else {
                continue;
            };
            let new_id = insert_contact(autocrypt_key).context("Step 10")?;

            // prefer_encrypt == 20 would mean EncryptPreference::Reset,
            // i.e. we shouldn't encrypt if possible.
            if prefer_encrypt != 20 {
                autocrypt_key_contacts.insert(original_id.try_into().context("Step 11")?, new_id);
            } else {
                autocrypt_key_contacts_with_reset_peerstate
                    .insert(original_id.try_into().context("Step 12")?, new_id);
            }

            let Some(verified_key) = verified_key else {
                continue;
            };
            let new_id = insert_contact(verified_key).context("Step 13")?;
            verified_key_contacts.insert(original_id.try_into().context("Step 14")?, new_id);

            let verifier_id = if addr_cmp(&verifier, &addr) {
                // Earlier versions of Delta Chat signalled a direct verification
                // by putting the contact's own address into the verifier column
                1 // 1=ContactId::SELF
            } else {
                // If the original verifier is unknown, we represent this in the database
                // by putting `new_id` into the place of the verifier,
                // i.e. we say that this contact verified itself.
                original_contact_id_from_addr(&verifier, new_id).context("Step 15")?
            };
            verifications.insert(new_id, verifier_id);

            let Some(secondary_verified_key) = secondary_verified_key else {
                continue;
            };
            let new_id = insert_contact(secondary_verified_key).context("Step 16")?;
            let verifier_id: u32 = if addr_cmp(&secondary_verifier, &addr) {
                1 // 1=ContactId::SELF
            } else {
                original_contact_id_from_addr(&secondary_verifier, new_id).context("Step 17")?
            };
            // Only use secondary verification if there is no primary verification:
            verifications.entry(new_id).or_insert(verifier_id);
        }
        info!(
            context,
            "Created key-contacts identified by autocrypt key: {autocrypt_key_contacts:?}"
        );
        info!(
            context,
            "Created key-contacts  with 'reset' peerstate identified by autocrypt key: {autocrypt_key_contacts_with_reset_peerstate:?}"
        );
        info!(
            context,
            "Created key-contacts identified by verified key: {verified_key_contacts:?}"
        );

        for (&new_contact, &verifier_original_contact) in &verifications {
            let verifier = if verifier_original_contact == 1 {
                1 // Verified by ContactId::SELF
            } else if verifier_original_contact == new_contact {
                new_contact // unkwnown verifier
            } else {
                // `verifications` contains the original contact id.
                // We need to get the new, verified-pgp-identified contact id.
                match verified_key_contacts.get(&verifier_original_contact) {
                    Some(v) => *v,
                    None => {
                        warn!(
                            context,
                            "Couldn't find key-contact for {verifier_original_contact} who verified {new_contact}"
                        );
                        continue;
                    }
                }
            };
            transaction
                .execute(
                    "UPDATE contacts SET verifier=? WHERE id=?",
                    (verifier, new_contact),
                )
                .context("Step 18")?;
        }
        info!(context, "Migrated verifications: {verifications:?}");
    }

    // ======================= Step 3: =======================
    // For each chat, modify the memberlist to retain the correct contacts
    // In the process, track the set of contacts which remained no any chat at all
    // in a `BTreeSet<u32>`, which initially contains all contact ids
    let mut orphaned_contacts: BTreeSet<u32> = transaction
        .prepare("SELECT id FROM contacts WHERE id>9")
        .context("Step 19")?
        .query_map((), |row| row.get::<usize, u32>(0))
        .context("Step 20")?
        .collect::<Result<BTreeSet<u32>, rusqlite::Error>>()
        .context("Step 21")?;

    {
        let mut stmt = transaction
            .prepare(
                "SELECT c.id, c.type, c.grpid, c.protected
            FROM chats c
            WHERE id>9",
            )
            .context("Step 22")?;
        let all_chats = stmt
            .query_map((), |row| {
                let id: u32 = row.get(0)?;
                let typ: u32 = row.get(1)?;
                let grpid: String = row.get(2)?;
                let protected: u32 = row.get(3)?;
                Ok((id, typ, grpid, protected))
            })
            .context("Step 23")?;
        let mut load_chat_contacts_stmt = transaction.prepare(
            "SELECT contact_id, add_timestamp>=remove_timestamp FROM chats_contacts
             WHERE chat_id=? AND contact_id>9",
        )?;
        let is_chatmail: Option<String> = transaction
            .query_row(
                "SELECT value FROM config WHERE keyname='is_chatmail'",
                (),
                |row| row.get(0),
            )
            .optional()
            .context("Step 23.1")?;
        let is_chatmail = is_chatmail
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or_default()
            != 0;
        let map_to_key_contact = |old_member: &u32| {
            autocrypt_key_contacts
                .get(old_member)
                .or_else(|| {
                    // For chatmail servers,
                    // we send encrypted even if the peerstate is reset,
                    // because an unencrypted message likely won't arrive.
                    // This is the same behavior as before key-contacts migration.
                    if is_chatmail {
                        autocrypt_key_contacts_with_reset_peerstate.get(old_member)
                    } else {
                        None
                    }
                })
                .copied()
        };

        let mut update_member_stmt = transaction
            .prepare("UPDATE chats_contacts SET contact_id=? WHERE contact_id=? AND chat_id=?")?;
        let mut addr_cmp_stmt = transaction
            .prepare("SELECT c.addr=d.addr FROM contacts c, contacts d WHERE c.id=? AND d.id=?")?;
        for chat in all_chats {
            let (chat_id, typ, grpid, protected) = chat.context("Step 24")?;
            // In groups, this also contains past members, i.e. `(_, false)` entries.
            let old_members: Vec<(u32, bool)> = load_chat_contacts_stmt
                .query_map((chat_id,), |row| {
                    let id: u32 = row.get(0)?;
                    let present: bool = row.get(1)?;
                    Ok((id, present))
                })
                .context("Step 25")?
                .collect::<Result<Vec<_>, _>>()
                .context("Step 26")?;

            let mut keep_address_contacts = |reason: &str| -> Result<()> {
                info!(
                    context,
                    "Chat {chat_id} will be an unencrypted chat with contacts identified by email address: {reason}."
                );
                for (m, _) in &old_members {
                    orphaned_contacts.remove(m);
                }

                // Unprotect this chat if it was protected.
                //
                // Otherwise we get protected chat with address-contact(s).
                transaction
                    .execute("UPDATE chats SET protected=0 WHERE id=?", (chat_id,))
                    .context("Step 26.0")?;

                Ok(())
            };
            let old_and_new_members: Vec<(u32, bool, Option<u32>)> = match typ {
                // 1:1 chats retain:
                // - address-contact if peerstate is in the "reset" state,
                //   or if there is no key-contact that has the right email address.
                // - key-contact identified by the Autocrypt key if Autocrypt key does not match the verified key.
                // - key-contact identified by the verified key if peerstate Autocrypt key matches the Verified key.
                //   Since the autocrypt and verified key-contact are identital in this case, we can add the Autocrypt key-contact,
                //   and the effect will be the same.
                100 => {
                    let Some((old_member, _)) = old_members.first() else {
                        info!(
                            context,
                            "1:1 chat {chat_id} doesn't contain contact, probably it's self or device chat."
                        );
                        continue;
                    };

                    let Some(new_contact) = map_to_key_contact(old_member) else {
                        keep_address_contacts("No peerstate, or peerstate in 'reset' state")?;
                        continue;
                    };
                    if !addr_cmp_stmt
                        .query_row((old_member, new_contact), |row| row.get::<_, bool>(0))?
                    {
                        keep_address_contacts("key contact has different email")?;
                        continue;
                    }
                    vec![(*old_member, true, Some(new_contact))]
                }

                // Group
                120 => {
                    if grpid.is_empty() {
                        // Ad-hoc group that has empty Chat-Group-ID
                        // because it was created in response to receiving a non-chat email.
                        keep_address_contacts("Empty chat-Group-ID")?;
                        continue;
                    } else if protected == 1 {
                        old_members
                            .iter()
                            .map(|&(id, present)| {
                                (id, present, verified_key_contacts.get(&id).copied())
                            })
                            .collect()
                    } else {
                        old_members
                            .iter()
                            .map(|&(id, present)| (id, present, map_to_key_contact(&id)))
                            .collect::<Vec<(u32, bool, Option<u32>)>>()
                    }
                }

                // Mailinglist
                140 => {
                    keep_address_contacts("Mailinglist")?;
                    continue;
                }

                // Broadcast channel
                160 => old_members
                    .iter()
                    .map(|(original, _)| {
                        (
                            *original,
                            true,
                            autocrypt_key_contacts
                                .get(original)
                                // There will be no unencrypted broadcast lists anymore,
                                // so, if a peerstate is reset,
                                // the best we can do is encrypting to this key regardless.
                                .or_else(|| {
                                    autocrypt_key_contacts_with_reset_peerstate.get(original)
                                })
                                .copied(),
                        )
                    })
                    .collect::<Vec<(u32, bool, Option<u32>)>>(),
                _ => {
                    warn!(context, "Invalid chat type {typ}");
                    continue;
                }
            };

            // If a group contains a contact without a key or with 'reset' peerstate,
            // downgrade to unencrypted Ad-Hoc group.
            if typ == 120
                && old_and_new_members
                    .iter()
                    .any(|&(_old, present, new)| present && new.is_none())
            {
                transaction
                    .execute("UPDATE chats SET grpid='' WHERE id=?", (chat_id,))
                    .context("Step 26.1")?;
                keep_address_contacts("Group contains contact without peerstate")?;
                continue;
            }

            let human_readable_transitions = old_and_new_members
                .iter()
                .map(|(old, _, new)| format!("{old}->{}", new.unwrap_or_default()))
                .collect::<Vec<String>>()
                .join(" ");
            info!(
                context,
                "Migrating chat {chat_id} to key-contacts: {human_readable_transitions}"
            );

            for (old_member, _, new_member) in old_and_new_members {
                if let Some(new_member) = new_member {
                    orphaned_contacts.remove(&new_member);
                    let res = update_member_stmt.execute((new_member, old_member, chat_id));
                    if res.is_err() {
                        // The same chat partner exists multiple times in the chat,
                        // with mutliple profiles which have different email addresses
                        // but the same key.
                        // We can only keep one of them.
                        // So, if one of them is not in the chat anymore, delete it,
                        // otherwise delete the one that was added least recently.
                        let member_to_delete: u32 = transaction
                            .query_row(
                                "SELECT contact_id
                               FROM chats_contacts
                              WHERE chat_id=? AND contact_id IN (?,?)
                           ORDER BY add_timestamp>=remove_timestamp, add_timestamp LIMIT 1",
                                (chat_id, new_member, old_member),
                                |row| row.get(0),
                            )
                            .context("Step 27")?;
                        info!(
                            context,
                            "Chat partner is in the chat {chat_id} multiple times. \
                            Deleting {member_to_delete}, then trying to update \
                            {old_member}->{new_member} again"
                        );
                        transaction
                            .execute(
                                "DELETE FROM chats_contacts WHERE chat_id=? AND contact_id=?",
                                (chat_id, member_to_delete),
                            )
                            .context("Step 28")?;
                        // If we removed `old_member`, then this will be a no-op,
                        // which is exactly what we want in this case:
                        update_member_stmt.execute((new_member, old_member, chat_id))?;
                    }
                } else {
                    info!(
                        context,
                        "Old member {old_member} in chat {chat_id} can't be upgraded to key-contact, removing them"
                    );
                    transaction
                        .execute(
                            "DELETE FROM chats_contacts WHERE contact_id=? AND chat_id=?",
                            (old_member, chat_id),
                        )
                        .context("Step 29")?;
                }
            }
        }
    }

    // ======================= Step 4: =======================
    {
        info!(
            context,
            "Marking contacts which remained in no chat at all as hidden: {orphaned_contacts:?}"
        );
        let mut mark_as_hidden_stmt = transaction
            .prepare("UPDATE contacts SET origin=? WHERE id=?")
            .context("Step 30")?;
        for contact in orphaned_contacts {
            mark_as_hidden_stmt
                .execute((0x8, contact))
                .context("Step 31")?;
        }
    }

    // ======================= Step 5: =======================
    // Prepare for rewriting `from_id`, `to_id` in messages
    {
        let mut contacts_map = autocrypt_key_contacts_with_reset_peerstate;
        for (old, new) in autocrypt_key_contacts {
            contacts_map.insert(old, new);
        }
        transaction
            .execute(
                "CREATE TABLE key_contacts_map (
                    old_id INTEGER PRIMARY KEY NOT NULL,
                    new_id INTEGER NOT NULL
                ) STRICT",
                (),
            )
            .context("Step 32")?;
        {
            let mut stmt = transaction
                .prepare("INSERT INTO key_contacts_map (old_id, new_id) VALUES (?, ?)")
                .context("Step 33")?;
            for ids in contacts_map {
                stmt.execute(ids).context("Step 34")?;
            }
        }
        transaction
            .execute(
                "INSERT INTO config (keyname, value) VALUES (
                    'first_key_contacts_msg_id',
                    IFNULL((SELECT MAX(id)+1 FROM msgs), 0)
                )",
                (),
            )
            .context("Step 35")?;
    }

    Ok(())
}

/// Rewrite `from_id`, `to_id` in >= 1000 messages starting from the newest ones, to key-contacts.
#[expect(clippy::arithmetic_side_effects)]
pub(crate) async fn msgs_to_key_contacts(context: &Context) -> Result<()> {
    let sql = &context.sql;
    if sql
        .get_raw_config_int64("first_key_contacts_msg_id")
        .await?
        <= Some(0)
    {
        return Ok(());
    }
    let trans_fn = |t: &mut rusqlite::Transaction| {
        let mut first_key_contacts_msg_id: u64 = t
            .query_one(
                "SELECT CAST(value AS INTEGER) FROM config WHERE keyname='first_key_contacts_msg_id'",
                (),
                |row| row.get(0),
            )
            .context("Get first_key_contacts_msg_id")?;
        let mut stmt = t
            .prepare(
                "UPDATE msgs SET
                    from_id=IFNULL(
                        (SELECT new_id FROM key_contacts_map WHERE old_id=msgs.from_id),
                        from_id
                    ),
                    to_id=IFNULL(
                        (SELECT new_id FROM key_contacts_map WHERE old_id=msgs.to_id),
                        to_id
                    )
                WHERE id>=? AND id<?
                AND chat_id>9
                AND (param GLOB '*\nc=1*' OR param GLOB 'c=1*')",
            )
            .context("Prepare stmt")?;
        let msgs_to_migrate = 1000;
        let mut msgs_migrated: u64 = 0;
        while first_key_contacts_msg_id > 0 && msgs_migrated < msgs_to_migrate {
            let start_msg_id = first_key_contacts_msg_id.saturating_sub(msgs_to_migrate);
            let cnt: u64 = stmt
                .execute((start_msg_id, first_key_contacts_msg_id))
                .context("UPDATE msgs")?
                .try_into()?;
            msgs_migrated += cnt;
            first_key_contacts_msg_id = start_msg_id;
        }
        t.execute(
            "UPDATE config SET value=? WHERE keyname='first_key_contacts_msg_id'",
            (first_key_contacts_msg_id,),
        )
        .context("Update first_key_contacts_msg_id")?;
        Ok((msgs_migrated, first_key_contacts_msg_id))
    };
    let start = Time::now();
    let mut msgs_migrated = 0;
    loop {
        let (n, first_key_contacts_msg_id) = sql.transaction(trans_fn).await?;
        msgs_migrated += n;
        if first_key_contacts_msg_id == 0 || time_elapsed(&start) >= Duration::from_millis(500) {
            break;
        }
    }
    sql.uncache_raw_config("first_key_contacts_msg_id").await;
    info!(
        context,
        "Rewriting {msgs_migrated} msgs to key-contacts took {:?}.",
        time_elapsed(&start),
    );
    Ok(())
}

impl Sql {
    async fn set_db_version(&self, version: i32) -> Result<()> {
        self.set_raw_config_int(VERSION_CFG, version).await?;
        Ok(())
    }

    // Sets db `version` in the `transaction`.
    fn set_db_version_trans(transaction: &mut rusqlite::Transaction, version: i32) -> Result<()> {
        transaction.execute(
            "UPDATE config SET value=? WHERE keyname=?;",
            (format!("{version}"), VERSION_CFG),
        )?;
        Ok(())
    }

    async fn set_db_version_in_cache(&self, version: i32) -> Result<()> {
        let mut lock = self.config_cache.write().await;
        lock.insert(VERSION_CFG.to_string(), Some(format!("{version}")));
        Ok(())
    }

    async fn execute_migration(&self, query: &str, version: i32) -> Result<()> {
        self.execute_migration_transaction(
            |transaction| {
                transaction.execute_batch(query)?;
                Ok(())
            },
            version,
        )
        .await
    }

    async fn execute_migration_transaction(
        &self,
        migration: impl Send + FnOnce(&mut rusqlite::Transaction) -> Result<()>,
        version: i32,
    ) -> Result<()> {
        #[cfg(test)]
        if STOP_MIGRATIONS_AT.try_with(|stop_migrations_at| version > *stop_migrations_at)
            == Ok(true)
        {
            println!("Not running migration {version}, because STOP_MIGRATIONS_AT is set");
            return Ok(());
        }

        self.transaction(move |transaction| {
            let curr_version: String = transaction.query_row(
                "SELECT IFNULL(value, ?) FROM config WHERE keyname=?;",
                ("0", VERSION_CFG),
                |row| row.get(0),
            )?;
            let curr_version: i32 = curr_version.parse()?;
            ensure!(curr_version < version, "Db version must be increased");
            Self::set_db_version_trans(transaction, version)?;
            migration(transaction)?;

            Ok(())
        })
        .await
        .with_context(|| format!("execute_migration failed for version {version}"))?;

        self.config_cache.write().await.clear();

        Ok(())
    }
}

#[cfg(test)]
mod migrations_tests;
