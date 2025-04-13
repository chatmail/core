//! Migrations module.

use anyhow::{ensure, Context as _, Result};
use deltachat_contact_tools::EmailAddress;
use rusqlite::OptionalExtension;

use crate::config::Config;
use crate::constants::ShowEmails;
use crate::context::Context;
use crate::imap;
use crate::message::MsgId;
use crate::provider::get_provider_by_domain;
use crate::sql::Sql;
use crate::tools::inc_and_check;

const DBVERSION: i32 = 68;
const VERSION_CFG: &str = "dbversion";
const TABLES: &str = include_str!("./tables.sql");

pub async fn run(context: &Context, sql: &Sql) -> Result<(bool, bool, bool, bool)> {
    let mut recalc_fingerprints = false;
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
    let mut update_icons = !exists_before_update;
    let mut disable_server_delete = false;
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
        recalc_fingerprints = true;
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
        update_icons = true;
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
        update_icons = true;
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
                        get_provider_by_domain(&domain).map(|provider| provider.id),
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
        use Config::*;
        sql.execute(
            r#"
CREATE TABLE imap_sync (folder TEXT PRIMARY KEY, uidvalidity INTEGER DEFAULT 0, uid_next INTEGER DEFAULT 0);"#,
()
        )
            .await?;
        for c in &[
            ConfiguredInboxFolder,
            ConfiguredSentboxFolder,
            ConfiguredMvboxFolder,
        ] {
            if let Some(folder) = context.get_config(*c).await? {
                let (uid_validity, last_seen_uid) =
                    imap::get_config_last_seen_uid(context, &folder).await?;
                if last_seen_uid > 0 {
                    imap::set_uid_next(context, &folder, last_seen_uid + 1).await?;
                    imap::set_uidvalidity(context, &folder, uid_validity).await?;
                }
            }
        }
        if exists_before_update {
            disable_server_delete = true;

            // Don't disable server delete if it was on by default (Nauta):
            if let Some(provider) = context.get_configured_provider().await? {
                if let Some(defaults) = &provider.config_defaults {
                    if defaults.iter().any(|d| d.key == Config::DeleteServerAfter) {
                        disable_server_delete = false;
                    }
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

    Ok((
        recalc_fingerprints,
        update_icons,
        disable_server_delete,
        recode_avatar,
    ))
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
        self.transaction(move |transaction| {
            let curr_version: String = transaction.query_row(
                "SELECT IFNULL(value, ?) FROM config WHERE keyname=?;",
                ("0", VERSION_CFG),
                |row| row.get(0),
            )?;
            let curr_version: i32 = curr_version.parse()?;
            ensure!(curr_version < version, "Db version must be increased");
            Self::set_db_version_trans(transaction, version)?;
            transaction.execute_batch(query)?;

            Ok(())
        })
        .await
        .with_context(|| format!("execute_migration failed for version {version}"))?;

        self.config_cache.write().await.clear();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::test_utils::TestContext;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_clear_config_cache() -> anyhow::Result<()> {
        // Some migrations change the `config` table in SQL.
        // This test checks that the config cache is invalidated in `execute_migration()`.

        let t = TestContext::new().await;
        assert_eq!(t.get_config_bool(Config::IsChatmail).await?, false);

        t.sql
            .execute_migration(
                "INSERT INTO config (keyname, value) VALUES ('is_chatmail', '1')",
                1000,
            )
            .await?;
        assert_eq!(t.get_config_bool(Config::IsChatmail).await?, true);
        assert_eq!(t.sql.get_raw_config_int(VERSION_CFG).await?.unwrap(), 1000);

        Ok(())
    }
}
