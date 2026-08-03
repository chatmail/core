-- Commented SQLite database schema.
--
-- This file should only be used for documentation,
-- do not run this SQL e.g. to create databases.
-- This is because we want to be 100% sure
-- that new users and users who run the migrations
-- get the same database schema.
--
-- This is a dump of the database schema using `sqlite3 dc.db .schema`,
-- formatted and commented afterwards.
-- Raw dump of the database schema does not have comments
-- for deprecated columns and columns added by migrations.
--
-- This is based on the version 161 of the database.
-- There may be new migrations added afterwards.

CREATE TABLE config (
  id INTEGER PRIMARY KEY,
  keyname TEXT UNIQUE,
  value TEXT NOT NULL
);
CREATE INDEX config_index1 ON config (keyname);

CREATE TABLE contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    name TEXT DEFAULT '', -- Name of the contact as set by the user.

    -- Email address last seen as the From address for this contact.
    -- For address-contacts that have empty "fingerprint" this should never change.
    -- For key-contacts this address may change when a new signed message is received.
    --
    -- This is the address messages are sent to unless the key
    -- advertises a different set of addresses, in which case
    -- this address should be ignored
    -- (and not appended to the list of addresses advertised in the key).
    addr TEXT DEFAULT '' COLLATE NOCASE,

    origin INTEGER DEFAULT 0,
    blocked INTEGER DEFAULT 0,
    last_seen INTEGER DEFAULT 0,
    param TEXT DEFAULT '',

    -- Name of the contact as sent by the contact itself.
    authname TEXT DEFAULT '',
    selfavatar_sent INTEGER DEFAULT 0,
    status TEXT DEFAULT '',
    is_bot INTEGER NOT NULL DEFAULT 0,

    -- OpenPGP key fingerprint for "key-contacts",
    -- empty string for "address-contacts".
    fingerprint TEXT NOT NULL DEFAULT '',
    verifier INTEGER NOT NULL DEFAULT 0,
    name_normalized TEXT
);
CREATE INDEX contacts_index1 ON contacts (name COLLATE NOCASE);
CREATE INDEX contacts_index2 ON contacts (addr COLLATE NOCASE);
CREATE INDEX contacts_fingerprint_index ON contacts (fingerprint);

CREATE TABLE chats (
    -- Chat ID 0 should never be used as it is used as a sentinel value in some APIs.
    -- 
    -- Chat IDs 1 to 9, including 9, are reserved.
    -- The first proper chat gets ID 10, but may not exist if it is deleted.
    --
    -- Chat ID 3 is the trash chat and this chat ID is assigned to deleted messages
    -- to create "tombstones".
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    type INTEGER DEFAULT 0,
    name TEXT DEFAULT '',

    -- Unused columns, drafts are now tracked as separate
    -- messages with a special msgs.state value.
    draft_timestamp INTEGER DEFAULT 0,
    draft_txt TEXT DEFAULT '',

    blocked INTEGER DEFAULT 0,
    grpid TEXT DEFAULT '',
    param TEXT DEFAULT '',
    archived INTEGER DEFAULT 0,
    gossiped_timestamp INTEGER DEFAULT 0, -- deprecated 2025-04-08, replaced with gossip_timestamp table
    locations_send_begin INTEGER DEFAULT 0,
    locations_send_until INTEGER DEFAULT 0,
    locations_last_sent INTEGER DEFAULT 0,
    created_timestamp INTEGER DEFAULT 0,
    muted_until INTEGER DEFAULT 0,
    ephemeral_timer INTEGER,
    protected INTEGER DEFAULT 0,

    -- Normalized name for search.
    name_normalized TEXT
);
CREATE INDEX chats_index1 ON chats (grpid);
CREATE INDEX chats_index2 ON chats (archived);
CREATE INDEX chats_index3 ON chats (locations_send_until);
CREATE INDEX chats_index4 ON chats (name);

CREATE TABLE chats_descriptions (
    chat_id INTEGER PRIMARY KEY AUTOINCREMENT,
    description TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE TABLE chats_contacts (
    chat_id INTEGER,
    contact_id INTEGER,
    add_timestamp NOT NULL DEFAULT 0,
    remove_timestamp NOT NULL DEFAULT 0,
    UNIQUE(chat_id, contact_id)
);
CREATE INDEX chats_contacts_index1 ON chats_contacts (chat_id);
CREATE INDEX chats_contacts_index2 ON chats_contacts (contact_id);

-- This table contains "message bubbles" that are normally visible
-- and "tombstones" that are put into the trash chat
-- or have a "hidden" column set to the true value.
--
-- Tombstones are used to avoid downloading and processing
-- the same messages twice, e.g. when the message is deleted
-- but another copy of it arrives later.
CREATE TABLE msgs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- TODO: define what does "incoming" message means.
    -- Messages sent by self, but arriving from a second device
    -- are processed by receive_imf, but are still "outgoing".

    -- The messages may be split into pre- and post-message.
    -- Pre-messages have a Chat-Post-Message-ID header
    -- which contains the Message-ID of the post-message.
    -- Post-messages have a Chat-Is-Post-Message header.
    --
    -- For outgoing messages that are split into pre-message
    -- and post-message, rfc724_mid contains the Message-ID
    -- of the post-message, and pre_rfc724_mid
    -- contains the Message-ID of the pre-message.
    --
    -- For incoming messages, when a pre-message arrives,
    -- rfc724_mid is set to the Message-ID of the post-message,
    -- and pre_rfc724_mid is set to the Message-ID of the arrived pre-messsage.
    -- For other messages rfc724_mid is taken from the Message-ID
    -- and pre_rfc724_mid is set to empty string.

    -- Message-ID as defined in RFC 724 (now replaced by RFC 5322)
    rfc724_mid TEXT DEFAULT '',
    -- Message-ID of the pre-message.
    pre_rfc724_mid TEXT DEFAULT '',

    -- Chat ID.
    --
    -- Chat ID 3 is the trash chat, messages with this ID are tombstones.
    chat_id INTEGER DEFAULT 0,

    -- Contact ID of the messag author.
    from_id INTEGER DEFAULT 0,

    -- For incoming messages, SELF (1).
    -- For outgoing messages, ID of the first recipient.
    -- TODO: it is not useful in group chats, can it be deprecated?
    to_id INTEGER DEFAULT 0,

    type INTEGER DEFAULT 0,
    state INTEGER DEFAULT 0,
    msgrmsg INTEGER DEFAULT 1,

    -- Size of the attachment for file parts, otherwise 0.
    bytes INTEGER DEFAULT 0,

    txt TEXT DEFAULT '', -- Message text for display.
    txt_normalized TEXT, -- Message text normalized for search.
    txt_raw TEXT DEFAULT '', -- deprecated 2025-03-29

    param TEXT DEFAULT '',

    -- For messages bookmarked into the Saved Messages chat,
    -- ID of the original message, making it possible to jump to it.
    starred INTEGER DEFAULT 0,

    timestamp INTEGER DEFAULT 0, -- Timestamp of the message used for sorting.
    timestamp_sent INTEGER DEFAULT 0, -- Timestamp of the message as sent in the Date header.
    timestamp_rcvd INTEGER DEFAULT 0,

    -- TODO: document how hidden field is used
    -- It is used at least for reactions for incoming messages.
    hidden INTEGER DEFAULT 0,

    -- mime_headers column actually contains BLOBs, i.e. it may
    -- contain non-UTF8 MIME messages.  TEXT was a bad choice, but
    -- thanks to SQLite 3 being dynamically typed, there is no need to
    -- change column type.
    mime_headers TEXT,

    -- True if mime_headers column is compressed with Brotli.
    mime_compressed INTEGER NOT NULL DEFAULT 0,

    mime_modified INTEGER DEFAULT 0,

    mime_in_reply_to TEXT,
    mime_references TEXT,

    location_id INTEGER DEFAULT 0,
    error TEXT DEFAULT '',

    -- Timer value in seconds. For incoming messages this
    -- timer starts when message is read, so we want to have
    -- the value stored here until the timer starts.
    ephemeral_timer INTEGER DEFAULT 0,

    -- Timestamp indicating when the message should be
    -- deleted. It is convenient to store it here because UI
    -- needs this value to display how much time is left until
    -- the message is deleted.
    ephemeral_timestamp INTEGER DEFAULT 0,

    subject TEXT DEFAULT '',
    download_state INTEGER DEFAULT 0,

    -- Information extracted from Received headers
    -- as a plain text for debugging.
    hop_info TEXT,

    deleted INTEGER NOT NULL DEFAULT 0,

    --
    -- Unused columns.
    --

    server_folder TEXT DEFAULT '', -- Deprecated column that was used before "imap" table, replaced by imap.folder
    server_uid INTEGER DEFAULT 0, -- Deprecated column that was used before "imap" table, replaced by imap.uid

    -- Unused column formely used to mark the messages
    -- that should be moved to the dedicated IMAP folder.
    -- It was replaced with imap.target, which is also now
    -- used only to mark the messages on IMAP for deletion.
    move_state INTEGER DEFAULT 1
);
CREATE INDEX msgs_index1 ON msgs (rfc724_mid);
CREATE INDEX msgs_index2 ON msgs (chat_id);
CREATE INDEX msgs_index3 ON msgs (timestamp);
CREATE INDEX msgs_index4 ON msgs (state);
CREATE INDEX msgs_index5 ON msgs (starred);
CREATE INDEX msgs_index6 ON msgs (location_id);
CREATE INDEX msgs_index7 ON msgs (state, hidden, chat_id, timestamp);
CREATE INDEX msgs_index8 ON msgs (ephemeral_timestamp);
CREATE INDEX msgs_index9 ON msgs (pre_rfc724_mid);

CREATE TABLE leftgrps (
    id INTEGER PRIMARY KEY,
    grpid TEXT DEFAULT ''
);
CREATE INDEX leftgrps_index1 ON leftgrps (grpid);

CREATE TABLE msgs_mdns (
    msg_id INTEGER,
    contact_id INTEGER,
    timestamp_sent INTEGER DEFAULT 0
);
CREATE INDEX msgs_mdns_index1 ON msgs_mdns (msg_id);

CREATE TABLE locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    latitude REAL DEFAULT 0.0,
    longitude REAL DEFAULT 0.0,
    accuracy REAL DEFAULT 0.0,
    timestamp INTEGER DEFAULT 0,
    chat_id INTEGER DEFAULT 0,
    from_id INTEGER DEFAULT 0,
    independent INTEGER DEFAULT 0
);
CREATE INDEX locations_index1 ON locations (from_id);
CREATE INDEX locations_index2 ON locations (timestamp);

CREATE TABLE devmsglabels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT,
    msg_id INTEGER DEFAULT 0
);
CREATE INDEX devmsglabels_index1 ON devmsglabels (label);

-- Table to store QR code tokens for SecureJoin protocol.
CREATE TABLE tokens (
    id INTEGER PRIMARY KEY,

    -- Namespace is one of:
    -- 0 - unknown
    -- 100 - invite number
    -- 110 - auth
    namespc INTEGER NOT NULL,

    foreign_key TEXT DEFAULT '' NOT NULL,
    token TEXT NOT NULL UNIQUE,
    timestamp INTEGER DEFAULT 0 NOT NULL
) STRICT;

-- State of the scanner of the QR code (Bob) in SecureJoin protocol.
CREATE TABLE bobstate (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invite TEXT NOT NULL,
    next_step INTEGER NOT NULL,
    chat_id INTEGER NOT NULL
);

CREATE TABLE smtp (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rfc724_mid TEXT NOT NULL,          -- Message-ID
  mime TEXT NOT NULL,                -- SMTP payload
  msg_id INTEGER NOT NULL,           -- ID of the message in `msgs` table
  recipients TEXT NOT NULL,          -- List of recipients separated by space
  retries INTEGER NOT NULL DEFAULT 0 -- Number of failed attempts to send the message
);

CREATE TABLE smtp_mdns (
    msg_id INTEGER NOT NULL, -- id of the message in msgs table which requested MDN (DEPRECATED 2024-06-21)
    from_id INTEGER NOT NULL, -- id of the contact that sent the message, MDN destination
    rfc724_mid TEXT NOT NULL, -- Message-ID header
    retries INTEGER NOT NULL DEFAULT 0 -- Number of failed attempts to send MDN
);
CREATE TABLE smtp_status_updates (
    msg_id INTEGER NOT NULL UNIQUE, -- msg_id of the webxdc instance with pending updates
    first_serial INTEGER NOT NULL, -- id in msgs_status_updates
    last_serial INTEGER NOT NULL, -- id in msgs_status_updates
    descr TEXT NOT NULL -- text to send along with the updates
);

-- Table of "sync items" to be grouped into sync messages
-- and sent to own devices.
CREATE TABLE multi_device_sync (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- JSON of the "sync item".
    item TEXT DEFAULT ''
);

CREATE TABLE reactions (
    msg_id INTEGER NOT NULL, -- id of the message reacted to
    contact_id INTEGER NOT NULL, -- id of the contact reacting to the message
    reaction TEXT DEFAULT '' NOT NULL, -- a sequence of emojis separated by spaces
    PRIMARY KEY(msg_id, contact_id),
    FOREIGN KEY(msg_id) REFERENCES msgs(id) ON DELETE CASCADE -- delete reactions when message is deleted
    FOREIGN KEY(contact_id) REFERENCES contacts(id) ON DELETE CASCADE -- delete reactions when contact is deleted
);
CREATE INDEX reactions_index1 ON reactions (msg_id);

CREATE TABLE pending_reactions (
    rfc724_mid TEXT NOT NULL,
    contact_id INTEGER NOT NULL,
    reaction TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    PRIMARY KEY(rfc724_mid, contact_id),
    FOREIGN KEY(contact_id) REFERENCES contacts(id) ON DELETE CASCADE
) STRICT;


CREATE TABLE connection_history (
    host TEXT NOT NULL, -- server hostname
    port INTEGER NOT NULL, -- server port
    alpn TEXT NOT NULL, -- ALPN such as smtp or imap
    addr TEXT NOT NULL, -- IP address
    timestamp INTEGER NOT NULL, -- timestamp of the most recent successful connection
    UNIQUE (host, port, alpn, addr)
) STRICT;

CREATE TABLE dns_cache (
  hostname TEXT NOT NULL,
  address TEXT NOT NULL, -- IPv4 or IPv6 address
  timestamp INTEGER NOT NULL,
  UNIQUE (hostname, address)
);

CREATE TABLE tls_spki (
    host TEXT NOT NULL UNIQUE,
    spki_hash TEXT NOT NULL, -- base64 of SPKI SHA-256 hash
    timestamp INTEGER NOT NULL -- timestamp of the last time we have seen this key
) STRICT;
CREATE INDEX tls_spki_index_timestamp ON tls_spki (timestamp);

CREATE TABLE http_cache (
    url TEXT PRIMARY KEY,
    expires INTEGER NOT NULL, -- When the cache entry is considered expired, timestamp in seconds.
    stale INTEGER NOT NULL, -- When the cache entry is considered stale, timestamp in seconds.
    blobname TEXT NOT NULL,
    mimetype TEXT NOT NULL DEFAULT '', -- MIME type extracted from Content-Type header.
    encoding TEXT NOT NULL DEFAULT '' -- Encoding from Content-Type header.
) STRICT;




-- Webxdc updates.
CREATE TABLE msgs_status_updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    msg_id INTEGER,
    update_item TEXT DEFAULT '',
    uid TEXT UNIQUE,
    FOREIGN KEY(msg_id) REFERENCES msgs(id) ON DELETE CASCADE
);
CREATE INDEX msgs_status_updates_index1 ON msgs_status_updates (msg_id);
CREATE INDEX msgs_status_updates_index2 ON msgs_status_updates (uid);

-- Webxdc realtime.
CREATE TABLE iroh_gossip_peers (
    msg_id INTEGER not NULL,
    topic BLOB NOT NULL,
    public_key BLOB NOT NULL,
    relay_server TEXT, UNIQUE (topic, public_key),
    PRIMARY KEY(topic, public_key)
) STRICT;

--
-- OpenPGP.
--

-- Storage for own private keys.
-- Only one of the keys is used.
--
-- In the past mulitple keys could be imported,
-- so this table can contain multiple keys for existing users.
-- Used key is identified by the "key_id" config value.
-- Other keys must never be used, even for decryption.
CREATE TABLE keypairs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  -- OpenPGP private key stored as a binary blob.
  private_key UNIQUE NOT NULL,

  -- Unused public key aka OpenPGP certificate.
  -- Stored only for compatibility.
  -- OpenPGP certificate is generated at runtime from the private key.
  public_key UNIQUE NOT NULL,

  -- 
  -- Unused columns.
  --
  --
  -- Columns "addr", "is_default" and "created" were
  -- dropped in migration 107
  -- but added back for compatibility in migration 110.

  addr TEXT DEFAULT '' COLLATE NOCASE,

  -- Migrated into "key_id" config value in migration 107.
  is_default INTEGER DEFAULT 0,

  created INTEGER DEFAULT 0
);

CREATE TABLE public_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE, -- Upper-case fingerprint of the key.
    public_key BLOB NOT NULL -- Binary key, not ASCII-armored
) STRICT;
CREATE INDEX public_key_index ON public_keys (fingerprint);

CREATE TABLE gossip_timestamp (
  chat_id INTEGER NOT NULL, 
  fingerprint TEXT NOT NULL, -- Upper-case fingerprint of the key.
  timestamp INTEGER NOT NULL,
  UNIQUE (chat_id, fingerprint)
) STRICT;
CREATE INDEX gossip_timestamp_index ON gossip_timestamp (chat_id, fingerprint);

-- Timestamps of distributing own key in the Autocrypt header of MDNs.
CREATE TABLE mdn_autocrypt_timestamp (
    fingerprint TEXT PRIMARY KEY NOT NULL, -- Upper-case fingerprint of the recipient key.
    attached_timestamp INTEGER NOT NULL
) STRICT;

-- Passwords used to derive symmetric keys for broadcast lists aka channels.
CREATE TABLE broadcast_secrets(
    chat_id INTEGER PRIMARY KEY NOT NULL,
    secret TEXT NOT NULL
) STRICT;


-- Candidate chatmail relays for automatic relay management.
CREATE TABLE relay_candidates(
    host TEXT PRIMARY KEY NOT NULL,
    last_tried INTEGER NOT NULL DEFAULT 0 -- Timestamp of the last connection attempt.
) STRICT;

CREATE TABLE transports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Email address associated with this transport.
    -- It uniquely identifies the transport.
    addr TEXT NOT NULL,

    -- JSON with the settings entered by the user.
    -- The settings are not necessary entered manually,
    -- but can be entered by scanning the QR code.
    -- These settings are only used during the transport configuration process.
    entered_param TEXT NOT NULL,

    -- JSON with the settings used to connect to the transport.
    -- These settings are derived from entered parameters
    -- and possibly autoconfiguration XML fetched over HTTPS.
    -- The settings stored here are known to have worked at least once,
    -- this is ensured during configuration.
    configured_param TEXT NOT NULL,

    add_timestamp INTEGER NOT NULL DEFAULT 0,
    is_published INTEGER DEFAULT 1 NOT NULL,
    last_rcvd_timestamp INTEGER NOT NULL DEFAULT 0,
    UNIQUE(addr)
);

CREATE TABLE removed_transports (
    addr TEXT NOT NULL,
    remove_timestamp INTEGER NOT NULL,
    UNIQUE(addr)
) STRICT;


CREATE TABLE imap (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transport_id INTEGER NOT NULL, -- ID of the transport in the `transports` table.
    rfc724_mid TEXT NOT NULL, -- Message-ID header
    folder TEXT NOT NULL, -- IMAP folder
    target TEXT NOT NULL, -- Destination folder. Empty string means that the message shall be deleted.
    uid INTEGER NOT NULL, -- UID
    uidvalidity INTEGER NOT NULL,
    UNIQUE (transport_id, folder, uid, uidvalidity)
) STRICT;
CREATE INDEX imap_folder ON imap(transport_id, folder);
CREATE INDEX imap_rfc724_mid ON imap(transport_id, rfc724_mid);
CREATE INDEX imap_only_rfc724_mid ON imap(rfc724_mid);

CREATE TABLE imap_markseen (
    id INTEGER PRIMARY KEY NOT NULL,
    FOREIGN KEY(id) REFERENCES imap(id) ON DELETE CASCADE
);

CREATE TABLE imap_sync (
    transport_id INTEGER NOT NULL, -- ID of the transport in the `transports` table.
    folder TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL DEFAULT 0,
    uid_next INTEGER NOT NULL DEFAULT 0,
    modseq INTEGER NOT NULL DEFAULT 0,
    UNIQUE (transport_id, folder)
) STRICT;
CREATE INDEX imap_sync_index ON imap_sync(transport_id, folder);

CREATE TABLE download (
    rfc724_mid TEXT PRIMARY KEY,
    msg_id INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE available_post_msgs (
    rfc724_mid TEXT PRIMARY KEY
) STRICT;

--
-- Statistics.
--

CREATE TABLE stats_securejoin_sources(
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
) STRICT;
CREATE TABLE stats_sending_enabled_events(timestamp INTEGER NOT NULL) STRICT;
CREATE TABLE stats_sending_disabled_events(timestamp INTEGER NOT NULL) STRICT;

-- Deprecated and unused tables.
--
-- We don't immediately drop unused tables,
-- because we want users to be able to downgrade.

-- Deprecated table for Autocrypt peer states.
-- It is replaced by the new "public_keys" table in migration 132
-- that introduced "key contacts" which have a fixed fingerprint.
CREATE TABLE acpeerstates (
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
  verifier TEXT DEFAULT '',
  secondary_verified_key,
  secondary_verified_key_fingerprint TEXT DEFAULT '',
  secondary_verifier TEXT DEFAULT '',
  backward_verified_key_id -- What we think the contact has as our verified key
  INTEGER,
  UNIQUE (addr) -- Only one peerstate per address
);
CREATE INDEX acpeerstates_index1 ON acpeerstates (addr);
CREATE INDEX acpeerstates_index3 ON acpeerstates (public_key_fingerprint);
CREATE INDEX acpeerstates_index4 ON acpeerstates (gossip_key_fingerprint);
CREATE INDEX acpeerstates_index5 ON acpeerstates (verified_key_fingerprint);

-- Deprecated table previously used to upload sync messages using IMAP APPEND.
-- Sync messages are sent over SMTP now as they should be sent to multiple transports.
CREATE TABLE imap_send (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mime TEXT NOT NULL, -- Message content
    msg_id INTEGER NOT NULL, -- ID of the message in the `msgs` table
    attempts INTEGER NOT NULL DEFAULT 0 -- Number of failed attempts to send the message
);

-- Deprecated table used for a job system.
CREATE TABLE jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    added_timestamp INTEGER,
    desired_timestamp INTEGER DEFAULT 0,
    action INTEGER,
    foreign_id INTEGER,
    param TEXT DEFAULT '',
    thread INTEGER DEFAULT 0,
    tries INTEGER DEFAULT 0
);
CREATE INDEX jobs_index1 ON jobs (desired_timestamp);

-- Backup of the keypairs left after migration 107.
-- Not used by any code, it was only for a recovery
-- in case migration 107 goes wrong.
CREATE TABLE old_keypairs (
    id INTEGER PRIMARY KEY,
    addr TEXT DEFAULT '' COLLATE NOCASE,
    is_default INTEGER DEFAULT 0,
    private_key,
    public_key,
    created INTEGER DEFAULT 0
);

-- Unused table, previously introduced for AEAP mechanism
-- which is replaced by key contacts.
CREATE TABLE sending_domains(
    domain TEXT PRIMARY KEY,
    dkim_works INTEGER DEFAULT 0
);
