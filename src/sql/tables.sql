CREATE TABLE config (
  id INTEGER PRIMARY KEY,
  keyname TEXT,
  value TEXT
);
CREATE INDEX config_index1 ON config (keyname);
CREATE TABLE contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT DEFAULT '',
    addr TEXT DEFAULT '' COLLATE NOCASE,
    origin INTEGER DEFAULT 0,
    blocked INTEGER DEFAULT 0,
    last_seen INTEGER DEFAULT 0,
    param TEXT DEFAULT '',
    authname TEXT DEFAULT '',
    selfavatar_sent INTEGER DEFAULT 0
);
CREATE INDEX contacts_index1 ON contacts (name COLLATE NOCASE);
CREATE INDEX contacts_index2 ON contacts (addr COLLATE NOCASE);
INSERT INTO contacts (id,name,origin) VALUES
(1,'self',262144), (2,'info',262144), (3,'rsvd',262144),
(4,'rsvd',262144), (5,'device',262144), (6,'rsvd',262144),
(7,'rsvd',262144), (8,'rsvd',262144), (9,'rsvd',262144);

CREATE TABLE chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type INTEGER DEFAULT 0,
    name TEXT DEFAULT '',
    draft_timestamp INTEGER DEFAULT 0,
    draft_txt TEXT DEFAULT '',
    blocked INTEGER DEFAULT 0,
    grpid TEXT DEFAULT '',
    param TEXT DEFAULT '',
    archived INTEGER DEFAULT 0,
    gossiped_timestamp INTEGER DEFAULT 0,
    locations_send_begin INTEGER DEFAULT 0,
    locations_send_until INTEGER DEFAULT 0,
    locations_last_sent INTEGER DEFAULT 0,
    created_timestamp INTEGER DEFAULT 0,
    muted_until INTEGER DEFAULT 0,
    ephemeral_timer INTEGER
);
CREATE INDEX chats_index1 ON chats (grpid);
CREATE INDEX chats_index2 ON chats (archived);
CREATE INDEX chats_index3 ON chats (locations_send_until);
INSERT INTO chats (id,type,name) VALUES
(1,120,'deaddrop'), (2,120,'rsvd'), (3,120,'trash'),
(4,120,'msgs_in_creation'), (5,120,'starred'), (6,120,'archivedlink'),
(7,100,'rsvd'), (8,100,'rsvd'), (9,100,'rsvd');

CREATE TABLE chats_contacts (chat_id INTEGER, contact_id INTEGER);
CREATE INDEX chats_contacts_index1 ON chats_contacts (chat_id);
CREATE INDEX chats_contacts_index2 ON chats_contacts (contact_id);

CREATE TABLE msgs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rfc724_mid TEXT DEFAULT '',
    server_folder TEXT DEFAULT '',
    server_uid INTEGER DEFAULT 0,
    chat_id INTEGER DEFAULT 0,
    from_id INTEGER DEFAULT 0,
    to_id INTEGER DEFAULT 0,
    timestamp INTEGER DEFAULT 0,
    type INTEGER DEFAULT 0,
    state INTEGER DEFAULT 0,
    msgrmsg INTEGER DEFAULT 1,
    bytes INTEGER DEFAULT 0,
    txt TEXT DEFAULT '',
    txt_raw TEXT DEFAULT '', -- deprecated 2025-03-29
    param TEXT DEFAULT '',
    starred INTEGER DEFAULT 0,
    timestamp_sent INTEGER DEFAULT 0,
    timestamp_rcvd INTEGER DEFAULT 0,
    hidden INTEGER DEFAULT 0,
    -- mime_headers column actually contains BLOBs, i.e. it may
    -- contain non-UTF8 MIME messages.  TEXT was a bad choice, but
    -- thanks to SQLite 3 being dynamically typed, there is no need to
    -- change column type.
    mime_headers TEXT,
    mime_in_reply_to TEXT,
    mime_references TEXT,
    move_state INTEGER DEFAULT 1,
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
    ephemeral_timestamp INTEGER DEFAULT 0
);

CREATE INDEX msgs_index1 ON msgs (rfc724_mid);
CREATE INDEX msgs_index2 ON msgs (chat_id);
CREATE INDEX msgs_index3 ON msgs (timestamp);
CREATE INDEX msgs_index4 ON msgs (state);
CREATE INDEX msgs_index5 ON msgs (starred);
CREATE INDEX msgs_index6 ON msgs (location_id);
CREATE INDEX msgs_index7 ON msgs (state, hidden, chat_id);
INSERT INTO msgs (id,msgrmsg,txt) VALUES
(1,0,'marker1'), (2,0,'rsvd'), (3,0,'rsvd'),
(4,0,'rsvd'), (5,0,'rsvd'), (6,0,'rsvd'), (7,0,'rsvd'),
(8,0,'rsvd'), (9,0,'daymarker');

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

CREATE TABLE leftgrps (
    id INTEGER PRIMARY KEY,
    grpid TEXT DEFAULT ''
);
CREATE INDEX leftgrps_index1 ON leftgrps (grpid);

CREATE TABLE keypairs (
    id INTEGER PRIMARY KEY,
    addr TEXT DEFAULT '' COLLATE NOCASE,
    is_default INTEGER DEFAULT 0,
    private_key,
    public_key,
    created INTEGER DEFAULT 0
);

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
    verified_key_fingerprint TEXT DEFAULT ''
);
CREATE INDEX acpeerstates_index1 ON acpeerstates (addr);
CREATE INDEX acpeerstates_index3 ON acpeerstates (public_key_fingerprint);
CREATE INDEX acpeerstates_index4 ON acpeerstates (gossip_key_fingerprint);
CREATE INDEX acpeerstates_index5 ON acpeerstates (verified_key_fingerprint);

CREATE TABLE msgs_mdns (
    msg_id INTEGER,
    contact_id INTEGER,
    timestamp_sent INTEGER DEFAULT 0
);
CREATE INDEX msgs_mdns_index1 ON msgs_mdns (msg_id);

CREATE TABLE tokens (
    id INTEGER PRIMARY KEY,
    namespc INTEGER DEFAULT 0,
    foreign_id INTEGER DEFAULT 0,
    token TEXT DEFAULT '',
    timestamp INTEGER DEFAULT 0
);

-- The currently running securejoin protocols, joiner-side.
-- CREATE TABLE bobstate (
--     id INTEGER PRIMARY KEY AUTOINCREMENT,
--     invite TEXT NOT NULL,
--     next_step INTEGER NOT NULL,
--     chat_id INTEGER NOT NULL
-- );

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
