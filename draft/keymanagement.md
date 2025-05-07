# New acpeerstates table

A proposal to replace `acpeerstates` table,
which has columns
- `id`
- `addr`
- `prefer_encrypted`
- `last_seen`
- `last_seen_autocrypt`
- `public_key`
- `public_key_fingrprint`
- `gossip_timestamp`
- `gossip_key`
- `gossip_key_fingerprint`
- `verified_key`
- `verified_key_fingerprint`
- `verifier`
- `secondary_verified_key`
- `secondary_verified_key_fingerprint`
- `secondary_verifier`
with a new `public_keys` table with columns
- `id`
- `addr` - address of the contact which is supposed to have the private key
- `public_key` - a blob with the OpenPGP public key
- `public_key_fingerprint` - public key fingerprint
- `introduced_by` - address of the contact if received directly in `Autocrypt` header, address of `Autocrypt-Gossip` sender otherwise
- `is_verified` - boolean flag indicating if the key was received in a verified group or not
- `timestamp` - timestamp of the most recent row update 

The table has consraints `UNIQUE(addr, introduced_by)`.
Note that there may be multiple rows with the same fingerprint,
e.g. if multiple peers gossiped the same key for a contact they all are introducers of the key.

`prefer_encrypted` is moved to the `contacts` table.


## Using the table to select the keys

### Sending a message to 1:1 chat

When sending a message to the contact in a 1:1 chat,
encrypt to the key where `introduced_by` equals `addr`:
```
SELECT *
FROM public_keys
WHERE addr=? AND introduced_by=addr
```
This row is guaranteed to be unique if it exists.

If direct Autocrypt key does not exist,
use the most recent one according to the timestamp key gossiped for this contact:
```
SELECT *
FROM public_keys
WHERE addr=?
ORDER BY timestamp DESC LIMIT 1
```

If the table contains a row with selected key and `is_verified` flag set,
display a green checkmark and "Introduced by <introduced_by>" in the 1:1 chat/contact profile.
Note that row with verification may be older than the most recent gossip.

### Sending a message to unprotected group chat

When sending a message to the contact in a non-verified group chat,
encrypt to the same key as used in 1:1 chat
and (NEW!) one or more most recent gossiped keys introduced by chat members:
```
SELECT public_key
FROM public_keys
WHERE addr=? AND introduced_by IN (<chat-member-list>)
ORDER BY timestamp DESC
```
It does not matter if the gossiped key has `is_verified` flag.

### Sending a message to protected group chat

When sending a message in a protected group chat,
construct a list of candidate keys for each contact
the same way as in an unprotected chat,
but then filter out the keys which do not have `is_verified` flag.


## Updating the table

When executing "setup contact" protocol
with the contact,
set the row with `addr` and `introduced_by` being equal
to the contact address and `is_verified` is true.
In this case the contact becomes directly verified.

When receiving a message,
first process the `Autocrypt` key,
then check verification properties to detect if gossip is signed with a verified key,
then process `Autocrypt-Gossip` key.

### 1. Processing the Autocrypt header

Take the key from the Autocrypt header
and insert or update the row
identified by `addr` and `introduced_by` being equal to the `From:` address.
Notify about setup change and reset `is_verified` flag if the key fingerprint has changed.
Always update the timestamp.

Update `prefer_encrypted` in the contacts table as needed
based on the `Autocrypt` header parameters,
whether the message is signed etc.

### 2. Check verification

Determine whether the green checkmark should now be displayed
on the 1:1 chat and update it accordingly,
insert system messages,
get it into broken state or out of it.

Now we know if the message is signed with a verified key.

### 3. Process `Autocrypt-Gossip`

Insert or update gossip keys
```
INSERT INTO public_keys (addr, public_key, public_key_fingerprint, introduced_by, is_verified, timestamp)
VALUES                  (?,    ?,          ?,                      <introducer>,  ?,           <now>)
ON CONFLICT
DO UPDATE SET public_key=excluded.public_key, public_key_fingerprint=excluded.public_key_fingerprint
```

`is_verified` should be set if the message is signed with a verified key,
independently of whether the key was gossiped in a protected chat or not.
