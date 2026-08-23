# Make relay and mailbox removal immediate (after keyupdates land)

Today "remove" only unpublishes a relay (`set_transport_unpublished()`):
the transport keeps its IMAP loop and is garbage collected only after 90 days
without incoming messages, which senders control and which can therefore mean *never*.
The removal delay is *unpredictable and invisible*,
contradicts what the UI suggests, and what a good privacy policy wants:
the profile keeps logging into a relay the user asked to remove,
and on top the relay keeps the mailbox active for 90 days
after the last login, storing incoming messages etc.

Once keyupdates (https://github.com/chatmail/core/pull/8621) lands,
I suggest switching to a "remove means remove" approach:

- `set_transport_unpublished()` triggers `remove_transport` directly,
  and syncs to our own devices through the `removed_transports` tombstone
  (which old cores already apply),
  and drops its entry from `context.metadata` so calls and iroh stop using it.

- Migration determines unpublished relays and removes them, locally per device.

- The whole "unpublished" machinery vanishes:
  the 90 day collection, `last_rcvd_timestamp`,
  the eviction branch of `try_make_space_for_new_relay()`,
  and `is_unpublished` in the UI-facing APIs.
  `set_transport_unpublished()` gets renamed to `remove_transport`.

- A new core/relay METADATA protocol to remove a mailbox and all its content
  on a relay, causing immediate NDNs to any contacts trying to send there still,
  therefore completing the "remove means remove" approach proposed by this issue.

  Note that `handle_ndn()` fails the *whole* message on one bounce so a message
  delivered through a surviving relay would be marked failed by the removed relay's NDN.
  It's a pre-existing problem but immediate relay-removal may increase its occurrence,
  but then again keyupdates may mitigate it in real life.


## Known problems

In multi-relay setups removing a relay loses messages during the **replacement gap**:
if the removal is replacement-shaped and one of our contacts sends us a message
while they knew only removed relays we already don't listen to anymore.
This happens for example with single-relay profiles
when you add a relay, then remove the previous.
Keyupdates minimize the replacement gap often to under a minute but do not eliminate it.
To help reduce lost/not-received messages during the "replacement gap"
we may only terminate the active scheduled IMAP tasks some minutes after removal.
Right now, we don't terminate them at all,
and rely on a restart cleaning removed relays up which is fine only for mobiles.

Replacement-shaped relay changes also invalidate invite links
that point to already removed relays that we don't listen to anymore.

Both problems are acceptable because the relay-list is still in "advanced options"
and we could provide a warning if we discover a replacement-shape:
We can record a `transports.published_since` column which is
written once, and synced also to old cores (i.e. no wire changes),
and can help deciding about posting a warning to users
by helping to answer the question 
"is there an older surviving relay if I delete this one?" and
"is there a non-expired invite link that points to since-removed relays?"
and basing a future warning to users on the answers.
Independently from a warning, recording relay age is also useful 
for any automated add/remove decisions later.

