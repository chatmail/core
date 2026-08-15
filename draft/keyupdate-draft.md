# A keyupdate push channel to maintain reliable chat connectivity


## Problem

A profile's relay list lives inside its own key,
as a signed notation that travels with the key.
A contact sends to the addresses contained in the key, signed by the key holder.
Rooted in the [Autocrypt 1](https://autocrypt.org) inline key-distribution specification,
there is no central directory, no probe and no removal notice,
so a contact's copy is only refreshed by traffic:
a message we send them, or a group message from someone else
that gossips our key onwards.

Reachability therefore decays exactly where traffic is thin.
Three situations turn that decay into a cut conversation,
or into costs of preventing one:

- **Mutual silence.**
  If neither side has written since our relays changed,
  the contact keeps the old list indefinitely.
  Their next message goes to a relay we no longer read,
  and they get silence rather than a bounce because the old account still exists.
  Even if a bounce comes, it's hard to effectively act on it for users.
  [#7878] is a user report of exactly this, and the reporter's objection
  is the design point:
  "people changing relays shouldn't need to know to write in every room
  they're in just to make sure everyone gets the update".
  It was closed expecting [#7865] to fix it, and [#7865] did land:
  the relay list is now carried in the key.
  That settled what gets distributed, not when,
  which is the part still missing.

- **Deliberate relay removal.**
  Users remove relays for good reasons:
  privacy, distrust of a provider, or wanting to use relays they chose.
  Here the cut would be immediate and total:
  every contact still on the old list would write to an address nobody reads.
  It does not happen today only because core doesn't really remove a relay,
  preventing lost messages at the costs of the "unpublished relay" workaround below.

- **Adding relays during degradation.**
  Relays sometimes get added precisely when the existing ones stop working,
  so the announcement would have to travel
  at the moment reachability is already impaired.
  A contact who does not learn the new relay
  keeps writing to an address that may already be dead.


What exists today only narrows the gap.
MDN key refresh ([#8481]) covers contacts who read our messages without
replying, so the exposed population is mutual silence
rather than all quiet contacts.
Unpublished relays buy time, and only for removal.


### The "unpublished relay" workaround is its own problem

"Remove" today marks a relay *unpublished*: the address stops being advertised,
but the relay keeps a full IMAP connection and keeps receiving.
This is deliberate ([#8384]) and it does buy safety for the cases above.
The price is that users cannot end their relationship with a relay:

- **Retention is unpredictable in both directions.**
  Cleanup requires 90 days both since the removal itself
  and since the last message received there,
  and every fetched message resets the second clock,
  with no filter for blocked contacts or spam,
  so a removed relay that keeps getting mail is kept indefinitely.
  Adding a relay at the five-relay cap does the opposite
  and hard-deletes the least recently used unpublished one at once.

- **A relay the user removed keeps being used.**
  Unpublished transports get an IMAP loop like any other
  and count against the same cap,
  so a profile can hold connections to five relays,
  four of them ones the user pressed "Remove" on.
  Chatmail relays only delete accounts after a period without any login,
  and core keeps logging in,
  so the account there outlives the removal as well.

- **Nothing the user can do shortens it.**
  Real deletion is documented as internal and test-only.
  Users are told at removal time that the relay is phased out,
  but not for how long,
  and not that we keep connecting and receiving there.
  [#8384] records the friction from a user: a removed relay still advertising
  TURN servers, and a permanent connection error with "no way to get rid of
  it", patched as a symptom in [#8550] while the relay itself stayed.

This grows with multi-relay setups, and multi-relay onboarding ([#8444]) brings them.
The [privacy notes being drafted for the apps](https://github.com/deltachat/deltachat-pages/pull/1385)
would somehow need to describe this behaviour, and the description would read badly.

Unpublished relays exist to protect exactly the contacts
the new keyupdate push channel would reach,
so the channel would let us drop the concept completely.


## Moving on from Autocrypt1: A keyupdate push channel

We should be able to hand our current key to our contacts
without waiting for a conversation to happen.
One way to address such a message is per recipient,
in chunks of about twenty contacts, as sketched in [#8588].
To name two problems: it reveals a slice of your contact list to each contact,
because the signature names every intended recipient in the chunk,
and it uploads the keyupdate message 10 times for 200 contacts.
This draft argues for a different way of sending key updates,
starting with a simple observation:

**A keyupdate needs to reach everyone holding a copy of our key,
and that audience already shares a secret: the identity key of a contact**.
From that key we can derive a secret deterministically,
so everyone already holding the key computes the same value,
and nobody else can.
That lets us re-use the symmetric broadcast encryption core already has:
one signed, symmetrically encrypted message to many recipients at once,
with the secret derived rather than generated and handed out to subscribers.

In chatmail clients "public" keys are by default hidden identities,
only transmitted in encrypted messages, with the goal of preventing
a curious or abusive relay operator to track identities.

What using automatically derived secrets and existing broadcast encryption buys:

- No new header names, no new key distribution or bookkeeping protocol (phew!),
  only a new `Chat-Content` value.

- Network cost is largely independent of contact count for senders.
  One message per relay change rather than one per chunk.
  Relays by default currently allow 1000 recipients per submission,
  so a keyupdate (which is below 10Kbyte even with Autocrypt2),
  would be uploaded once for anyone below 1K contacts,
  which today is the vast majority by a wide margin.

- Recipients learn nothing about our contact list.
  Every recipient gets the same encrypted message with no per-recipient framing,
  and no chunk has to group contacts together.
  The submitting relay still sees the envelope, as it does today.

- Contacts acquired at any point in the past are reached.
  The secret comes from the key itself and not from a shared session,
  so a contact from years ago can decrypt an update sent today,
  given they have updated to a post-keyupdate app release.

Delivery would not have to be complete to be useful.
In group chats, cooperative Autocrypt gossip spreads what arrived:
members who received the fresher key pass it on to the others,
whenever one of them next writes to the group.

Pushing keyupdates removes the last reason to keep "unpublished relays" around,
so "Remove" can mean actually removed, like users intend it.
It would also unblock automatic relay management.
What ships under that name today is initial onboarding only
([#8444], still off by default): no rotation, no removal.
Designing those is hard while changing a relay is unsafe,
because any automatic change would silently cut off
the contacts who do not hear about it.
Keyupdates would lift that constraint and could land in the next release,
well before automatic addition/removal mechanics are settled.


## Keyupdates are decryptable forever, MUST only contain key updates

Anyone who ever obtained our "public" key could derive the secret
and decrypt these messages, forever.
Nothing here is ephemeral and the secret never rotates,
so blocking or deleting a contact does not take that ability away.

However, deriving the secret is not the same as getting the message:
keyupdates go only to our own contacts (see below),
so the wider set only matters for someone who also obtains a copy,
a relay in the path for example.

This is acceptable because the payload is "contacts-public" anyway:
it is the key and its relay list,
the same data we hand out in every chat where we participate.
Whoever can derive the secret already holds an earlier copy of that key,
so what a keyupdate adds for them is the current relay list.
It follows that **the keyupdate channel must never carry user generated data
or metadata besides the public key itself.**


## When a keyupdate goes out

Sending should be driven by a diff, not by an event.
A device records the relay list it last announced,
and a keyupdate is due only when the current relay list differs from it.
That single decision gives us the rest:

- **Debounced.**
  Changes within a short window should go out as one message,
  so an automatic relay add/remove yields one keyupdate,
  and an add followed by a removal of the same yields none.

- **Short debouncing for user observability**:
  Around 30 seconds may be a good enough debounce window to start with.
  It is long enough that several changes usually travel in one keyupdate
  (current initial onboarding adds up to three relays sequentially),
  and short enough that someone changing relays by hand
  can still watch the effect arrive with chat peers,
  which is worth more than optimising against a few small extra messages.

- **Behind real traffic.**
  The message should leave from the SMTP loop once its queue is drained,
  so a keyupdate never delays a user message
  and is only attempted on a connection that just proved to work.

- **Nothing on upgrade.**
  Existing profiles must start with their current relay list
  already recorded as announced.
  Otherwise the keyupdate release would send unnecessary noise
  without any actual relay changes.

- **Exactly one device in a multi-device setup announces.**
  A device applying a relay change received over
  multi-device sync should record the resulting list as announced without sending.
  That also systematically prevents a device catching up on a backlog of old sync
  messages from announcing withering historical states.


## Cryptographic and implementation considerations

The keyupdate design needs no new cryptographic primitives,
only the broadcast machinery named above with a different secret.
Both symmetric secrets core has today, for broadcast channels and for
securejoin, are random values shared out of band by QR code or invite.
Deriving one from public key material instead
is the part most worth scrutinising.

**The construction of the derived secret:**

- Derive the secret as a canonical `keyupdate/` followed by the hex of
  `SHA256("keyupdate" || <primary key packet body>)`,
  where the body is the OpenPGP primary key packet without its packet header:
  one octet version, four octets big-endian creation time,
  one octet algorithm, for v6 a four-octet length of the key material,
  then the key material.
  This layout is normative and must be pinned by test vectors,
  not left as "whatever the OpenPGP library happens to serialize".

- Send it as an ordinary [RFC 9580] password-encrypted message.
  Nothing about the format is specific to keyupdates,
  it is what any OpenPGP implementation writes for a passphrase:
  one [v6 SKESK] packet whose [salted S2K]
  (type 1, SHA-256, eight random salt bytes)
  turns the secret, via HKDF, into the key
  that wraps a fresh random session key,
  plus one [SEIPDv2] packet, AES-128 in OCB mode, ZLIB compressed,
  signed by the sender.
  AES-128 is what all our symmetrically encrypted messages already use.
  Carry our key in a protected `Autocrypt` header,
  next to a protected `Chat-Content: key-update` header.

Properties that follow, and requirements they imply:

- **Who can read it is not who we send it to.**
  Anyone holding a copy of our key can derive the secret (see above),
  including people who got it by gossip or vCard.
  What we choose is the recipient set:
  unblocked key-contacts we share an accepted 1:1,
  group or subscribed-channel chat with.
  Subscribers of our own channels should be left out,
  because they could be massive and it doesn't contribute to better chat connectivity.
  Receivers in turn can accept from any unblocked key-contact.

- **Retroactive.**
  The primary key packet is fixed when the key is generated,
  and re-signing with a new relay list does not touch it,
  so the secret is stable for the lifetime of the key.

- **v4 and v6 keys both work.**
  The derivation reads the serialized key body, not the fingerprint,
  so it does not depend on the fingerprint algorithm.
  The body layout does differ between the two versions, so the digest differs per version.
  Both derivations should be pinned by test vectors,
  since deployed contacts recompute them from their stored copies.

- **Only update the key the secret was derived from.**
  A keyupdate must be signed by that key and carry an update to it,
  and anything else is dropped.
  The rule is needed because the AEAD tag only proves the writer knew the
  secret, which every key holder does, so it authenticates nobody by itself.
  Certificate merging already prevents a forged relay list,
  but without the rule anyone holding a contact's key could send
  a stream of messages carrying freshly generated keys in the Autocrypt
  header, each silently creating a contact and a stored key
  the user never sees, because keyupdates are trashed.
  Note that keyupdates can only arrive for contacts whose key we already have.

- **Domain-separated.**
  A v6 fingerprint is also a SHA-256 over the same key material,
  but the two preimages are already disjoint,
  so the hashed `keyupdate` prefix is documentation rather than protection.
  The `keyupdate/` prefix on the password string does carry weight:
  it separates these secrets from the securejoin and broadcast secrets
  that share the same trial-decryption pool.

- **Replay changes nothing.**
  An old update can be replayed forever.
  The relay list lives in the direct key signature,
  and certificate merging keeps the one with the newest creation time,
  on a tie the one already stored.
  The rest of the certificate is fixed today:
  a key carries one encryption subkey that never rotates,
  so an old copy differs from the current one only in that signature.
  Rotating Autocrypt 2 subkeys might need a fresh look at this.

- **Trial decryption must stay bounded.**
  A symmetrically encrypted message carries no hint of which secret opens it,
  so a receiver has to try every secret it knows until one works,
  and the cost of a single failed attempt matters.
  Core already restricts symmetric decryption to a single ESK packet with a
  salted S2K, so an attacker cannot make it expensive with an iterated S2K
  or a stack of session keys.
  A single hash is on purpose here: the secret is a full 256-bit digest
  rather than a passphrase, so hardening would buy nothing.
  What is not bounded is one certificate parse per unblocked key-contact,
  which any sender could trigger with undecryptable garbage.
  Keyupdate secrets should therefore be tried last,
  after the securejoin and broadcast secrets.
  Parsing and deriving on-demand in the try-decryption pipeline
  is probably fine even for thousands of contacts,
  at tens of microseconds per certificate.

- **One body, many deliveries.**
  The body would be rendered once and independently from the contact count.
  The SMTP envelope still lists every distinct relay address,
  chunked at whatever limit the relay advertises over IMAP METADATA.
  The relay therefore learns the keyupdate addressee set,
  though it can track our send and receive history anyway
  and largely observes a similar set over time.

- **Invisible on arrival.**
  The key should be applied on the normal Autocrypt path
  and the message then trashed rather than filed:
  no chat, no counter, and no refresh of the sender's "last seen",
  because an invisible message should not light up an online dot.

- **Old clients stay quiet.**
  Without the secret the message is undecryptable,
  and with `force_encryption` being true by default
  unsigned incoming mail is discarded before any chat is touched.
  A user who turns encryption enforcement off,
  and who already has a plain-address chat with our address,
  may see an undecipherable message there.
  No new chat and no contact request should ever be created.
  Old and new clients can therefore ship together,
  with coverage growing as clients update.

- **Not sent to our own devices.**
  We inform about relay changes through regular multi-device sync,
  because changing transports involves private credentials for accessing a relay address,
  and because we perform some merging on concurrent transport additions.


## Out of scope: envelope SMTP failures can terminate all sending

A permanently refused `RCPT TO` would fail the whole SMTP transaction,
and core then drops the queued message
without attempting the remaining chunks,
so with one envelope a single dead address
would cost the announcement for everyone behind it.
Chatmail relays never get there: they accept every recipient
and report delivery failures afterwards as DSNs.
The hazard is real only on a deployment that rejects unknown or
over-quota recipients at `RCPT TO`,
and it affects regular group messages and even 1:1 chats today,
so it is out of scope for keyupdates, which carry less critical data.
Losing all relays on both sides at once is out of scope too,
but for a different reason: nothing we send can help there,
see the last section.


## Open questions

- Should a keyupdate be rate limited beyond coalescing,
  for a profile whose relay list flaps on its own?
  Manual fiddling is bounded by the person
  doing it, but future automatic relay add/remove needs to think about limits.

- What should happen to delivery status notifications for dead addresses in
  a large envelope? They arrive per address and refer to one Message-ID
  but we don't do much with them. We could probably evolve to exclude such
  bounced addresses from future key updates but it shouldn't block
  a first key update implementation.

- Is the sending set right? Narrowing the keyupdate recipient set
  by activity would shrink the envelope, but it would also disclose
  to the relay which of our contacts are close ones.
  Note that a quiet contact is indistinguishable from one who left,
  so dropping them silently loses their next message.


## What a reliable keyupdate rollout might open up

None of the following sections is proposed here.
But each of them becomes thinkable once changing relay setups is safer.


### Maximizing reliable deletion ("forward secrecy") with Autocrypt 2

The keyupdate channel is not necessarily only about relays.
Autocrypt 2 ([#8317]) introduces expiring, rotating subkeys,
whose distribution has a similar shape as the problem above:
a contact we never write to ends up not having our "reliable deletion" encryption keys.
The described keyupdate mechanism could help,
or at least it could play into the cadence of updates ...


### Forward-rotating through the relay network

Today a relay change feels like something to be survived.
If keyupdates make it routine, it becomes something we could choose to do:
Better relays appear, and a profile could drift towards them
instead of staying wherever it happened to be born.
A safe frequency is capped by how reliably keyupdates land,
which is the interesting part:
rotation is exactly as feasible as the keyupdate channel is reliable.


### Immortal chat connectivity: surviving total relay loss

One case is already out of reach of anything we send directly.
In [#8329] both sides lost all their relays at once,
so any announcement would go to addresses the chat partner can not access anymore.
Cooperative Autocrypt gossip can still bridge that
if some mutual contact remains reachable from both sides,
which is what the reporters ended up relying on,
and failing that an out-of-band re-exchange restores contact,
which works since [#8358], rerunning the full securejoin protocol
when the address is outdated.

Harder still is a whole region losing all its relays at once:
nobody can announce anything to anybody, no push channel helps,
and there may be no mutual contact left to bridge it.
But new relays, for example in sprouting mesh networks, might become available
and wouldn't it be useful to re-establish chat connectivity with those
who might be able to help you, or where you can pool resources?

Interestingly, a keyupdate message is not addressed to anyone in particular.
It is one ciphertext readable by whoever holds the sender's key,
so it does not have to be directly delivered to be useful:
something parked now can be picked up later.
Making it discoverable without handing everyone a way to enumerate and track profiles
is an interesting enough challenge to make cryptographers have exciting discussions.
But during emergencies people really just want things to work
and we could ask users in some way "It seems you lost access to all chats.
Do you want to enable emergency recovery mode?"

We could then ephemerally park keyupdates at all accessible relays,
and scan what relay-stored key updates are decryptable for us.
As soon as chat connectivity recovers for first bunches of people,
they spread it further through cooperative Autocrypt gossip,
re-establishing chats over time, scaling chat connectivity for everyone.


[#7865]: https://github.com/chatmail/core/issues/7865 "Distribute information about relays in the key signature"
[#7878]: https://github.com/chatmail/core/issues/7878 "DeltaChat seems to sometimes propagate the incorrect relays for users who switched relays"
[#8317]: https://github.com/chatmail/core/issues/8317 "Autocrypt 2 support"
[#8329]: https://github.com/chatmail/core/issues/8329 "Scanning QR for existing contact doesn't update relay list"
[#8358]: https://github.com/chatmail/core/pull/8358 "fix: Rerun the full securejoin protocol if the address was outdated"
[#8384]: https://github.com/chatmail/core/issues/8384 "Remove hidden relays automatically"
[#8444]: https://github.com/chatmail/core/pull/8444 "feat: Basic multi-relay onboarding"
[#8481]: https://github.com/chatmail/core/pull/8481 "Improve and speed up autocrypt/pgp gossipping with MDNs"
[#8550]: https://github.com/chatmail/core/pull/8550 "fix: multi relay connectivity"
[#8588]: https://github.com/chatmail/core/pull/8588 "feat: Key update messages"
[RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html "OpenPGP"
[v6 SKESK]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.3.2 "RFC 9580 5.3.2: Version 6 Symmetric Key Encrypted Session Key Packet Format"
[SEIPDv2]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.13.2 "RFC 9580 5.13.2: Version 2 Symmetrically Encrypted and Integrity Protected Data Packet Format"
[salted S2K]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.7.1.2 "RFC 9580 3.7.1.2: Salted S2K"
