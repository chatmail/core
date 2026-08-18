# A keyupdate push channel to maintain reliable chat connectivity

[Multi-relay support for chat profiles was added in March 2026][multi-relay],
allowing them to use multiple relays for receiving and sending messages.
While instant onboarding is being extended to multi-relay onboarding ([#8444]),
adding and removing relays automatically is not settled,
not least because changing a relay is unsafe today.
This draft proposes a *keyupdate push channel*
that shares our current key with our contacts when it changes,
without waiting for a chat interaction.
It helps keep chats connected now,
and makes automatic relay changes safe enough to design later.
The draft stays with the concept:
how such a message is encrypted and addressed is left to the two
implementations summarized in [Two ways to send a keyupdate](#two-ways-to-send-a-keyupdate).


## Problems of maintaining reliable chat connectivity today

A profile's relay list lives inside its own key, as a signed notation that travels with the key.
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
The [privacy notes being drafted for the apps][privacy notes]
would somehow need to describe this behaviour, and the description would read badly.

Unpublished relays exist to protect exactly the contacts
the new keyupdate push channel would reach,
so the keyupdate push channel would let us drop the concept completely.


## Moving on from Autocrypt1: A keyupdate push channel

We should be able to hand our current key to our contacts
without waiting for a conversation to happen.
A keyupdate is a message that does exactly that:
it carries our current key with its signed relay list
to the contacts who still hold an older copy,
sent when that list changes rather than when a chat happens.

Whichever way such a message is sent, the same things follow from it:

- **Contacts acquired at any point in the past are reached**,
  and not only the ones we happen to write to,
  given they have updated to a post-keyupdate app release.

- **Delivery does not have to be complete to be useful.**
  In group chats, cooperative Autocrypt gossip spreads what arrived:
  members who received the fresher key pass it on to the others,
  whenever one of them next writes to the group.

- **"Remove" can mean actually removed.**
  Pushing keyupdates removes the last reason to keep "unpublished relays" around,
  so removing a relay can do what users intend it to do.

- **Automatic relay management becomes easier to design.**
  What ships under that name today is initial onboarding only
  ([#8444], still off by default): no rotation, no removal.
  Designing those proved to be hard while changing a relay is unsafe,
  because any automatic change would silently cut off
  the contacts who do not hear about it.
  Keyupdates would lift that constraint and could land in the next release,
  well before automatic addition/removal mechanics are settled.


## Constraints of keyupdate messages, metadata and processing

- **A keyupdate carries the key and nothing else.**
  The keyupdate push payload is "contacts-public":
  it is the key and its relay list,
  the same data we hand out in every chat where we participate.
  But a keyupdate is not a conversation,
  and it travels automatically to an audience nobody picks per message,
  so **the keyupdate channel must never carry user generated data
  or metadata besides the public key itself and it must not reveal
  to contacts the identity of other contacts.**

- **It is end-to-end encrypted.**
  In chatmail clients "public" keys are by default hidden identities,
  only transmitted in encrypted messages, with the goal of preventing
  a curious or abusive relay operator to track identities.

- **It goes to contacts, not to subscribers, and not to our own devices.**
  The recipients are unblocked key-contacts we share an accepted 1:1,
  group or subscribed-channel chat with.
  Subscribers of our own channels should be left out,
  because they could be a big number and it doesn't contribute to better chat connectivity.
  Our own devices learn relay changes through regular multi-device sync,
  because changing transports involves private credentials
  for accessing a relay address,
  and because we perform some merging on concurrent transport additions.

- **It is accepted from any unblocked key-contact.**
  The relay list lives in a direct key self-signature,
  and certificate merging verifies it and prefers the newest one,
  so merging, and not the way a keyupdate arrived,
  is the cryptographic gate for every certificate we get.
  A stale relay list is worth updating in any case,
  whatever chat state we have with that contact.

- **Replay changes nothing.**
  An old update can be replayed forever,
  but certificate merging keeps the direct key signature
  with the newest creation time, on a tie the one already stored,
  so a replay can not revert a relay list.
  The rest of the certificate is fixed today:
  a key carries one encryption subkey that never rotates.
  Rotating Autocrypt 2 subkeys might need a fresh look at this.

- **It is invisible on arrival.**
  The key should be applied on the normal Autocrypt path
  and the message then trashed rather than filed:
  no chat, no counter, and no refresh of the sender's "last seen",
  because an invisible message should not light up an online dot.

- **It stays quiet on clients that do not know it yet.**
  No new chat and no contact request should ever be created there.
  Old and new clients can therefore ship together,
  with coverage growing as clients update.


## When and how a keyupdate goes out

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

- **Nothing on upgrade.**
  Existing profiles must start with their current relay list
  already recorded as announced.
  Otherwise the keyupdate release would send unnecessary noise
  without any actual relay changes.

- **Exactly one device in a multi-device setup announces.**
  A device applying a relay change received over
  multi-device sync should record the resulting list as announced without sending.
  That also systematically prevents a device catching up on a backlog of old sync
  messages from announcing historical states.

- **Behind real traffic.**
  The message should best leave from the SMTP loop once its queue is drained,
  so a keyupdate never delays a user message
  and is only attempted on a connection that just proved to work.



## Two ways to send a keyupdate

Nothing above says how a keyupdate reaches its recipients,
and two implementations currently explore that question:

- [#8601] sends a single symmetrically encrypted message
  to all recipients at once, re-using the broadcast machinery core has,
  with the secret derived from our own key
  so that everyone already holding a copy computes the same value.
  Nothing in the message is recipient-specific
  and its cost is largely independent of the recipient count.
  Wire format, secret derivation, audience and sending policy
  are documented in its `src/keyupdate.rs` module docs.

- [#8588] (WIP) sends ordinary asymmetrically encrypted messages,
  addressed per recipient in chunks of a few dozen contacts,
  staying on paths core already has
  at a cost that grows with the number of contacts.

Both fit the concept described here,
and they trade off differently on who can decrypt a keyupdate,
what a relay observes, and how much machinery is involved,
which is a discussion for the PRs rather than for this draft.


## Open questions

- Should a keyupdate be rate limited for a profile whose relay list flaps on its own?
  Manual fiddling is bounded by the person
  doing it, but future automatic relay add/remove needs to think about limits.

- What should happen to delivery status notifications for dead addresses?
  They arrive per address and refer to one Message-ID
  but we don't do much with them. We could probably evolve to exclude such
  bounced addresses from future key updates but it shouldn't block
  a first key update implementation.

- Is the sending set right? Narrowing the keyupdate recipient set
  by activity would shrink what we send, but it would also disclose
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

Interestingly, a keyupdate does not have to be addressed to anyone in particular.
Sent as one ciphertext readable by whoever holds the sender's key ([#8601]),
it does not have to be directly delivered to be useful:
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
[#8601]: https://github.com/chatmail/core/pull/8601 "feat: introduce keyupdate message to inform contacts about relay changes"
[multi-relay]: https://delta.chat/en/2026-03-31-zero#maximizing-availability-and-resilience-through-multi-path-delivery "Maximizing availability and resilience through multi-path delivery"
[privacy notes]: https://github.com/deltachat/deltachat-pages/pull/1385 "Privacy notes being drafted for the apps"
