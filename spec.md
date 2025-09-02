# Chatmail Specification

Version: 0.37.0
Status:  In-progress 
Format:  [Semantic Line Breaks](https://sembr.org/)

This document roughly describes how chatmail 
apps use the standard e-mail system 
to implement typical messenger functions.

- [Encryption](#encryption)
- [Outgoing messages](#outgoing-messages)
- [Incoming messages](#incoming-messages)
- [Forwarded messages](#forwarded-messages)
- [Groups](#groups)
    - [Outgoing group messages](#outgoing-group-messages)
    - [Incoming group messages](#incoming-group-messages)
    - [Add and remove members](#add-and-remove-members)
    - [Change group name](#change-group-name)
    - [Set group image](#set-group-image)
- [Request editing](#request-editing)
- [Request deletion](#request-deletion)
- [Set profile image](#set-profile-image)
- [Locations](#locations)
    - [User locations](#user-locations)
    - [Points of interest](#points-of-interest)
- [Stickers](#stickers)
- [Voice messages](#voice-messages)
- [Reactions](#reactions)
- [Attaching a contact to a message](#attaching-a-contact-to-a-message)
- [Transitioning to a new e-mail address (AEAP)](#transitioning-to-a-new-e-mail-address-aeap)
- [Miscellaneous](#miscellaneous)
    - [Sync messages](#sync-messages)


# Encryption

Messages SHOULD be encrypted by the
[Autocrypt](https://autocrypt.org/level1.html) standard;
`prefer-encrypt=mutual` MAY be set by default.

Meta data (at least the subject and all chat-headers) SHOULD be encrypted
by the [Protected Headers](https://tools.ietf.org/id/draft-autocrypt-lamps-protected-headers-02.html) standard.


# Outgoing messages

Messengers MUST add a `Chat-Version: 1.0` header to outgoing messages.
For filtering and smart appearance of the messages in normal MUAs,
the `Subject` header SHOULD be `Message from <sender name>`.
Replies to messages MAY follow the typical `Re:`-format.

The body MAY contain text which MUST have the content type `text/plain`
or `multipart/alternative` containing `text/plain`.

The text MAY be divided into a user-text-part and a footer-part using the
line `-- ` (minus, minus, space, lineend).

The user-text-part MUST contain only user generated content.
User generated content are eg. texts a user has actually typed
or pasted or forwarded from another user.
Full quotes, footers or sth. like that MUST NOT go to the user-text-part.

    From: sender@domain
    To: rcpt@domain
    Chat-Version: 1.0
    Content-Type: text/plain
    Subject: Message from sender@domain

    Hello world!


# Incoming messages

The `Chat-Version` header MAY be used
to detect if a messages comes from a compatible messenger.

The `Subject` header MUST NOT be used
to detect compatible messengers, groups or whatever.

Messenger SHOULD show the `Subject`
if the message comes from a normal MUA together with the email-body.
The email-body SHOULD be converted
to plain text, full-quotes and similar regions SHOULD be cut.

Attachments SHOULD be shown where possible.
If an attachment cannot be shown, a non-distracting warning SHOULD be printed.


# Forwarded messages

Forwarded messages are outgoing messages that contain a forwarded-header
before the user generated content.

The forwarded header MUST contain two lines: 
The first line contains the text
`---------- Forwarded message ----------`
(10 minus, space, text `Forwarded message`, space, 10 minus). 
The second line starts with `From: ` followed by the original sender
which SHOULD be anonymized or just a placeholder.

    From: sender@domain
    To: rcpt@domain
    Chat-Version: 1.0
    Content-Type: text/plain
    Subject: Chat: Forwarded message

    ---------- Forwarded message ----------
    From: Messenger

    Hello world!

Incoming forwarded messages are detected by the header.
The messenger SHOULD mark these messages in a way that
it becomes obvious that the message is not created by the sender.
Note that most messengers do not show the original sender of forwarded messages
but MUAs typically expose the sender in the UI.


# Groups

Groups are chats with usually more than one recipient,
each defined by an email-address.
The sender plus the recipients are the group members.
All group members form the member list.

To allow different groups with the same members,
groups are identified by a group-id.
The group-id MUST be created only from the characters
`0`-`9`, `A`-`Z`, `a`-`z` `_` and `-`,
MUST have a length of at least 11 characters
and no more than 32 characters.

Groups MUST have a group-name.
The group-name is any non-zero-length UTF-8 string.

Groups MAY have a group-image.


## Outgoing groups messages

All group members MUST be added to the `From`/`To` headers.
The group-id MUST be written to the `Chat-Group-ID` header.
The group-name MUST be written to `Chat-Group-Name` header
(the forced presence of this header makes it easier
to join a group chat on a second device any time).

The `Subject` header of outgoing group messages
SHOULD be set to the group-name.

To identify the group-id on replies from normal MUAs,
the group-id MUST also be added to the message-id of outgoing messages.
The message-id MUST have the format `Gr.<group-id>.<unique data>`.

    From: member1@domain
    To: member2@domain, member3@domain
    Chat-Version: 1.0
    Chat-Group-ID: 12345uvwxyZ
    Chat-Group-Name: My Group
    Message-ID: Gr.12345uvwxyZ.0001@domain
    Subject: Chat: My Group: Hello group ...

    Hello group - this group contains three members

Messengers adding the member list in the form `Name <email-address>`
MUST take care only to distribute the names authorized by the contacts themselves.
Otherwise, names as _Daddy_ or _Honey_ may be distributed
(this issue is also true for normal MUAs, however,
for more contact- and chat-centralized apps
such situations happen more frequently).


## Incoming group messages

The messenger MUST search incoming messages for the group-id
in the following headers: `Chat-Group-ID`,
`Message-ID`, `In-Reply-To` and `References` (in this order).

If the messenger finds a valid and existent group-id,
the message SHOULD be assigned to the given group.
If the messenger finds a valid but not existent group-id,
the messenger MAY create a new group.
If no group-id is found,
the message MAY be assigned
to a normal single-user chat with the email-address given in `From`.


## Add and remove members

Messenger clients MUST init the member list
from the `From`/`To` headers on the first group message.

When a member is added later,
a `Chat-Group-Member-Added` action header must be sent
with the value set to the email-address of the added member.
When receiving a `Chat-Group-Member-Added` header, however,
_all missing_ members  the `From`/`To` headers has to be added.
This is to mitigate problems when receiving messages
in different orders, esp. on creating new groups.

To remove a member, a `Chat-Group-Member-Removed` header must be sent
with the value set to the email-address of the member to remove.
When receiving a `Chat-Group-Member-Removed` header,
only exactly the given member has to be removed from the member list.

Messenger clients MUST NOT construct the member list
on other group messages
(this is to avoid accidentally altered To-lists in normal MUAs;
the user does not expect adding a user to a _message_
will also add him to the _group_ "forever").

The messenger SHOULD send an explicit mail for each added or removed member.
The body of the message SHOULD contain
a localized description about what happened
and the message SHOULD appear as a message or action from the sender.

    From: member1@domain
    To: member2@domain, member3@domain, member4@domain
    Chat-Version: 1.0
    Chat-Group-ID: 12345uvwxyZ
    Chat-Group-Name: My Group
    Chat-Group-Member-Added: member4@domain
    Message-ID: Gr.12345uvwxyZ.0002@domain
    Subject: Chat: My Group: Hello, ...

    Hello, I've added member4@domain to our group.  Now we have 4 members.

To remove a member:

    From: member1@domain
    To: member2@domain, member3@domain
    Chat-Version: 1.0
    Chat-Group-ID: 12345uvwxyZ
    Chat-Group-Name: My Group
    Chat-Group-Member-Removed: member4@domain
    Message-ID: Gr.12345uvwxyZ.0003@domain
    Subject: Chat: My Group: Hello, ...

    Hello, I've removed member4@domain from our group.  Now we have 3 members.


## Change group name

To change the group-name,
the messenger MUST send the action header `Chat-Group-Name-Changed`
with the value set to the old group name to all group members.
The new group name goes to the header `Chat-Group-Name`.

The messenger SHOULD send an explicit mail for each name change.
The body of the message SHOULD contain
a localized description about what happened
and the message SHOULD appear as a message or action from the sender.

    From: member1@domain
    To: member2@domain, member3@domain
    Chat-Version: 1.0
    Chat-Group-ID: 12345uvwxyZ
    Chat-Group-Name: Our Group
    Chat-Group-Name-Changed: My Group
    Message-ID: Gr.12345uvwxyZ.0004@domain
    Subject: Chat: Our Group: Hello, ...

    Hello, I've changed the group name from "My Group" to "Our Group".


## Set group image

A group MAY have a group-image.
To change or set the group-image,
the messenger MUST attach an image file to a message
and MUST add the header `Chat-Group-Avatar`
with the value set to the image name.

To remove the group-image,
the messenger MUST add the header `Chat-Group-Avatar: 0`.

The messenger SHOULD send an explicit mail for each group image change.
The body of the message SHOULD contain
a localized description about what happened
and the message SHOULD appear as a message or action from the sender.


    From: member1@domain
    To: member2@domain, member3@domain
    Chat-Version: 1.0
    Chat-Group-ID: 12345uvwxyZ
    Chat-Group-Name: Our Group
    Chat-Group-Avatar: image.jpg
    Message-ID: Gr.12345uvwxyZ.0005@domain
    Subject: Chat: Our Group: Hello, ...
    Content-Type: multipart/mixed; boundary="==break=="

    --==break==
    Content-Type: text/plain

    Hello, I've changed the group image.
    --==break==
    Content-Type: image/jpeg
    Content-Disposition: attachment; filename="image.jpg"

    /9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAYEBQYFBAYGBQYHBw ...
    --==break==--

The image format SHOULD be image/jpeg or image/png.
To save data, it is RECOMMENDED
to add a `Chat-Group-Avatar` only on image changes.


# Request editing

To request recipients to edit the text of an already sent message,
the messenger MUST set the header `Chat-Edit`
with value set to the message-id of the message to edit
and the body to the new message text.

The body MAY be prefixed by a quote
and the emoji "✏️" directly before the new text.
Both MUST be skipped by the recipient.

Receiving messengers MUST look up the message-id from `Chat-Edit`,
replace the text and MAY indicate the edit in the UI.

The new message text MUST NOT be empty.
It is not possible to edit images or other attachments, including HTML messages.
However, they can be deleted for everyone.

Example:

    From: sender@domain
    To: rcpt@domain
    Chat-Version: 1.0
    Message-ID: 00001@domain
    Content-Type: text/plain

    Hello wordl!

The typo from the message above can be fixed by the following message:

    From: sender@domain
    To: rcpt@domain
    Chat-Version: 1.0
    Chat-Edit: 00001@domain
    In-Reply-To: 00001@domain
    Message-ID: 00002@domain
    Content-Type: text/plain

    On 2025-03-27, sender@domain wrote:
    > Hello wordl!

    ✏️Hello world!


# Request deletion

To request recipient to delete a message,
the messenger MUST set the header `Chat-Delete`
with the value set to the message-id of the message to delete.

Receiving messengers MUST look up the message-id, delete the corresponding message
and MAY indicating the deletion in the UI.

The sender MUST set the body to any, non-empty text.
The receiver MUST ignore the body.

Example:

    From: sender@domain
    To: rcpt@domain
    Chat-Version: 1.0
    Message-ID: 00003@domain
    Content-Type: text/plain

    reminder for my pin: 1234

The message above can be requested for deletion by the following message:

    From: sender@domain
    To: rcpt@domain
    Chat-Version: 1.0
    Chat-Delete: 00003@domain
    Message-ID: 00004@domain
    Content-Type: text/plain

    foo


# Set profile image

A user MAY have a profile-image that MAY be distributed to their contacts.
To change or set the profile-image,
the messenger MUST add the header `Chat-User-Avatar: base64:IMAGEDATA`.
To bypass limits of headers, it is recommended not to use the outer header
and to limit the size to 20k.

To remove the profile-image,
the messenger MUST add the header `Chat-User-Avatar: 0`.

To distribute the image,
the messenger MAY send the profile image
together with the next mail to a given contact
(to do this only once,
the messenger has to keep a `user_avatar_update_state` somewhere).
Alternatively, the messenger MAY send an explicit mail
for each profile-image change to all contacts using a compatible messenger.
The messenger SHOULD NOT send an explicit mail to normal MUAs.

    From: sender@domain
    To: rcpt@domain
    Chat-Version: 1.0
    Subject: Chat: Hello, ...
    Content-Type: multipart/mixed; boundary="==break=="

    --==break==
    Content-Type: text/plain
    Chat-User-Avatar: base64:AKCgkJi3j4l5kjoldfUAKCgkJi3j4lldfHjgWICwgIEBQY ...

    Hello, I've changed my profile image.
    --==break==--

The image format SHOULD be image/jpeg or image/png.
Note that `Chat-User-Avatar` may appear together with all other headers,
eg. there may be a `Chat-User-Avatar` and a `Chat-Group-Avatar` header
in the same message.
To save data, it is RECOMMENDED to add a `Chat-User-Avatar` header
only on image changes.

In older specs, the profile-image was sent as an attachment
and `Chat-User-Avatar:` specified its name.
However, it turned out that these attachments are kind of unexpected to users,
therefore the profile-image go to the header now.


# Locations

Locations can be attached to messages using
[standard kml-files](https://www.opengeospatial.org/standards/kml/)
with well-known names.


## User locations

To send the location of the sender,
the app can attach a file with the name `location.kml`.
The file can contain one or more locations.
Apps that support location streaming will typically collect some location events
and send them together in one file.
As each location has an independent timestamp,
the apps can show the location as a track.

Note that the `addr` attribute inside the  `location.kml` file
MUST match the users email-address.
Otherwise, the file is discarded silently;
this is to protect against getting wrong locations,
eg. forwarded from a normal MUA.

    <?xml version="1.0" encoding="UTF-8"?>
    <kml xmlns="http://www.opengis.net/kml/2.2">
      <Document addr="foo@domain">
        <Placemark>
          <Timestamp><when>2020-01-11T20:40:19Z</when></Timestamp>
          <Point><coordinates accuracy="1.2">1.234,5.678</coordinates></Point>
        </Placemark>
        <Placemark>
          <Timestamp><when>2020-01-11T20:40:25Z</when></Timestamp>
          <Point><coordinates accuracy="5.4">7.654,3.21</coordinates></Point>
        </Placemark>
      </Document>
    </kml>


## Points of interest

To send an "Point of interest", a POI,
use a normal message and attach a file with the name  `message.kml`.
In contrast to user locations, this file should contain only one location
and an address-attribute is not needed -
as the location belongs to the message content,
it is fine if the location is detected on forwarding etc.

    <?xml version="1.0" encoding="UTF-8"?>
    <kml xmlns="http://www.opengis.net/kml/2.2">
      <Document>
        <Placemark>
          <Timestamp><when>2020-01-01T20:40:19Z</when></Timestamp>
          <Point><coordinates accuracy="1.2">1.234,5.678</coordinates></Point>
        </Placemark>
      </Document>
    </kml>


# Stickers

Stickers are send as normal images
with the additional header `Chat-Content: sticker`.

It is discouraged to send stickers together with user generated text,
however, stickers can be used as a reply to a message
and also the footer should be set as usual.

    From: alice@example.org
    To: bob@example.com
    Chat-Version: 1.0
    Chat-Content: sticker
    Message-ID: Mr.12345uvwxyZ.0005@example.org
    Subject: Message from Alice
    Content-Type: multipart/mixed; boundary="==break=="

    --==break==
    Content-Type: text/plain

    -- 
    Hi there! I am using this new messenger!
    --==break==
    Content-Type: image/png
    Content-Disposition: attachment; filename="sticker.png"

    R0lGODlhpAGkAfe9AP+zd2eQkZhrI//z9v++PMb///+scrdDT3BtbtrZ2f/LQSsREcdIVf9 ...
    --==break==--

Typical sticker formats are `image/png`, `image/gif` and `image/webp`.
Animated stickers are supported
by just using an image format that supports animation.


# Voice messages

Messengers SHOULD add a `Chat-Voice-message: 1` header
if an attached audio file is a voice message.

Messengers MAY add a `Chat-Duration` header
to specify the duration of attached audio or video files.
The value MUST be the duration in milliseconds.
This allows the receiver to show the time without knowing the file format.

    In-Reply-To: Gr.12345uvwxyZ.0005@domain
    Chat-Voice-Message: 1
    Chat-Duration: 10000


# Reactions

Messengers MAY implement [RFC 9078](https://tools.ietf.org/html/rfc9078) reactions.
Received reaction should be interpreted as overwriting all previous reactions
received from the same contact.
This semantics is compatible to [XEP-0444](https://xmpp.org/extensions/xep-0444.html).
As an extension to RFC 9078, it is allowed to send empty reaction message,
in which case all previously sent reactions are retracted.


# Attaching a contact to a message

Messengers MAY allow the user to attach a contact to a message
in order to share it with the chat partner.
The contact MUST be sent as a [vCard](https://datatracker.ietf.org/doc/html/rfc6350).

The vCard MUST contain `EMAIL`,
`FN` (display name),
and `VERSION` (which version of the vCard standard you're using).
If available, it SHOULD contain
`REV` (current timestamp),
`PHOTO` (avatar), and
`KEY` (OpenPGP public key,
in binary format,
encoded with vanilla base64;
note that this is different from the OpenPGP 'ASCII Armor' format).

Example vCard:

```
BEGIN:VCARD
VERSION:4.0
EMAIL:alice@example.org
FN:Alice Wonderland
KEY:data:application/pgp-keys;base64,[Base64-data]
PHOTO:data:image/jpeg;base64,[image in Base64]
REV:20240418T184242Z
END:VCARD
```

It is fine if messengers do include a full vCard parser
and e.g. simply search for the line starting with `EMAIL`
in order to get the email address.


# Verifications

Keys obtained using [SecureJoin](https://securejoin.readthedocs.io) protocol
and corresponding contacts
are considered "verified".

As an extension to `Autocrypt-Gossip` header,
chatmail clients can add `_verified=1` attribute
(underscore marks the attribute as non-critical)
to indicate that they have the gossiped key
and the corresponding contact marked as verified.

When receiving such `Autocrypt-Gossip` header
in a message signed by a verified key,
chatmail clients mark the gossiped key
as indirectly verified.


# Transitioning to a new e-mail address (AEAP)

When receiving a message:
- If the key exists, but belongs to another address
- AND there is a `Chat-Version` header
- AND the message is signed correctly
- AND the From address is (also) in the encrypted (and therefore signed) headers 
- AND the message timestamp is newer than the contact's `lastseen`
  (to prevent changing the address back when messages arrive out of order)
  (this condition is not that important
  since we will have eventual consistency even without it):

  Replace the contact in _all_ groups,
  possibly deduplicate the members list,
  and add a system message to all of these chats.


# Miscellaneous

Messengers SHOULD use the header `In-Reply-To` as usual.

Messengers MAY send and receive Message Disposition Notifications
(MDNs, [RFC 8098](https://tools.ietf.org/html/rfc8098),
[RFC 3503](https://tools.ietf.org/html/rfc3503))
using the `Chat-Disposition-Notification-To` header
instead of the `Disposition-Notification-To`
(which unfortunately forces many other MUAs
to send weird mails not following any standard).


## Sync messages

If some action is required by a message header,
the action should only be performed if the _effective date_ is newer
than the date the last action was performed.

We define the effective date of a message
as the sending time of the message as indicated by its Date header,
or the time of first receipt if that date is in the future or unavailable.

Copyright © Chatmail contributors.
