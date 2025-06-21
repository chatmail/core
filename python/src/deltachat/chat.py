"""Chat and Location related API."""

import calendar
import json
import mimetypes
import os
from datetime import datetime, timezone
from typing import Optional

from . import const
from .capi import ffi, lib
from .cutil import (
    as_dc_charpointer,
    from_dc_charpointer,
    from_optional_dc_charpointer,
    iter_array,
)
from .message import Message


class Chat:
    """Chat object which manages members and through which you can send and retrieve messages.

    You obtain instances of it through :class:`deltachat.account.Account`.
    """

    def __init__(self, account, id: int) -> None:
        from .account import Account

        assert isinstance(account, Account), repr(account)
        self.account = account
        self.id = id

    def __eq__(self, other) -> bool:
        if other is None:
            return False
        return self.id == getattr(other, "id", None) and self.account._dc_context == other.account._dc_context

    def __ne__(self, other) -> bool:
        return not self == other

    def __repr__(self) -> str:
        return f"<Chat id={self.id} name={self.get_name()}>"

    @property
    def _dc_chat(self):
        return ffi.gc(lib.dc_get_chat(self.account._dc_context, self.id), lib.dc_chat_unref)

    def delete(self) -> None:
        """Delete this chat and all its messages.

        Note:

        - does not delete messages on server
        - the chat or contact is not blocked, new message will arrive
        """
        lib.dc_delete_chat(self.account._dc_context, self.id)

    def block(self) -> None:
        """Block this chat."""
        lib.dc_block_chat(self.account._dc_context, self.id)

    def accept(self) -> None:
        """Accept this contact request chat."""
        lib.dc_accept_chat(self.account._dc_context, self.id)

    # ------  chat status/metadata API ------------------------------

    def is_group(self) -> bool:
        """Return True if this chat is a group chat.

        :returns: True if chat is a group-chat, False otherwise
        """
        return lib.dc_chat_get_type(self._dc_chat) == const.DC_CHAT_TYPE_GROUP

    def is_single(self) -> bool:
        """Return True if this chat is a single/direct chat, False otherwise."""
        return lib.dc_chat_get_type(self._dc_chat) == const.DC_CHAT_TYPE_SINGLE

    def is_mailinglist(self) -> bool:
        """Return True if this chat is a mailing list, False otherwise."""
        return lib.dc_chat_get_type(self._dc_chat) == const.DC_CHAT_TYPE_MAILINGLIST

    def is_broadcast(self) -> bool:
        """Return True if this chat is a broadcast list, False otherwise."""
        return lib.dc_chat_get_type(self._dc_chat) == const.DC_CHAT_TYPE_BROADCAST

    def is_multiuser(self) -> bool:
        """Return True if this chat is a multi-user chat (group, mailing list or broadcast), False otherwise."""
        return lib.dc_chat_get_type(self._dc_chat) in (
            const.DC_CHAT_TYPE_GROUP,
            const.DC_CHAT_TYPE_MAILINGLIST,
            const.DC_CHAT_TYPE_BROADCAST,
        )

    def is_self_talk(self) -> bool:
        """Return True if this chat is the self-chat (a.k.a. "Saved Messages"), False otherwise."""
        return bool(lib.dc_chat_is_self_talk(self._dc_chat))

    def is_device_talk(self) -> bool:
        """Returns True if this chat is the "Device Messages" chat, False otherwise."""
        return bool(lib.dc_chat_is_device_talk(self._dc_chat))

    def is_muted(self) -> bool:
        """return true if this chat is muted.

        :returns: True if chat is muted, False otherwise.
        """
        return bool(lib.dc_chat_is_muted(self._dc_chat))

    def is_pinned(self) -> bool:
        """Return True if this chat is pinned, False otherwise."""
        return lib.dc_chat_get_visibility(self._dc_chat) == const.DC_CHAT_VISIBILITY_PINNED

    def is_archived(self) -> bool:
        """Return True if this chat is archived, False otherwise.
        :returns: True if archived, False otherwise.
        """
        return lib.dc_chat_get_visibility(self._dc_chat) == const.DC_CHAT_VISIBILITY_ARCHIVED

    def is_contact_request(self) -> bool:
        """return True if this chat is a contact request chat.

        :returns: True if chat is a contact request chat, False otherwise.
        """
        return bool(lib.dc_chat_is_contact_request(self._dc_chat))

    def is_promoted(self) -> bool:
        """return True if this chat is promoted, i.e.
        the member contacts are aware of their membership,
        have been sent messages.

        :returns: True if chat is promoted, False otherwise.
        """
        return not lib.dc_chat_is_unpromoted(self._dc_chat)

    def can_send(self) -> bool:
        """Check if messages can be sent to a give chat.
        This is not true eg. for the contact requests or for the device-talk.

        :returns: True if the chat is writable, False otherwise
        """
        return bool(lib.dc_chat_can_send(self._dc_chat))

    def is_protected(self) -> bool:
        """return True if this chat is a protected chat.

        :returns: True if chat is protected, False otherwise.
        """
        return bool(lib.dc_chat_is_protected(self._dc_chat))

    def get_name(self) -> Optional[str]:
        """return name of this chat.

        :returns: unicode name
        """
        return from_dc_charpointer(lib.dc_chat_get_name(self._dc_chat))

    def set_name(self, name: str) -> bool:
        """set name of this chat.

        :param name: as a unicode string.
        :returns: True on success, False otherwise
        """
        name_c = as_dc_charpointer(name)
        return bool(lib.dc_set_chat_name(self.account._dc_context, self.id, name_c))

    def get_color(self):
        """return the color of the chat.
        :returns: color as 0x00rrggbb.
        """
        return lib.dc_chat_get_color(self._dc_chat)

    def get_summary(self):
        """return dictionary with summary information."""
        dc_res = lib.dc_chat_get_info_json(self.account._dc_context, self.id)
        s = from_dc_charpointer(dc_res)
        return json.loads(s)

    def mute(self, duration: Optional[int] = None) -> None:
        """mutes the chat.

        :param duration: Number of seconds to mute the chat for. None to mute until unmuted again.
        :returns: None
        """
        mute_duration = -1 if duration is None else duration
        ret = lib.dc_set_chat_mute_duration(self.account._dc_context, self.id, mute_duration)
        if not bool(ret):
            raise ValueError("Call to dc_set_chat_mute_duration failed")

    def unmute(self) -> None:
        """unmutes the chat.

        :returns: None
        """
        ret = lib.dc_set_chat_mute_duration(self.account._dc_context, self.id, 0)
        if not bool(ret):
            raise ValueError("Failed to unmute chat")

    def pin(self) -> None:
        """Pin the chat."""
        lib.dc_set_chat_visibility(self.account._dc_context, self.id, const.DC_CHAT_VISIBILITY_PINNED)

    def unpin(self) -> None:
        """Unpin the chat."""
        if self.is_pinned():
            lib.dc_set_chat_visibility(self.account._dc_context, self.id, const.DC_CHAT_VISIBILITY_NORMAL)

    def archive(self) -> None:
        """Archive the chat."""
        lib.dc_set_chat_visibility(self.account._dc_context, self.id, const.DC_CHAT_VISIBILITY_ARCHIVED)

    def unarchive(self) -> None:
        """Unarchive the chat."""
        if self.is_archived():
            lib.dc_set_chat_visibility(self.account._dc_context, self.id, const.DC_CHAT_VISIBILITY_NORMAL)

    def get_mute_duration(self) -> int:
        """Returns the number of seconds until the mute of this chat is lifted.

        :param duration:
        :returns: Returns the number of seconds the chat is still muted for. (0 for not muted, -1 forever muted)
        """
        return lib.dc_chat_get_remaining_mute_duration(self._dc_chat)

    def get_ephemeral_timer(self) -> int:
        """get ephemeral timer.

        :returns: ephemeral timer value in seconds
        """
        return lib.dc_get_chat_ephemeral_timer(self.account._dc_context, self.id)

    def set_ephemeral_timer(self, timer: int) -> bool:
        """set ephemeral timer.

        :param: timer value in seconds

        :returns: True on success, False otherwise
        """
        return bool(lib.dc_set_chat_ephemeral_timer(self.account._dc_context, self.id, timer))

    def get_type(self) -> int:
        """(deprecated) return type of this chat.

        :returns: one of const.DC_CHAT_TYPE_*
        """
        return lib.dc_chat_get_type(self._dc_chat)

    def get_encryption_info(self) -> Optional[str]:
        """Return encryption info for this chat.

        :returns: a string with encryption preferences of all chat members
        """
        res = lib.dc_get_chat_encrinfo(self.account._dc_context, self.id)
        return from_dc_charpointer(res)

    def get_join_qr(self) -> Optional[str]:
        """get/create Join-Group QR Code as ascii-string.

        this string needs to be transferred to another DC account
        in a second channel (typically used by mobiles with QRcode-show + scan UX)
        where account.join_with_qrcode(qr) needs to be called.
        """
        res = lib.dc_get_securejoin_qr(self.account._dc_context, self.id)
        return from_dc_charpointer(res)

    # ------  chat messaging API ------------------------------

    def send_msg(self, msg: Message) -> Message:
        """send a message by using a ready Message object.

        :param msg: a :class:`deltachat.message.Message` instance
           previously returned by
           e.g. :meth:`deltachat.message.Message.new_empty`.
        :raises ValueError: if message can not be sent.

        :returns: a :class:`deltachat.message.Message` instance as
           sent out.  This is the same object as was passed in, which
           has been modified with the new state of the core.
        """
        if msg.is_out_preparing():
            assert msg.id != 0
            # get a fresh copy of dc_msg, the core needs it
            maybe_msg = Message.from_db(self.account, msg.id)
            if maybe_msg is not None:
                msg = maybe_msg
            else:
                raise ValueError("message does not exist")

        sent_id = lib.dc_send_msg(self.account._dc_context, self.id, msg._dc_msg)
        if sent_id == 0:
            raise ValueError("message could not be sent")
        # modify message in place to avoid bad state for the caller
        sent_msg = Message.from_db(self.account, sent_id)
        if sent_msg is None:
            raise ValueError("cannot load just sent message from the database")
        msg._dc_msg = sent_msg._dc_msg
        return msg

    def send_text(self, text):
        """send a text message and return the resulting Message instance.

        :param msg: unicode text
        :raises ValueError: if message can not be send/chat does not exist.
        :returns: the resulting :class:`deltachat.message.Message` instance
        """
        msg = as_dc_charpointer(text)
        msg_id = lib.dc_send_text_msg(self.account._dc_context, self.id, msg)
        if msg_id == 0:
            raise ValueError("The message could not be sent. Does the chat exist?")
        return Message.from_db(self.account, msg_id)

    def send_file(self, path, mime_type="application/octet-stream"):
        """send a file and return the resulting Message instance.

        :param path: path to the file.
        :param mime_type: the mime-type of this file, defaults to application/octet-stream.
        :raises ValueError: if message can not be send/chat does not exist.
        :returns: the resulting :class:`deltachat.message.Message` instance
        """
        msg = Message.new_empty(self.account, view_type="file")
        msg.set_file(path, mime_type)
        sent_id = lib.dc_send_msg(self.account._dc_context, self.id, msg._dc_msg)
        if sent_id == 0:
            raise ValueError("message could not be sent")
        return Message.from_db(self.account, sent_id)

    def send_image(self, path):
        """send an image message and return the resulting Message instance.

        :param path: path to an image file.
        :raises ValueError: if message can not be send/chat does not exist.
        :returns: the resulting :class:`deltachat.message.Message` instance
        """
        mime_type = mimetypes.guess_type(path)[0]
        msg = Message.new_empty(self.account, view_type="image")
        msg.set_file(path, mime_type)
        sent_id = lib.dc_send_msg(self.account._dc_context, self.id, msg._dc_msg)
        if sent_id == 0:
            raise ValueError("message could not be sent")
        return Message.from_db(self.account, sent_id)

    def send_prepared(self, message):
        """send a previously prepared message.

        :param message: a :class:`Message` instance previously returned by
                        :meth:`prepare_file`.
        :raises ValueError: if message can not be sent.
        :returns: a :class:`deltachat.message.Message` instance as sent out.
        """
        assert message.id != 0 and message.is_out_preparing()
        # get a fresh copy of dc_msg, the core needs it
        msg = Message.from_db(self.account, message.id)

        # pass 0 as chat-id because core-docs say it's ok when out-preparing
        sent_id = lib.dc_send_msg(self.account._dc_context, 0, msg._dc_msg)
        if sent_id == 0:
            raise ValueError("message could not be sent")
        assert sent_id == msg.id
        # modify message in place to avoid bad state for the caller
        msg._dc_msg = Message.from_db(self.account, sent_id)._dc_msg

    def set_draft(self, message):
        """set message as draft.

        :param message: a :class:`Message` instance
        :returns: None
        """
        if message is None:
            lib.dc_set_draft(self.account._dc_context, self.id, ffi.NULL)
        else:
            lib.dc_set_draft(self.account._dc_context, self.id, message._dc_msg)

    def get_draft(self):
        """get draft message for this chat.

        :param message: a :class:`Message` instance
        :returns: Message object or None (if no draft available)
        """
        x = lib.dc_get_draft(self.account._dc_context, self.id)
        if x == ffi.NULL:
            return None
        dc_msg = ffi.gc(x, lib.dc_msg_unref)
        return Message(self.account, dc_msg)

    def get_messages(self):
        """return list of messages in this chat.

        :returns: list of :class:`deltachat.message.Message` objects for this chat.
        """
        dc_array = ffi.gc(
            lib.dc_get_chat_msgs(self.account._dc_context, self.id, 0, 0),
            lib.dc_array_unref,
        )
        return list(iter_array(dc_array, lambda x: Message.from_db(self.account, x)))

    def count_fresh_messages(self):
        """return number of fresh messages in this chat.

        :returns: number of fresh messages
        """
        return lib.dc_get_fresh_msg_cnt(self.account._dc_context, self.id)

    def mark_noticed(self):
        """mark all messages in this chat as noticed.

        Noticed messages are no longer fresh.
        """
        return lib.dc_marknoticed_chat(self.account._dc_context, self.id)

    # ------  group management API ------------------------------

    def add_contact(self, obj):
        """add a contact to this chat.

        :params obj: Contact, Account or e-mail address.
        :raises ValueError: if contact could not be added
        :returns: None
        """
        from .contact import Contact

        if isinstance(obj, Contact):
            contact = obj
        else:
            contact = self.account.create_contact(obj)

        ret = lib.dc_add_contact_to_chat(self.account._dc_context, self.id, contact.id)
        if ret != 1:
            raise ValueError(f"could not add contact {contact!r} to chat")
        return contact

    def remove_contact(self, obj):
        """remove a contact from this chat.

        :params obj: Contact, Account or e-mail address.
        :raises ValueError: if contact could not be removed
        :returns: None
        """
        contact = self.account.get_contact(obj)
        ret = lib.dc_remove_contact_from_chat(self.account._dc_context, self.id, contact.id)
        if ret != 1:
            raise ValueError(f"could not remove contact {contact!r} from chat")

    def get_contacts(self):
        """get all contacts for this chat.
        :returns: list of :class:`deltachat.contact.Contact` objects for this chat.
        """
        from .contact import Contact

        dc_array = ffi.gc(
            lib.dc_get_chat_contacts(self.account._dc_context, self.id),
            lib.dc_array_unref,
        )
        return list(iter_array(dc_array, lambda id: Contact(self.account, id)))

    def num_contacts(self):
        """return number of contacts in this chat."""
        dc_array = ffi.gc(
            lib.dc_get_chat_contacts(self.account._dc_context, self.id),
            lib.dc_array_unref,
        )
        return lib.dc_array_get_cnt(dc_array)

    def set_profile_image(self, img_path):
        """Set group profile image.

        If the group is already promoted (any message was sent to the group),
        all group members are informed by a special status message that is sent
        automatically by this function.
        :params img_path: path to image object
        :raises ValueError: if profile image could not be set
        :returns: None
        """
        assert os.path.exists(img_path), img_path
        p = as_dc_charpointer(img_path)
        res = lib.dc_set_chat_profile_image(self.account._dc_context, self.id, p)
        if res != 1:
            raise ValueError(f"Setting Profile Image {p!r} failed")

    def remove_profile_image(self):
        """remove group profile image.

        If the group is already promoted (any message was sent to the group),
        all group members are informed by a special status message that is sent
        automatically by this function.
        :raises ValueError: if profile image could not be reset
        :returns: None
        """
        res = lib.dc_set_chat_profile_image(self.account._dc_context, self.id, ffi.NULL)
        if res != 1:
            raise ValueError("Removing Profile Image failed")

    def get_profile_image(self):
        """Get group profile image.

        For groups, this is the image set by any group member using
        set_chat_profile_image(). For normal chats, this is the image
        set by each remote user on their own using dc_set_config(context,
        "selfavatar", image).
        :returns: path to profile image, None if no profile image exists.
        """
        dc_res = lib.dc_chat_get_profile_image(self._dc_chat)
        if dc_res == ffi.NULL:
            return None
        return from_dc_charpointer(dc_res)

    # ------  location streaming API ------------------------------

    def is_sending_locations(self) -> bool:
        """return True if this chat has location-sending enabled currently.
        :returns: True if location sending is enabled.
        """
        return bool(lib.dc_is_sending_locations_to_chat(self.account._dc_context, self.id))

    def enable_sending_locations(self, seconds) -> None:
        """enable sending locations for this chat.

        all subsequent messages will carry a location with them.
        """
        lib.dc_send_locations_to_chat(self.account._dc_context, self.id, seconds)

    def get_locations(self, contact=None, timestamp_from=None, timestamp_to=None):
        """return list of locations for the given contact in the given timespan.

        :param contact: the contact for which locations shall be returned.
        :param timespan_from: a datetime object or None (indicating "since beginning")
        :param timespan_to: a datetime object or None (indicating up till now)
        :returns: list of :class:`deltachat.chat.Location` objects.
        """
        time_from = 0 if timestamp_from is None else calendar.timegm(timestamp_from.utctimetuple())
        time_to = 0 if timestamp_to is None else calendar.timegm(timestamp_to.utctimetuple())

        contact_id = 0 if contact is None else contact.id

        dc_array = lib.dc_get_locations(self.account._dc_context, self.id, contact_id, time_from, time_to)
        return [
            Location(
                latitude=lib.dc_array_get_latitude(dc_array, i),
                longitude=lib.dc_array_get_longitude(dc_array, i),
                accuracy=lib.dc_array_get_accuracy(dc_array, i),
                timestamp=datetime.fromtimestamp(lib.dc_array_get_timestamp(dc_array, i), timezone.utc),
                marker=from_optional_dc_charpointer(lib.dc_array_get_marker(dc_array, i)),
            )
            for i in range(lib.dc_array_get_cnt(dc_array))
        ]


class Location:
    def __init__(self, latitude, longitude, accuracy, timestamp, marker) -> None:
        assert isinstance(timestamp, datetime)
        self.latitude = latitude
        self.longitude = longitude
        self.accuracy = accuracy
        self.timestamp = timestamp
        self.marker = marker

    def __eq__(self, other) -> bool:
        return self.__dict__ == other.__dict__
