import io
import os
import re
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from queue import Empty, Queue

from . import const
from .account import Account
from .capi import ffi, lib
from .cutil import from_optional_dc_charpointer
from .hookspec import account_hookimpl


def get_dc_event_name(integer, _DC_EVENTNAME_MAP={}):
    if not _DC_EVENTNAME_MAP:
        for name in dir(const):
            if name.startswith("DC_EVENT_"):
                _DC_EVENTNAME_MAP[getattr(const, name)] = name
    return _DC_EVENTNAME_MAP[integer]


class FFIEvent:
    def __init__(self, name: str, data1, data2) -> None:
        self.name = name
        self.data1 = data1
        self.data2 = data2

    def __str__(self) -> str:
        if self.name == "DC_EVENT_INFO":
            return f"INFO {self.data2}"
        if self.name == "DC_EVENT_WARNING":
            return f"WARNING {self.data2}"
        if self.name == "DC_EVENT_ERROR":
            return f"ERROR {self.data2}"
        return "{name} data1={data1} data2={data2}".format(**self.__dict__)


class FFIEventLogger:
    """If you register an instance of this logger with an Account
    you'll get all ffi-events printed.
    """

    # to prevent garbled logging
    _loglock = threading.RLock()

    def __init__(self, account, logid=None, init_time=None) -> None:
        self.account = account
        self.logid = logid or self.account.get_config("displayname")
        if init_time is None:
            init_time = time.time()
        self.init_time = init_time

    @account_hookimpl
    def ac_process_ffi_event(self, ffi_event: FFIEvent) -> None:
        self.account.log(str(ffi_event))

    @account_hookimpl
    def ac_log_line(self, message):
        t = threading.current_thread()
        tname = getattr(t, "name", t)
        if tname == "MainThread":
            tname = "MAIN"
        elapsed = time.time() - self.init_time
        locname = tname
        if self.logid:
            locname += "-" + self.logid
        s = f"{elapsed:2.2f} [{locname}] {message}"

        if os.name == "posix":
            WARN = "\033[93m"
            ERROR = "\033[91m"
            ENDC = "\033[0m"
            if message.startswith("DC_EVENT_WARNING"):
                s = WARN + s + ENDC
            if message.startswith("DC_EVENT_ERROR"):
                s = ERROR + s + ENDC
        with self._loglock:
            print(s, flush=True)


class FFIEventTracker:
    account: Account
    _event_queue: Queue

    def __init__(self, account: Account, timeout=None) -> None:
        self.account = account
        self._timeout = timeout
        self._event_queue = Queue()

    @account_hookimpl
    def ac_process_ffi_event(self, ffi_event: FFIEvent):
        self._event_queue.put(ffi_event)

    def set_timeout(self, timeout):
        self._timeout = timeout

    def consume_events(self, check_error=True):
        while not self._event_queue.empty():
            self.get(check_error=check_error)

    def get(self, timeout=None, check_error=True):
        timeout = timeout if timeout is not None else self._timeout
        ev = self._event_queue.get(timeout=timeout)
        if check_error and ev.name == "DC_EVENT_ERROR":
            raise ValueError(f"unexpected event: {ev}")
        return ev

    def iter_events(self, timeout=None, check_error=True):
        while True:
            yield self.get(timeout=timeout, check_error=check_error)

    def get_matching(self, event_name_regex, check_error=True, timeout=None):
        rex = re.compile(f"^(?:{event_name_regex})$")
        for ev in self.iter_events(timeout=timeout, check_error=check_error):
            if rex.match(ev.name):
                return ev

    def get_info_contains(self, regex: str) -> FFIEvent:
        rex = re.compile(regex)
        while True:
            ev = self.get_matching("DC_EVENT_INFO")
            if rex.search(ev.data2):
                return ev

    def get_info_regex_groups(self, regex, check_error=True):
        rex = re.compile(regex)
        while True:
            ev = self.get_matching("DC_EVENT_INFO", check_error=check_error)
            m = rex.match(ev.data2)
            if m is not None:
                return m.groups()

    def wait_for_connectivity(self, connectivity):
        """Wait for the specified connectivity.
        This only works reliably if the connectivity doesn't change
        again too quickly, otherwise we might miss it.
        """
        while True:
            if self.account.get_connectivity() == connectivity:
                return
            self.get_matching("DC_EVENT_CONNECTIVITY_CHANGED")

    def wait_for_connectivity_change(self, previous, expected_next):
        """Wait until the connectivity changes to `expected_next`.
        Fails the test if it changes to something else.
        """
        while True:
            current = self.account.get_connectivity()
            if current == expected_next:
                return
            if current != previous:
                raise Exception("Expected connectivity " + str(expected_next) + " but got " + str(current))

            self.get_matching("DC_EVENT_CONNECTIVITY_CHANGED")

    def ensure_event_not_queued(self, event_name_regex):
        __tracebackhide__ = True
        rex = re.compile(f"(?:{event_name_regex}).*")
        while True:
            try:
                ev = self._event_queue.get(False)
            except Empty:
                break
            else:
                assert not rex.match(ev.name), f"event found {ev}"

    def wait_securejoin_inviter_progress(self, target):
        while True:
            event = self.get_matching("DC_EVENT_SECUREJOIN_INVITER_PROGRESS")
            if event.data2 >= target:
                print(f"** SECUREJOINT-INVITER PROGRESS {target}", self.account)
                break

    def wait_securejoin_joiner_progress(self, target):
        while True:
            event = self.get_matching("DC_EVENT_SECUREJOIN_JOINER_PROGRESS")
            if event.data2 >= target:
                break

    def wait_idle_inbox_ready(self):
        """Has to be called after start_io() to wait for fetch_existing_msgs to run
        so that new messages are not mistaken for old ones:
        - ac1 and ac2 are created
        - ac1 sends a message to ac2
        - ac2 is still running FetchExsistingMsgs job and thinks it's an existing, old message
        - therefore no DC_EVENT_INCOMING_MSG is sent
        """
        self.get_matching("DC_EVENT_IMAP_INBOX_IDLE")

    def wait_next_incoming_message(self):
        """wait for and return next incoming message."""
        ev = self.get_matching("DC_EVENT_INCOMING_MSG")
        return self.account.get_message_by_id(ev.data2)

    def wait_next_messages_changed(self):
        """wait for and return next message-changed message or None
        if the event contains no msgid
        """
        ev = self.get_matching("DC_EVENT_MSGS_CHANGED")
        if ev.data2 > 0:
            return self.account.get_message_by_id(ev.data2)
        return None

    def wait_next_reactions_changed(self):
        """wait for and return next reactions-changed message."""
        ev = self.get_matching("DC_EVENT_REACTIONS_CHANGED")
        assert ev.data1 > 0
        return self.account.get_message_by_id(ev.data2)

    def wait_msg_delivered(self, msg):
        ev = self.get_matching("DC_EVENT_MSG_DELIVERED")
        assert ev.data1 == msg.chat.id
        assert ev.data2 == msg.id
        assert msg.is_out_delivered()


class EventThread(threading.Thread):
    """Event Thread for an account.

    With each Account init this callback thread is started.
    """

    def __init__(self, account: Account) -> None:
        self.account = account
        super(EventThread, self).__init__(name="events")
        self.daemon = True
        self._marked_for_shutdown = False
        self.start()

    @contextmanager
    def log_execution(self, message):
        self.account.log(message + " START")
        yield
        self.account.log(message + " FINISHED")

    def mark_shutdown(self) -> None:
        self._marked_for_shutdown = True

    def wait(self, timeout=None) -> None:
        if self == threading.current_thread():
            # we are in the callback thread and thus cannot
            # wait for the thread-loop to finish.
            return
        self.join(timeout=timeout)

    def run(self) -> None:
        """get and run events until shutdown."""
        with self.log_execution("EVENT THREAD"):
            event_emitter = ffi.gc(
                lib.dc_get_event_emitter(self.account._dc_context),
                lib.dc_event_emitter_unref,
            )
            while not self._marked_for_shutdown:
                with self.swallow_and_log_exception("Unexpected error in event thread"):
                    event = lib.dc_get_next_event(event_emitter)
                    if event == ffi.NULL or self._marked_for_shutdown:
                        break
                    self._process_event(event)

    def _process_event(self, event) -> None:
        evt = lib.dc_event_get_id(event)
        data1 = lib.dc_event_get_data1_int(event)
        # the following code relates to the deltachat/_build.py's helper
        # function which provides us signature info of an event call
        evt_name = get_dc_event_name(evt)
        if lib.dc_event_has_string_data(evt):
            data2 = from_optional_dc_charpointer(lib.dc_event_get_data2_str(event))
        else:
            data2 = lib.dc_event_get_data2_int(event)

        lib.dc_event_unref(event)
        ffi_event = FFIEvent(name=evt_name, data1=data1, data2=data2)
        with self.swallow_and_log_exception(f"ac_process_ffi_event {ffi_event}"):
            self.account._pm.hook.ac_process_ffi_event(account=self, ffi_event=ffi_event)
        for name, kwargs in self._map_ffi_event(ffi_event):
            hook = getattr(self.account._pm.hook, name)
            info = f"call {name} kwargs={kwargs} failed"
            with self.swallow_and_log_exception(info):
                hook(**kwargs)

    @contextmanager
    def swallow_and_log_exception(self, info):
        try:
            yield
        except Exception as ex:
            logfile = io.StringIO()
            traceback.print_exception(*sys.exc_info(), file=logfile)
            self.account.log(f"{info}\nException {ex}\nTraceback:\n{logfile.getvalue()}")

    def _map_ffi_event(self, ffi_event: FFIEvent):
        name = ffi_event.name
        account = self.account
        if name == "DC_EVENT_CONFIGURE_PROGRESS":
            data1 = ffi_event.data1
            if data1 == 0 or data1 == 1000:
                success = data1 == 1000
                comment = ffi_event.data2
                yield "ac_configure_completed", {"success": success, "comment": comment}
        elif name == "DC_EVENT_INCOMING_MSG":
            msg = account.get_message_by_id(ffi_event.data2)
            if msg is not None:
                yield ("ac_incoming_message", {"message": msg})
        elif name == "DC_EVENT_MSGS_CHANGED":
            if ffi_event.data2 != 0:
                msg = account.get_message_by_id(ffi_event.data2)
                if msg is not None:
                    if msg.is_outgoing():
                        yield "ac_outgoing_message", {"message": msg}
                    elif msg.is_in_fresh():
                        yield "ac_incoming_message", {"message": msg}
        elif name == "DC_EVENT_REACTIONS_CHANGED":
            assert ffi_event.data1 > 0
            msg = account.get_message_by_id(ffi_event.data2)
            if msg is not None:
                yield "ac_reactions_changed", {"message": msg}
        elif name == "DC_EVENT_MSG_DELIVERED":
            msg = account.get_message_by_id(ffi_event.data2)
            if msg is not None:
                yield "ac_message_delivered", {"message": msg}
        elif name == "DC_EVENT_CHAT_MODIFIED":
            chat = account.get_chat_by_id(ffi_event.data1)
            yield "ac_chat_modified", {"chat": chat}
