import fnmatch
import io
import os
import pathlib
import queue
import subprocess
import sys
import threading
import time
import weakref
import random
from queue import Queue
from typing import Callable, Dict, List, Optional, Set

import pytest
from _pytest._code import Source

import deltachat

from . import Account, account_hookimpl, const, get_core_info
from .events import FFIEventLogger, FFIEventTracker

E2EE_INFO_MSGS = 1
"""
The number of info messages added to new e2ee chats.
Currently this is "End-to-end encryption available".
"""


def pytest_addoption(parser):
    group = parser.getgroup("deltachat testplugin options")
    group.addoption(
        "--chatmail",
        action="store",
        default=None,
        help="chatmail server domain name",
    )
    group.addoption(
        "--ignored",
        action="store_true",
        help="Also run tests marked with the ignored marker",
    )
    group.addoption(
        "--strict-tls",
        action="store_true",
        help="Never accept invalid TLS certificates for test accounts",
    )
    group.addoption(
        "--extra-info",
        action="store_true",
        help="show more info on failures (imap server state, config)",
    )
    group.addoption(
        "--debug-setup",
        action="store_true",
        help="show events during configure and start io phases of online accounts",
    )


def pytest_configure(config):
    cfg = config.getoption("--chatmail")
    if not cfg:
        cfg = os.getenv("CHATMAIL_DOMAIN")
        if cfg:
            config.option.chatmail = cfg

    # Make sure we don't get garbled output because threads keep running
    # collect all ever created accounts in a weakref-set (so we don't
    # keep objects unnecessarily alive) and enable/disable logging
    # for each pytest test phase # (setup/call/teardown).
    # Additionally make the acfactory use a logging/no-logging default.

    class LoggingAspect:
        def __init__(self) -> None:
            self._accounts: weakref.WeakSet = weakref.WeakSet()

        @deltachat.global_hookimpl
        def dc_account_init(self, account):
            self._accounts.add(account)

        def disable_logging(self, item):
            for acc in self._accounts:
                acc.disable_logging()
            acfactory = item.funcargs.get("acfactory")
            if acfactory:
                acfactory.set_logging_default(False)

        def enable_logging(self, item):
            for acc in self._accounts:
                acc.enable_logging()
            acfactory = item.funcargs.get("acfactory")
            if acfactory:
                acfactory.set_logging_default(True)

        @pytest.hookimpl(hookwrapper=True)
        def pytest_runtest_setup(self, item):
            if item.get_closest_marker("ignored"):
                if not item.config.getvalue("ignored"):
                    pytest.skip("use --ignored to run this test")
            self.enable_logging(item)
            yield
            self.disable_logging(item)

        @pytest.hookimpl(hookwrapper=True)
        def pytest_pyfunc_call(self, pyfuncitem):
            self.enable_logging(pyfuncitem)
            yield
            self.disable_logging(pyfuncitem)

        @pytest.hookimpl(hookwrapper=True)
        def pytest_runtest_teardown(self, item):
            logging = item.config.getoption("--extra-info")
            if logging:
                self.enable_logging(item)
            yield
            if logging:
                self.disable_logging(item)

    la = LoggingAspect()
    config.pluginmanager.register(la)
    deltachat.register_global_plugin(la)


def pytest_report_header(config):
    info = get_core_info()
    summary = [
        "Deltachat core={} sqlite={} journal_mode={}".format(
            info["deltachat_core_version"],
            info["sqlite_version"],
            info["journal_mode"],
        ),
    ]

    chatmail_opt = config.getoption("--chatmail")
    if chatmail_opt:
        summary.append(f"Chatmail account provider: {chatmail_opt}")

    return summary


@pytest.fixture(scope="session")
def testprocess(request):
    """Return live account configuration manager.

    The returned object is a :class:`TestProcess` object."""
    return TestProcess(pytestconfig=request.config)


class TestProcess:
    """A pytest session-scoped instance to help with managing "live" account configurations."""

    _addr2files: Dict[str, Dict[pathlib.Path, bytes]]

    def __init__(self, pytestconfig) -> None:
        self.pytestconfig = pytestconfig
        self._addr2files = {}
        self._configlist: List[Dict[str, str]] = []

    def get_liveconfig_producer(self):
        """provide live account configs, cached on a per-test-process scope
        so that test functions can reuse already known live configs.
        """
        chatmail_opt = self.pytestconfig.getoption("--chatmail")
        if chatmail_opt:
            # Use a chatmail instance.
            domain = chatmail_opt
            MAX_LIVE_CREATED_ACCOUNTS = 10
            for index in range(MAX_LIVE_CREATED_ACCOUNTS):
                try:
                    yield self._configlist[index]
                except IndexError:
                    part = "".join(random.choices("2345789acdefghjkmnpqrstuvwxyz", k=6))
                    username = f"ci-{part}"
                    password = f"{username}${username}"
                    addr = f"{username}@{domain}"
                    config = {"addr": addr, "mail_pw": password}
                    print("newtmpuser {}: addr={}".format(index, config["addr"]))
                    self._configlist.append(config)
                    yield config
            pytest.fail(f"more than {MAX_LIVE_CREATED_ACCOUNTS} live accounts requested.")
        else:
            pytest.skip(
                "specify CHATMAIL_DOMAIN or --chatmail to provide live accounts",
            )

    def cache_maybe_retrieve_configured_db_files(self, cache_addr, db_target_path):
        db_target_path = pathlib.Path(db_target_path)
        assert not db_target_path.exists()

        try:
            filescache = self._addr2files[cache_addr]
        except KeyError:
            print("CACHE FAIL for", cache_addr)
            return False
        else:
            print("CACHE HIT for", cache_addr)
            targetdir = db_target_path.parent
            write_dict_to_dir(filescache, targetdir)
            return True

    def cache_maybe_store_configured_db_files(self, acc):
        addr = acc.get_config("addr")
        assert acc.is_configured()
        # don't overwrite existing entries
        if addr not in self._addr2files:
            print("storing cache for", addr)
            basedir = pathlib.Path(acc.get_blobdir()).parent
            self._addr2files[addr] = create_dict_from_files_in_path(basedir)
            return True


def create_dict_from_files_in_path(base):
    cachedict = {}
    for path in base.glob("**/*"):
        if path.is_file():
            cachedict[path.relative_to(base)] = path.read_bytes()
    return cachedict


def write_dict_to_dir(dic, target_dir):
    assert dic
    for relpath, content in dic.items():
        path = target_dir.joinpath(relpath)
        if not path.parent.exists():
            os.makedirs(path.parent)
        path.write_bytes(content)


@pytest.fixture()
def data(request):
    """Test data."""

    class Data:
        def __init__(self) -> None:
            # trying to find test data heuristically
            # because we are run from a dev-setup with pytest direct,
            # through tox, and then maybe also from deltachat-binding
            # users like "deltabot".
            self.paths = [
                os.path.normpath(x)
                for x in [
                    os.path.join(os.path.dirname(request.fspath.strpath), "data"),
                    os.path.join(os.path.dirname(request.fspath.strpath), "..", "..", "test-data"),
                    os.path.join(os.path.dirname(__file__), "..", "..", "..", "test-data"),
                ]
            ]

        def get_path(self, bn):
            """return path of file or None if it doesn't exist."""
            for path in self.paths:
                fn = os.path.join(path, *bn.split("/"))
                if os.path.exists(fn):
                    return fn
            print(f"WARNING: path does not exist: {fn!r}")
            return None

        def read_path(self, bn, mode="r"):
            fn = self.get_path(bn)
            if fn is not None:
                with open(fn, mode) as f:
                    return f.read()

    return Data()


class ACSetup:
    """
    Accounts setup helper to deal with multiple configure-process
    and io & imap initialization phases.

    From tests, use the higher level
    public ACFactory methods instead of its private helper class.
    """

    CONFIGURING = "CONFIGURING"
    CONFIGURED = "CONFIGURED"
    IDLEREADY = "IDLEREADY"

    _configured_events: Queue

    def __init__(self, testprocess, init_time) -> None:
        self._configured_events = Queue()
        self._account2state: Dict[Account, str] = {}
        self._account2config: Dict[Account, Dict[str, str]] = {}
        self._imap_cleaned: Set[str] = set()
        self.testprocess = testprocess
        self.init_time = init_time

    def log(self, *args):
        print("[acsetup]", f"{time.time() - self.init_time:.3f}", *args)

    def add_configured(self, account):
        """add an already configured account."""
        assert account.is_configured()
        self._account2state[account] = self.CONFIGURED
        self.log("added already configured account", account, account.get_config("addr"))

    def start_configure(self, account):
        """add an account and start its configure process."""

        class PendingTracker:
            @account_hookimpl
            def ac_configure_completed(this, success: bool, comment: Optional[str]) -> None:
                self._configured_events.put((account, success, comment))

        account.add_account_plugin(PendingTracker(), name="pending_tracker")
        self._account2state[account] = self.CONFIGURING
        account.configure()
        self.log("started configure on", account)

    def wait_one_configured(self, account):
        """wait until this account has successfully configured."""
        if self._account2state[account] == self.CONFIGURING:
            while True:
                acc = self._pop_config_success()
                if acc == account:
                    break
            self.init_imap(acc)
            self.init_logging(acc)
            acc._evtracker.consume_events()

    def bring_online(self):
        """Wait for all accounts to become ready to receive messages.

        This will initialize logging, start IO and the direct_imap attribute
        for each account which either is CONFIGURED already or which is CONFIGURING
        and successfully completing the configuration process.
        """
        print("wait_all_configured finds accounts=", self._account2state)
        for acc, state in self._account2state.items():
            if state == self.CONFIGURED:
                self._onconfigure_start_io(acc)
                self._account2state[acc] = self.IDLEREADY

        while self.CONFIGURING in self._account2state.values():
            acc = self._pop_config_success()
            self._onconfigure_start_io(acc)
            self._account2state[acc] = self.IDLEREADY
        print("finished, account2state", self._account2state)

    def _pop_config_success(self):
        acc, success, comment = self._configured_events.get()
        if not success:
            pytest.fail(f"configuring online account {acc} failed: {comment}")
        self._account2state[acc] = self.CONFIGURED
        if acc in self._account2config:
            acc.update_config(self._account2config[acc])
        return acc

    def _onconfigure_start_io(self, acc):
        self.init_imap(acc)
        self.init_logging(acc)
        acc.start_io()
        print(acc._logid, "waiting for inbox IDLE to become ready")
        acc._evtracker.wait_idle_inbox_ready()
        acc._evtracker.consume_events()
        acc.log("inbox IDLE ready")

    def init_logging(self, acc):
        """idempotent function for initializing logging (will replace existing logger)."""
        logger = FFIEventLogger(acc, logid=acc._logid, init_time=self.init_time)
        acc.add_account_plugin(logger, name="logger-" + acc._logid)

    def init_imap(self, acc):
        """initialize direct_imap and cleanup server state."""
        from deltachat.direct_imap import DirectImap

        assert acc.is_configured()
        if not hasattr(acc, "direct_imap"):
            acc.direct_imap = DirectImap(acc)
        addr = acc.get_config("addr")
        if addr not in self._imap_cleaned:
            imap = acc.direct_imap
            for folder in imap.list_folders():
                if folder.lower() == "inbox" or folder.lower() == "deltachat":
                    assert imap.select_folder(folder)
                    imap.delete("1:*", expunge=True)
                else:
                    imap.conn.folder.delete(folder)
            acc.log(f"imap cleaned for addr {addr}")
            self._imap_cleaned.add(addr)


class ACFactory:
    """Account factory"""

    init_time: float
    _finalizers: List[Callable[[], None]]
    _accounts: List[Account]
    _acsetup: ACSetup
    _preconfigured_keys: List[str]

    def __init__(self, request, testprocess, tmpdir, data) -> None:
        self.init_time = time.time()
        self.tmpdir = tmpdir
        self.pytestconfig = request.config
        self.data = data
        self.testprocess = testprocess
        self._liveconfig_producer = testprocess.get_liveconfig_producer()

        self._finalizers = []
        self._accounts = []
        self._acsetup = ACSetup(testprocess, self.init_time)
        self._preconfigured_keys = ["alice", "bob", "charlie", "dom", "elena", "fiona"]
        self.set_logging_default(False)
        request.addfinalizer(self.finalize)

    def log(self, *args):
        print("[acfactory]", f"{time.time() - self.init_time:.3f}", *args)

    def finalize(self):
        while self._finalizers:
            fin = self._finalizers.pop()
            fin()

        while self._accounts:
            acc = self._accounts.pop()
            if acc is not None:
                imap = getattr(acc, "direct_imap", None)
                if imap is not None:
                    imap.shutdown()
                    del acc.direct_imap
                acc.shutdown()
                acc.disable_logging()

    def get_next_liveconfig(self):
        """
        Base function to get functional online configurations
        where we can make valid SMTP and IMAP connections with.
        """
        configdict = next(self._liveconfig_producer).copy()

        if self.pytestconfig.getoption("--strict-tls"):
            # Enable strict certificate checks for online accounts
            configdict["imap_certificate_checks"] = str(const.DC_CERTCK_STRICT)
            configdict["smtp_certificate_checks"] = str(const.DC_CERTCK_STRICT)

        assert "addr" in configdict and "mail_pw" in configdict
        return configdict

    def _get_cached_account(self, addr) -> Optional[Account]:
        if addr in self.testprocess._addr2files:
            return self._getaccount(addr)
        return None

    def get_unconfigured_account(self, closed=False) -> Account:
        return self._getaccount(closed=closed)

    def _getaccount(self, try_cache_addr=None, closed=False) -> Account:
        logid = f"ac{len(self._accounts) + 1}"
        # we need to use fixed database basename for maybe_cache_* functions to work
        path = self.tmpdir.mkdir(logid).join("dc.db")
        if try_cache_addr:
            self.testprocess.cache_maybe_retrieve_configured_db_files(try_cache_addr, path)
        ac = Account(path.strpath, logging=self._logging, closed=closed)
        ac._logid = logid  # later instantiated FFIEventLogger needs this
        ac._evtracker = ac.add_account_plugin(FFIEventTracker(ac))
        if self.pytestconfig.getoption("--debug-setup"):
            self._acsetup.init_logging(ac)
        self._accounts.append(ac)
        return ac

    def set_logging_default(self, logging) -> None:
        self._logging = bool(logging)

    def remove_preconfigured_keys(self) -> None:
        self._preconfigured_keys = []

    def _preconfigure_key(self, account):
        # Only set a preconfigured key if we haven't used it yet for another account.
        try:
            keyname = self._preconfigured_keys.pop(0)
        except IndexError:
            pass
        else:
            fname_sec = self.data.read_path(f"key/{keyname}-secret.asc")
            if fname_sec:
                account._preconfigure_keypair(fname_sec)
                return True
            print("WARN: could not use preconfigured keys")

    def get_pseudo_configured_account(self, passphrase: Optional[str] = None) -> Account:
        # do a pseudo-configured account
        ac = self.get_unconfigured_account(closed=bool(passphrase))
        if passphrase:
            ac.open(passphrase)
        acname = ac._logid
        addr = f"{acname}@offline.org"
        ac.update_config(
            {
                "configured_addr": addr,
                "displayname": acname,
            },
        )
        self._preconfigure_key(ac)
        self._acsetup.init_logging(ac)
        return ac

    def new_online_configuring_account(self, cloned_from=None, cache=False, **kwargs) -> Account:
        if cloned_from is None:
            configdict = self.get_next_liveconfig()
        else:
            # XXX we might want to transfer the key to the new account
            configdict = {
                "addr": cloned_from.get_config("addr"),
                "mail_pw": cloned_from.get_config("mail_pw"),
                "imap_certificate_checks": cloned_from.get_config("imap_certificate_checks"),
                "smtp_certificate_checks": cloned_from.get_config("smtp_certificate_checks"),
            }
        configdict.update(kwargs)
        ac = self._get_cached_account(addr=configdict["addr"]) if cache else None
        if ac is not None:
            # make sure we consume a preconfig key, as if we had created a fresh account
            self._preconfigured_keys.pop(0)
            self._acsetup.add_configured(ac)
            return ac
        ac = self.prepare_account_from_liveconfig(configdict)
        self._acsetup.start_configure(ac)
        return ac

    def prepare_account_from_liveconfig(self, configdict) -> Account:
        ac = self.get_unconfigured_account()
        assert "addr" in configdict and "mail_pw" in configdict, configdict
        configdict.setdefault("bcc_self", False)
        configdict.setdefault("mvbox_move", False)
        configdict.setdefault("sync_msgs", False)
        configdict.setdefault("delete_server_after", 0)
        ac.update_config(configdict)
        self._acsetup._account2config[ac] = configdict
        self._preconfigure_key(ac)
        return ac

    def wait_configured(self, account) -> None:
        """Wait until the specified account has successfully completed configure."""
        self._acsetup.wait_one_configured(account)

    def bring_accounts_online(self) -> None:
        print("bringing accounts online")
        self._acsetup.bring_online()
        print("all accounts online")

    def get_online_accounts(self, num):
        accounts = [self.new_online_configuring_account(cache=True) for i in range(num)]
        self.bring_accounts_online()
        # we cache fully configured and started accounts
        for acc in accounts:
            self.testprocess.cache_maybe_store_configured_db_files(acc)
        return accounts

    def run_bot_process(self, module, ffi=True):
        fn = module.__file__

        bot_cfg = self.get_next_liveconfig()
        bot_ac = self.prepare_account_from_liveconfig(bot_cfg)
        self._acsetup.start_configure(bot_ac)
        self.wait_configured(bot_ac)
        bot_ac.start_io()
        # Wait for DC_EVENT_IMAP_INBOX_IDLE so that all emails appeared in the bot's Inbox later are
        # considered new and not existing ones, and thus processed by the bot.
        print(bot_ac._logid, "waiting for inbox IDLE to become ready")
        bot_ac._evtracker.wait_idle_inbox_ready()
        bot_ac.stop_io()
        self._acsetup._account2state[bot_ac] = self._acsetup.IDLEREADY

        # Forget ac as it will be opened by the bot subprocess
        # but keep something in the list to not confuse account generation
        self._accounts[self._accounts.index(bot_ac)] = None

        args = [
            sys.executable,
            "-u",
            fn,
            "--email",
            bot_cfg["addr"],
            "--password",
            bot_cfg["mail_pw"],
            bot_ac.db_path,
        ]
        if ffi:
            args.insert(-1, "--show-ffi")
        print("$", " ".join(args))
        popen = subprocess.Popen(
            args=args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # combine stdout/stderr in one stream
            bufsize=0,  # line buffering
            close_fds=True,  # close all FDs other than 0/1/2
            universal_newlines=True,  # give back text
        )
        bot = BotProcess(popen, addr=bot_cfg["addr"])
        self._finalizers.append(bot.kill)
        return bot

    def dump_imap_summary(self, logfile):
        for ac in self._accounts:
            ac.dump_account_info(logfile=logfile)
            imap = getattr(ac, "direct_imap", None)
            if imap is not None:
                imap.dump_imap_structures(self.tmpdir, logfile=logfile)

    def get_accepted_chat(self, ac1: Account, ac2: Account):
        ac2.create_chat(ac1)
        return ac1.create_chat(ac2)

    def introduce_each_other(self, accounts, sending=True):
        to_wait = []
        for i, acc in enumerate(accounts):
            for acc2 in accounts[i + 1 :]:
                chat = self.get_accepted_chat(acc, acc2)
                if sending:
                    chat.send_text("hi")
                    to_wait.append(acc2)
                    acc2.create_chat(acc).send_text("hi back")
                    to_wait.append(acc)
        for acc in to_wait:
            acc.log("waiting for incoming message")
            acc._evtracker.wait_next_incoming_message()


@pytest.fixture()
def acfactory(request, tmpdir, testprocess, data):
    """Account factory."""
    am = ACFactory(request=request, tmpdir=tmpdir, testprocess=testprocess, data=data)
    yield am
    if hasattr(request.node, "rep_call") and request.node.rep_call.failed:
        if testprocess.pytestconfig.getoption("--extra-info"):
            logfile = io.StringIO()
            am.dump_imap_summary(logfile=logfile)
            print(logfile.getvalue())
            # request.node.add_report_section("call", "imap-server-state", s)


class BotProcess:
    stdout_queue: queue.Queue

    def __init__(self, popen, addr) -> None:
        self.popen = popen

        # The first thing the bot prints to stdout is an invite link.
        self.qr = self.popen.stdout.readline()
        self.addr = addr

        # we read stdout as quickly as we can in a thread and make
        # the (unicode) lines available for readers through a queue.
        self.stdout_queue = queue.Queue()
        self.stdout_thread = t = threading.Thread(target=self._run_stdout_thread, name="bot-stdout-thread")
        t.daemon = True
        t.start()

    def _run_stdout_thread(self) -> None:
        try:
            while True:
                line = self.popen.stdout.readline()
                if not line:
                    break
                line = line.strip()
                self.stdout_queue.put(line)
                print("bot-stdout: ", line)
        finally:
            self.stdout_queue.put(None)

    def kill(self) -> None:
        self.popen.kill()

    def wait(self, timeout=None) -> None:
        self.popen.wait(timeout=timeout)

    def fnmatch_lines(self, pattern_lines):
        patterns = [x.strip() for x in Source(pattern_lines.rstrip()).lines if x.strip()]
        for next_pattern in patterns:
            print("+++FNMATCH:", next_pattern)
            ignored = []
            while True:
                line = self.stdout_queue.get()
                if line is None:
                    if ignored:
                        print("BOT stdout terminated after these lines")
                        for line in ignored:
                            print(line)
                    raise IOError("BOT stdout-thread terminated")
                if fnmatch.fnmatch(line, next_pattern):
                    print("+++MATCHED:", line)
                    break
                else:
                    print("+++IGN:", line)
                    ignored.append(line)


@pytest.fixture()
def tmp_db_path(tmpdir):
    """Return a path inside the temporary directory where the database can be created."""
    return tmpdir.join("test.db").strpath


@pytest.fixture()
def lp():
    """Log printer fixture."""

    class Printer:
        def sec(self, msg: str) -> None:
            print()
            print("=" * 10, msg, "=" * 10)

        def step(self, msg: str) -> None:
            print("-" * 5, "step " + msg, "-" * 5)

        def indent(self, msg: str) -> None:
            print("  " + msg)

    return Printer()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, "rep_" + rep.when, rep)
