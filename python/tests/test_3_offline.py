import os
from datetime import datetime, timedelta, timezone

import pytest

import deltachat as dc
from deltachat.tracker import ImexFailed
from deltachat import Account, Message
from deltachat.testplugin import E2EE_INFO_MSGS


class TestOfflineAccountBasic:
    def test_wrong_db(self, tmp_path):
        p = tmp_path / "hello.db"
        p.write_text("123")
        with pytest.raises(ValueError):
            _account = Account(str(p))

    def test_os_name(self, tmp_path):
        p = tmp_path / "hello.db"
        # we can't easily test if os_name is used in X-Mailer
        # outgoing messages without a full Online test
        # but we at least check Account accepts the arg
        ac1 = Account(str(p), os_name="solarpunk")
        ac1.get_info()

    def test_preconfigure_keypair(self, acfactory, data):
        ac = acfactory.get_unconfigured_account()
        alice_secret = data.read_path("key/alice-secret.asc")
        assert alice_secret
        ac._preconfigure_keypair(alice_secret)

    def test_getinfo(self, acfactory):
        ac1 = acfactory.get_unconfigured_account()
        d = ac1.get_info()
        assert d["arch"]
        assert d["number_of_chats"] == "0"
        assert d["bcc_self"] == "1"

    def test_is_not_configured(self, acfactory):
        ac1 = acfactory.get_unconfigured_account()
        assert not ac1.is_configured()
        with pytest.raises(ValueError):
            ac1.check_is_configured()

    def test_wrong_config_keys(self, acfactory):
        ac1 = acfactory.get_unconfigured_account()
        with pytest.raises(KeyError):
            ac1.set_config("lqkwje", "value")
        with pytest.raises(KeyError):
            ac1.get_config("lqkwje")

    def test_set_config_int_conversion(self, acfactory):
        ac1 = acfactory.get_unconfigured_account()
        ac1.set_config("mvbox_move", False)
        assert ac1.get_config("mvbox_move") == "0"
        ac1.set_config("mvbox_move", True)
        assert ac1.get_config("mvbox_move") == "1"
        ac1.set_config("mvbox_move", 0)
        assert ac1.get_config("mvbox_move") == "0"
        ac1.set_config("mvbox_move", 1)
        assert ac1.get_config("mvbox_move") == "1"

    def test_update_config(self, acfactory):
        ac1 = acfactory.get_unconfigured_account()
        ac1.update_config({"mvbox_move": False})
        assert ac1.get_config("mvbox_move") == "0"

    def test_has_bccself(self, acfactory):
        ac1 = acfactory.get_unconfigured_account()
        assert "bcc_self" in ac1.get_config("sys.config_keys").split()
        assert ac1.get_config("bcc_self") == "1"

    def test_selfcontact_if_unconfigured(self, acfactory):
        ac1 = acfactory.get_unconfigured_account()
        assert not ac1.get_self_contact().addr

    def test_selfcontact_configured(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        me = ac1.get_self_contact()
        assert me.display_name
        assert me.addr

    def test_get_config_fails(self, acfactory):
        ac1 = acfactory.get_unconfigured_account()
        with pytest.raises(KeyError):
            ac1.get_config("123123")

    def test_empty_group_bcc_self_enabled(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        ac1.set_config("bcc_self", "1")
        chat = ac1.create_group_chat(name="group1")
        msg = chat.send_text("msg1")
        assert msg in chat.get_messages()

    def test_empty_group_bcc_self_disabled(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        ac1.set_config("bcc_self", "0")
        chat = ac1.create_group_chat(name="group1")
        msg = chat.send_text("msg1")
        assert msg in chat.get_messages()


class TestOfflineContact:
    def test_contact_attr(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        contact1 = ac1.create_contact("some1@example.org", name="some1")
        contact2 = ac1.create_contact("some1@example.org", name="some1")
        contact3 = None
        str(contact1)
        repr(contact1)
        assert contact1 == contact2
        assert contact1 != contact3
        assert contact1.id
        assert contact1.addr == "some1@example.org"
        assert contact1.display_name == "some1"
        assert not contact1.is_blocked()
        assert not contact1.is_verified()

    def test_get_blocked(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        contact1 = ac1.create_contact("some1@example.org", name="some1")
        contact2 = ac1.create_contact("some2@example.org", name="some2")
        ac1.create_contact("some3@example.org", name="some3")
        assert ac1.get_blocked_contacts() == []
        contact1.block()
        assert ac1.get_blocked_contacts() == [contact1]
        contact2.block()
        blocked = ac1.get_blocked_contacts()
        assert len(blocked) == 2 and contact1 in blocked and contact2 in blocked
        contact2.unblock()
        assert ac1.get_blocked_contacts() == [contact1]

    def test_create_self_contact(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        contact1 = ac1.create_contact(ac1.get_config("addr"))
        assert contact1.id == 1

    def test_get_contacts_and_delete(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        ac2 = acfactory.get_pseudo_configured_account()
        contact1 = ac1.create_contact(ac2)
        contacts = ac1.get_contacts()
        assert len(contacts) == 1

        assert not ac1.get_contacts(query="some2")
        assert not ac1.get_contacts(query="some1")
        assert len(ac1.get_contacts(with_self=True)) == 2
        assert contact1 in ac1.get_contacts()

        assert ac1.delete_contact(contact1)
        assert contact1 not in ac1.get_contacts()

    def test_delete_referenced_contact_hides_contact(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        contact1 = ac1.create_contact("some1@example.com", name="some1")
        msg = contact1.create_chat().send_text("one message")
        assert ac1.delete_contact(contact1)
        assert not msg.filemime

    def test_create_chat_flexibility(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        ac2 = acfactory.get_pseudo_configured_account()
        chat1 = ac1.create_chat(ac2)  # This creates a key-contact chat
        chat2 = ac1.create_chat(ac2.get_self_contact().addr)  # This creates address-contact chat
        assert chat1 != chat2
        ac3 = acfactory.get_unconfigured_account()
        with pytest.raises(ValueError):
            ac1.create_chat(ac3)

    def test_contact_rename(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        contact = ac1.create_contact("some1@example.com", name="some1")
        chat = ac1.create_chat(contact)
        assert chat.get_name() == "some1"
        ac1.create_contact("some1@example.com", name="renamed")
        ev = ac1._evtracker.get_matching("DC_EVENT_CHAT_MODIFIED")
        assert ev.data1 == chat.id
        assert chat.get_name() == "renamed"


class TestOfflineChat:
    @pytest.fixture()
    def ac1(self, acfactory):
        return acfactory.get_pseudo_configured_account()

    @pytest.fixture()
    def chat1(self, ac1):
        return ac1.create_contact("some1@example.org", name="some1").create_chat()

    def test_display(self, chat1):
        str(chat1)
        repr(chat1)

    def test_is_group(self, chat1):
        assert not chat1.is_group()

    def test_chat_by_id(self, chat1):
        chat2 = chat1.account.get_chat_by_id(chat1.id)
        assert chat2 == chat1
        with pytest.raises(ValueError):
            chat1.account.get_chat_by_id(123123)

    def test_chat_idempotent(self, chat1, ac1):
        contact1 = chat1.get_contacts()[0]
        chat2 = contact1.create_chat()
        chat3 = None
        assert chat2.id == chat1.id
        assert chat2.get_name() == chat1.get_name()
        assert chat1 == chat2
        assert not chat1.__ne__(chat2)
        assert chat1 != chat3

        for ichat in ac1.get_chats():
            if ichat.id == chat1.id:
                break
        else:
            pytest.fail("could not find chat")

    def test_group_chat_add_second_account(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        ac2 = acfactory.get_pseudo_configured_account()
        chat = ac1.create_group_chat(name="title1")
        contact = chat.add_contact(ac2)
        assert contact.addr == ac2.get_config("addr")
        assert contact.name == ac2.get_config("displayname")
        assert contact.account == ac1
        chat.remove_contact(ac2)

    def test_group_chat_creation(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        ac2 = acfactory.get_pseudo_configured_account()
        ac3 = acfactory.get_pseudo_configured_account()
        contact1 = ac1.create_contact(ac2)
        contact2 = ac1.create_contact(ac3)
        chat = ac1.create_group_chat(name="title1", contacts=[contact1, contact2])
        assert chat.get_name() == "title1"
        assert contact1 in chat.get_contacts()
        assert contact2 in chat.get_contacts()
        assert not chat.is_promoted()
        chat.set_name("title2")
        assert chat.get_name() == "title2"

        d = chat.get_summary()
        print(d)
        assert d["id"] == chat.id
        assert d["type"] == chat.get_type()
        assert d["name"] == chat.get_name()
        assert d["archived"] == chat.is_archived()
        # assert d["param"] == chat.param
        assert d["color"] == chat.get_color()
        assert not d["profile_image"] if chat.get_profile_image() is None else chat.get_profile_image()
        assert not d["draft"] if chat.get_draft() is None else chat.get_draft()

    def test_group_chat_creation_with_translation(self, ac1):
        ac1.set_stock_translation(dc.const.DC_STR_GROUP_NAME_CHANGED_BY_YOU, "abc %1$s xyz %2$s")
        ac1._evtracker.consume_events()
        with pytest.raises(ValueError):
            ac1.set_stock_translation(dc.const.DC_STR_FILE, "xyz %1$s")
        ac1._evtracker.get_matching("DC_EVENT_WARNING")
        with pytest.raises(ValueError):
            ac1.set_stock_translation(dc.const.DC_STR_CONTACT_NOT_VERIFIED, "xyz %2$s")
        ac1._evtracker.get_matching("DC_EVENT_WARNING")
        with pytest.raises(ValueError):
            ac1.set_stock_translation(500, "xyz %1$s")
        ac1._evtracker.get_matching("DC_EVENT_WARNING")
        chat = ac1.create_group_chat(name="homework", contacts=[])
        assert chat.get_name() == "homework"
        chat.send_text("Now we have a group for homework")
        assert chat.is_promoted()
        chat.set_name("Homework")
        assert chat.get_messages()[-1].text == "abc homework xyz Homework"

    @pytest.mark.parametrize("verified", [True, False])
    def test_group_chat_qr(self, acfactory, ac1, verified):
        ac2 = acfactory.get_pseudo_configured_account()
        chat = ac1.create_group_chat(name="title1", verified=verified)
        assert chat.is_group()
        qr = chat.get_join_qr()
        assert ac2.check_qr(qr).is_ask_verifygroup

    def test_removing_blocked_user_from_group(self, ac1, acfactory, lp):
        """
        Test that blocked contact is not unblocked when removed from a group.
        See https://github.com/deltachat/deltachat-core-rust/issues/2030
        """
        lp.sec("Create a group chat with a contact")
        ac2 = acfactory.get_pseudo_configured_account()
        contact = ac1.create_contact(ac2)
        group = ac1.create_group_chat("title", contacts=[contact])
        group.send_text("First group message")

        lp.sec("ac1 blocks contact")
        contact.block()
        assert contact.is_blocked()

        lp.sec("ac1 removes contact from their group")
        group.remove_contact(contact)
        assert contact.is_blocked()

    def test_get_set_profile_image_simple(self, ac1, data):
        chat = ac1.create_group_chat(name="title1")
        p = data.get_path("d.png")
        chat.set_profile_image(p)
        p2 = chat.get_profile_image()
        assert open(p, "rb").read() == open(p2, "rb").read()
        chat.remove_profile_image()
        assert chat.get_profile_image() is None

    def test_mute(self, ac1):
        chat = ac1.create_group_chat(name="title1")
        assert not chat.is_muted()
        assert chat.get_mute_duration() == 0
        chat.mute()
        assert chat.is_muted()
        assert chat.get_mute_duration() == -1
        chat.unmute()
        assert not chat.is_muted()
        chat.mute(50)
        assert chat.is_muted()
        assert chat.get_mute_duration() <= 50
        with pytest.raises(ValueError):
            chat.mute(-51)

        # Regression test, this caused Rust panic previously
        chat.mute(2**63 - 1)
        assert chat.is_muted()
        assert chat.get_mute_duration() == -1

    def test_delete_and_send_fails(self, ac1, chat1):
        chat1.delete()
        ac1._evtracker.wait_next_messages_changed()
        with pytest.raises(ValueError):
            chat1.send_text("msg1")

    def test_message_eq_contains(self, chat1):
        msg = chat1.send_text("msg1")
        msg2 = None
        assert msg != msg2
        assert msg in chat1.get_messages()
        assert not (msg not in chat1.get_messages())
        str(msg)
        repr(msg)

    def test_message_send_text(self, chat1):
        msg = chat1.send_text("msg1")
        assert msg
        assert msg.is_text()
        assert not msg.is_audio()
        assert not msg.is_video()
        assert not msg.is_gif()
        assert not msg.is_file()
        assert not msg.is_image()

        assert not msg.is_in_fresh()
        assert not msg.is_in_noticed()
        assert not msg.is_in_seen()
        assert msg.is_out_pending()
        assert not msg.is_out_failed()
        assert not msg.is_out_delivered()
        assert not msg.is_out_mdn_received()

    def test_message_image(self, chat1, data, lp):
        with pytest.raises(ValueError):
            chat1.send_image(path="notexists")
        fn = data.get_path("d.png")
        lp.sec("sending image")
        chat1.account._evtracker.consume_events()
        msg = chat1.send_image(fn)
        chat1.account._evtracker.get_matching("DC_EVENT_NEW_BLOB_FILE")
        assert msg.is_image()
        assert msg
        assert msg.id > 0
        assert os.path.exists(msg.filename)
        assert msg.filemime == "image/png"

    @pytest.mark.parametrize(
        ("fn", "typein", "typeout"),
        [
            ("r", None, "application/octet-stream"),
            ("r.txt", None, "text/plain"),
            ("r.txt", "text/plain", "text/plain"),
            ("r.txt", "image/png", "image/png"),
        ],
    )
    def test_message_file(self, chat1, data, lp, fn, typein, typeout):
        lp.sec("sending file")
        fp = data.get_path(fn)
        msg = chat1.send_file(fp, typein)
        assert msg
        assert msg.id > 0
        assert msg.is_file()
        assert os.path.exists(msg.filename)
        assert msg.filename.endswith(".txt") == fn.endswith(".txt")
        assert msg.filemime == typeout
        msg2 = chat1.send_file(fp, typein)
        assert msg2 != msg
        assert msg2.filename == msg.filename

    def test_create_contact(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        email = "hello <hello@example.org>"
        contact1 = ac1.create_contact(email)
        assert contact1.addr == "hello@example.org"
        assert contact1.name == "hello"
        contact1 = ac1.create_contact(email, name="world")
        assert contact1.name == "world"
        contact2 = ac1.create_contact("display1 <x@example.org>", "real")
        assert contact2.name == "real"

    def test_send_lots_of_offline_msgs(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        ac1.set_config("configured_mail_server", "example.org")
        ac1.set_config("configured_mail_user", "example.org")
        ac1.set_config("configured_mail_pw", "example.org")
        ac1.set_config("configured_send_server", "example.org")
        ac1.set_config("configured_send_user", "example.org")
        ac1.set_config("configured_send_pw", "example.org")
        ac1.start_io()
        chat = ac1.create_contact("some1@example.org", name="some1").create_chat()
        for i in range(50):
            chat.send_text("hello")

    def test_create_chat_simple(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        contact1 = ac1.create_contact("some1@example.org", name="some1")
        contact1.create_chat().send_text("hello")

    def test_chat_message_distinctions(self, ac1, chat1):
        past1s = datetime.now(timezone.utc) - timedelta(seconds=1)
        msg = chat1.send_text("msg1")
        ts = msg.time_sent
        assert msg.time_received is None
        assert ts.strftime("Y")
        assert past1s < ts
        contact = msg.get_sender_contact()
        assert contact == ac1.get_self_contact()

    def test_import_export_on_unencrypted_acct(self, acfactory, tmp_path):
        backupdir = tmp_path / "backup"
        backupdir.mkdir()
        ac1 = acfactory.get_pseudo_configured_account()
        ac_contact = acfactory.get_pseudo_configured_account()
        chat = ac1.create_contact(ac_contact).create_chat()
        # send a text message
        msg = chat.send_text("msg1")
        # send a binary file
        bin = tmp_path / "some.bin"
        bin.write_bytes(b"\00123" * 10000)
        msg = chat.send_file(str(bin))
        contact = msg.get_sender_contact()
        assert contact == ac1.get_self_contact()
        assert not list(backupdir.iterdir())
        ac1.stop_io()
        path = ac1.export_all(str(backupdir))
        assert os.path.exists(path)
        ac2 = acfactory.get_unconfigured_account()
        ac2.import_all(path)
        contacts = ac2.get_contacts()
        assert len(contacts) == 1
        contact2 = contacts[0]
        assert contact2.addr == ac_contact.get_config("addr")
        chat2 = contact2.create_chat()
        messages = chat2.get_messages()
        assert len(messages) == 2 + E2EE_INFO_MSGS
        assert messages[0 + E2EE_INFO_MSGS].text == "msg1"
        assert os.path.exists(messages[1 + E2EE_INFO_MSGS].filename)

    def test_import_export_on_encrypted_acct(self, acfactory, tmp_path):
        passphrase1 = "passphrase1"
        passphrase2 = "passphrase2"
        backupdir = tmp_path / "backup"
        backupdir.mkdir()
        ac1 = acfactory.get_pseudo_configured_account(passphrase=passphrase1)
        ac2 = acfactory.get_pseudo_configured_account()

        chat = ac1.create_contact(ac2).create_chat()
        # send a text message
        msg = chat.send_text("msg1")
        # send a binary file
        bin = tmp_path / "some.bin"
        bin.write_bytes(b"\00123" * 10000)
        msg = chat.send_file(str(bin))
        contact = msg.get_sender_contact()
        assert contact == ac1.get_self_contact()

        assert not list(backupdir.iterdir())
        ac1.stop_io()

        path = ac1.export_all(str(backupdir))
        assert os.path.exists(path)

        ac2 = acfactory.get_unconfigured_account(closed=True)
        ac2.open(passphrase2)
        ac2.import_all(path)

        # check data integrity
        contacts = ac2.get_contacts()
        assert len(contacts) == 1
        contact2 = contacts[0]
        contact2_addr = contact2.addr
        chat2 = contact2.create_chat()
        messages = chat2.get_messages()
        assert len(messages) == 2 + E2EE_INFO_MSGS
        assert messages[0 + E2EE_INFO_MSGS].text == "msg1"
        assert os.path.exists(messages[1 + E2EE_INFO_MSGS].filename)

        ac2.shutdown()

        # check that passphrase is not lost after import:
        ac2 = Account(ac2.db_path, logging=ac2._logging, closed=True)
        ac2.open(passphrase2)

        # check data integrity
        contacts = ac2.get_contacts()
        assert len(contacts) == 1
        contact2 = contacts[0]
        assert contact2.addr == contact2_addr
        chat2 = contact2.create_chat()
        messages = chat2.get_messages()
        assert len(messages) == 2 + E2EE_INFO_MSGS
        assert messages[0 + E2EE_INFO_MSGS].text == "msg1"
        assert os.path.exists(messages[1 + E2EE_INFO_MSGS].filename)

    def test_import_export_with_passphrase(self, acfactory, tmp_path):
        passphrase = "test_passphrase"
        wrong_passphrase = "wrong_passprase"
        backupdir = tmp_path / "backup"
        backupdir.mkdir()
        ac1 = acfactory.get_pseudo_configured_account()
        ac_contact = acfactory.get_pseudo_configured_account()

        chat = ac1.create_contact(ac_contact).create_chat()
        # send a text message
        msg = chat.send_text("msg1")
        # send a binary file
        bin = tmp_path / "some.bin"
        bin.write_bytes(b"\00123" * 10000)
        msg = chat.send_file(str(bin))
        contact = msg.get_sender_contact()
        assert contact == ac1.get_self_contact()

        assert not list(backupdir.iterdir())
        ac1.stop_io()

        path = ac1.export_all(str(backupdir), passphrase)
        assert os.path.exists(path)

        ac2 = acfactory.get_unconfigured_account()
        with pytest.raises(ImexFailed):
            ac2.import_all(path, wrong_passphrase)
        ac2.import_all(path, passphrase)

        # check data integrity
        contacts = ac2.get_contacts()
        assert len(contacts) == 1
        contact2 = contacts[0]
        assert contact2.addr == ac_contact.get_config("addr")
        chat2 = contact2.create_chat()
        messages = chat2.get_messages()
        assert len(messages) == 2 + E2EE_INFO_MSGS
        assert messages[0 + E2EE_INFO_MSGS].text == "msg1"
        assert os.path.exists(messages[1 + E2EE_INFO_MSGS].filename)

    def test_import_encrypted_bak_into_encrypted_acct(self, acfactory, tmp_path):
        """
        Test that account passphrase isn't lost if backup failed to be imported.
        See https://github.com/deltachat/deltachat-core-rust/issues/3379
        """
        acct_passphrase = "passphrase1"
        bak_passphrase = "passphrase2"
        wrong_passphrase = "wrong_passprase"
        backupdir = tmp_path / "backup"
        backupdir.mkdir()

        ac1 = acfactory.get_pseudo_configured_account()
        ac_contact = acfactory.get_pseudo_configured_account()
        chat = ac1.create_contact(ac_contact).create_chat()
        # send a text message
        msg = chat.send_text("msg1")
        # send a binary file
        bin = tmp_path / "some.bin"
        bin.write_bytes(b"\00123" * 10000)
        msg = chat.send_file(str(bin))
        contact = msg.get_sender_contact()
        assert contact == ac1.get_self_contact()

        assert not list(backupdir.iterdir())
        ac1.stop_io()

        path = ac1.export_all(str(backupdir), bak_passphrase)
        assert os.path.exists(path)

        ac2 = acfactory.get_unconfigured_account(closed=True)
        ac2.open(acct_passphrase)
        with pytest.raises(ImexFailed):
            ac2.import_all(path, wrong_passphrase)
        ac2.import_all(path, bak_passphrase)

        # check data integrity
        contacts = ac2.get_contacts()
        assert len(contacts) == 1
        contact2 = contacts[0]
        assert contact2.addr == ac_contact.get_config("addr")
        chat2 = contact2.create_chat()
        messages = chat2.get_messages()
        assert len(messages) == 2 + E2EE_INFO_MSGS
        assert messages[0 + E2EE_INFO_MSGS].text == "msg1"
        assert os.path.exists(messages[1 + E2EE_INFO_MSGS].filename)

        ac2.shutdown()

        # check that passphrase is not lost after import
        ac2 = Account(ac2.db_path, logging=ac2._logging, closed=True)
        ac2.open(acct_passphrase)

        # check data integrity
        contacts = ac2.get_contacts()
        assert len(contacts) == 1
        contact2 = contacts[0]
        assert contact2.addr == ac_contact.get_config("addr")
        chat2 = contact2.create_chat()
        messages = chat2.get_messages()
        assert len(messages) == 2 + E2EE_INFO_MSGS
        assert messages[0 + E2EE_INFO_MSGS].text == "msg1"
        assert os.path.exists(messages[1 + E2EE_INFO_MSGS].filename)

    def test_set_get_draft(self, chat1):
        msg1 = Message.new_empty(chat1.account, "text")
        msg1.set_text("hello")
        chat1.set_draft(msg1)
        msg1.set_text("obsolete")
        msg2 = chat1.get_draft()
        assert msg2.text == "hello"
        chat1.set_draft(None)
        assert chat1.get_draft() is None

    def test_qr_setup_contact(self, acfactory):
        ac1 = acfactory.get_pseudo_configured_account()
        ac2 = acfactory.get_pseudo_configured_account()
        qr = ac1.get_setup_contact_qr()
        assert qr.startswith("https://i.delta.chat")
        res = ac2.check_qr(qr)
        assert res.is_ask_verifycontact()
        assert not res.is_ask_verifygroup()
        assert res.contact_id == 10

    def test_audit_log_view_without_daymarker(self, acfactory, lp):
        ac1 = acfactory.get_pseudo_configured_account()
        ac2 = acfactory.get_pseudo_configured_account()

        lp.sec("ac1: test audit log (show only system messages)")
        chat = ac1.create_group_chat(name="audit log sample data")

        # promote chat
        chat.send_text("hello")
        assert chat.is_promoted()

        lp.sec("create test data")
        chat.add_contact(ac2)
        chat.set_name("audit log test group")
        chat.send_text("a message in between")

        lp.sec("check message count of only system messages (without daymarkers)")
        sysmessages = [x for x in chat.get_messages() if x.is_system_message()]
        assert len(sysmessages) == 3
