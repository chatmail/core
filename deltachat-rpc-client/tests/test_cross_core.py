import subprocess
import time

import pytest

from deltachat_rpc_client import DeltaChat, Rpc


def test_install_venv_and_use_other_core(tmp_path, get_core_python_env):
    python, rpc_server_path = get_core_python_env("2.24.0")
    subprocess.check_call([python, "-m", "pip", "install", "deltachat-rpc-server==2.24.0"])
    rpc = Rpc(accounts_dir=tmp_path.joinpath("accounts"), rpc_server_path=rpc_server_path)

    with rpc:
        dc = DeltaChat(rpc)
        assert dc.rpc.get_system_info()["deltachat_core_version"] == "v2.24.0"


@pytest.mark.parametrize("version", ["2.24.0"])
def test_qr_setup_contact(acf, alice_and_remote_bob, version) -> None:
    """Test other-core Bob profile can do securejoin with Alice on current core."""
    alice, alice_contact_bob, remote_eval = alice_and_remote_bob(version)

    qr_code = alice.get_qr_code()
    remote_eval(f"bob.secure_join({qr_code!r})")
    alice.wait_for_securejoin_inviter_success()

    # Test that Alice verified Bob's profile.
    alice_contact_bob_snapshot = alice_contact_bob.get_snapshot()
    assert alice_contact_bob_snapshot.is_verified

    remote_eval("bob.wait_for_securejoin_joiner_success()")

    # Test that Bob verified Alice's profile.
    assert remote_eval("bob_contact_alice.get_snapshot().is_verified")

    # Test that Bob can also scan a QR code
    # of Alice for which the key is not known yet.
    # For the test above Bob already knew the key from a vCard.
    alice2 = acf.get_online_account()
    qr_code = alice2.get_qr_code()
    remote_eval(f"bob.secure_join({qr_code!r})")
    remote_eval("bob.wait_for_securejoin_joiner_success()")
    alice2.wait_for_securejoin_inviter_success()


@pytest.mark.parametrize("version", ["2.24.0"])
def test_qr_setup_contact_multitransport(acf, alice_and_remote_bob, version) -> None:
    """Test other-core Bob profile can do securejoin with Alice on current core, with multiple transports."""
    alice, alice_contact_bob, remote_eval = alice_and_remote_bob(version)
    relay_qr = acf.get_account_qr()
    alice.add_transport_from_qr(relay_qr)
    alice.add_transport_from_qr(relay_qr)

    qr_code = alice.get_qr_code()
    remote_eval(f"bob.secure_join({qr_code!r})")
    alice.wait_for_securejoin_inviter_success()

    # Test that Alice verified Bob's profile.
    alice_contact_bob_snapshot = alice_contact_bob.get_snapshot()
    assert alice_contact_bob_snapshot.is_verified

    remote_eval("bob.wait_for_securejoin_joiner_success()")

    # Test that Bob verified Alice's profile.
    assert remote_eval("bob_contact_alice.get_snapshot().is_verified")


def test_send_and_receive_message(alice_and_remote_bob) -> None:
    """Test other-core Bob profile can send a message to Alice on current core."""
    alice, alice_contact_bob, remote_eval = alice_and_remote_bob("2.23.0")

    remote_eval("bob_contact_alice.create_chat().send_text('hello')")

    msg = alice.wait_for_incoming_msg()
    assert msg.get_snapshot().text == "hello"


def test_second_device(acf, alice_and_remote_bob) -> None:
    """Test setting up current version as a second device for old version."""
    _alice, alice_contact_bob, remote_eval = alice_and_remote_bob("2.23.0")

    remote_eval("locals().setdefault('future', bob._rpc.provide_backup.future(bob.id))")
    qr = remote_eval("bob._rpc.get_backup_qr(bob.id)")
    new_account = acf.get_unconfigured_account()
    new_account._rpc.get_backup(new_account.id, qr)
    remote_eval("locals()['future']()")

    assert new_account.get_config("addr") == remote_eval("bob.get_config('addr')")


def test_keyupdate_against_core_2_48_march_2026(acf, alice_and_remote_bob):
    """Test 2.48 Bob learns a new relay of Alice from a keyupdate, and is shown nothing."""
    alice, alice_contact_bob, remote_eval = alice_and_remote_bob("2.48.0")

    def bob_sees():
        return remote_eval(
            "{'chats': len(bob.get_chatlist()),"
            " 'fresh': len(bob._rpc.get_fresh_msgs(bob.id)),"
            " 'contacts': len(bob.get_contacts()),"
            " 'alice_chat': bob._rpc.get_chat_id_by_contact_id(bob.id, bob_contact_alice.id) or 0}",
        )

    # Keyupdates go to contacts who plausibly hold our key:
    # an accepted chat alone is not enough, a message must have flowed.
    alice_chat = alice_contact_bob.create_chat()
    alice.set_config("keyupdate_debounce", "1")
    old_addr = alice.get_config("configured_addr")
    alice_chat.send_text("hi")
    assert remote_eval("bob.wait_for_incoming_msg().get_snapshot().text") == "hi"
    before = bob_sees()

    # Certificate merging keeps the newest direct key signature,
    # and signature timestamps have one-second resolution:
    # without waiting, the re-signed key can tie with the copy Bob holds, keeping his.
    time.sleep(2)
    alice.add_transport_from_qr(acf.get_account_qr())
    alice.bring_online()
    (new_addr,) = [t["addr"] for t in alice.list_transports() if t["addr"] != old_addr]

    # The 2.48 core has no encryption enforcement, but the keyupdate MDN without
    # referenced message keeps it invisible; merging happens before the trashing.
    for _ in range(60):
        if new_addr in remote_eval("bob_contact_alice.get_encryption_info()"):
            break
        time.sleep(1)
    else:
        pytest.fail("Bob never received the keyupdate")

    # It also leaves no trace: no chat with Alice, no message anywhere,
    # and no address-contact for the address it was sent from.
    assert bob_sees() == before
