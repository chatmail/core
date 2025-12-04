import subprocess

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
def test_qr_setup_contact(alice_and_remote_bob, version) -> None:
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


def test_send_and_receive_message(alice_and_remote_bob) -> None:
    """Test other-core Bob profile can send a message to Alice on current core."""
    alice, alice_contact_bob, remote_eval = alice_and_remote_bob("2.20.0")

    remote_eval("bob_contact_alice.create_chat().send_text('hello')")

    msg = alice.wait_for_incoming_msg()
    assert msg.get_snapshot().text == "hello"


def test_second_device(acfactory, alice_and_remote_bob) -> None:
    """Test setting up current version as a second device for old version."""
    _alice, alice_contact_bob, remote_eval = alice_and_remote_bob("2.20.0")

    remote_eval("locals().setdefault('future', bob._rpc.provide_backup.future(bob.id))")
    qr = remote_eval("bob._rpc.get_backup_qr(bob.id)")
    new_account = acfactory.get_unconfigured_account()
    new_account._rpc.get_backup(new_account.id, qr)
    remote_eval("locals()['future']()")

    assert new_account.get_config("addr") == remote_eval("bob.get_config('addr')")
