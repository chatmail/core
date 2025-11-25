import pytest


@pytest.mark.parametrize("version", ["2.20.0", "2.10.0"])
def test_qr_setup_contact(alice_and_remote_bob, version) -> None:
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
    alice, alice_contact_bob, remote_eval = alice_and_remote_bob("2.20.0")

    remote_eval("bob_contact_alice.create_chat().send_text('hello')")

    msg = alice.wait_for_incoming_msg()
    assert msg.get_snapshot().text == "hello"
