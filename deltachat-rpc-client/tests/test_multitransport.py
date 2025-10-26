import pytest

from deltachat_rpc_client.rpc import JsonRpcError


def test_add_second_address(acfactory) -> None:
    account = acfactory.new_configured_account()
    assert len(account.list_transports()) == 1

    qr = acfactory.get_account_qr()
    account.add_transport_from_qr(qr)
    assert len(account.list_transports()) == 2

    account.add_transport_from_qr(qr)
    assert len(account.list_transports()) == 3

    first_addr = account.list_transports()[0]["addr"]
    second_addr = account.list_transports()[1]["addr"]

    # Cannot delete the first address.
    with pytest.raises(JsonRpcError):
        account.delete_transport(first_addr)

    account.delete_transport(second_addr)
    assert len(account.list_transports()) == 2


def test_change_address(acfactory) -> None:
    """Test Alice configuring a second transport and setting it as a primary one."""
    alice, bob = acfactory.get_online_accounts(2)

    bob.create_chat(alice)

    alice_chat_bob = alice.create_chat(bob)
    alice_chat_bob.send_text("Hello!")

    msg1 = bob.wait_for_incoming_msg().get_snapshot()
    sender_addr1 = msg1.sender.get_snapshot().address

    alice.stop_io()
    old_alice_addr = alice.get_config("configured_addr")
    qr = acfactory.get_account_qr()
    alice.add_transport_from_qr(qr)
    new_alice_addr = alice.list_transports()[1]["addr"]
    alice.set_config("configured_addr", new_alice_addr)
    alice.start_io()

    alice_chat_bob.send_text("Hello again!")

    msg2 = bob.wait_for_incoming_msg().get_snapshot()
    sender_addr2 = msg2.sender.get_snapshot().address

    assert msg1.sender == msg2.sender
    assert sender_addr1 != sender_addr2
    assert sender_addr1 == old_alice_addr
    assert sender_addr2 == new_alice_addr
