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
