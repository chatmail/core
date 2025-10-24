def test_add_second_address(acfactory) -> None:
    account = acfactory.new_configured_account()
    assert len(account.list_transports()) == 1

    qr = acfactory.get_account_qr()
    account.add_transport_from_qr(qr)
    assert len(account.list_transports()) == 2
