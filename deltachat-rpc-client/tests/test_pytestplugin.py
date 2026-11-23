from unittest.mock import MagicMock

import pytest

from deltachat_rpc_client.pytestplugin import RPCAccountFactory


@pytest.mark.parametrize("domain", [None, ""])
@pytest.mark.parametrize("method", ["get_credentials", "get_account_qr"])
def test_online_accounts_require_chatmail_domain(monkeypatch, domain, method) -> None:
    if domain is None:
        monkeypatch.delenv("CHATMAIL_DOMAIN", raising=False)
    else:
        monkeypatch.setenv("CHATMAIL_DOMAIN", domain)
    factory = RPCAccountFactory(MagicMock())

    with pytest.raises(pytest.skip.Exception, match="CHATMAIL_DOMAIN is not configured"):
        getattr(factory, method)()


def test_online_accounts_use_configured_domain(monkeypatch) -> None:
    monkeypatch.setenv("CHATMAIL_DOMAIN", "ci.example.org")
    factory = RPCAccountFactory(MagicMock())

    address, password = factory.get_credentials()
    username, domain = address.split("@")
    assert domain == "ci.example.org"
    assert password == f"{username}${username}"
    assert factory.get_account_qr() == "dcaccount:ci.example.org"
