import pytest

from deltachat_rpc_client import EventType
from deltachat_rpc_client.rpc import JsonRpcError


def wait_for_autocrypt_setup_message(account):
    while True:
        event = account.wait_for_event()
        if event.kind == EventType.MSGS_CHANGED and event.msg_id != 0:
            msg_id = event.msg_id
            msg = account.get_message_by_id(msg_id)
            if msg.get_snapshot().is_setupmessage:
                return msg


def test_autocrypt_setup_message_key_transfer(acfactory):
    alice1 = acfactory.get_online_account()

    alice2 = acfactory.get_unconfigured_account()
    alice2.add_or_update_transport({"addr": alice1.get_config("addr"), "password": alice1.get_config("mail_pw")})
    alice2.bring_online()

    setup_code = alice1.initiate_autocrypt_key_transfer()
    msg = wait_for_autocrypt_setup_message(alice2)

    # Test that entering wrong code returns an error.
    with pytest.raises(JsonRpcError):
        msg.continue_autocrypt_key_transfer("7037-0673-6287-3013-4095-7956-5617-6806-6756")

    msg.continue_autocrypt_key_transfer(setup_code)


def test_ac_setup_message_twice(acfactory):
    alice1 = acfactory.get_online_account()

    alice2 = acfactory.get_unconfigured_account()
    alice2.add_or_update_transport({"addr": alice1.get_config("addr"), "password": alice1.get_config("mail_pw")})
    alice2.bring_online()

    # Send the first Autocrypt Setup Message and ignore it.
    _setup_code = alice1.initiate_autocrypt_key_transfer()
    wait_for_autocrypt_setup_message(alice2)

    # Send the second Autocrypt Setup Message and import it.
    setup_code = alice1.initiate_autocrypt_key_transfer()
    msg = wait_for_autocrypt_setup_message(alice2)

    msg.continue_autocrypt_key_transfer(setup_code)
