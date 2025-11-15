import echo_and_quit
import py
import pytest


@pytest.fixture(scope="session")
def datadir():
    """The py.path.local object of the test-data/ directory."""
    for path in reversed(py.path.local(__file__).parts()):
        datadir = path.join("test-data")
        if datadir.isdir():
            return datadir
    pytest.skip("test-data directory not found")
    return None


@pytest.mark.skip("The test is flaky in CI and crashes the interpreter as of 2025-11-12")
def test_echo_quit_plugin(acfactory, lp):
    lp.sec("creating one echo_and_quit bot")
    botproc = acfactory.run_bot_process(echo_and_quit)

    lp.sec("creating a temp account to contact the bot")
    (ac1,) = acfactory.get_online_accounts(1)

    lp.sec("sending a message to the bot")
    bot_chat = ac1.qr_setup_contact(botproc.qr)
    ac1._evtracker.wait_securejoin_joiner_progress(1000)
    bot_chat.send_text("hello")

    lp.sec("waiting for the reply message from the bot to arrive")
    reply = ac1._evtracker.wait_next_incoming_message()
    assert reply.chat == bot_chat
    assert "hello" in reply.text
    lp.sec("send quit sequence")
    bot_chat.send_text("/quit")
    botproc.wait()
