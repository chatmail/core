import os
import subprocess
import sys

import execnet


def get_cross_v220(tmp_path, alice):
    venv = tmp_path.joinpath("venv1")
    python = sys.executable
    subprocess.check_call([python, "-m", "venv", venv])
    v = "2.20.0"
    pip = venv.joinpath("bin", "pip")
    subprocess.check_call([pip, "install", "pytest", f"deltachat-rpc-server=={v}", f"deltachat-rpc-client=={v}"])

    python = venv.joinpath("bin", "python")
    gw = execnet.makegateway(f"popen//python={python}")

    accounts_dir = str(tmp_path.joinpath("account1_venv1"))
    channel = gw.remote_exec(v220_loop)
    channel.send((accounts_dir, str(venv.joinpath("bin", "deltachat-rpc-server")), os.environ.get("CHATMAIL_DOMAIN")))
    sysinfo = channel.receive()
    assert sysinfo == "v2.20.0"
    channel.send(alice.self_contact.make_vcard())

    def eval(eval_str):
        channel.send(eval_str)
        return channel.receive()

    return eval


def v220_loop(channel):
    import os
    import pathlib

    from deltachat_rpc_client import DeltaChat, Rpc
    from deltachat_rpc_client.pytestplugin import ACFactory

    accounts_dir, rpc_server_path, chatmail_domain = channel.receive()
    os.environ["CHATMAIL_DOMAIN"] = chatmail_domain
    bin_path = str(pathlib.Path(rpc_server_path).parent)
    os.environ["PATH"] = bin_path + ":" + os.environ["PATH"]

    rpc = Rpc(accounts_dir=accounts_dir)
    with rpc:
        dc = DeltaChat(rpc)
        channel.send(dc.rpc.get_system_info()["deltachat_core_version"])
        acfactory = ACFactory(dc)
        bob = acfactory.get_online_account()
        alice_vcard = channel.receive()
        [alice_contact] = bob.import_vcard(alice_vcard)
        ns = {"bob": bob, "alice_contact": alice_contact}

        while 1:
            eval_str = channel.receive()
            res = eval(eval_str, ns)
            try:
                channel.send(res)
            except Exception:
                # some unserializable result
                channel.send(None)


def test_qr_setup_contact(acfactory, tmp_path) -> None:
    (alice,) = acfactory.get_online_accounts(1)

    remote_eval = get_cross_v220(tmp_path, alice)

    qr_code = alice.get_qr_code()
    remote_eval(f"bob.secure_join({qr_code!r})")
    alice.wait_for_securejoin_inviter_success()

    # Test that Alice verified Bob's profile.
    vcard = remote_eval("bob.self_contact.make_vcard()")
    [alice_contact_bob] = alice.import_vcard(vcard)
    alice_contact_bob_snapshot = alice_contact_bob.get_snapshot()
    assert alice_contact_bob_snapshot.is_verified

    remote_eval("bob.wait_for_securejoin_joiner_success()")

    # Test that Bob verified Alice's profile.
    assert remote_eval("alice_contact.get_snapshot().is_verified")
