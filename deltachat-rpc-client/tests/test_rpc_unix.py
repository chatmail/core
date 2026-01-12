from os import environ
import platform  # noqa
import signal
import subprocess
from sys import stderr
from time import sleep

import pytest

from deltachat_rpc_client import DeltaChat, RpcUnixSocket


@pytest.mark.skipif("platform.system() == 'Windows'")
def test_rpc_unix(tmp_path):
    socket_file = "/tmp/chatmail.sock" # path needs to be relative or short

    path = environ.get("PATH")
    assert path is not None

    popen = subprocess.Popen(
        f"deltachat-rpc-server --unix {socket_file}",
        shell=True,
        env=dict(
            DC_ACCOUNTS_PATH=f"{tmp_path}/accounts/test",
            rust_log="info",
            PATH=path
        )
    )

    sleep(1) # wait until socket exists # TODO this should not be needed

    rpc = RpcUnixSocket(socket_path=socket_file)
    with rpc:
        dc = DeltaChat(rpc)
        assert dc.rpc.get_system_info()["deltachat_core_version"] is not None
    popen.send_signal(signal.SIGINT)
    popen.wait()
