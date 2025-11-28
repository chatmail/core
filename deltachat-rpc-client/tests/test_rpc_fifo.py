import os
import platform  # noqa
import subprocess

import pytest

from deltachat_rpc_client import DeltaChat, RpcFIFO


@pytest.mark.skipif("platform.system() == 'Windows'")
def test_rpc_fifo(tmp_path):
    fn_request_fifo = tmp_path.joinpath("request_fifo")
    fn_response_fifo = tmp_path.joinpath("response_fifo")
    os.mkfifo(fn_request_fifo)
    os.mkfifo(fn_response_fifo)
    popen = subprocess.Popen(f"deltachat-rpc-server <{fn_request_fifo} >{fn_response_fifo}", shell=True)

    rpc = RpcFIFO(fn_response_fifo=fn_response_fifo, fn_request_fifo=fn_request_fifo)
    with rpc:
        dc = DeltaChat(rpc)
        assert dc.rpc.get_system_info()["deltachat_core_version"] is not None
    popen.wait()
