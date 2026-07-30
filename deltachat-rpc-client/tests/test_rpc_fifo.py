import os
import platform  # noqa
import subprocess
import threading

import pytest

from deltachat_rpc_client import DeltaChat, RpcFIFO


@pytest.mark.skipif("platform.system() == 'Windows'")
def test_rpc_fifo(tmp_path):
    fn_request_fifo = tmp_path.joinpath("request_fifo")
    fn_response_fifo = tmp_path.joinpath("response_fifo")
    os.mkfifo(fn_request_fifo)
    os.mkfifo(fn_response_fifo)
    # without DC_ACCOUNTS_PATH the server creates an "accounts" dir in the current
    # working directory, which during a test run is inside the checkout
    env = {**os.environ, "DC_ACCOUNTS_PATH": str(tmp_path.joinpath("accounts"))}
    popen = subprocess.Popen(f"deltachat-rpc-server <{fn_request_fifo} >{fn_response_fifo}", shell=True, env=env)

    rpc = RpcFIFO(fn_response_fifo=fn_response_fifo, fn_request_fifo=fn_request_fifo)
    with rpc:
        dc = DeltaChat(rpc)
        assert dc.rpc.get_system_info()["deltachat_core_version"] is not None
    popen.wait()


@pytest.mark.skipif("platform.system() == 'Windows'")
def test_rpc_fifo_close_with_persistent_server(tmp_path):
    """close() must return even if the server keeps the response FIFO open."""
    fn_request_fifo = tmp_path.joinpath("request_fifo")
    fn_response_fifo = tmp_path.joinpath("response_fifo")
    os.mkfifo(fn_request_fifo)
    os.mkfifo(fn_response_fifo)
    env = {**os.environ, "DC_ACCOUNTS_PATH": str(tmp_path.joinpath("accounts"))}
    popen = subprocess.Popen(f"exec deltachat-rpc-server <{fn_request_fifo} >{fn_response_fifo}", shell=True, env=env)

    try:
        # keep the request FIFO open so the server never sees EOF on its stdin
        with open(fn_request_fifo, "wb"):
            rpc = RpcFIFO(fn_response_fifo=fn_response_fifo, fn_request_fifo=fn_request_fifo)
            rpc.start()
            assert rpc.get_system_info()["deltachat_core_version"] is not None

            closed = threading.Event()
            threading.Thread(target=lambda: (rpc.close(), closed.set()), daemon=True).start()
            assert closed.wait(timeout=30), "RpcFIFO.close() did not return"
    finally:
        popen.kill()
        popen.wait()
