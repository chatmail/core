import platform
import subprocess
import sys

from deltachat_rpc_client import DeltaChat, Rpc


def test_install_venv_and_use_other_core(tmp_path):
    venv = tmp_path.joinpath("venv1")
    subprocess.check_call([sys.executable, "-m", "venv", venv])
    if platform.system() == "Windows":
        python = venv / "Scripts" / "python.exe"
    else:
        python = venv / "bin" / "python"
    subprocess.check_call([python, "-m", "pip", "install", "deltachat-rpc-server==2.20.0"])
    rpc = Rpc(accounts_dir=tmp_path.joinpath("accounts"), rpc_server_path=venv.joinpath("bin", "deltachat-rpc-server"))

    with rpc:
        dc = DeltaChat(rpc)
        assert dc.rpc.get_system_info()["deltachat_core_version"] == "v2.20.0"
