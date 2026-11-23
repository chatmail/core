#!/usr/bin/env python3
"""Check the Windows ARM64 binary and exercise its database over stdio JSON-RPC."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading


binary = Path(sys.argv[1]).resolve()
with binary.open("rb") as executable:
    assert executable.read(2) == b"MZ", "Expected a Windows executable"
    executable.seek(0x3C)
    pe_offset = struct.unpack("<I", executable.read(4))[0]
    executable.seek(pe_offset)
    assert executable.read(4) == b"PE\0\0", "Expected a PE header"
    machine = struct.unpack("<H", executable.read(2))[0]
    assert machine == 0xAA64, f"Expected ARM64 (0xAA64), got {machine:#x}"

subprocess.run([binary, "--version"], check=True, timeout=30)

with tempfile.TemporaryDirectory() as accounts:
    process = subprocess.Popen(
        [binary],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        env={**os.environ, "DC_ACCOUNTS_PATH": accounts},
    )
    # Bound the whole exchange, including reads if the server stops responding.
    timer = threading.Timer(60, process.kill)
    timer.start()
    try:
        def request(request_id, method):
            process.stdin.write(json.dumps({
                "jsonrpc": "2.0", "id": request_id, "method": method, "params": [],
            }) + "\n")
            process.stdin.flush()
            for line in process.stdout:
                response = json.loads(line)
                if response.get("id") == request_id:
                    assert "error" not in response, response
                    return response["result"]
            raise RuntimeError(f"RPC server exited before replying to {method}")

        assert request(1, "get_all_account_ids") == []
        account_id = request(2, "add_account")
        assert isinstance(account_id, int) and account_id > 0, account_id
        assert request(3, "get_all_account_ids") == [account_id]
        print("ARM64 executable started and created an account successfully")
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=10)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            timer.cancel()
            process.stdout.close()
    assert process.returncode == 0, process.returncode
