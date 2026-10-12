import os
import sys

import pytest


def anonymous_mib(pid):
    with open(f"/proc/{pid}/smaps_rollup") as f:
        for line in f:
            if line.startswith("Anonymous:"):
                return int(line.split()[1]) // 1024
    raise LookupError("Anonymous")


@pytest.mark.skipif(sys.platform != "linux", reason="reads /proc")
def test_attachment_memory_is_returned(acf, rpc, tmp_path):
    # See also comments for `tune_malloc` in `deltachat-rpc-server/src/main.rs`
    ac1, ac2 = acf.get_online_accounts(2)
    chat1 = acf.get_accepted_chat(ac1, ac2)
    chat2 = ac2.create_chat(ac1)
    blob = tmp_path / "blob.bin"
    blob.write_bytes(os.urandom(20 << 20))
    before = anonymous_mib(rpc.process.pid)

    for sender_chat, receiver in ((chat1, ac2), (chat2, ac1)):
        sender_chat.send_file(str(blob))
        event = receiver.wait_for_incoming_msg_event()
        assert receiver.get_message_by_id(event.msg_id).get_snapshot().file_bytes == 20 << 20
    for ac in (ac1, ac2):
        rpc.wait_for_all_work_done(ac.id)

    grown = anonymous_mib(rpc.process.pid) - before
    assert grown < 64, f"the server kept {grown} MiB after two 20 MiB attachments"
