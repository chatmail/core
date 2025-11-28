"""JSON-RPC client module."""

from __future__ import annotations

import itertools
import json
import logging
import os
import subprocess
import sys
from queue import Empty, Queue
from threading import Thread
from typing import TYPE_CHECKING, Any, Iterator, Optional

if TYPE_CHECKING:
    import io


class JsonRpcError(Exception):
    """JSON-RPC error."""


class RpcMethod:
    """RPC method."""

    def __init__(self, rpc: "Rpc", name: str):
        self.rpc = rpc
        self.name = name

    def __call__(self, *args) -> Any:
        """Call JSON-RPC method synchronously."""
        future = self.future(*args)
        return future()

    def future(self, *args) -> Any:
        """Call JSON-RPC method asynchronously."""
        request_id = next(self.rpc.id_iterator)
        request = {
            "jsonrpc": "2.0",
            "method": self.name,
            "params": args,
            "id": request_id,
        }
        self.rpc.request_results[request_id] = queue = Queue()
        self.rpc.request_queue.put(request)

        def rpc_future():
            """Wait for the request to receive a result."""
            response = queue.get()
            if response is RpcShutdownError:
                raise RpcShutdownError(f"no response for {request_id}/{self.name} but rpc is shutting down")
            if "error" in response:
                raise JsonRpcError(response["error"])
            return response.get("result", None)

        return rpc_future


class RpcShutdownError(Exception):
    """Raised in RPC methods if the connection to server is closing."""


class BaseRpc:
    """Base Rpc class which requires 'connect_to_server' and 'disconnect_from_server' methods
    from subclasses to work concretely."""

    def __init__(self):
        self.id_iterator: Iterator[int]
        self.event_queues: dict[int, Queue]
        # Map from request ID to a Queue which provides a single result
        self.request_results: dict[int, Queue]
        self.request_queue: Queue[Any]
        self.server_stdin: io.Writer[bytes]
        self.server_stdout: io.Reader[bytes]
        self.closing: bool
        self.reader_thread: Thread
        self.writer_thread: Thread
        self.events_thread: Thread

    def start(self) -> None:
        """Start RPC server subprocess."""
        self.server_stdout, self.server_stdin = self.connect_to_server()
        self.id_iterator = itertools.count(start=1)
        self.event_queues = {}
        self.request_results = {}
        self.request_queue = Queue()
        self.closing = False
        self.reader_thread = Thread(target=self.reader_loop)
        self.reader_thread.start()
        self.writer_thread = Thread(target=self.writer_loop)
        self.writer_thread.start()
        self.events_thread = Thread(target=self.events_loop)
        self.events_thread.start()

    def close(self) -> None:
        """Terminate RPC server process and wait until the reader loop finishes."""
        self.closing = True
        self.disconnect_from_server()
        self.reader_thread.join()
        self.events_thread.join()
        self.request_queue.put(None)
        self.writer_thread.join()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        self.close()

    def reader_loop(self) -> None:
        """Process JSON-RPC responses from the RPC server process output."""
        try:
            while line := self.server_stdout.readline():
                response = json.loads(line)
                if "id" in response:
                    response_id = response["id"]
                    self.request_results.pop(response_id).put(response)
                else:
                    logging.warning("Got a response without ID: %s", response)
        except Exception:
            # Log an exception if the reader loop dies.
            logging.exception("Exception in the reader loop")

        # terminate pending rpc requests because no responses can arrive anymore
        for queue in self.request_results.values():
            queue.put(RpcShutdownError)

    def writer_loop(self) -> None:
        """Writer loop ensuring only a single thread writes requests."""
        try:
            while request := self.request_queue.get():
                data = (json.dumps(request) + "\n").encode()
                self.server_stdin.write(data)
                self.server_stdin.flush()

        except Exception:
            # Log an exception if the writer loop dies.
            logging.exception("Exception in the writer loop")

    def get_queue(self, account_id: int) -> Queue:
        """Get event queue corresponding to the given account ID."""
        if account_id not in self.event_queues:
            self.event_queues[account_id] = Queue()
        return self.event_queues[account_id]

    def events_loop(self) -> None:
        """Request new events and distributes them between queues."""
        try:
            while True:
                if self.closing:
                    return
                try:
                    event = self.get_next_event()
                except RpcShutdownError:
                    return
                account_id = event["contextId"]
                queue = self.get_queue(account_id)
                event = event["event"]
                logging.debug("account_id=%d got an event %s", account_id, event)
                queue.put(event)
        except Exception:
            # Log an exception if the event loop dies.
            logging.exception("Exception in the event loop")

    def wait_for_event(self, account_id: int) -> Optional[dict]:
        """Wait for the next event from the given account and returns it."""
        queue = self.get_queue(account_id)
        return queue.get()

    def clear_all_events(self, account_id: int):
        """Remove all queued-up events for a given account. Useful for tests."""
        queue = self.get_queue(account_id)
        try:
            while True:
                queue.get_nowait()
        except Empty:
            pass

    def __getattr__(self, attr: str):
        return RpcMethod(self, attr)


class Rpc(BaseRpc):
    """RPC client that runs and connects to a deltachat-rpc-server in a subprocess."""

    def __init__(self, accounts_dir: Optional[str] = None, rpc_server_path: Optional[str] = "deltachat-rpc-server"):
        """Initialize RPC client.

        The given arguments will be passed to subprocess.Popen().
        """
        super(Rpc, self).__init__()
        self._accounts_dir = accounts_dir
        self.rpc_server_path: str = rpc_server_path

    def connect_to_server(self):
        popen_kwargs = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE}
        if sys.version_info >= (3, 11):
            # Prevent subprocess from capturing SIGINT.
            popen_kwargs["process_group"] = 0
        else:
            # `process_group` is not supported before Python 3.11.
            popen_kwargs["preexec_fn"] = os.setpgrp  # noqa: PLW1509

        if self._accounts_dir:
            popen_kwargs["env"] = os.environ.copy()
            popen_kwargs["env"]["DC_ACCOUNTS_PATH"] = str(self._accounts_dir)

        process = subprocess.Popen(self.rpc_server_path, **popen_kwargs)
        return process.stdout, process.stdin

    def disconnect_from_server(self):
        self.stop_io_for_all_accounts()
        self.server_stdin.close()


class RpcFIFO(BaseRpc):
    """RPC client that runs and connects to a deltachat-rpc-server through FIFO files."""

    def __init__(self, fn_request_fifo: str, fn_response_fifo: str):
        super(RpcFIFO, self).__init__()
        self.fn_request_fifo = fn_request_fifo
        self.fn_response_fifo = fn_response_fifo

    def connect_to_server(self):
        server_stdin = open(self.fn_request_fifo, "wb")  # noqa
        server_stdout = open(self.fn_response_fifo, "rb")  # noqa
        return server_stdout, server_stdin

    def disconnect_from_server(self):
        self.server_stdin.close()
        self.server_stdout.close()
