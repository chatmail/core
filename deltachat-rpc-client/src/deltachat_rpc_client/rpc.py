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
from typing import Any, BinaryIO, Iterator, Optional


class JsonRpcError(Exception):
    """JSON-RPC error."""


class RpcShutdownError(JsonRpcError):
    """Raised in RPC methods if the connection to server is closing."""


class RpcMethod:
    """RPC method."""

    def __init__(self, rpc: "BaseRpc", name: str):
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
            if response is None:
                raise RpcShutdownError(f"no response for {request_id}/{self.name} while rpc is shutting down")
            if "error" in response:
                raise JsonRpcError(response["error"])
            return response.get("result", None)

        return rpc_future


class BaseRpc:
    """Base Rpc class which requires 'connect_to_server' and 'disconnect_from_server' methods
    from subclasses to work concretely."""

    def __init__(self):
        self.id_iterator: Iterator[int]
        self.event_queues: dict[int, Queue]
        # Map from request ID to a Queue which provides a single result
        self.request_results: dict[int, Queue]
        self.request_queue: Queue[Any]
        self.server_stdin: BinaryIO
        self.server_stdout: BinaryIO
        self.closing: bool
        self.reader_stopping: bool
        self.reader_thread: Thread
        self.writer_thread: Thread
        self.events_thread: Thread

    def start(self) -> None:
        """Connect to the RPC server and wait for successful initialization.

        This method blocks until the RPC server responds to an initial
        health-check RPC call (get_system_info).
        If the server fails to start
        (e.g., due to an invalid accounts directory),
        a JsonRpcError is raised.
        """
        self.server_stdout, self.server_stdin = self.connect_to_server()
        self.id_iterator = itertools.count(start=1)
        self.event_queues = {}
        self.request_results = {}
        self.request_queue = Queue()
        self.closing = False
        self.reader_stopping = False
        self.reader_thread = Thread(target=self.reader_loop)
        self.reader_thread.start()
        self.writer_thread = Thread(target=self.writer_loop)
        self.writer_thread.start()
        self.events_thread = Thread(target=self.events_loop)
        self.events_thread.start()

        # Perform a health-check RPC call to ensure the server started
        # successfully and the accounts directory is usable.
        try:
            system_info = self.get_system_info()
        except (JsonRpcError, Exception) as e:
            details = self.get_startup_error_details()
            if details:
                raise JsonRpcError(f"RPC server failed to start: {details}") from e
            raise JsonRpcError(f"RPC server startup check failed: {e}") from e
        logging.info(
            "RPC server ready. Core version: %s",
            system_info.get("deltachat_core_version", "unknown"),
        )

    def get_startup_error_details(self) -> str:
        """Return server-side diagnostics for a failed startup."""
        return ""

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
                # not self.closing: the subprocess server still answers the
                # stop_io_for_all_accounts() that close() sends
                if self.reader_stopping:
                    break
                response = json.loads(line)
                if "id" in response:
                    response_id = response["id"]
                    self.request_results.pop(response_id).put(response)
                else:
                    logging.warning("Got a response without ID: %s", response)
        except Exception:
            # Log an exception if the reader loop dies.
            logging.exception("Exception in the reader loop")
        finally:
            # terminate pending rpc requests because no responses can arrive anymore
            for queue in list(self.request_results.values()):
                queue.put(None)

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
            while events := self.get_next_event_batch():
                for event in events:
                    account_id = event["contextId"]
                    queue = self.get_queue(account_id)
                    payload = event["event"]
                    logging.debug("account_id=%d got an event %s", account_id, payload)
                    queue.put(payload)
                if self.closing:
                    return
        except RpcShutdownError:
            # The server connection went away while waiting for the next batch.
            return
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


class RpcSubprocess(BaseRpc):
    """RPC client that runs and connects to a deltachat-rpc-server in a subprocess."""

    def __init__(self, accounts_dir: Optional[str] = None, rpc_server_path="deltachat-rpc-server"):
        super(RpcSubprocess, self).__init__()
        self._accounts_dir = accounts_dir
        self.rpc_server_path = rpc_server_path
        self.process: subprocess.Popen

    def connect_to_server(self):
        popen_kwargs = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
        if sys.version_info >= (3, 11):
            # Prevent subprocess from capturing SIGINT.
            popen_kwargs["process_group"] = 0
        else:
            # `process_group` is not supported before Python 3.11.
            popen_kwargs["preexec_fn"] = os.setpgrp  # noqa: PLW1509

        if self._accounts_dir:
            popen_kwargs["env"] = os.environ.copy()
            popen_kwargs["env"]["DC_ACCOUNTS_PATH"] = str(self._accounts_dir)

        self.process = subprocess.Popen(self.rpc_server_path, **popen_kwargs)
        return self.process.stdout, self.process.stdin

    def get_startup_error_details(self) -> str:
        # The reader_loop already saw EOF on stdout, so the process
        # has exited and stderr is available.
        return self.process.stderr.read().decode(errors="replace").strip()

    def disconnect_from_server(self):
        self.stop_io_for_all_accounts()
        self.server_stdin.close()


# backward compatibility
Rpc = RpcSubprocess


class RpcFIFO(BaseRpc):
    """RPC client connecting to an already running deltachat-rpc-server.

    Only use one client per FIFO pair: a FIFO has no per-client routing,
    so a second client would steal responses and events.
    """

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
        # a server outliving this client keeps the response FIFO open, so closing
        # it would deadlock on the buffer lock held by the blocked readline()
        self.reader_stopping = True
        self.wakeup_reader()
        self.reader_thread.join()
        self.server_stdout.close()

    def wakeup_reader(self) -> None:
        try:
            fd = os.open(self.fn_response_fifo, os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            return  # nobody is reading anymore, so there is nothing to wake
        try:
            os.write(fd, b"\n")
        finally:
            os.close(fd)
