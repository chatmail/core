"""JSON-RPC client module."""

from __future__ import annotations

import contextlib
import itertools
import json
import logging
import os
import subprocess
import sys
from queue import Empty, Queue
from threading import Thread
from typing import Any, Iterator, Optional


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
        queue: Queue = Queue()
        # Register before testing for shutdown, so that either the reader loop
        # finds this request while draining, or the test below catches it here.
        # Testing first would race with the reader loop finishing in between.
        self.rpc.request_results[request_id] = queue
        if self.rpc.request_queue_closed:
            self.rpc._fail_request(request_id)
        else:
            self.rpc.request_queue.put(request)

        def rpc_future():
            """Wait for the request to receive a result."""
            response = queue.get()
            if "error" in response:
                raise JsonRpcError(response["error"])
            return response.get("result", None)

        return rpc_future


class Rpc:
    """RPC client."""

    def __init__(
        self,
        accounts_dir: Optional[str] = None,
        rpc_server_path="deltachat-rpc-server",
        **kwargs,
    ):
        """Initialize RPC client.

        The 'kwargs' arguments will be passed to subprocess.Popen().
        """
        if accounts_dir:
            kwargs["env"] = {
                **kwargs.get("env", os.environ),
                "DC_ACCOUNTS_PATH": str(accounts_dir),
            }

        self._kwargs = kwargs
        self.rpc_server_path = rpc_server_path
        self.process: subprocess.Popen
        self.id_iterator: Iterator[int]
        self.event_queues: dict[int, Queue]
        # Map from request ID to a Queue which provides a single result
        self.request_results: dict[int, Queue]
        self.request_queue: Queue[Any]
        # Emulates `request_queue.shutdown(immediate=False)`, which needs Python 3.13:
        # https://github.com/python/cpython/blob/v3.13.0/Lib/queue.py#L236-L257
        # Note that `request_queue_closed` is set by the reader loop.
        self.request_queue_closed: bool
        self.closing: bool
        self.reader_thread: Thread
        self.writer_thread: Thread
        self.events_thread: Thread

    def start(self) -> None:
        """Start RPC server subprocess and wait for successful initialization.

        This method blocks until the RPC server responds to an initial
        health-check RPC call (get_system_info).
        If the server fails to start
        (e.g., due to an invalid accounts directory),
        a JsonRpcError is raised.
        """
        popen_kwargs = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
        if sys.version_info >= (3, 11):
            # Prevent subprocess from capturing SIGINT.
            popen_kwargs["process_group"] = 0
        else:
            # `process_group` is not supported before Python 3.11.
            popen_kwargs["preexec_fn"] = os.setpgrp  # noqa: PLW1509

        popen_kwargs.update(self._kwargs)
        self.process = subprocess.Popen(self.rpc_server_path, **popen_kwargs)

        self.id_iterator = itertools.count(start=1)
        self.event_queues = {}
        self.request_results = {}
        self.request_queue = Queue()
        self.request_queue_closed = False
        self.closing = False
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
            # The reader_loop already saw EOF on stdout, so the process
            # has exited and stderr is available.
            stderr = self.process.stderr.read().decode(errors="replace").strip()
            self.closing = True
            self._shutdown_loops()
            if stderr:
                raise JsonRpcError(f"RPC server failed to start: {stderr}") from e
            raise JsonRpcError(f"RPC server startup check failed: {e}") from e
        logging.info(
            "RPC server ready. Core version: %s",
            system_info.get("deltachat_core_version", "unknown"),
        )

    def close(self) -> None:
        """Terminate RPC server process and wait until the reader loop finishes."""
        self.closing = True
        self.stop_io_for_all_accounts()
        # Let `events_loop` stop cleanly on `closing` before the pipe goes away,
        # otherwise it might exit through an "RPC server closed" error instead.
        self.events_thread.join()
        self._shutdown_loops()

    def _shutdown_loops(self) -> None:
        """Close the server pipe and wait for the loop threads to finish.

        The writer blocks on an empty request queue,
        so it needs the sentinel to notice the shutdown.
        """
        with contextlib.suppress(BrokenPipeError):
            # An exited server may leave data unflushed,
            # which close() would try to write out again.
            self.process.stdin.close()
        self.request_queue.put(None)
        self.reader_thread.join()
        self.writer_thread.join()
        self.events_thread.join()

    def _fail_request(self, request_id: int) -> None:
        """Answer a registered request with an error, unless it was answered already."""
        queue = self.request_results.pop(request_id, None)
        if queue is not None:
            queue.put({"error": {"code": -32000, "message": "RPC server closed"}})

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        self.close()

    def reader_loop(self) -> None:
        """Process JSON-RPC responses from the RPC server process output."""
        try:
            while line := self.process.stdout.readline():
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
            # Shut the request queue first, so that requests registered from now
            # on are failed by their caller, then answer the pending ones here.
            self.request_queue_closed = True
            for request_id in list(self.request_results):
                self._fail_request(request_id)

    def writer_loop(self) -> None:
        """Writer loop ensuring only a single thread writes requests."""
        try:
            while request := self.request_queue.get():
                data = (json.dumps(request) + "\n").encode()
                self.process.stdin.write(data)
                self.process.stdin.flush()
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
