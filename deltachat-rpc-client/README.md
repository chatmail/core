# Delta Chat RPC python client

RPC client connects to standalone Delta Chat RPC server `deltachat-rpc-server`
and provides asynchronous interface to it.

## Getting started

To use Delta Chat RPC client, first build a `deltachat-rpc-server` with `cargo build -p deltachat-rpc-server`
or download a prebuilt release.
Install it anywhere in your `PATH`.

[Create a virtual environment](https://docs.python.org/3/library/venv.html)
if you don't have one already and activate it.
```
$ python -m venv env
$ . env/bin/activate
```

Install `deltachat-rpc-client` from source:
```
$ cd deltachat-rpc-client
$ pip install .
```

## Testing

1. Build `deltachat-rpc-server` with `cargo build -p deltachat-rpc-server`.
2. Install tox `pip install -U tox`
3. Run `CHATMAIL_DOMAIN=nine.testrun.org PATH="../target/debug:$PATH" tox`.

Additional arguments to `tox` are passed to pytest, e.g. `tox -- -s` does not capture test output.


## Activating current checkout of deltachat-rpc-client and -server for development 

Go to root repository directory and run: 
```
$ scripts/make-rpc-testenv.sh 
$ source venv/bin/activate 
```

## Using in REPL

Setup a development environment:
```
$ tox --devenv env
$ . env/bin/activate
```

```
$ python
>>> from deltachat_rpc_client import *
>>> rpc = Rpc()
>>> rpc.start()
>>> dc = DeltaChat(rpc)
>>> system_info = dc.get_system_info()
>>> system_info["level"]
'awesome'
>>> rpc.close()
```
