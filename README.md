<p align="center">
<img alt="Chatmail logo" src="https://github.com/user-attachments/assets/25742da7-a837-48cd-a503-b303af55f10d" width="300" style="float:middle;" />
</p>

<p align="center">
  <a href="https://github.com/chatmail/core/actions/workflows/ci.yml">
    <img alt="Rust CI" src="https://github.com/chatmail/core/actions/workflows/ci.yml/badge.svg">
  </a>
  <a href="https://deps.rs/repo/github/chatmail/core">
    <img alt="dependency status" src="https://deps.rs/repo/github/chatmail/core/status.svg">
  </a>
</p>

The chatmail core library implements low-level network and encryption protocols, 
integrated by many chat bots and higher level applications, 
allowing to securely participate in the globally scaled e-mail server network. 
We provide reproducibly-built `deltachat-rpc-server` static binaries
that offer a stdio-based high-level JSON-RPC API for instant messaging purposes. 

The following protocols are handled without requiring API users to know much about them: 

- secure TLS setup with DNS caching and shadowsocks/proxy support 

- robust [SMTP](https://github.com/chatmail/async-imap) 
  and [IMAP](https://github.com/chatmail/async-smtp) handling

- safe and interoperable [MIME parsing](https://github.com/staktrace/mailparse) 
  and [MIME building](https://github.com/stalwartlabs/mail-builder). 

- security-audited end-to-end encryption with [rPGP](https://github.com/rpgp/rpgp)
  and [Autocrypt and SecureJoin protocols](https://securejoin.rtfd.io)

- ephemeral [Peer-to-Peer networking using Iroh](https://iroh.computer) for multi-device setup and
  [webxdc realtime data](https://delta.chat/en/2024-11-20-webxdc-realtime). 

- a simulation- and real-world tested [P2P group membership
  protocol without requiring server state](https://github.com/chatmail/models/tree/main/group-membership). 


## Installing Rust and Cargo

To download and install the official compiler for the Rust programming language, and the Cargo package manager, run the command in your user environment:

```
$ curl https://sh.rustup.rs -sSf | sh
```

> On Windows, you may need to also install **Perl** to be able to compile deltachat-core.

## Using the CLI client

Compile and run the command line utility, using `cargo`:

```
$ cargo run --locked -p deltachat-repl -- ~/profile-db
```
where ~/profile-db is the database file. The utility will create it if it does not exist.

Optionally, install `deltachat-repl` binary with
```
$ cargo install --locked --path deltachat-repl/
```
and run as
```
$ deltachat-repl ~/profile-db
```

Configure your account (if not already configured):

```
Chatmail is awaiting your commands.
> set addr your@email.org
> set mail_pw yourpassword
> configure
```

Connect to your mail server (if already configured):

```
> connect
```

Export your public key to a vCard file:

```
> make-vcard my.vcard 1
```

Create contacts by address or vCard file:

```
> addcontact yourfriends@email.org
> import-vcard key-contact.vcard
```

List contacts:

```
> listcontacts
Contact#Contact#11: key-contact@email.org <key-contact@email.org>
Contact#Contact#Self: Me √ <your@email.org>
2 key contacts.
Contact#Contact#10: yourfriends@email.org <yourfriends@email.org>
1 address contacts.
```

Create a chat with your friend and send a message:

```
> createchat 10
Single#Chat#12 created successfully.
> chat 12
Selecting chat Chat#12
Single#Chat#12: yourfriends@email.org [yourfriends@email.org] Icon: profile-db-blobs/4138c52e5bc1c576cda7dd44d088c07.png
0 messages.
81.252µs to create this list, 123.625µs to mark all messages as noticed.
> send hi
```

List messages when inside a chat:

```
> chat
```

For more commands type:

```
> help
```

## Installing libdeltachat system wide

```
$ git clone https://github.com/chatmail/core.git
$ cd deltachat-core-rust
$ cmake -B build . -DCMAKE_INSTALL_PREFIX=/usr
$ cmake --build build
$ sudo cmake --install build
```

## Development

```sh
# run tests
$ cargo test --all
# build c-ffi
$ cargo build -p deltachat_ffi --release
```

## Debugging environment variables 

- `DCC_MIME_DEBUG`: if set outgoing and incoming message will be printed 

- `RUST_LOG=async_imap=trace,async_smtp=trace`: enable IMAP and
SMTP tracing in addition to info messages.

### Expensive tests

Some tests are expensive and marked with `#[ignore]`, to run these
use the `--ignored` argument to the test binary (not to cargo itself):
```sh
$ cargo test -- --ignored
```

### Fuzzing

Install [`cargo-bolero`](https://github.com/camshaft/bolero) with
```sh
$ cargo install cargo-bolero
```

Run fuzzing tests with
```sh
$ cd fuzz
$ cargo bolero test fuzz_mailparse -s NONE
```

Corpus is created at `fuzz/fuzz_targets/corpus`,
you can add initial inputs there.
For `fuzz_mailparse` target corpus can be populated with
`../test-data/message/*.eml`.

## Features

- `vendored`: When using Openssl for TLS, this bundles a vendored version.

## Update Provider Data

To add the updates from the
[provider-db](https://github.com/chatmail/provider-db) to the core,
check line `REV=` inside `./scripts/update-provider-database.sh`
and then run the script.

## Language bindings and frontend projects

Language bindings are available for:

- **C** \[[📂 source](./deltachat-ffi) | [📚 docs](https://c.delta.chat)\]
- **JS**: \[[📂 source](./deltachat-rpc-client) | [📦 npm](https://www.npmjs.com/package/@deltachat/jsonrpc-client) | [📚 docs](https://js.jsonrpc.delta.chat/)\]
- **Python** \[[📂 source](./python) | [📦 pypi](https://pypi.org/project/deltachat) | [📚 docs](https://py.delta.chat)\]
- **Go**
  - over jsonrpc: \[[📂 source](https://github.com/deltachat/deltachat-rpc-client-go/)\]
  - over cffi[^1]: \[[📂 source](https://github.com/deltachat/go-deltachat/)\]
- **Free Pascal**[^1] \[[📂 source](https://github.com/deltachat/deltachat-fp/)\]
- **Java** and **Swift** (contained in the Android/iOS repos)

The following "frontend" projects make use of the Rust-library
or its language bindings:

- [Android](https://github.com/deltachat/deltachat-android)
- [iOS](https://github.com/deltachat/deltachat-ios)
- [Desktop](https://github.com/deltachat/deltachat-desktop)
- [Pidgin](https://code.ur.gs/lupine/purple-plugin-delta/)
- [Telepathy](https://code.ur.gs/lupine/telepathy-padfoot/)
- [Ubuntu Touch](https://codeberg.org/lk108/deltatouch)
- several **Bots**

[^1]: Out of date / unmaintained, if you like those languages feel free to start maintaining them. If you have questions we'll help you, please ask in the issues.
