# @deltachat/jsonrpc-client

This package is a client for the jsonrpc server.

> If you are looking for the functions in the documentation, they are under [`RawClient`](https://js.jsonrpc.delta.chat/classes/RawClient.html).

### Important Terms

- [delta chat core](https://github.com/deltachat/deltachat-core-rust/) the heart of all Delta Chat clients. Handels all the heavy lifting (email, encryption, ...) and provides an easy api for bots and clients (`getChatlist`, `getChat`, `getContact`, ...).
- [jsonrpc](https://www.jsonrpc.org/specification) is a json based protocol
  for applications to speak to each other by [remote procedure calls](https://en.wikipedia.org/wiki/Remote_procedure_call) (short RPC),
  which basically means that the client can call methods on the server by sending a json messages.
- [`deltachat-rpc-server`](https://github.com/deltachat/deltachat-core-rust/tree/main/deltachat-rpc-server) provides the jsonrpc api over stdio (stdin/stdout)
- [`@deltachat/stdio-rpc-server`](https://www.npmjs.com/package/@deltachat/stdio-rpc-server) is an easy way to install `deltachat-rpc-server` from npm and use it from nodejs.

#### Transport

You need to connect this client to an instance of deltachat core via a transport.

Currently there are 2 transports available:

- (recomended) `StdioTransport` usable from `StdioDeltaChat` - speak to `deltachat-rpc-server` directly
- `WebsocketTransport` usable from `WebsocketDeltaChat`

You can also make your own transport, for example deltachat desktop uses a custom transport that sends the json messages over electron ipc.
Just implement your transport based on the `Transport` interface - look at how the [stdio transport is implemented](https://github.com/deltachat/deltachat-core-rust/blob/7121675d226e69fd85d0194d4b9c4442e4dd8299/deltachat-jsonrpc/typescript/src/client.ts#L113) for an example, it's not hard.

## Usage

> The **minimum** nodejs version for `@deltachat/stdio-rpc-server` is `16`

```
npm i @deltachat/stdio-rpc-server @deltachat/jsonrpc-client
```

```js
import { startDeltaChat } from "@deltachat/stdio-rpc-server";
// Import constants you might need later
import { C } from "@deltachat/jsonrpc-client";

async function main() {
  const dc = await startDeltaChat("deltachat-data");
  console.log(await dc.rpc.getSystemInfo());
  dc.close();
}
main();
```

For a more complete example refer to <https://github.com/deltachat-bot/echo/tree/master/nodejs_stdio_jsonrpc>.

### Listening for events

```ts
dc.on("Info", (accountId, { msg }) =>
  console.info(accountId, "[core:info]", msg)
);
// Or get an event emitter for only one account
const emitter = dc.getContextEvents(accountId);
emitter.on("IncomingMsg", async ({ chatId, msgId }) => {
  const message = await dc.rpc.getMessage(accountId, msgId);
  console.log("got message in chat " + chatId + " : ", message.text);
});
```

### Getting Started

This section describes how to handle the Delta Chat core library over the jsonrpc bindings.
For general information about Delta Chat itself,
see <https://delta.chat> and <https://github.com/deltachat>.

Let's start.

First of all, you have to start the deltachat-rpc-server process.

```js
import { startDeltaChat } from "@deltachat/stdio-rpc-server";
const dc = await startDeltaChat("deltachat-data");
```

Then we have to create an Account (also called Context or profile) that is bound to a database.
The database is a normal SQLite file with a "blob directory" beside it.
But these details are handled by deltachat's account manager.
So you just have to tell the account manager to create a new account:

```js
const accountId = await dc.rpc.addAccount();
```

After that, register event listeners so you can see what core is doing:
Intenally `@deltachat/jsonrpc-client` implments a loop that waits for new events and then emits them to javascript land.
```js
dc.on("Info", (accountId, { msg }) =>
  console.info(accountId, "[core:info]", msg)
);
```

Now you can **configure the account:**
```js
// use some real test credentials here
await dc.rpc.setConfig(accountId, "addr", "alice@example.org")
await dc.rpc.setConfig(accountId, "mail_pw", "***")
// you can also set multiple config options in one call
await dc.rpc.batchSetConfig(accountId, {
     "addr": "alice@example.org",
     "mail_pw": "***"
})

// after setting the credentials attempt to login
await dc.rpc.configure(accountId)
```

`configure()` returns a promise that is rejected on error (with await is is thrown).
The configuration itself may take a while. You can monitor it's progress like this:
```js
dc.on("ConfigureProgress", (accountId, { progress, comment }) => {
    console.log(accountId, "ConfigureProgress", progress, comment);
});
// make sure to register this event handler before calling `dc.rpc.configure()`
```

The configuration result is saved in the database.
On subsequent starts it is not needed to call `dc.rpc.configure(accountId)`
(you can check this using `dc.rpc.isConfigured(accountId)`).

On a successfully configuration delta chat core automatically connects to the server, however subsequent starts you **need to do that manually** by calling `dc.rpc.startIo(accountId)` or `dc.rpc.startIoForAllAccounts()`.

```js
if (!await dc.rpc.isConfigured(accountId)) {
    // use some real test credentials here
    await dc.rpc.batchSetConfig(accountId, {
        "addr": "alice@example.org",
        "mail_pw": "***"
    })
    await dc.rpc.configure(accountId)
} else {
    await dc.rpc.startIo(accountId)
}
```

Now you can **send the first message:**

```js
const contactId = await dc.rpc.createContact(accountId, "bob@example.org", null /* optional name */)
const chatId = await dc.rpc.createChatByContactId(accountId, contactId)

await dc.rpc.miscSendTextMessage(accountId, chatId, "Hi, here is my first message!")
```

`dc.rpc.miscSendTextMessage()` returns immediately;
the sending itself is done in the background.
If you check the testing address (bob),
you should receive a normal e-mail.
Answer this e-mail in any e-mail program with "Got it!",
and the IO you started above will **receive the message**.

You can then **list all messages** of a chat as follows:

```js
let i = 0;
for (const msgId of await exp.rpc.getMessageIds(120, 12, false, false)) {
    i++;
    console.log(`Message: ${i}`, (await dc.rpc.getMessage(120, msgId)).text);
}
```

This will output the following two lines:
```
Message 1: Hi, here is my first message!
Message 2: Got it!
```

<!-- TODO: ### Clean shutdown? - seems to be more advanced to call async functions on exit, also is this needed in this usecase? -->

## Further information

- `@deltachat/stdio-rpc-server`
  - [package on npm](https://www.npmjs.com/package/@deltachat/stdio-rpc-server)
  - [source code on github](https://github.com/deltachat/deltachat-core-rust/tree/main/deltachat-rpc-server/npm-package)
- [use `@deltachat/stdio-rpc-server` on an usuported platform](https://github.com/deltachat/deltachat-core-rust/tree/main/deltachat-rpc-server/npm-package#how-to-use-on-an-unsupported-platform)
- The issue-tracker for the core library is here: <https://github.com/deltachat/deltachat-core-rust/issues>

If you need further assistance,
please do not hesitate to contact us
through the channels shown at https://delta.chat/en/contribute

Please keep in mind, that your derived work
must respect the Mozilla Public License 2.0 of deltachat-rpc-server
and the respective licenses of the libraries deltachat-rpc-server links with.