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
    dc.close()
}
main()
```

For a more complete example refer to <https://github.com/deltachat-bot/echo/tree/master/nodejs_stdio_jsonrpc>.

### Listening for events

```ts
dc.on("Info", (accountId, { msg }) =>
    console.info(accountId, "[core:info]", msg)
);
// Or get an event emitter for only one account
const emitter = dc.getContextEvents(accountId)
emitter.on("IncomingMsg", async ({chatId, msgId}) => {
    const message = await dc.rpc.getMessage(accountId, msgId)
    console.log("got message in chat "+chatId+" : ", message.text) 
})
```

## Further information

- `@deltachat/stdio-rpc-server`
  - [package on npm](https://www.npmjs.com/package/@deltachat/stdio-rpc-server)
  - [source code on github](https://github.com/deltachat/deltachat-core-rust/tree/main/deltachat-rpc-server/npm-package)
- [use `@deltachat/stdio-rpc-server` on an usuported platform](https://github.com/deltachat/deltachat-core-rust/tree/main/deltachat-rpc-server/npm-package#how-to-use-on-an-unsupported-platform)