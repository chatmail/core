import * as T from "../generated/types.js";
import { EventType } from "../generated/types.js";
import * as RPC from "../generated/jsonrpc.js";
import { RawClient } from "../generated/client.js";
import { BaseTransport, Request } from "yerpc";
import { TinyEmitter } from "@deltachat/tiny-emitter";

type Events = { ALL: (accountId: number, event: EventType) => void } & {
  [Property in EventType["kind"]]: (
    accountId: number,
    event: Extract<EventType, { kind: Property }>,
  ) => void;
};

type ContextEvents = { ALL: (event: EventType) => void } & {
  [Property in EventType["kind"]]: (
    event: Extract<EventType, { kind: Property }>,
  ) => void;
};

export type DcEvent = EventType;
export type DcEventType<T extends EventType["kind"]> = Extract<
  EventType,
  { kind: T }
>;

export class BaseDeltaChat<
  Transport extends BaseTransport<any>,
> extends TinyEmitter<Events> {
  rpc: RawClient;
  private contextEmitters: { [key: number]: TinyEmitter<ContextEvents> } = {};

  //@ts-ignore
  private eventTask: Promise<void>;

  constructor(
    public transport: Transport,
    /**
     * Whether to start calling {@linkcode RawClient.getNextEvent}
     * and emitting the respective events on this class.
     */
    startEventLoop: boolean,
  ) {
    super();
    this.rpc = new RawClient(this.transport);
    if (startEventLoop) {
      this.eventTask = this.eventLoop();
    }
  }

  /**
   * @see the constructor's `startEventLoop`
   */
  async eventLoop(): Promise<void> {
    while (true) {
      for (const event of await this.rpc.getNextEventBatch()) {
        //@ts-ignore
        this.emit(event.event.kind, event.contextId, event.event);
        this.emit("ALL", event.contextId, event.event);

        if (this.contextEmitters[event.contextId]) {
          this.contextEmitters[event.contextId].emit(
            event.event.kind,
            //@ts-ignore
            event.event as any,
          );
          this.contextEmitters[event.contextId].emit("ALL", event.event as any);
        }
      }
    }
  }

  /**
   * @deprecated use {@linkcode BaseDeltaChat.rpc.getAllAccounts} instead.
   */
  async listAccounts(): Promise<T.Account[]> {
    return await this.rpc.getAllAccounts();
  }

  /**
   * A convenience function to listen on events binned by `account_id`
   * (see {@linkcode RawClient.getAllAccounts}).
   */
  getContextEvents(account_id: number) {
    if (this.contextEmitters[account_id]) {
      return this.contextEmitters[account_id];
    } else {
      this.contextEmitters[account_id] = new TinyEmitter();
      return this.contextEmitters[account_id];
    }
  }
}

export class StdioDeltaChat extends BaseDeltaChat<StdioTransport> {
  close() {}
  constructor(input: any, output: any, startEventLoop: boolean) {
    const transport = new StdioTransport(input, output);
    super(transport, startEventLoop);
  }
}

export class StdioTransport extends BaseTransport {
  constructor(
    public input: any,
    public output: any,
  ) {
    super();

    var buffer = "";
    this.output.on("data", (data: any) => {
      buffer += data.toString();
      while (buffer.includes("\n")) {
        const n = buffer.indexOf("\n");
        const line = buffer.substring(0, n);
        const message = JSON.parse(line);
        this._onmessage(message);
        buffer = buffer.substring(n + 1);
      }
    });
  }

  _send(message: any): void {
    const serialized = JSON.stringify(message);
    this.input.write(serialized + "\n");
  }
}
