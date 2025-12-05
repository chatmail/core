import { StdioDeltaChat } from "@deltachat/jsonrpc-client";

export interface SearchOptions {
  /** whether take deltachat-rpc-server inside of $PATH*/
  takeVersionFromPATH: boolean;

  /** whether to disable the DELTA_CHAT_RPC_SERVER environment variable */
  disableEnvPath: boolean;
}

/**
 * 
 * @returns absolute path to deltachat-rpc-server binary
 * @throws when it is not found
 */
export function getRPCServerPath(
  options?: Partial<SearchOptions>
): string;



export type DeltaChatOverJsonRpcServer = StdioDeltaChat & {
    readonly pathToServerBinary: string;
};

export interface StartOptions {
  /** whether to disable outputting stderr to the parent process's stderr */
  muteStdErr: boolean;
}

/**
 * 
 * @param directory directory for accounts folder
 * @param options 
 */
export function startDeltaChat(directory: string, options?: Partial<SearchOptions & StartOptions> ): DeltaChatOverJsonRpcServer

export class DeltaChatOverJsonRpc extends StdioDeltaChat {
  constructor(
    directory: string,
    options?: Partial<SearchOptions & StartOptions>
  );
  readonly pathToServerBinary: string;
}

export namespace FnTypes {
    export type getRPCServerPath = typeof getRPCServerPath
    export type startDeltaChat = typeof startDeltaChat
}