// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The plugin uses a few Node built-ins, which Amp provides at runtime but
// the harness does not type: pulling in @types/node would bring the whole
// Node surface into a compile-only check whose point is that the plugin
// stays dependency-free. Declare just the members the plugin uses, so a
// drift in how it uses them still fails the typecheck.
declare module 'node:os' {
  export function userInfo(): {
    uid: number
    gid: number
    username: string
    homedir: string
    shell: string | null
  }
  export function homedir(): string
}

declare module 'node:fs' {
  export function lstatSync(path: string): {
    uid: number
    mode: number
    size: number
    isFile(): boolean
    isDirectory(): boolean
    isSymbolicLink(): boolean
  }
  export function readFileSync(path: string, encoding: 'utf8'): string
}

declare module 'node:fs/promises' {
  export function lstat(path: string): Promise<{
    uid: number
    mode: number
    size: number
    mtimeMs: number
    isFile(): boolean
    isDirectory(): boolean
    isSocket(): boolean
  }>
  export function stat(path: string): Promise<{ mtimeMs: number }>
  export function mkdir(path: string, options: { recursive: true, mode: number }): Promise<string | undefined>
  interface FileHandle {
    appendFile(data: string): Promise<void>
    close(): Promise<void>
  }
  export function open(path: string, flags: 'a', mode: number): Promise<FileHandle>
}

declare module 'node:path' {
  export function dirname(path: string): string
  export function isAbsolute(path: string): boolean
  export function join(...paths: string[]): string
}

declare module 'node:child_process' {
  interface ExecFileSyncOptions {
    input?: string
    timeout?: number
    maxBuffer?: number
    windowsHide?: boolean
    env?: Record<string, string>
    encoding?: 'utf8'
    stdio?: readonly ('ignore' | 'pipe' | 'inherit')[]
  }
  export function execFileSync(
    file: string,
    args: readonly string[],
    options: ExecFileSyncOptions & { encoding: 'utf8' },
  ): string
  export function execFileSync(
    file: string,
    args: readonly string[],
    options: ExecFileSyncOptions,
  ): string | Uint8Array
  export function execFile(
    file: string,
    args: readonly string[],
    options: { timeout?: number, maxBuffer?: number, windowsHide?: boolean },
    callback: (error: Error | null, stdout: string, stderr: string) => void,
  ): {
    stdin: {
      on(event: 'error', listener: (error: Error) => void): unknown
      end(chunk: string): unknown
    } | null
  }
}

declare module 'node:crypto' {
  interface Hash {
    update(data: string): Hash
    digest(encoding: 'hex'): string
  }
  export function createHash(algorithm: 'sha256'): Hash
  export function createHmac(algorithm: 'sha256', key: string): Hash
  export function randomBytes(size: number): { toString(encoding: 'hex'): string }
  export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean
}

declare module 'node:net' {
  // Only compared by identity: the proven request must reuse this socket.
  export class Socket {
    readonly destroyed: boolean
  }
}

declare module 'node:http' {
  import type { Socket } from 'node:net'
  export class Agent {
    constructor(options: { keepAlive: boolean, maxSockets: number, maxFreeSockets: number })
    destroy(): void
  }
  interface IncomingMessage {
    statusCode?: number
    headers: Record<string, string | string[] | undefined>
    on(event: 'data', listener: (chunk: Buffer) => void): IncomingMessage
    on(event: 'end', listener: () => void): IncomingMessage
    on(event: 'error', listener: (error: Error) => void): IncomingMessage
  }
  interface ClientRequest {
    on(event: 'error', listener: (error: Error) => void): ClientRequest
    on(event: 'socket', listener: (socket: Socket) => void): ClientRequest
    end(body?: string): ClientRequest
    destroy(error?: Error): ClientRequest
  }
  export function request(
    options: {
      hostname: string
      port: string
      path: string
      method: string
      headers: Record<string, string>
      agent: Agent
      signal?: AbortSignal
    },
    callback: (res: IncomingMessage) => void,
  ): ClientRequest
}

interface Buffer extends Uint8Array {
  toString(encoding?: string): string
}
declare const Buffer: {
  from(value: string, encoding?: string): Buffer
  concat(chunks: readonly Uint8Array[]): Buffer
}
declare const process: {
  env: Record<string, string | undefined>
  platform: string
  pid: number
  getuid?(): number
  kill(pid: number, signal?: number | string): boolean
}
