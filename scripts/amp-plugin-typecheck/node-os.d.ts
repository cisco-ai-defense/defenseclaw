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
    isDirectory(): boolean
    isFile(): boolean
    isSymbolicLink(): boolean
  }
}

declare module 'node:fs/promises' {
  export function lstat(path: string): Promise<{
    uid: number
    mode: number
    isDirectory(): boolean
    isSocket(): boolean
  }>
  export function stat(path: string): Promise<{ mtimeMs: number }>
  export function mkdir(
    path: string,
    options: { recursive?: boolean, mode?: number },
  ): Promise<string | undefined>
  export function open(path: string, flags: 'a', mode: number): Promise<{
    appendFile(data: string): Promise<void>
    close(): Promise<void>
  }>
}

declare module 'node:net' {
  export interface Socket {}
}

declare module 'node:http' {
  import type { Socket } from 'node:net'
  export class Agent {
    constructor(options: { keepAlive?: boolean, maxSockets?: number, maxFreeSockets?: number })
    destroy(): void
  }
  export interface IncomingMessage {
    statusCode?: number
    headers: Record<string, string | string[] | undefined>
    on(event: 'data', listener: (chunk: Buffer) => void): this
    on(event: 'end', listener: () => void): this
    on(event: 'error', listener: (error: Error) => void): this
  }
  export interface ClientRequest {
    on(event: 'error', listener: (error: Error) => void): this
    on(event: 'socket', listener: (socket: Socket) => void): this
    destroy(error?: Error): this
    end(chunk?: string): this
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

declare module 'node:path' {
  export function dirname(path: string): string
  export function join(...paths: string[]): string
}

declare module 'node:child_process' {
  export function execFileSync(
    file: string,
    args: readonly string[],
    options: {
      input: string
      timeout?: number
      maxBuffer?: number
      windowsHide?: boolean
      encoding: 'utf8'
    },
  ): string
  export function execFileSync(
    file: string,
    args: readonly string[],
    options: {
      timeout?: number
      maxBuffer?: number
      windowsHide?: boolean
      stdio?: readonly ('ignore' | 'pipe' | 'inherit')[]
    },
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

interface Buffer extends Uint8Array {
  toString(encoding?: 'utf8' | 'hex'): string
}
declare const Buffer: {
  from(value: string, encoding?: 'utf8' | 'hex'): Buffer
  concat(list: readonly Uint8Array[]): Buffer
}
declare const process: {
  env: Record<string, string | undefined>
  platform: string
  getuid?: () => number
}
