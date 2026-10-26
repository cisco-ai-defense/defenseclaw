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

declare module 'node:fs/promises' {
  export function mkdir(path: string, options: { recursive: boolean, mode: number }): Promise<string | undefined>
  export function open(path: string, flags: string, mode: number): Promise<{
    appendFile(data: string): Promise<void>
    close(): Promise<void>
  }>
  export function stat(path: string): Promise<{ mtimeMs: number }>
  export function lstat(path: string): Promise<{
    uid: number
    mode: number
    isDirectory(): boolean
    isSocket(): boolean
  }>
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

declare module 'node:path' {
  export function dirname(path: string): string
  export function isAbsolute(path: string): boolean
  export function join(...paths: string[]): string
}

declare module 'node:child_process' {
  interface ExecFileSyncOptions {
    timeout?: number
    maxBuffer?: number
    windowsHide?: boolean
    env?: Record<string, string>
    input?: string
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
  ): Uint8Array
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

declare module 'node:net' {
  export interface Socket {}
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
    on(event: 'data', listener: (chunk: Buffer) => void): void
    on(event: 'end', listener: () => void): void
    on(event: 'error', listener: (error: Error) => void): void
  }
  interface ClientRequest {
    on(event: 'error', listener: (error: Error) => void): void
    on(event: 'socket', listener: (socket: Socket) => void): void
    destroy(error?: Error): void
    end(body?: string): void
  }
  export function request(options: {
    hostname: string
    port: string
    path: string
    method: string
    headers: Record<string, string>
    agent: Agent
    signal?: AbortSignal
  }, callback: (res: IncomingMessage) => void): ClientRequest
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
  toString(encoding?: string): string
}
declare const Buffer: {
  from(value: string, encoding?: string): Buffer
  concat(chunks: readonly Buffer[]): Buffer
}
declare const process: { env: Record<string, string | undefined>, platform: string, getuid?(): number }
