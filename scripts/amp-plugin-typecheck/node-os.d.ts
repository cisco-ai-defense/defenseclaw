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
}

declare module 'node:fs/promises' {
  export function lstat(path: string): Promise<{
    uid: number
    mode: number
    isDirectory(): boolean
    isSocket(): boolean
  }>
}

declare module 'node:path' {
  export function dirname(path: string): string
}

declare module 'node:child_process' {
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

declare const Buffer: { from(value: string): Uint8Array }
declare const process: { env: Record<string, string | undefined> }
