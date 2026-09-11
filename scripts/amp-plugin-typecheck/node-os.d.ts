// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The plugin resolves the invoking account through `node:os`, which Amp
// provides at runtime but the harness does not type: pulling in @types/node
// would bring the whole Node surface into a compile-only check whose point is
// that the plugin stays dependency-free. Declare just the members the plugin
// reads, so a drift in how it uses them still fails the typecheck.
declare module 'node:os' {
  export function userInfo(): {
    uid: number
    gid: number
    username: string
    homedir: string
    shell: string | null
  }
}
