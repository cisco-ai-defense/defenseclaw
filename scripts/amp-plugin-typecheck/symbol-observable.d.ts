// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Amp's public package uses the TC39 observable symbol, which TypeScript's
// standard library does not yet declare. Keep the compatibility declaration
// inside the compile-only harness so dependency checking can remain enabled.
declare global {
  interface SymbolConstructor {
    readonly observable: unique symbol
  }
}

export {}
