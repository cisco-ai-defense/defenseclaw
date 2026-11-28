// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build (linux || darwin) && (amd64 || arm64)

package hookpaths

// goroutineKey names the calling goroutine: the address of its runtime
// record (its g), which the runtime keeps in a register (arm64) or the
// thread's TLS slot (amd64) for the goroutine that runs (getg). It was the
// goroutine number, read from the first line of a traceback of the whole
// stack (runtime.Stack): 35 to 55 us on the deep stack of a copy-mode actor
// decision, which looks its call up about 27 times (each HookCall,
// HookCallState, ShareBodyUnreadCauses and private-key read, the directory
// walk), a tenth of the hook's answer and the p99 past 1.12x 1.0.10
// (rel-1-0-10:GAP-2215). Reading the register is the same in every frame.
//
// No two live goroutines have the same g, and a goroutine keeps its g for its
// whole life, over stack growth and thread moves. The runtime gives the g of
// an ended goroutine to a later one, so a key names one goroutine only while
// it runs: every hook call ends before the goroutine that began it does (its
// end is deferred), so no open call has the key of a goroutine that did not
// begin it.
func goroutineKey() uint64 { return uint64(getg()) }

// getg is the address of the calling goroutine's g (goroutine_key_*.s).
func getg() uintptr
