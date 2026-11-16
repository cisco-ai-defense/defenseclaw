// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package initgc keeps the garbage collector off while a DefenseClaw
// binary's packages initialize. The hook and the gateway link the whole CLI,
// whose package init allocates about 45 MB and keeps most of it. With the
// collector on, every process ran six or seven collections before main,
// about half the CPU of a hook or launcher-guard start. On an 8-processor
// Windows host a Claude Code turn that reads 60 files at once starts 120 of
// these processes, and that start-up CPU held the 60 answers for 3 to 4 s
// (GAP-0050). The package path sorts before the internal packages, so Go
// initializes it ahead of them; main calls Restore first.
package initgc

import "runtime/debug"

// configured is the collector setting the process started with (GOGC).
var configured = debug.SetGCPercent(-1)

// Restore gives the collector back the setting the process started with.
func Restore() { debug.SetGCPercent(configured) }
