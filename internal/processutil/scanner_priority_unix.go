// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package processutil

import "golang.org/x/sys/unix"

// A scan runs below the priority of the gateway that starts it (rel-1-0-10
// GAP-0251). The gateway answers every hook call within the hook answer
// budget (3.5 s from the start of the hook process), and each skill, plugin
// or MCP scan is a whole runtime of its own (the Python CLI or the scanner
// runtime). A startup rescan that admits a hundred plugins at once (Hermes
// ships 106, and an update brings new copies of all of them) keeps two such
// scans running for minutes; on a two-core Windows host they took the CPU
// the gateway needed, and the first tool call after setup ran unchecked
// ("the gateway is running but did not answer in time"). At the same
// priority the gateway's work took about five times as long beside busy
// scans (TestHookWorkAnswersWhileScansFillTheCPU). So each scan that
// RunTracked starts (skill and plugin scans, the plugin manifest read, the
// scanner version probe) runs nicer than the gateway on Linux and macOS and
// in the below-normal priority class on Windows, and so does each MCP scan
// that RunTreeIsolated starts on Linux and Windows. A scan still uses every
// idle cycle; the gateway's work, hook answers first, runs ahead of it.
// What a scanner starts inherits the lower priority.

// scannerNiceIncrement is how much nicer than the gateway a scan runs on
// Linux and macOS, capped at maxNice.
const scannerNiceIncrement = 10

// maxNice is the lowest Unix scheduling priority.
const maxNice = 19

// lowerScannerPriority makes the caller scannerNiceIncrement nicer, up to
// maxNice: on Linux the calling thread (the nice value is a thread attribute,
// which a fork and an exec keep), on macOS the whole process. Only the
// supervisor of a scan calls it, on the thread that then execs or starts the
// scanner, so the scanner and what it starts inherit the value; the gateway
// itself is never niced. A failure leaves the priority as it was: the scan
// still runs, at the gateway priority.
func lowerScannerPriority() {
	current := currentNice()
	if target := min(current+scannerNiceIncrement, maxNice); target > current {
		_ = unix.Setpriority(unix.PRIO_PROCESS, 0, target)
	}
}
