// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"runtime"
	"sync"
	"testing"
)

// hookCaseSlots holds one slot per shell hook a parallel subtest may have
// running. The slot count is the CPUs of this process, at least 4 and at most
// 16 (the golden test runs at most 16 hooks at once): most of a hook case is
// the hook waiting out its own outage window (3 s for a gateway that is not
// there), which costs no CPU, so a small count already overlaps the waits,
// and a hook still gets its answer window on a small CI runner.
var hookCaseSlots = sync.OnceValue(func() chan struct{} {
	return make(chan struct{}, max(4, min(16, runtime.GOMAXPROCS(0))))
})

// parallelHookCase runs the calling subtest in parallel with its siblings,
// holding one hook slot until the subtest and its cleanups are done. Use it
// only in a subtest that owns everything it touches (its own t.TempDir, its
// own server, its own port), starts no executable it has just written
// (a fork elsewhere while that file is open for writing makes the exec fail
// with ETXTBSY, GAP-1208), and sets no package variable or environment
// variable. The parent must not close what its subtests use before they end:
// a parallel subtest runs after the parent function has returned, so use
// t.Cleanup there, not defer.
func parallelHookCase(t *testing.T) {
	t.Helper()
	t.Parallel()
	slots := hookCaseSlots()
	slots <- struct{}{}
	t.Cleanup(func() { <-slots })
}

// warmNativeGatewayForHookTests builds the native gateway fixture once, in
// the parent test and before its parallel subtests start. The copy is written
// while nothing else in the process forks, so no subtest can exec it while a
// forked child still holds its write descriptor.
func warmNativeGatewayForHookTests(t *testing.T) {
	t.Helper()
	installNativeGatewayForHookTest(t, t.TempDir())
}
