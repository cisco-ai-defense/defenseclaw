// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package pinnedtest swaps a file at the check/use instant of a guard that
// takes its FileInfo with pathidentity.LstatPinned or StatPinned, so a test
// can prove the guard refuses the swapped file without any timing.
package pinnedtest

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// SwapAfterCheck renames replacement over path right after the first pinned
// stat of path returns, before the guard opens the path. It returns the
// number of swaps done (0 or 1). The hook is process-wide: a test that uses
// it must not run in parallel with another one that does.
func SwapAfterCheck(t testing.TB, path, replacement string) *atomic.Int32 {
	t.Helper()
	var swaps atomic.Int32
	want := filepath.Clean(path)
	restore := pathidentity.SetPinnedStatHookForTest(func(p string) {
		if filepath.Clean(p) != want || !swaps.CompareAndSwap(0, 1) {
			return
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Errorf("swap %s at the check/use instant: %v", path, err)
		}
	})
	t.Cleanup(restore)
	return &swaps
}
