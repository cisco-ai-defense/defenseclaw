// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

// substrate-1 GAP-0885: the own-shell walk (guestOwnShellFolders) does work
// that grows with the statements times the folders it follows, not with
// their square. On the failing-cd fan shapes (cd .cache; $CMD; cd s0 ..
// cd s7; then N statements, each run in up to 256 folders) join scanned its
// output for every folder it was handed (slices.Contains), so each statement
// cost folders^2, and the unread-command check was handed each && subtree
// again at every level of a chain, so a chain cost its length squared. The
// test counts that work (guestOwnShellWork) instead of timing it: the
// folder entries join probes and the statement bytes the unread check is
// handed.

// gap0885Walks gives each walk its own folder: guestOwnShellWalk keeps the
// last walks by script, folder and home, and a kept walk does no work.
var gap0885Walks atomic.Int64

// gap0885Work walks command once and returns the walk's counted work, and
// whether it read any statement after the unread command.
func gap0885Work(t *testing.T, command string) (probes, unreadBytes int64, read bool) {
	t.Helper()
	var joinProbes, checked atomic.Int64
	count := func(probes, unreadBytes int) {
		joinProbes.Add(int64(probes))
		checked.Add(int64(unreadBytes))
	}
	guestOwnShellWork.Store(&count)
	defer guestOwnShellWork.Store(nil)
	cwd := fmt.Sprintf("/home/u/w%d", gap0885Walks.Add(1))
	read = guestOwnShellFolders(command, cwd, "/home/u") != nil
	return joinProbes.Load(), checked.Load(), read
}

// gap0885CDs is k cds that may each fail: each one may double the folders.
func gap0885CDs(k int) string {
	var b strings.Builder
	for i := range k {
		fmt.Fprintf(&b, "cd s%d\n", i)
	}
	return b.String()
}

// gap0885Touches is n touch commands, each its own statement or, with sep
// " && ", one chain.
func gap0885Touches(n int, sep string) string {
	parts := make([]string, n)
	for i := range n {
		parts[i] = fmt.Sprintf("touch f%d", i)
	}
	return strings.Join(parts, sep)
}

// The three shapes of the gap (RV-SEC10 tcorpus2): fan8, fan8and, and
// fan8and with the unread command last, so the unread check runs along the
// whole chain.
func gap0885Fan(k, n int) string {
	return "cd .cache\nbash <<< 'true'\n$CMD\n" + gap0885CDs(k) + gap0885Touches(n, "\n") + "\necho x > out.txt"
}

func gap0885FanAnd(k, n int) string {
	return "cd .cache\n$CMD\n" + gap0885CDs(k) + gap0885Touches(n, " && ")
}

func gap0885FanAndLate(k, n int) string {
	return "cd .cache\n" + gap0885CDs(k) + gap0885Touches(n, " && ") + " && $CMD"
}

// gap0885Folders is the folders the walk follows after cd .cache and k
// failing cds: each doubles them, up to the bound.
func gap0885Folders(k int) int64 {
	return min(int64(2)<<k, maxSandboxGuestOwnShellFolders)
}

func TestGAP0885OwnShellWalkWorkIsStatementsTimesFolders(t *testing.T) {
	shapes := []struct {
		name  string
		shape func(k, n int) string
		read  bool
	}{
		{"fan", gap0885Fan, true},
		{"fanand", gap0885FanAnd, true},
		{"fanandlate", gap0885FanAndLate, false},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			// At the bound (fan8, 256 folders), join probes each folder
			// entry it is handed once: a few probes a statement and folder,
			// not one per folder already joined.
			for _, n := range []int{100, 200} {
				command := shape.shape(8, n)
				probes, unreadBytes, read := gap0885Work(t, command)
				statements := int64(n + 8 + 4)
				ceiling := 4 * statements * gap0885Folders(8)
				t.Logf("GAP0885 %s k=8 n=%d bytes=%d probes=%d (ceiling %d) unreadBytes=%d", shape.name, n, len(command), probes, ceiling, unreadBytes)
				if read != shape.read {
					t.Errorf("%s n=%d: walk read statements after the unread command = %v, want %v", shape.name, n, read, shape.read)
				}
				if probes == 0 || probes > ceiling {
					t.Errorf("%s n=%d: join probed %d folder entries, want 1..%d (4 x %d statements x %d folders)", shape.name, n, probes, ceiling, statements, gap0885Folders(8))
				}
				// The unread check reads each statement once: never more
				// bytes than the call has.
				if unreadBytes > int64(len(command)) {
					t.Errorf("%s n=%d: the unread check was handed %d bytes of a %d-byte call", shape.name, n, unreadBytes, len(command))
				}
			}
			// Doubling the folders (k=5: 64, k=6: 128) about doubles join's
			// work; folders^2 work would make it four times.
			small, _, _ := gap0885Work(t, shape.shape(5, 100))
			large, _, _ := gap0885Work(t, shape.shape(6, 100))
			t.Logf("GAP0885 %s n=100 probes k=5 %d, k=6 %d (x%.2f)", shape.name, small, large, float64(large)/float64(small))
			if small == 0 || 2*large > 5*small {
				t.Errorf("%s: join probes %d at 64 folders, %d at 128: over x2.5 for twice the folders", shape.name, small, large)
			}
			// Doubling the statements about doubles the unread check's
			// bytes; a chain re-read at every level makes it four times.
			_, shortBytes, _ := gap0885Work(t, shape.shape(8, 200))
			_, longBytes, _ := gap0885Work(t, shape.shape(8, 400))
			t.Logf("GAP0885 %s k=8 unreadBytes n=200 %d, n=400 %d", shape.name, shortBytes, longBytes)
			if shortBytes == 0 || 2*longBytes > 5*shortBytes {
				t.Errorf("%s: the unread check was handed %d bytes at 200 statements, %d at 400: over x2.5 for twice the statements", shape.name, shortBytes, longBytes)
			}
		})
	}
}
