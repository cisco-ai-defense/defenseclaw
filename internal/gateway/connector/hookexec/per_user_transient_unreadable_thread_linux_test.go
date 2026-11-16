// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// A live thread of another process of the account that cannot be read for a
// moment (a process in the middle of exec) does not keep the recorded gateway
// from being the sole holder of its listener: the scan reads it again. A thread
// that stays unreadable does, as before. Without the second read, a call to a
// frozen own gateway on a host that builds or tests code was blamed on another
// process.
func TestListenerSoleHolderProofReadsAMomentarilyUnreadableThreadAgain(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every descriptor list")
	}
	const gateway = 4242
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	rows := []string{"0: 0100007F:4A1A 00000000:0000 0A 0 0 0 1000 0 11"}
	for _, tc := range []struct {
		name    string
		holds   []int
		settles bool
		want    bool
	}{
		{"unreadable for a moment, no listener held", []int{77}, true, true},
		{"unreadable for a moment, other socket and the listener copy", []int{11}, true, false},
		{"unreadable beyond the window", []int{77}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			procRoot := t.TempDir()
			writeThreadSockets(t, procRoot, gateway, gateway, []int{11})
			writeFakeProcess(t, procRoot, 5000,
				fakeThread{5000, "S", true, "own", nil},
				fakeThread{5001, "S", false, "own", tc.holds})
			fds := filepath.Join(procRoot, strconv.Itoa(5000), "task", "5001", "fd")
			if tc.settles {
				done := make(chan struct{})
				t.Cleanup(func() { <-done })
				go func() {
					defer close(done)
					time.Sleep(60 * time.Millisecond)
					_ = os.Chmod(fds, 0o755)
				}()
			}
			started := time.Now()
			got := listenersHeldOnlyBy(procTables(t, rows, nil), procRoot, gateway, server)
			if got != tc.want {
				t.Fatalf("listenersHeldOnlyBy = %v, want %v", got, tc.want)
			}
			if elapsed := time.Since(started); elapsed > unreadableThreadWindow+time.Second {
				t.Fatalf("the scan took %s, past the retry window %s", elapsed, unreadableThreadWindow)
			}
		})
	}
}
