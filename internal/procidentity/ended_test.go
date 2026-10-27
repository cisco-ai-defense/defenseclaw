// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package procidentity

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// oss-outage-open round l loop 1 (P2): a zombie installer (or, on Windows,
// an exited one whose process object a handle keeps) kept its pid and its
// identity, so every reader held its lock for good. Ended tells it apart.
func TestEndedTellsAnExitedUnreapedProcessFromALiveOne(t *testing.T) {
	if Ended(os.Getpid()) {
		t.Fatal("this process reads as ended")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(self, "-test.run=^$")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid := child.Process.Pid
	reaped := false
	defer func() {
		if !reaped {
			_ = child.Wait()
		}
	}()
	deadline := time.Now().Add(20 * time.Second)
	for !Ended(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("pid %d never read as ended after it exited", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	reaped = true
	if Ended(pid) {
		t.Fatalf("a reaped pid %d still reads as ended", pid)
	}
	if Ended(0) || Ended(-1) {
		t.Fatal("no pid reads as ended")
	}
}
