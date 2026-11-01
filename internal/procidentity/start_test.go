// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package procidentity

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

// StartTime orders processes the way the GAP-1465 legacy lock rule needs: a
// child started now is later than this test process, both are in the past.
func TestStartTimeOrdersAChildAfterItsParent(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("no start time reader on " + runtime.GOOS)
	}
	self, ok := StartTime(os.Getpid())
	if !ok || self.After(time.Now().Add(time.Second)) {
		t.Fatalf("own start = %v, %v", self, ok)
	}
	time.Sleep(1100 * time.Millisecond)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^$", "-test.timeout=30s")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Wait() }()
	started, ok := StartTime(child.Process.Pid)
	if !ok {
		t.Skip("the child exited before its start was read")
	}
	if !started.After(self) {
		t.Fatalf("child start %v is not after the parent's %v", started, self)
	}
	if _, ok := StartTime(0); ok {
		t.Fatal("pid 0 has a start time")
	}
}
