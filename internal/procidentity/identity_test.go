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

// The macOS record is ps's lstart in the C locale and UTC, one space apart.
func TestLstartIsPsStartInTheCLocale(t *testing.T) {
	for _, tc := range []struct {
		at   time.Time
		want string
	}{
		{time.Date(2026, 10, 5, 7, 4, 2, 0, time.UTC), "Mon Oct 5 07:04:02 2026"},
		{time.Date(2026, 10, 25, 23, 59, 59, 0, time.UTC), "Sun Oct 25 23:59:59 2026"},
		{time.Date(2027, 1, 1, 0, 0, 0, 0, time.FixedZone("EDT", -4*3600)), "Fri Jan 1 04:00:00 2027"},
	} {
		if got := lstart(tc.at.Unix()); got != tc.want {
			t.Errorf("lstart(%s) = %q, want %q", tc.at, got, tc.want)
		}
	}
}

// oss-outage-open round k: the record names a live process the same way
// every time it is read (nothing in it is a time read now), and names no
// process once it has exited.
func TestOfNamesAProcessTheSameWayUntilItExits(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		if _, ok := Of(os.Getpid()); ok {
			t.Fatal("a system without a reader named a process")
		}
		return
	}
	first, ok := Of(os.Getpid())
	if !ok || first == "" {
		t.Fatal("no identity for this process")
	}
	time.Sleep(1100 * time.Millisecond)
	if again, _ := Of(os.Getpid()); again != first {
		t.Fatalf("identity moved: %q then %q", first, again)
	}
	if parent, ok := Of(os.Getppid()); !ok || parent == "" {
		t.Fatal("no identity for the parent process")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exited := exec.Command(self, "-test.run=^$")
	if err := exited.Run(); err != nil {
		t.Fatal(err)
	}
	if got, ok := Of(exited.ProcessState.Pid()); ok {
		t.Fatalf("an exited process still has an identity %q", got)
	}
	for _, pid := range []int{0, -1} {
		if _, ok := Of(pid); ok {
			t.Fatalf("pid %d has an identity", pid)
		}
	}
}
