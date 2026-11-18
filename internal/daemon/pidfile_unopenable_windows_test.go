// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// rel-1-0-10:GAP-1314, black box: gateway.pid names this home's gateway,
// which this caller cannot open (one started elevated in another logon
// session; the stand-in is a child whose process DACL grants only SYSTEM).
// IsRunning cannot verify it, so it is not running for this shell, but the
// record stays: a refused stop must change nothing, and the elevated stop
// afterwards needs it. A creation time the kernel process list contradicts
// (a reused PID) is positive proof, and that record is still removed.
func TestIsRunningKeepsPIDFileOfUnopenableGateway(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestGAP1164ReusedPIDHelper$")
	child.Env = append(os.Environ(), "DC_GAP1164_HELPER=1")
	child.SysProcAttr = &syscall.SysProcAttr{ProcessAttributes: &syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		SecurityDescriptor: uintptr(unsafe.Pointer(sd)),
	}}
	err = child.Start()
	// sd is referenced only through a uintptr while CreateProcess reads it.
	runtime.KeepAlive(sd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	pid := child.Process.Pid
	var created windows.Filetime
	var timesErr error
	if err := child.Process.WithHandle(func(h uintptr) {
		var exit, kernel, user windows.Filetime
		timesErr = windows.GetProcessTimes(windows.Handle(h), &created, &exit, &kernel, &user)
	}); err != nil || timesErr != nil {
		t.Fatalf("creation time from the CreateProcess handle: %v %v", err, timesErr)
	}
	if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)); err == nil {
		_ = windows.CloseHandle(h)
		t.Skip("the child opens for this caller (SeDebugPrivilege?): not the unopenable shape")
	}

	d := New(t.TempDir())
	write := func(identity string) []byte {
		t.Helper()
		data, err := json.Marshal(pidInfo{PID: pid, Executable: os.Args[0], DataDir: d.dataDir, StartIdentity: identity})
		if err != nil {
			t.Fatal(err)
		}
		if err := safefile.WritePrivate(d.pidFile, data); err != nil {
			t.Fatal(err)
		}
		return data
	}

	want := write(strconv.FormatInt(created.Nanoseconds(), 10))
	if running, got := d.IsRunning(); running {
		t.Fatalf("IsRunning() = true, %d for a gateway this caller cannot open or verify", got)
	}
	if got, err := os.ReadFile(d.pidFile); err != nil || string(got) != string(want) {
		t.Fatalf("gateway.pid of this home's unopenable gateway after IsRunning = %q, %v; want it unchanged", got, err)
	}

	write("1")
	if running, _ := d.IsRunning(); running {
		t.Fatal("IsRunning() = true for a reused PID")
	}
	if _, err := os.Stat(d.pidFile); !os.IsNotExist(err) {
		t.Fatalf("gateway.pid naming a reused PID (creation time differs) was kept: %v", err)
	}
}
