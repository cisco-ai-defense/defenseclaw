// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// rel-1-0-10:GAP-1164, black box: a gateway of this home this caller cannot
// open (one started elevated in another logon session: its process DACL
// grants only Administrators, SYSTEM and that session) still holds the port
// when its creation time is the one its gateway-api.json recorded. The
// stand-in is a child whose process DACL grants only SYSTEM; the creation
// time comes from the handle CreateProcess returned. Another creation time
// (a reused PID) is still "not held".
func TestHomeGatewayHoldsPortUnopenableGateway(t *testing.T) {
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
	if err := child.Start(); err != nil {
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
	recorded := strconv.FormatInt(created.Nanoseconds(), 10)
	if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)); err == nil {
		_ = windows.CloseHandle(h)
		t.Skip("the child opens for this caller (SeDebugPrivilege?): not the unopenable shape")
	}

	dir := t.TempDir()
	const port = 18975
	prev := homeGatewayPortHolder
	homeGatewayPortHolder = func(string, int) (PortHolder, error) { return PortHolder{PID: pid, UID: -1}, nil }
	t.Cleanup(func() { homeGatewayPortHolder = prev })
	write := func(identity string) {
		t.Helper()
		record := filepath.Join(dir, "gateway-api.json")
		_ = os.Remove(record)
		body := fmt.Sprintf(`{"pid":%d,"host":"127.0.0.1","port":%d,"start_identity":%q}`, pid, port, identity)
		if err := os.WriteFile(record, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := safefile.ProtectFile(record); err != nil {
			t.Fatal(err)
		}
	}

	write(recorded)
	if !HomeGatewayHoldsPort(dir, "127.0.0.1", port) {
		t.Fatal("this home's gateway that does not open for this caller, with its recorded creation time, holds the port")
	}
	write("1")
	if HomeGatewayHoldsPort(dir, "127.0.0.1", port) {
		t.Fatal("an unopenable process with another creation time (a reused PID) holds the port")
	}
}
