// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

const podSignalFilterHelper = "DC_PROCESSUTIL_POD_SIGNAL_FILTER_HELPER"

func TestPodSignalFallbackBlocksProcessGroupAndPID1(t *testing.T) {
	if os.Getenv(podSignalFilterHelper) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPodSignalFallbackBlocksProcessGroupAndPID1$")
		cmd.Env = append(os.Environ(), podSignalFilterHelper+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("signal filter helper: %v\n%s", err, out)
		}
		return
	}
	filter, err := scannerFilter(true)
	if err != nil {
		t.Fatal(err)
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	err = unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0)
	runtime.KeepAlive(filter)
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range []int{1, 0, -1, -syscall.Getpgrp()} {
		if err := unix.Kill(pid, 0); err != unix.EPERM {
			t.Errorf("kill(%d, 0) = %v, want EPERM", pid, err)
		}
	}
	if err := unix.Kill(os.Getpid(), 0); err != nil {
		t.Errorf("self signal check was refused: %v", err)
	}
}
