//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"syscall"
	"unsafe"
)

// The uid membership check of each candidate group (GAP-0528) is Open
// Directory's mbr_check_membership(3) on the uuids mbr_uid_to_uuid(3) and
// mbr_gid_to_uuid(3) give, the calls `dsmemberutil checkmembership -u <uid>
// -g <gid>` makes. Starting dsmemberutil for each group cost three processes
// a group (the tool, the process-group watchdog shell and the shell it
// starts): an account in 95 groups (93 file-sharing groups on the lab Mac)
// started about 300 processes in one second at every 15-minute refresh of
// its directory facts, against a budget of 4 gateway processes per hook call
// (rel-1-0-6:GAP-0326). The same calls made in this process answer the same
// question with no process. What is checked, and which answer lists a group,
// is unchanged: only where the answer comes from moved.
//
// Release builds are CGO_ENABLED=0, so the trampolines in
// membership_darwin_*.s reach libSystem the way golang.org/x/sys/unix does,
// through the runtime's libc call path (internal/systemd does the same for
// launch_activate_socket).

//go:cgo_import_dynamic libc_mbr_uid_to_uuid mbr_uid_to_uuid "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_mbr_gid_to_uuid mbr_gid_to_uuid "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_mbr_check_membership mbr_check_membership "/usr/lib/libSystem.B.dylib"

var (
	mbrUIDToUUIDTrampolineAddr       uintptr
	mbrGIDToUUIDTrampolineAddr       uintptr
	mbrCheckMembershipTrampolineAddr uintptr
)

//go:linkname membershipSyscall syscall.syscall
func membershipSyscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

// openDirectoryUIDMember asks Open Directory whether uid is a member of gid.
// Replaced in tests.
var openDirectoryUIDMember = func(uid, gid uint32) (bool, error) {
	user, group, member := new([16]byte), new([16]byte), new(int32)
	// Each call returns 0 or an errno, as an int: only the low 32 bits are
	// defined.
	if rc, _, _ := membershipSyscall(mbrUIDToUUIDTrampolineAddr, uintptr(uid), uintptr(unsafe.Pointer(user)), 0); int32(rc) != 0 {
		return false, fmt.Errorf("unixidentity: mbr_uid_to_uuid(%d): %w", uid, syscall.Errno(int32(rc)))
	}
	if rc, _, _ := membershipSyscall(mbrGIDToUUIDTrampolineAddr, uintptr(gid), uintptr(unsafe.Pointer(group)), 0); int32(rc) != 0 {
		return false, fmt.Errorf("unixidentity: mbr_gid_to_uuid(%d): %w", gid, syscall.Errno(int32(rc)))
	}
	rc, _, _ := membershipSyscall(mbrCheckMembershipTrampolineAddr,
		uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(group)), uintptr(unsafe.Pointer(member)))
	runtime.KeepAlive(user)
	runtime.KeepAlive(group)
	if int32(rc) != 0 {
		return false, fmt.Errorf("unixidentity: mbr_check_membership(uid %d, gid %d): %w", uid, gid, syscall.Errno(int32(rc)))
	}
	return *member != 0, nil
}

// accountGroupsRunner is the command runner of the group listings: it
// answers each dsmemberutil uid membership check in this process and runs
// every other tool (id) as before.
var accountGroupsRunner = inProcessMembership(runTrustedCommand)

// inProcessMembership answers `dsmemberutil checkmembership -u <uid> -g
// <gid>` with openDirectoryUIDMember, in dsmemberutil's own words, under the
// same bound as the tool: the caller's context and defaultCommandTimeout. A
// failed or late answer is an error, as a failed or late dsmemberutil was.
// Every other command goes to next.
func inProcessMembership(next commandRunner) commandRunner {
	return func(ctx context.Context, path string, args []string, filters ...outputFilter) (commandResult, error) {
		uid, gid, ok := checkMembershipArgs(path, args)
		if !ok {
			return next(ctx, path, args, filters...)
		}
		if ctx == nil {
			ctx = context.Background()
		}
		ctx, cancel := context.WithTimeout(ctx, defaultCommandTimeout)
		defer cancel()
		if err := ctx.Err(); err != nil {
			return commandResult{}, fmt.Errorf("unixidentity: dsmemberutil timed out: %w", err)
		}
		type answer struct {
			member bool
			err    error
		}
		check := openDirectoryUIDMember
		done := make(chan answer, 1)
		go func() {
			member, err := check(uid, gid)
			done <- answer{member, err}
		}()
		select {
		case got := <-done:
			if got.err != nil {
				return commandResult{}, got.err
			}
			if got.member {
				return commandResult{stdout: []byte("user is a member of the group\n")}, nil
			}
			return commandResult{stdout: []byte("user is not a member of the group\n")}, nil
		case <-ctx.Done():
			return commandResult{}, fmt.Errorf("unixidentity: dsmemberutil timed out: %w", ctx.Err())
		}
	}
}

// checkMembershipArgs recognises exactly the uid membership check
// uidVerifiedGroupIDs runs.
func checkMembershipArgs(path string, args []string) (uid, gid uint32, ok bool) {
	if path != darwinDSMemberUtil || len(args) != 5 ||
		!slices.Equal([]string{args[0], args[1], args[3]}, []string{"checkmembership", "-u", "-g"}) {
		return 0, 0, false
	}
	u, err := strconv.ParseUint(args[2], 10, 32)
	if err != nil {
		return 0, 0, false
	}
	g, err := strconv.ParseUint(args[4], 10, 32)
	if err != nil {
		return 0, 0, false
	}
	return uint32(u), uint32(g), true
}
