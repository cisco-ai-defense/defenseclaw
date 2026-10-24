// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procReplaceFileW = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

// replaceFileLikeSetup replaces path with replacement as the published
// standalone Setup does: [IO.File]::Replace, which calls ReplaceFileW with
// merge and access-list errors ignored, keeping the old file at backup.
func replaceFileLikeSetup(replacement, path, backup string) error {
	const ignoreMergeErrors, ignoreACLErrors = 0x2, 0x4
	names := make([]*uint16, 3)
	for i, name := range []string{path, replacement, backup} {
		pointer, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
		names[i] = pointer
	}
	ok, _, err := procReplaceFileW.Call(uintptr(unsafe.Pointer(names[0])), uintptr(unsafe.Pointer(names[1])),
		uintptr(unsafe.Pointer(names[2])), ignoreMergeErrors|ignoreACLErrors, 0, 0)
	if ok == 0 {
		return err
	}
	return nil
}

// GAP-0200: the published older Setup replaces the installed hook binary with
// one [IO.File]::Replace, which fails while any process holds the file open
// without delete sharing. A running hook image does not block it; the
// read-only checks DefenseClaw runs on every hook call did. Run every such
// check on the hook path continuously and replace the file underneath them
// as that Setup does: no replace may fail.
func TestReadOnlyHookBinaryChecksNeverBlockAnInstallerReplace(t *testing.T) {
	dir := t.TempDir()
	hook := filepath.Join(dir, windowsHookBinaryName)
	if err := os.WriteFile(hook, []byte("MZ installed hook"), 0o600); err != nil {
		t.Fatal(err)
	}
	checks := map[string]func(){
		"stableNativeWindowsPE":       func() { _ = stableNativeWindowsPE(hook) },
		"readStableNativeWindowsFile": func() { _, _ = readStableNativeWindowsFile(hook, 1<<20) },
		"managed hook digest":         func() { _, _ = managedHookBinarySHA256Hex(hook, false, 1<<20, 0) },
		"hook script digests":         func() { _, _ = readNativeFileShared(hook) },
	}
	for index, name := range slices.Sorted(maps.Keys(checks)) {
		check := checks[name]
		t.Run(name, func(t *testing.T) {
			var stop atomic.Bool
			var wg sync.WaitGroup
			for range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for !stop.Load() {
						check()
					}
				}()
			}
			failed := 0
			var last error
			for i := range 400 {
				replacement := filepath.Join(dir, fmt.Sprintf("replacement-%d", i))
				if err := os.WriteFile(replacement, []byte(fmt.Sprintf("MZ release %d", i)), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := replaceFileLikeSetup(replacement, hook, fmt.Sprintf("%s.backup-%d-%d", hook, index, i)); err != nil {
					failed++
					last = err
					_ = os.Remove(replacement)
				}
			}
			stop.Store(true)
			wg.Wait()
			if failed != 0 {
				t.Fatalf("%d of 400 replaces of the hook binary failed while %s ran: %v", failed, name, last)
			}
		})
	}
}
