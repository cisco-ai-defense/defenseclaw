// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package connector

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// A file system that cannot exchange two names must not turn a rollback
// conversion into a plain replacement: that is a check followed by a rename,
// and a save made between them would be lost. The conversion is refused, the
// file keeps every save, and no staging file is left.
func TestRollbackConversionRefusesWhereTheFileSystemCannotExchange(t *testing.T) {
	toEarlier := devinWindowsHookFormPairs([]string{devinGuardTestLauncher}, false)
	comment := []byte("// operator note added during rollback\n")
	for _, saves := range []int{0, 1, devinConversionAttempts} {
		name := map[int]string{0: "no save", 1: "one save", devinConversionAttempts: "saves under every attempt"}[saves]
		t.Run(name, func(t *testing.T) {
			real := atomicExchange
			atomicExchange = func(_, _ string) error { return unix.ENOTSUP }
			t.Cleanup(func() { atomicExchange = real })
			dataDir, root, path, _ := devinProjectSetUp(t)
			setUp, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			made := 0
			atomicFileAfterConfirm = func(p string) {
				if made >= saves || !sameManagedTargetPath(p, path) {
					return
				}
				made++
				old, rerr := os.ReadFile(path)
				if rerr == nil {
					rerr = os.WriteFile(path, append(append([]byte{}, comment...), old...), 0o600)
				}
				if rerr != nil {
					t.Error(rerr)
				}
			}
			t.Cleanup(func() { atomicFileAfterConfirm = nil })
			_, err = convertDevinHooksFile(path, dataDir, "devin", toEarlier, true, nil)
			atomicFileAfterConfirm = nil
			if !errors.Is(err, errHeldConversionNeedsExchange) {
				t.Fatalf("conversion error = %v, want the refusal for a file system without exchange", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := setUp
			if saves > 0 {
				want = append(append([]byte{}, comment...), setUp...)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("file = %q, want the bytes before the conversion plus %d save(s)", got, saves)
			}
			leftovers, _ := filepath.Glob(filepath.Join(root, ".tmp-*"))
			if len(leftovers) != 0 {
				t.Fatalf("staging files left behind: %v", leftovers)
			}
		})
	}
}

// A file that is removed between the check and the replacement is not created
// again: the conversion starts over from what is there and finds nothing to do.
func TestRollbackConversionDoesNotRecreateAFileRemovedBeforePublication(t *testing.T) {
	toEarlier := devinWindowsHookFormPairs([]string{devinGuardTestLauncher}, false)
	dataDir, root, path, _ := devinProjectSetUp(t)
	atomicFileAfterConfirm = func(p string) {
		if sameManagedTargetPath(p, path) {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(func() { atomicFileAfterConfirm = nil })
	n, err := convertDevinHooksFile(path, dataDir, "devin", toEarlier, true, nil)
	atomicFileAfterConfirm = nil
	if err != nil || n != 0 {
		t.Fatalf("conversion = %d, %v; want nothing rewritten and no error", n, err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("the removed file was created again: %v", err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(root, ".tmp-*"))
	if len(leftovers) != 0 {
		t.Fatalf("staging files left behind: %v", leftovers)
	}
}
