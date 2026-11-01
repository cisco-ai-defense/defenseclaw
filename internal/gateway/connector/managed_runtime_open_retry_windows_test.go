// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"io/fs"
	"testing"

	"golang.org/x/sys/windows"
)

func TestManagedRuntimeOpenTransientWindows(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{err: &fs.PathError{Op: "open", Path: `C:\x`, Err: windows.ERROR_SHARING_VIOLATION}, want: true},
		{err: &fs.PathError{Op: "open", Path: `C:\x`, Err: windows.ERROR_LOCK_VIOLATION}, want: true},
		{err: &fs.PathError{Op: "open", Path: `C:\x`, Err: windows.ERROR_ACCESS_DENIED}, want: false},
		{err: &fs.PathError{Op: "open", Path: `C:\x`, Err: windows.ERROR_FILE_NOT_FOUND}, want: false},
	} {
		if got := managedRuntimeOpenTransient(tc.err); got != tc.want {
			t.Fatalf("managedRuntimeOpenTransient(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
