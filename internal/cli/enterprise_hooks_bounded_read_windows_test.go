// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEnterpriseHookBoundedReadSharesPublicationAndRetriesTransientHolder(t *testing.T) {
	newRecord := func(t *testing.T) (string, os.FileInfo, *uint16) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "protected_targets.json")
		if err := os.WriteFile(path, []byte(`{"targets":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		return path, info, name
	}
	t.Run("publisher keeps renamed handle with delete access", func(t *testing.T) {
		path, info, name := newRecord(t)
		holder, err := windows.CreateFile(name, windows.GENERIC_READ|windows.DELETE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(holder)
		data, err := readEnterpriseHookBoundedFile(path, info, 1024, "hook guardian authorization")
		if err != nil || string(data) != `{"targets":[]}` {
			t.Fatalf("shared publication read = %q, %v", data, err)
		}
	})
	t.Run("exclusive transient holder", func(t *testing.T) {
		path, _, _ := newRecord(t)
		attempts := 0
		file, err := openEnterpriseHookBoundedFileWithRetry(path, func(path string) (*os.File, error) {
			attempts++
			if attempts < 3 {
				return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_SHARING_VIOLATION}
			}
			return os.Open(path)
		})
		if err != nil || attempts != 3 {
			t.Fatalf("transient holder open = %v after %d attempts", err, attempts)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("persistent holder stays an error", func(t *testing.T) {
		path, _, _ := newRecord(t)
		attempts := 0
		_, err := openEnterpriseHookBoundedFileWithRetry(path, func(path string) (*os.File, error) {
			attempts++
			return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_SHARING_VIOLATION}
		})
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || attempts != 10 {
			t.Fatalf("persistent holder error = %v after %d attempts", err, attempts)
		}
	})
}
