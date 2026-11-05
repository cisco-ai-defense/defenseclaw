// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// GAP-0038 (review): a FIFO named gateway-activity.json parked the hook call
// in the read while it held the package-wide mutex, and a link to /dev/zero
// read without bound. Both read as no record: the call returns at once and
// a fresh regular record replaces them.
func TestPersistCoworkActivityIgnoresAFIFOOrDeviceRecord(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	for name, plant := range map[string]func(t *testing.T, path string){
		"fifo": func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"symlink to /dev/zero": func(t *testing.T, path string) {
			if err := os.Symlink("/dev/zero", path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dataDir, path := plantCoworkActivityRecord(t, plant)
			persistCoworkActivityWithin(t, dataDir, "PreToolUse", now)
			requireFreshCoworkActivity(t, dataDir, path, now)
		})
	}
}

// The open itself neither follows a final link nor waits for a FIFO writer
// (a FIFO swapped in after the Lstat).
func TestOpenCoworkActivityRecordRefusesALinkAndDoesNotBlockOnAFIFO(t *testing.T) {
	_, link := plantCoworkActivityRecord(t, func(t *testing.T, path string) {
		if err := os.Symlink("/dev/zero", path); err != nil {
			t.Fatal(err)
		}
	})
	if file, err := openCoworkActivityRecord(link); err == nil {
		file.Close()
		t.Fatal("opened the record through a symbolic link")
	}
	_, fifo := plantCoworkActivityRecord(t, func(t *testing.T, path string) {
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	done := make(chan error, 1)
	go func() {
		file, err := openCoworkActivityRecord(fifo)
		if err == nil {
			file.Close()
		}
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("open of a FIFO record blocked")
	}
}
