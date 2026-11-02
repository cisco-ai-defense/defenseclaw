// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const cleanDarwinACLListing = "drwx------  3 user  staff  96 Nov  2 10:00 /x\n"

func TestHookAPIACLVerdictCacheReusesPassUntilInodeOrTimesChange(t *testing.T) {
	cache := &hookAPIACLVerdictCache{max: 8}
	stamp := hookAPIDirectoryStamp{dev: 1, ino: 10, mtime: unix.Timespec{Sec: 100}, ctime: unix.Timespec{Sec: 100}}
	identify := func(string) (hookAPIDirectoryStamp, bool) { return stamp, true }
	inspections := 0
	inspect := func(context.Context, string) ([]byte, error) {
		inspections++
		return []byte(cleanDarwinACLListing), nil
	}
	validate := func() {
		t.Helper()
		if err := cache.validate("/x", time.Second, identify, inspect); err != nil {
			t.Fatal(err)
		}
	}

	validate()
	validate()
	if inspections != 1 {
		t.Fatalf("inspections = %d, want the second request served from the cache", inspections)
	}
	stamp.mtime = unix.Timespec{Sec: 101}
	validate()
	if inspections != 2 {
		t.Fatalf("an mtime change did not invalidate the verdict (inspections = %d)", inspections)
	}
	stamp.ctime = unix.Timespec{Sec: 102}
	validate()
	if inspections != 3 {
		t.Fatalf("a status change (ACL, mode, owner) did not invalidate the verdict (inspections = %d)", inspections)
	}
	stamp.ino = 11
	validate()
	if inspections != 4 {
		t.Fatalf("an inode change did not invalidate the verdict (inspections = %d)", inspections)
	}
	validate()
	if inspections != 4 {
		t.Fatalf("an unchanged folder was inspected again (inspections = %d)", inspections)
	}
}

func TestHookAPIACLVerdictCacheNeverCachesFailures(t *testing.T) {
	cache := &hookAPIACLVerdictCache{max: 8}
	identify := func(string) (hookAPIDirectoryStamp, bool) {
		return hookAPIDirectoryStamp{dev: 1, ino: 10}, true
	}
	inspections := 0
	writable := "drwx------+ 3 user  staff  96 Nov  2 10:00 /x\n 0: user:someone allow add_file,delete\n"
	inspect := func(context.Context, string) ([]byte, error) {
		inspections++
		return []byte(writable), nil
	}
	for i := 0; i < 2; i++ {
		if err := cache.validate("/x", time.Second, identify, inspect); err == nil {
			t.Fatal("a write-capable ACL passed")
		}
	}
	if inspections != 2 {
		t.Fatalf("a failing verdict was cached (inspections = %d)", inspections)
	}
}

func TestHookAPIACLVerdictCacheRetriesTimeoutOnce(t *testing.T) {
	cache := &hookAPIACLVerdictCache{max: 8}
	identify := func(string) (hookAPIDirectoryStamp, bool) {
		return hookAPIDirectoryStamp{dev: 1, ino: 10}, true
	}
	attempts := 0
	inspect := func(ctx context.Context, _ string) ([]byte, error) {
		attempts++
		if attempts == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return []byte(cleanDarwinACLListing), nil
	}
	if err := cache.validate("/x", 10*time.Millisecond, identify, inspect); err != nil {
		t.Fatalf("a single timeout failed the request: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want one retry", attempts)
	}
}
