//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"os/user"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor"
)

func TestKernelBlockNameResolvesDirectoryOnlyUIDAndCachesIt(t *testing.T) {
	uid := 2147483640
	if _, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		t.Skip("test UID exists in this host's account database")
	}
	now := time.Unix(100, 0)
	lookups := 0
	cache := &kernelBlockNameCache{
		lookup: func(gotUID int) (string, error) {
			lookups++
			if gotUID != uid {
				t.Fatalf("looked up UID %d, want %d", gotUID, uid)
			}
			return "directory-user@example.test", nil
		},
		now: func() time.Time { return now },
	}
	event := sensor.KernelEvent{UID: &uid}
	for range 2 {
		if got := kernelBlockUserNameWithLookup(event, cache.name); got != "directory-user" {
			t.Fatalf("resolved name = %q", got)
		}
	}
	if lookups != 1 {
		t.Fatalf("lookup count = %d, want 1", lookups)
	}
	event.User = "sensor-user"
	if got := kernelBlockUserNameWithLookup(event, cache.name); got != event.User || lookups != 1 {
		t.Fatalf("sensor name = %q, lookups = %d", got, lookups)
	}
	now = now.Add(kernelBlockNameCacheTTL)
	event.User = ""
	if got := kernelBlockUserNameWithLookup(event, cache.name); got != "directory-user" || lookups != 2 {
		t.Fatalf("refreshed name = %q, lookups = %d", got, lookups)
	}
}

func TestKernelBlockNameLookupFailureStaysUnnamed(t *testing.T) {
	uid := 2147483640
	lookups := 0
	cache := &kernelBlockNameCache{
		lookup: func(int) (string, error) {
			lookups++
			return "unverified-name", errors.New("directory unavailable")
		},
		now: time.Now,
	}
	for range 2 {
		if got := kernelBlockUserNameWithLookup(sensor.KernelEvent{UID: &uid}, cache.name); got != "" {
			t.Fatalf("failed lookup resolved to %q", got)
		}
	}
	if lookups != 1 {
		t.Fatalf("failed lookup count = %d, want 1", lookups)
	}
}
