// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"context"
	"errors"
	"testing"
)

// macOS has no per-account flush: --user flushes nothing, so the other
// accounts keep their cache. Without --user the guardian flush runs.
func TestIdentityRefreshMacOSFlushesOnlyWithoutUser(t *testing.T) {
	saved := identityRefreshFlushDirectoryCaches
	t.Cleanup(func() { identityRefreshFlushDirectoryCaches = saved })
	runs := 0
	identityRefreshFlushDirectoryCaches = func(context.Context) error { runs++; return nil }
	flush, warning := identityRefreshPlatformFlushOSCache("eng2")
	if flush.Flushed != "none" || flush.Reason != "no_per_user_flush" || warning == nil || runs != 0 {
		t.Fatalf("--user: %+v %v runs %d", flush, warning, runs)
	}
	flush, warning = identityRefreshPlatformFlushOSCache("")
	if flush.Flushed != "all" || flush.Method != "dscacheutil" || warning != nil || runs != 1 {
		t.Fatalf("all: %+v %v runs %d", flush, warning, runs)
	}
	identityRefreshFlushDirectoryCaches = func(context.Context) error { return errors.New("dsmemberutil: exit 1") }
	if flush, warning := identityRefreshPlatformFlushOSCache(""); flush.Reason != "failed" || warning == nil || warning.Code != "os_cache_flush_failed" {
		t.Fatalf("failed flush: %+v %v", flush, warning)
	}
}
