// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// macOS has no per-account flush: --user flushes nothing, so the other
// accounts keep their cache.
func TestIdentityRefreshMacOSFlushesOnlyWithoutUser(t *testing.T) {
	saved := identityRefreshRun
	t.Cleanup(func() { identityRefreshRun = saved })
	var ran []string
	identityRefreshRun = func(path string, args ...string) error {
		ran = append(ran, filepath.Base(path)+" "+strings.Join(args, " "))
		return nil
	}
	flush, warning := identityRefreshPlatformFlushOSCache("eng2")
	if flush.Flushed != "none" || flush.Reason != "no_per_user_flush" || warning == nil || len(ran) != 0 {
		t.Fatalf("--user: %+v %v ran %v", flush, warning, ran)
	}
	flush, warning = identityRefreshPlatformFlushOSCache("")
	if flush.Flushed != "all" || warning != nil || strings.Join(ran, ";") != "dscacheutil -flushcache;dsmemberutil flushcache" {
		t.Fatalf("all: %+v %v ran %v", flush, warning, ran)
	}
}
