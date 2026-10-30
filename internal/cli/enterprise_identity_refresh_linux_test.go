// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityRefreshSSSDFlushIsPerUserWithUser(t *testing.T) {
	dir := t.TempDir()
	savedBin, savedNSS, savedBackend, savedRun := identityRefreshSSSCache, identityRefreshNSSwitch, identityRefreshSSSDBackend, identityRefreshRun
	t.Cleanup(func() {
		identityRefreshSSSCache, identityRefreshNSSwitch, identityRefreshSSSDBackend, identityRefreshRun = savedBin, savedNSS, savedBackend, savedRun
	})
	identityRefreshSSSCache = filepath.Join(dir, "sss_cache")
	identityRefreshNSSwitch = filepath.Join(dir, "nsswitch.conf")
	identityRefreshSSSDBackend = identityRefreshUsesSSSD
	var ran []string
	identityRefreshRun = func(path string, args ...string) error {
		ran = append(ran, filepath.Base(path)+" "+strings.Join(args, " "))
		return nil
	}
	if flush, _ := identityRefreshPlatformFlushOSCache("eng2@corp.example.com"); flush.Flushed != "none" || flush.Reason != "not_sssd" || len(ran) != 0 {
		t.Fatalf("no SSSD: %+v ran %v", flush, ran)
	}
	if err := os.WriteFile(identityRefreshSSSCache, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identityRefreshNSSwitch, []byte("# x\npasswd:     files sss systemd\ngroup: files sss\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	flush, warning := identityRefreshPlatformFlushOSCache("eng2@corp.example.com")
	if flush.Flushed != "user" || flush.Method != "sss_cache" || warning != nil || ran[0] != "sss_cache -u eng2@corp.example.com" {
		t.Fatalf("--user: %+v %v ran %v", flush, warning, ran)
	}
	flush, _ = identityRefreshPlatformFlushOSCache("")
	if flush.Flushed != "all" || ran[1] != "sss_cache -E" {
		t.Fatalf("all: %+v ran %v", flush, ran)
	}
	identityRefreshRun = func(string, ...string) error { return errors.New("exit status 1") }
	if flush, warning := identityRefreshPlatformFlushOSCache(""); flush.Flushed != "none" || flush.Reason != "failed" || warning == nil || warning.Code != "os_cache_flush_failed" {
		t.Fatalf("failed flush: %+v %v", flush, warning)
	}
	if err := os.WriteFile(identityRefreshNSSwitch, []byte("passwd: files\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if identityRefreshUsesSSSD() {
		t.Fatal("a files-only passwd line is not SSSD")
	}
}
