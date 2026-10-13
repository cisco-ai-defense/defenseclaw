// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func TestManifestHomes(t *testing.T) {
	restore, restoreAccounts, restoreMode := validateManifestTrust, loadEligibleAccounts, enrollmentModeFor
	validateManifestTrust = func(string) error { return nil }
	var eligible []enterprisehooks.UnixEligibleAccount
	loadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return eligible, nil }
	mode := ""
	enrollmentModeFor = func(string) (string, error) { return mode, nil }
	defer func() {
		validateManifestTrust, loadEligibleAccounts, enrollmentModeFor = restore, restoreAccounts, restoreMode
	}()

	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yaml")
	if homes, digest, err := manifestHomes(path); err != nil || homes != nil || digest != "" {
		t.Fatalf("missing manifest: %v %v %q", homes, err, digest)
	}
	body := `version: 1
targets:
  - user: alice
    user_home: /home/alice
    connector: codex
  - user: alice
    user_home: /home/alice/
    connector: claudecode
  - user: bob
    user_home: /home/bob
    connector: codex
    enabled: false
  - user: carol
    user_home: relative/path
    connector: codex
`
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	homes, digest, err := manifestHomes(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(homes, []string{"/home/alice"}) || len(digest) != 64 {
		t.Fatalf("homes %v digest %q", homes, digest)
	}

	// Every agent on machine policy: no rows, yet the accounts the enumerator
	// found eligible are watched (GAP-1470). The excluded account never
	// reaches the record. Under manifest enrollment the record is stale and
	// adds no home a target does not enroll.
	machinePolicy := filepath.Join(dir, "machine-policy.yaml")
	if err := os.WriteFile(machinePolicy, []byte("version: 1\ntargets: []\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	eligible = []enterprisehooks.UnixEligibleAccount{
		{User: "zoe", UID: 1002, Home: "/Users/zoe"}, {User: "amy", UID: 1001, Home: "/Users/amy/"},
		{User: "amy", UID: 1001, Home: "/Users/amy"},
	}
	homes, eligibleDigest, err := manifestHomes(machinePolicy)
	if err != nil || !reflect.DeepEqual(homes, []string{"/Users/amy", "/Users/zoe"}) {
		t.Fatalf("machine-policy-only homes %v %v", homes, err)
	}
	mode = "manifest"
	if homes, staleDigest, err := manifestHomes(machinePolicy); err != nil || len(homes) != 0 || staleDigest == eligibleDigest {
		t.Fatalf("manifest enrollment homes %v %v (digest unchanged: %v)", homes, err, staleDigest == eligibleDigest)
	}
	// A target the administrator disabled enrolls nothing: the stale record
	// does not bring its home back (GAP-1488). The targets of alice do not
	// say, and an absent enabled means enabled.
	eligible = []enterprisehooks.UnixEligibleAccount{
		{User: "alice", UID: 1001, Home: "/home/alice"}, {User: "bob", UID: 1003, Home: "/home/bob"},
	}
	if homes, _, err := manifestHomes(path); err != nil || !reflect.DeepEqual(homes, []string{"/home/alice"}) {
		t.Fatalf("manifest enrollment with a disabled target: homes %v %v, want only /home/alice", homes, err)
	}
	mode, eligible = "", nil

	validateManifestTrust = func(string) error { return errors.New("untrusted") }
	if _, _, err := manifestHomes(path); err == nil {
		t.Fatal("untrusted manifest accepted")
	}
	validateManifestTrust = func(string) error { return nil }

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := watchManifest(context.Background(), path, digest, 10*time.Millisecond, logger)
	if err := os.WriteFile(path, []byte(body+"  - user: dave\n    user_home: /home/dave\n    connector: codex\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("manifest change did not end the helper context")
	}
}
