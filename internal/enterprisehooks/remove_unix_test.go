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

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestRemoveUserHooksKeepsTheUsersOwnConfig(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := InstallOptions{
		ConnectorName: "codex",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      "test-token",
		OTLPPathToken: strings.Repeat("d", 64),
		GuardrailMode: "action",
		HookFailMode:  "closed",
		AgentVersion:  "codex-cli 0.142.0",
		Registry:      connector.NewDefaultRegistry(),
	}
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	hookScript := filepath.Join(home, ".defenseclaw", "hooks", "codex-hook.sh")
	if data, _ := os.ReadFile(codexConfig); !strings.Contains(string(data), hookScript) {
		t.Fatalf("install did not register the hook:\n%s", data)
	}
	if err := RemoveUserHooks(context.Background(), opts); err != nil {
		t.Fatalf("RemoveUserHooks: %v", err)
	}
	data, err := os.ReadFile(codexConfig)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), hookScript) {
		t.Fatalf("DefenseClaw's hook is still registered:\n%s", data)
	}
	if !strings.Contains(string(data), `model = "gpt-5"`) {
		t.Fatalf("the user's own setting was removed:\n%s", data)
	}
	if lock := connector.LoadHookContractLockEntry(filepath.Join(home, ".defenseclaw"), "codex"); strings.TrimSpace(lock.Connector) != "" {
		t.Fatalf("hook contract lock entry kept: %+v", lock)
	}
	if _, err := os.Lstat(filepath.Join(home, ".defenseclaw", "hooks", ".hook-codex.token")); !os.IsNotExist(err) {
		t.Fatalf("the connector's hook credential was kept: %v", err)
	}
	// A second removal and a missing home are both no-ops.
	if err := RemoveUserHooks(context.Background(), opts); err != nil {
		t.Fatalf("repeat RemoveUserHooks: %v", err)
	}
	gone := opts
	gone.UserHome = filepath.Join(home, "deleted-user")
	if err := RemoveUserHooks(context.Background(), gone); err != nil {
		t.Fatalf("a deleted home must not fail uninstall: %v", err)
	}

	// uninstall --purge deletes everything in ~/.defenseclaw, so it
	// refuses one that is a link: it would delete the user's own files.
	linked := newTestHome(t)
	notes := filepath.Join(linked, "Documents", "notes.txt")
	if err := os.MkdirAll(filepath.Dir(notes), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notes, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(notes), filepath.Join(linked, ".defenseclaw")); err != nil {
		t.Fatal(err)
	}
	purge := opts
	purge.UserHome = linked
	if err := PurgeUserState(context.Background(), purge); err == nil {
		t.Fatal("PurgeUserState followed a linked ~/.defenseclaw")
	}
	if _, err := os.Stat(notes); err != nil {
		t.Fatalf("the purge removed the user's own file: %v", err)
	}
}

// RHEL-U2-12: uninstall --purge deleted the ~/.defenseclaw of an account
// that ran its own per-user DefenseClaw install (config, .venv, audit data).
// The purge removes only what the enterprise deployment wrote: a folder
// with the account's own install stays whole, one the managed install wrote
// alone still goes.
func TestPurgeUserStateKeepsTheAccountsOwnInstall(t *testing.T) {
	skipIfRoot(t)
	write := func(dataDir string, files ...string) {
		t.Helper()
		for _, name := range files {
			path := filepath.Join(dataDir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	own := newTestHome(t)
	ownData := filepath.Join(own, ".defenseclaw")
	ownFiles := []string{"config.yaml", ".venv/bin/python", "audit.db", "connector_backups/codex/config.toml", "hooks/.hook-codex.token"}
	write(ownData, ownFiles...)
	opts := InstallOptions{UserHome: own, OwnerUID: os.Getuid(), OwnerGID: os.Getgid()}
	err := PurgeUserState(context.Background(), opts)
	var kept *UserInstallKeptError
	if !errors.As(err, &kept) || strings.Join(kept.Found, ",") != "config.yaml,.venv,audit.db" {
		t.Fatalf("PurgeUserState of an account's own install = %v, want a UserInstallKeptError", err)
	}
	for _, name := range ownFiles {
		if _, err := os.Stat(filepath.Join(ownData, filepath.FromSlash(name))); err != nil {
			t.Fatalf("the purge removed the account's own %s: %v", name, err)
		}
	}

	managedOnly := newTestHome(t)
	write(filepath.Join(managedOnly, ".defenseclaw"), "hook_contract_lock.json", "hooks/.hook-codex.token")
	opts.UserHome = managedOnly
	if err := PurgeUserState(context.Background(), opts); err != nil {
		t.Fatalf("PurgeUserState of a managed-only folder: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(managedOnly, ".defenseclaw")); !os.IsNotExist(err) {
		t.Fatalf("the managed-only state stayed: %v", err)
	}
}
