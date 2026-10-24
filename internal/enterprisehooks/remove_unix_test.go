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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// r102 GAP-0430: removing an account's last connector left the shared hook
// scripts and the hook contract lock in a ~/.defenseclaw that existed
// before; a remaining connector keeps them.
func TestRemoveUserHooksRemovesTheSharedRuntimeWithTheLastConnector(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	facts := filepath.Join(dataDir, "session-facts.json")
	if err := os.WriteFile(facts, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := func(name, version string) InstallOptions {
		return InstallOptions{
			ConnectorName: name, UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
			APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000", APIToken: "test-token",
			OTLPPathToken: strings.Repeat("d", 64), GuardrailMode: "action", HookFailMode: "closed",
			AgentVersion: version, Registry: connector.NewDefaultRegistry(),
		}
	}
	codex := options("codex", "codex-cli 0.142.0")
	if _, err := Install(context.Background(), codex); err != nil {
		t.Fatalf("Install: %v", err)
	}
	shared := filepath.Join(dataDir, "hooks", "_hardening.sh")
	lock := filepath.Join(dataDir, "hook_contract_lock.json")
	for _, path := range []string{shared, lock} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("install wrote no %s: %v", path, err)
		}
	}
	// Another connector's runtime record keeps the shared runtime.
	peer := filepath.Join(dataDir, "hooks", ".hookcfg.hermes")
	if err := os.WriteFile(peer, []byte("DEFENSECLAW_FAIL_MODE=closed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveUserHooks(context.Background(), codex); err != nil {
		t.Fatalf("RemoveUserHooks: %v", err)
	}
	if _, err := os.Stat(shared); err != nil {
		t.Fatalf("the shared scripts went while another connector's record remained: %v", err)
	}
	if err := os.Remove(peer); err != nil {
		t.Fatal(err)
	}
	if err := RemoveUserHooks(context.Background(), codex); err != nil {
		t.Fatalf("RemoveUserHooks: %v", err)
	}
	for _, path := range []string{shared, filepath.Join(dataDir, "hooks", "inspect-tool.sh"), lock} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s was kept after the last connector was removed: %v", path, err)
		}
	}
	if _, err := os.Stat(facts); err != nil {
		t.Fatalf("the account's other DefenseClaw file went: %v", err)
	}
}

// An install of one connector and the removal of the account's last other
// one ran unserialized: the removal could read an empty hook contract lock
// while the install had written the shared scripts and not recorded itself
// yet, then remove the scripts and the lock, and leave the new connector's
// hook without its runtime. Both hold the shared hook runtime lock, and the
// removal checks again once it has it.
func TestInstallAndLastConnectorRemovalSerializeOnTheSharedRuntime(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	codex := InstallOptions{
		ConnectorName: "codex", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000", APIToken: "test-token",
		OTLPPathToken: strings.Repeat("d", 64), GuardrailMode: "action", HookFailMode: "closed",
		AgentVersion: "codex-cli 0.142.0", Registry: connector.NewDefaultRegistry(),
	}
	if _, err := Install(context.Background(), codex); err != nil {
		t.Fatalf("Install: %v", err)
	}
	shared := filepath.Join(dataDir, "hooks", "_hardening.sh")
	blocked := func(what string, done <-chan error) {
		t.Helper()
		select {
		case err := <-done:
			t.Fatalf("%s finished while another install held the shared hook runtime: %v", what, err)
		case <-time.After(500 * time.Millisecond):
		}
	}

	// Another connector's install is under way: it wrote the shared scripts
	// and has not recorded itself in the hook contract lock yet.
	unlock, err := lockSharedHookRuntime(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	removed := make(chan error, 1)
	go func() { removed <- RemoveUserHooks(context.Background(), codex) }()
	blocked("the removal of the last connector", removed)
	if _, err := os.Stat(shared); err != nil {
		t.Fatalf("the removal took the shared scripts of the install under way: %v", err)
	}
	// The install records its connector, then lets go.
	peer := filepath.Join(dataDir, "hooks", ".hookcfg.hermes")
	if err := os.WriteFile(peer, []byte("DEFENSECLAW_FAIL_MODE=closed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := <-removed; err != nil {
		t.Fatalf("RemoveUserHooks: %v", err)
	}
	if _, err := os.Stat(shared); err != nil {
		t.Fatalf("the removal took the shared scripts the finished install uses: %v", err)
	}

	// An install waits for a removal under way the same way.
	if unlock, err = lockSharedHookRuntime(context.Background(), home); err != nil {
		t.Fatal(err)
	}
	installed := make(chan error, 1)
	go func() {
		_, err := Install(context.Background(), codex)
		installed <- err
	}()
	blocked("the install", installed)
	unlock()
	if err := <-installed; err != nil {
		t.Fatalf("Install: %v", err)
	}
	if entry := connector.LoadHookContractLockEntry(dataDir, "codex"); entry.Connector != "codex" {
		t.Fatalf("the install after the wait did not record codex: %+v", entry)
	}
}

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
	if _, err := PurgeUserState(context.Background(), purge); err == nil {
		t.Fatal("PurgeUserState followed a linked ~/.defenseclaw")
	}
	if _, err := os.Stat(notes); err != nil {
		t.Fatalf("the purge removed the user's own file: %v", err)
	}
}
