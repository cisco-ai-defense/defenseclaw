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
	// A second removal and a missing home are both no-ops.
	if err := RemoveUserHooks(context.Background(), opts); err != nil {
		t.Fatalf("repeat RemoveUserHooks: %v", err)
	}
	gone := opts
	gone.UserHome = filepath.Join(home, "deleted-user")
	if err := RemoveUserHooks(context.Background(), gone); err != nil {
		t.Fatalf("a deleted home must not fail uninstall: %v", err)
	}
}
