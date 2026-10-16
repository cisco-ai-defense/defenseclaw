//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// GAP-0588: on Windows, too, a Devin config.json that went missing after
// DefenseClaw managed it is put back with the account's settings before the
// hooks go in, and the repair reports it.
func TestDevinWindowsSetupPutsBackAMissingConfigWithTheAccountsSettings(t *testing.T) {
	previous := DevinHooksPathOverride
	DevinHooksPathOverride = ""
	t.Cleanup(func() { DevinHooksPathOverride = previous })
	home := t.TempDir()
	config := filepath.Join(home, "AppData", "Roaming", "devin", "config.json")
	if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`{"model":"claude-haiku-4-5","permissions":{"allow":["read"]}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{
		DataDir:           filepath.Join(home, ".defenseclaw"),
		APIAddr:           "127.0.0.1:18970",
		APIToken:          "tok-test",
		ConfigHome:        filepath.Dir(config),
		HookFailMode:      "closed",
		ManagedEnterprise: true,
	}
	conn := NewDevinConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	spec, _ := agentConfigSpecFor("devin")
	if _, err := os.Stat(spec.copyPath(opts.DataDir)); err != nil {
		t.Fatalf("no copy of config.json after setup: %v", err)
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	keys, ok := jsoncTopKeys(data)
	sort.Strings(keys)
	if !ok || strings.Join(keys, ",") != "hooks,model,permissions" {
		t.Fatalf("restored config.json keys = %v %t:\n%s", keys, ok, data)
	}
	if commands := devinConfigCommands(t, config); len(commands) == 0 {
		t.Fatalf("the repair registered no hooks in %s", config)
	}
	if status := AgentConfigStatus("devin", opts, started, false); status != AgentConfigRestoredLastGood {
		t.Fatalf("repair status = %q", status)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	for _, path := range []string{spec.copyPath(opts.DataDir), spec.noticePath(opts.DataDir)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s survived teardown: %v", path, err)
		}
	}
}
