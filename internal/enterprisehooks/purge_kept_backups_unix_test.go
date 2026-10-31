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
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The purge of one account runs the teardown of every connector that still
// keeps a backup, then deletes ~/.defenseclaw. A teardown leaves a file that
// differs from what DefenseClaw wrote, and its backup, for the account. The
// purge deleted that backup with the state, so the file could never be put
// back (rel-1-0-3 GAP-0258). It now keeps the state and names the file. A
// config whose DefenseClaw entries the teardown removes keeps the account's
// own edits and needs no backup, so the purge goes on; so does a purge with
// no backup left.
func TestPurgeKeepsTheStateWhileATeardownKeepsAnEditedFile(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	previousPath := connector.OpenCodePluginPathOverride
	connector.OpenCodePluginPathOverride = ""
	t.Cleanup(func() { connector.OpenCodePluginPathOverride = previousPath })

	options := func(home, name, version string) InstallOptions {
		return InstallOptions{
			ConnectorName: name, UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
			APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
			APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
			GuardrailMode: "action", HookFailMode: "closed", AgentVersion: version,
			Registry: connector.NewDefaultRegistry(),
		}
	}
	installOpenCode := func(t *testing.T) (string, string, string, InstallOptions) {
		t.Helper()
		home := newTestHome(t)
		opts := options(home, "opencode", "2.1.4")
		if _, err := Install(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
		plugin := filepath.Join(home, ".config", "opencode", "plugins", "defenseclaw.js")
		receipt := filepath.Join(home, ".defenseclaw", "connector_backups", "opencode", "config.json")
		for _, path := range []string{plugin, receipt} {
			if _, err := os.Stat(path); err != nil {
				t.Fatal(err)
			}
		}
		return home, plugin, receipt, opts
	}
	purge := func(home string) (PurgeSummary, error) {
		return PurgeUserState(context.Background(), InstallOptions{
			UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Registry: connector.NewDefaultRegistry(),
		})
	}

	t.Run("edited plugin keeps the state", func(t *testing.T) {
		home, plugin, receipt, _ := installOpenCode(t)
		original, err := os.ReadFile(plugin)
		if err != nil {
			t.Fatal(err)
		}
		edited := append(append([]byte(nil), original...), []byte("\n// operator edit\n")...)
		if err := os.WriteFile(plugin, edited, 0o600); err != nil {
			t.Fatal(err)
		}
		receiptBytes, err := os.ReadFile(receipt)
		if err != nil {
			t.Fatal(err)
		}
		summary, err := purge(home)
		if err == nil || !strings.Contains(err.Error(), "kept the per-user state for its backups") ||
			!strings.Contains(err.Error(), plugin) || !strings.Contains(err.Error(), "differs from what DefenseClaw wrote") ||
			!strings.Contains(err.Error(), "rerun the purge") {
			t.Fatalf("purge with an edited plugin = %+v, %v", summary, err)
		}
		if summary.Data {
			t.Fatalf("the purge reported the state removed: %+v", summary)
		}
		if data, err := os.ReadFile(plugin); err != nil || !bytes.Equal(data, edited) {
			t.Fatalf("the edited plugin changed: %v", err)
		}
		if data, err := os.ReadFile(receipt); err != nil || !bytes.Equal(data, receiptBytes) {
			t.Fatalf("the purge changed the backup of the edited plugin: %v", err)
		}
		// The remedy: put back the file DefenseClaw wrote. The rerun then
		// removes it, its backup and the state.
		if err := os.WriteFile(plugin, original, 0o600); err != nil {
			t.Fatal(err)
		}
		if summary, err := purge(home); err != nil || !summary.Data {
			t.Fatalf("purge after the remedy = %+v, %v", summary, err)
		}
		for _, path := range []string{plugin, filepath.Join(home, ".defenseclaw")} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s remains after the purge: %v", path, err)
			}
		}
	})

	t.Run("a backup that cannot be read keeps the state", func(t *testing.T) {
		home, plugin, receipt, _ := installOpenCode(t)
		if err := os.WriteFile(receipt, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := purge(home); err == nil || !strings.Contains(err.Error(), "kept the per-user state") {
			t.Fatalf("purge with an unreadable backup = %v", err)
		}
		for _, path := range []string{plugin, receipt} {
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("%s went: %v", path, err)
			}
		}
	})

	t.Run("pristine plugin purges", func(t *testing.T) {
		home, plugin, _, _ := installOpenCode(t)
		if summary, err := purge(home); err != nil || !summary.Data {
			t.Fatalf("purge of a pristine install = %+v, %v", summary, err)
		}
		for _, path := range []string{plugin, filepath.Join(home, ".defenseclaw")} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s remains after the purge: %v", path, err)
			}
		}
	})

	t.Run("edited config keeps the account's edits", func(t *testing.T) {
		home := newTestHome(t)
		config := filepath.Join(home, ".codex", "config.toml")
		if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(config, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(context.Background(), options(home, "codex", "codex-cli 0.142.0")); err != nil {
			t.Fatal(err)
		}
		installed, err := os.ReadFile(config)
		if err != nil {
			t.Fatal(err)
		}
		edited := append([]byte("approval_policy = \"never\"\n"), installed...)
		if err := os.WriteFile(config, edited, 0o600); err != nil {
			t.Fatal(err)
		}
		if summary, err := purge(home); err != nil || !summary.Data {
			t.Fatalf("purge after an edited config = %+v, %v", summary, err)
		}
		data, err := os.ReadFile(config)
		if err != nil {
			t.Fatalf("the purge removed the edited config: %v", err)
		}
		if !strings.Contains(string(data), `model = "gpt-5"`) || !strings.Contains(string(data), `approval_policy = "never"`) {
			t.Fatalf("the account's own settings went:\n%s", data)
		}
		if strings.Contains(string(data), filepath.Join(home, ".defenseclaw")) {
			t.Fatalf("DefenseClaw's entries remain:\n%s", data)
		}
	})

	t.Run("missing backup", func(t *testing.T) {
		// No backup is left to lose. The account's own file at the plugin
		// path (no DefenseClaw ownership marker) stays; the state goes.
		home, plugin, receipt, _ := installOpenCode(t)
		if err := os.Remove(receipt); err != nil {
			t.Fatal(err)
		}
		own := []byte("// my own opencode plugin\nexport const Mine = async () => ({});\n")
		if err := os.WriteFile(plugin, own, 0o600); err != nil {
			t.Fatal(err)
		}
		if summary, err := purge(home); err != nil || !summary.Data {
			t.Fatalf("purge without a backup = %+v, %v", summary, err)
		}
		if data, err := os.ReadFile(plugin); err != nil || !bytes.Equal(data, own) {
			t.Fatalf("the purge changed the account's own plugin: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(home, ".defenseclaw")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the state remains: %v", err)
		}
	})
}
