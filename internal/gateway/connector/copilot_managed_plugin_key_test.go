// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func withCopilotMachineSettings(t *testing.T, content string, managedHost bool) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	path := filepath.Join(t.TempDir(), "GitHubCopilot", "managed-settings.json")
	if content != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	previousPath, previousHost := copilotMachineManagedSettingsPath, copilotManagedHost
	copilotMachineManagedSettingsPath = func() string { return path }
	copilotManagedHost = func() bool { return managedHost }
	t.Cleanup(func() { copilotMachineManagedSettingsPath, copilotManagedHost = previousPath, previousHost })
	return path
}

// GAP-1254: an OSS per-user Copilot setup removes the
// enabledPlugins["defenseclaw@defenseclaw"] key an earlier managed install
// left in Copilot's machine managed-settings file, so the Copilot CLI no
// longer warns at every start that the marketplace "defenseclaw" is not
// found. Everything else in the file stays.
func TestPerUserCopilotSetupRemovesTheLeftoverManagedPluginKey(t *testing.T) {
	t.Run("only the key: the file goes", func(t *testing.T) {
		path := withCopilotMachineSettings(t, `{"enabledPlugins":{"defenseclaw@defenseclaw":true}}`, false)
		removeOrphanedCopilotVSCodeLocalRendersForPerUser(SetupOpts{})
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("managed-settings.json holding only DefenseClaw's key stayed: %v", err)
		}
	})
	t.Run("other settings stay", func(t *testing.T) {
		path := withCopilotMachineSettings(t, `{"sandbox":{"enabled":true},"enabledPlugins":{"defenseclaw@defenseclaw":true,"other@corp":true}}`, false)
		removeOrphanedCopilotVSCodeLocalRendersForPerUser(SetupOpts{})
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]map[string]bool
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", data, err)
		}
		if _, ok := doc["enabledPlugins"]["defenseclaw@defenseclaw"]; ok || !doc["enabledPlugins"]["other@corp"] || !doc["sandbox"]["enabled"] {
			t.Fatalf("managed settings after setup = %s", data)
		}
	})
	for name, content := range map[string]string{
		"the key set false":        `{"enabledPlugins":{"defenseclaw@defenseclaw":false}}`,
		"no DefenseClaw key":       `{"enabledPlugins":{"other@corp":true}}`,
		"a file that is not JSON":  `{"enabledPlugins":{"defenseclaw@defenseclaw":true}, // comment`,
		"enabledPlugins not a map": `{"enabledPlugins":["defenseclaw@defenseclaw"]}`,
	} {
		t.Run("left alone: "+name, func(t *testing.T) {
			path := withCopilotMachineSettings(t, content, false)
			removeOrphanedCopilotVSCodeLocalRendersForPerUser(SetupOpts{})
			if data, err := os.ReadFile(path); err != nil || string(data) != content {
				t.Fatalf("file changed: %q, %v", data, err)
			}
		})
	}
	t.Run("a managed computer keeps it", func(t *testing.T) {
		content := `{"enabledPlugins":{"defenseclaw@defenseclaw":true}}`
		path := withCopilotMachineSettings(t, content, true)
		removeOrphanedCopilotVSCodeLocalRendersForPerUser(SetupOpts{})
		removeOrphanedCopilotVSCodeLocalRendersForPerUser(SetupOpts{ManagedEnterprise: true})
		if data, err := os.ReadFile(path); err != nil || string(data) != content {
			t.Fatalf("the managed install's key changed: %q, %v", data, err)
		}
	})
	t.Run("no file", func(t *testing.T) {
		path := withCopilotMachineSettings(t, "", false)
		removeOrphanedCopilotVSCodeLocalRendersForPerUser(SetupOpts{})
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("setup created %s: %v", path, err)
		}
	})
	t.Run("an account that cannot write the file is told what to remove", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs a POSIX account without write access to the folder")
		}
		content := `{"enabledPlugins":{"defenseclaw@defenseclaw":true}}`
		path := withCopilotMachineSettings(t, content, false)
		if err := os.Chmod(filepath.Dir(path), 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(filepath.Dir(path), 0o755) })
		var warn bytes.Buffer
		if removeLeftoverCopilotManagedPluginKey(path, &warn) {
			t.Fatal("reported a removal it could not make")
		}
		if !strings.Contains(warn.String(), path) || !strings.Contains(warn.String(), "defenseclaw@defenseclaw") || !strings.Contains(warn.String(), "administrator") {
			t.Fatalf("warning = %q", warn.String())
		}
		if data, err := os.ReadFile(path); err != nil || string(data) != content {
			t.Fatalf("file changed: %q, %v", data, err)
		}
	})
}
