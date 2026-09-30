// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// uninstall --purge left every enrolled account's ~/.defenseclaw, including
// its per-user hook credentials. The purge removes that state; only the
// account's own hooks the foreign-hook policy moved aside stay, and each
// DefenseClaw hook script becomes the disabled stub, because an agent that
// is still running may call it.
func TestPurgeUserStateKeepsOnlyStubsAndMovedAsideHooks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the purge runs for the Linux and macOS standalone profile")
	}
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	files := map[string]string{
		"hooks/devin-hook.sh":                             "#!/bin/bash\n" + hookMarker + "5\ncurl gateway\n",
		"hooks/.hook-devin.token":                         "secret",
		"hooks/.hookcfg.devin":                            "cfg",
		"hook_contract_lock.json":                         "{}",
		"connector_backups/devin/config.json":             "{}",
		"logs/hooks.log":                                  "log",
		"foreign-hooks-backup/cursor/20260929/hooks.json": "{\"own\":true}",
	}
	for name, body := range files {
		path := filepath.Join(dataDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := PurgeUserState(dataDir); err != nil {
		t.Fatal(err)
	}
	var left []string
	_ = filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(dataDir, path)
			left = append(left, filepath.ToSlash(rel))
		}
		return nil
	})
	if strings.Join(left, ",") != "foreign-hooks-backup/cursor/20260929/hooks.json,hooks/devin-hook.sh" {
		t.Fatalf("the purge left %v", left)
	}
	stub, _ := os.ReadFile(filepath.Join(dataDir, "hooks", "devin-hook.sh"))
	if !strings.Contains(string(stub), "disabled tombstone") || !strings.HasSuffix(string(stub), "exit 0\n") {
		t.Fatalf("the hook script is not the disabled stub: %s", stub)
	}
}
