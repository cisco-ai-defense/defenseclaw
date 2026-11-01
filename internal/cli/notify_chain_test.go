// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The notifier defenseclaw-hook notify chains carries the chain marker, so a
// wrapper that calls DefenseClaw's notifier again ends the chain instead of
// looping, whatever spelling of the notifier it uses.
func TestOriginalCodexNotifyCommandMarksTheChainedNotifier(t *testing.T) {
	dataDir := t.TempDir()
	if originalCodexNotifyCommand(dataDir, "{}") != nil {
		t.Fatal("a command without a backup")
	}
	notifier := filepath.Join(dataDir, "my-notifier")
	original, _ := json.Marshal([]string{notifier, "turn-ended"})
	backup, _ := json.Marshal(map[string]interface{}{"had_notify": true, "original_notify": json.RawMessage(original)})
	if err := os.WriteFile(filepath.Join(dataDir, "codex_config_backup.json"), backup, 0o600); err != nil {
		t.Fatal(err)
	}
	command := originalCodexNotifyCommand(dataDir, `{"type":"agent-turn-complete"}`)
	if command == nil {
		t.Fatal("no command for the backed-up notifier")
	}
	if want := []string{notifier, "turn-ended", `{"type":"agent-turn-complete"}`}; !slices.Equal(command.Args, want) {
		t.Fatalf("args = %q, want %q", command.Args, want)
	}
	if !slices.Contains(command.Env, codexNotifyChainedEnv+"=1") {
		t.Fatalf("the chained notifier has no %s", codexNotifyChainedEnv)
	}
}
