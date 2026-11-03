// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStripCodexSelfNotify(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir()}
	hook := filepath.Join(t.TempDir(), "defenseclaw-hook")
	setHookBinaryOverride(t, hook)
	native := []string{hook, "notify"}
	bridge := codexShellNotifyCommand(opts)
	asJSON := func(argv []string) string {
		raw, _ := json.Marshal(argv)
		return string(raw)
	}
	const cua = `C:\Users\operator\AppData\Local\OpenAI\Codex\codex-computer-use.exe`
	userNotify := []string{"/usr/bin/notify-send", "codex"}

	tests := []struct {
		name     string
		in       []string
		previous []string
		want     []string
	}{
		{"direct native", native, nil, nil},
		{"direct bridge", bridge, nil, nil},
		{"direct native keeps previous", native, userNotify, userNotify},
		{"nested native", []string{cua, "turn-ended", "--previous-notify", asJSON(native)}, nil, []string{cua, "turn-ended"}},
		{"nested bridge", []string{"/opt/cua", "turn-ended", "--previous-notify", asJSON(bridge)}, nil, []string{"/opt/cua", "turn-ended"}},
		{"nested keeps previous", []string{cua, "turn-ended", "--previous-notify", asJSON(native)}, userNotify,
			[]string{cua, "turn-ended", "--previous-notify", asJSON(userNotify)}},
		{"unrelated", userNotify, nil, userNotify},
		{"unrelated previous", []string{cua, "turn-ended", "--previous-notify", asJSON(userNotify)}, nil,
			[]string{cua, "turn-ended", "--previous-notify", asJSON(userNotify)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripCodexSelfNotify(tc.in, tc.previous, opts); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("stripCodexSelfNotify(%q, %q) = %q, want %q", tc.in, tc.previous, got, tc.want)
			}
		})
	}
}

// A backup written before self-references were stripped must not loop after
// upgrade: the forwarded original drops the nested DefenseClaw notifier.
func TestCodexOriginalNotifyStripsSelfReferenceFromExistingBackup(t *testing.T) {
	dataDir := t.TempDir()
	hook := filepath.Join(t.TempDir(), "defenseclaw-hook")
	setHookBinaryOverride(t, hook)
	nested, _ := json.Marshal([]string{hook, "notify"})
	original, _ := json.Marshal([]string{"/opt/cua", "turn-ended", "--previous-notify", string(nested)})
	backup, _ := json.Marshal(codexConfigBackup{HadNotify: true, OriginalNotify: original})
	if err := os.WriteFile(filepath.Join(dataDir, "codex_config_backup.json"), backup, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := CodexOriginalNotify(dataDir), []string{"/opt/cua", "turn-ended"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CodexOriginalNotify = %q, want %q", got, want)
	}
}
