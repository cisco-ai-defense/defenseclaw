// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func codexNotifyJSON(argv []string) string {
	raw, _ := json.Marshal(argv)
	return string(raw)
}

// A wrapper can wrap a wrapper, use the --flag=value spelling, or carry a
// value that is not an argv. Only DefenseClaw's notifier is taken out, at any
// depth; everything else stays as it was written, and a chain deeper than the
// limit is cut instead of run unread.
func TestStripCodexSelfNotifyNestedAndMalformed(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir()}
	hook := filepath.Join(t.TempDir(), "defenseclaw-hook")
	setHookBinaryOverride(t, hook)
	ours := []string{hook, "notify"}
	user := []string{"/usr/bin/notify-send", "codex"}
	inner := []string{"/opt/cua", "turn-ended", "--previous-notify", codexNotifyJSON(ours)}

	deep := ours
	for i := 0; i < codexNotifyNestLimit+2; i++ {
		deep = []string{"/opt/cua", "--previous-notify", codexNotifyJSON(deep)}
	}
	if got := stripCodexSelfNotify(deep, nil, opts); strings.Contains(strings.Join(got, " "), hook) {
		t.Fatalf("a chain deeper than the limit still runs DefenseClaw's notifier: %q", got)
	}

	tests := []struct {
		name     string
		in       []string
		previous []string
		want     []string
	}{
		{"wrapper of a wrapper", []string{"/opt/cua", "turn-ended", "--previous-notify", codexNotifyJSON(inner)}, nil,
			[]string{"/opt/cua", "turn-ended", "--previous-notify", codexNotifyJSON([]string{"/opt/cua", "turn-ended"})}},
		{"wrapper of a wrapper keeps previous", []string{"/opt/cua", "--previous-notify", codexNotifyJSON(inner)}, user,
			[]string{"/opt/cua", "--previous-notify", codexNotifyJSON([]string{"/opt/cua", "turn-ended", "--previous-notify", codexNotifyJSON(user)})}},
		{"inline flag", []string{"/opt/cua", "--previous-notify=" + codexNotifyJSON(ours)}, nil, []string{"/opt/cua"}},
		{"inline flag keeps previous", []string{"/opt/cua", "--previous-notify=" + codexNotifyJSON(ours)}, user,
			[]string{"/opt/cua", "--previous-notify=" + codexNotifyJSON(user)}},
		{"not json", []string{"/opt/cua", "--previous-notify", "[" + hook}, nil, []string{"/opt/cua", "--previous-notify", "[" + hook}},
		{"not a list of strings", []string{"/opt/cua", "--previous-notify", `[1,2]`}, nil, []string{"/opt/cua", "--previous-notify", `[1,2]`}},
		{"empty list", []string{"/opt/cua", "--previous-notify", `[]`}, nil, []string{"/opt/cua", "--previous-notify", `[]`}},
		{"null", []string{"/opt/cua", "--previous-notify", `null`}, nil, []string{"/opt/cua", "--previous-notify", `null`}},
		{"flag without value", []string{"/opt/cua", "--previous-notify"}, nil, []string{"/opt/cua", "--previous-notify"}},
		{"unrelated spacing kept", []string{"/opt/cua", "--previous-notify", `[ "/usr/bin/notify-send" ]`}, nil,
			[]string{"/opt/cua", "--previous-notify", `[ "/usr/bin/notify-send" ]`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripCodexSelfNotify(tc.in, tc.previous, opts); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("stripCodexSelfNotify(%q, %q) = %q, want %q", tc.in, tc.previous, got, tc.want)
			}
		})
	}
}

// The notifier a wrapper chains in place of ours is never that same wrapper:
// it would run twice on every turn.
func TestCodexUnwrapSelfNotifyNeverChainsTheWrapperIntoItself(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir()}
	hook := filepath.Join(t.TempDir(), "defenseclaw-hook")
	setHookBinaryOverride(t, hook)
	wrapped := []string{"/opt/cua", "turn-ended", "--previous-notify", codexNotifyJSON([]string{hook, "notify"})}
	bare := []string{"/opt/cua", "turn-ended"}
	if got, changed := codexUnwrapSelfNotify(wrapped, bare, opts); !changed || !reflect.DeepEqual(got, bare) {
		t.Fatalf("codexUnwrapSelfNotify = %q, %v; want %q, true", got, changed, bare)
	}
	user := []string{"/usr/bin/notify-send"}
	if got, changed := codexUnwrapSelfNotify(user, bare, opts); changed || !reflect.DeepEqual(got, user) {
		t.Fatalf("an unrelated notifier changed: %q, %v", got, changed)
	}
}

// Per-user Setup registers no notifier. A wrapper that still chains the
// notifier an older Setup wrote is healed in config.toml: on a first Setup it
// keeps only the wrapper (also as the backup), and later it chains the
// account's earlier notifier instead of ours. A teardown leaves it as is.
func TestCodexSetupHealsAWrapperThatChainsDefenseClawsNotifier(t *testing.T) {
	dir := t.TempDir()
	hook := filepath.Join(dir, "bin", "defenseclaw-hook")
	setHookBinaryOverride(t, hook)
	configPath := filepath.Join(dir, "config.toml")
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()
	c := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970", APIToken: "test-token-codex-notify"}
	if codexRegistersNotify(opts) {
		t.Skip("this profile registers DefenseClaw's notifier")
	}
	writeNotify := func(argv []string) {
		t.Helper()
		raw, _ := os.ReadFile(configPath)
		cfg := map[string]interface{}{}
		if len(raw) > 0 {
			if err := parseCodexTOML(raw, &cfg); err != nil {
				t.Fatal(err)
			}
		}
		cfg["notify"] = argv
		out, err := editCodexOwnedTOML(raw, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	notifyOf := func() []string {
		t.Helper()
		raw, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		var parsed map[string]interface{}
		if err := toml.Unmarshal(raw, &parsed); err != nil {
			t.Fatalf("invalid TOML after Setup: %v", err)
		}
		argv, _ := codexNotifyArgv(parsed["notify"])
		return argv
	}
	cua := []string{filepath.Join(dir, "cua"), "turn-ended"}
	wrapperOf := func(chained []string) []string {
		return append(append([]string(nil), cua...), "--previous-notify", codexNotifyJSON(chained))
	}

	for _, ours := range [][]string{{hook, "notify"}, codexShellNotifyCommand(opts)} {
		_ = os.Remove(filepath.Join(dir, "codex_config_backup.json"))
		writeNotify(wrapperOf(ours))
		for run := 0; run < 2; run++ {
			if err := c.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			if got := notifyOf(); !reflect.DeepEqual(got, cua) {
				t.Fatalf("notify after Setup %d under a wrapper of %q = %q, want %q", run+1, ours, got, cua)
			}
			if got := CodexOriginalNotify(dir); !reflect.DeepEqual(got, cua) {
				t.Fatalf("backed-up original after Setup %d = %q, want %q", run+1, got, cua)
			}
		}
	}

	// The account's own notifier was backed up by an earlier Setup; a wrapper
	// added later around an older Setup's notifier chains it again.
	_ = os.Remove(filepath.Join(dir, "codex_config_backup.json"))
	user := []string{filepath.Join(dir, "my-notifier")}
	writeNotify(user)
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	writeNotify(wrapperOf([]string{hook, "notify"}))
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if got, want := notifyOf(), wrapperOf(user); !reflect.DeepEqual(got, want) {
		t.Fatalf("notify after Setup = %q, want %q", got, want)
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got, want := notifyOf(), wrapperOf(user); !reflect.DeepEqual(got, want) {
		t.Fatalf("notify after Teardown = %q, want %q", got, want)
	}
}

// Teardown with the notifier an earlier release registered, whose backup holds
// a wrapper of that same notifier, puts the wrapper back without it.
func TestCodexRestoreNotifyStripsDefenseClawFromABackedUpWrapper(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir()}
	hook := filepath.Join(t.TempDir(), "defenseclaw-hook")
	setHookBinaryOverride(t, hook)
	ours := []string{hook, "notify"}
	original, _ := json.Marshal([]string{"/opt/cua", "turn-ended", "--previous-notify", codexNotifyJSON(ours)})
	cfg := map[string]interface{}{"notify": ours}
	if err := restoreCodexNotify(cfg, codexConfigBackup{HadNotify: true, OriginalNotify: original}, opts); err != nil {
		t.Fatal(err)
	}
	if got, _ := codexNotifyArgv(cfg["notify"]); !reflect.DeepEqual(got, []string{"/opt/cua", "turn-ended"}) {
		t.Fatalf("restored notify = %q", got)
	}
}
