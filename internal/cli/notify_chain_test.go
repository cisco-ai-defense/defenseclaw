// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// The notifier defenseclaw-hook notify chains carries the chain marker, the
// digest of that turn's payload, so a wrapper that calls DefenseClaw's
// notifier again with the same payload ends the chain instead of looping,
// whatever spelling of the notifier it uses.
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
	payload := `{"type":"agent-turn-complete"}`
	if want := codexNotifyChainedEnv + "=" + codexNotifyPayloadDigest(payload); !slices.Contains(command.Env, want) {
		t.Fatalf("the chained notifier lacks %s", want)
	}
	if slices.Contains(command.Env, codexNotifyChainedEnv+"=1") {
		t.Fatalf("the chained notifier carries a constant %s", codexNotifyChainedEnv)
	}
}

// An inherited value stays out of the child: the marker is the digest of this
// turn's payload, whatever the parent environment held.
func TestOriginalCodexNotifyCommandOverridesAnInheritedMarker(t *testing.T) {
	t.Setenv(codexNotifyChainedEnv, "inherited")
	dataDir := t.TempDir()
	original, _ := json.Marshal([]string{filepath.Join(dataDir, "my-notifier")})
	backup, _ := json.Marshal(map[string]interface{}{"had_notify": true, "original_notify": json.RawMessage(original)})
	if err := os.WriteFile(filepath.Join(dataDir, "codex_config_backup.json"), backup, 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"type":"agent-turn-complete","turn-id":"t1"}`
	command := originalCodexNotifyCommand(dataDir, payload)
	if command == nil {
		t.Fatal("no command for the backed-up notifier")
	}
	last := ""
	for _, kv := range command.Env {
		if len(kv) > len(codexNotifyChainedEnv) && kv[:len(codexNotifyChainedEnv)+1] == codexNotifyChainedEnv+"=" {
			last = kv[len(codexNotifyChainedEnv)+1:]
		}
	}
	if last != codexNotifyPayloadDigest(payload) {
		t.Fatalf("effective %s = %q, want the payload digest", codexNotifyChainedEnv, last)
	}
}

// Only a call that carries the digest of its own payload ends the chain. A
// constant, an inherited value from another turn and an unset variable
// suppress nothing: the turn is forwarded and chained as before.
func TestCodexNotifyChainEndsOnlyOnTheMatchingPayloadDigest(t *testing.T) {
	payload := `{"type":"agent-turn-complete","turn-id":"t1"}`
	other := `{"type":"agent-turn-complete","turn-id":"t2"}`
	perUser := hookexec.Options{}
	for _, tc := range []struct {
		name  string
		set   bool
		value string
		want  bool
	}{
		{"unset", false, "", false},
		{"empty", true, "", false},
		{"constant 1", true, "1", false},
		{"constant true", true, "true", false},
		{"digest of another turn", true, codexNotifyPayloadDigest(other), false},
		{"upper-case digest", true, strings.ToUpper(codexNotifyPayloadDigest(payload)), false},
		{"matching digest", true, codexNotifyPayloadDigest(payload), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(codexNotifyChainedEnv, tc.value)
			} else {
				_ = os.Unsetenv(codexNotifyChainedEnv)
			}
			if got := codexNotifyChainEnded(perUser, payload); got != tc.want {
				t.Fatalf("chain ended = %v, want %v", got, tc.want)
			}
		})
	}
}

// Managed and Secure Client installs never read the marker, even when the
// digest matches, and a managed standalone host sees the variable as unset.
func TestCodexNotifyChainMarkerIsIgnoredWhenManagedOrSecureClient(t *testing.T) {
	payload := `{"type":"agent-turn-complete"}`
	t.Setenv(codexNotifyChainedEnv, codexNotifyPayloadDigest(payload))
	if !codexNotifyChainEnded(hookexec.Options{}, payload) {
		t.Fatal("a per-user notify with the matching digest must end the chain")
	}
	for name, opts := range map[string]hookexec.Options{
		"managed":       {ManagedEnterprise: true},
		"secure client": {SecureClient: true},
		"both":          {ManagedEnterprise: true, SecureClient: true},
	} {
		if codexNotifyChainEnded(opts, payload) {
			t.Fatalf("%s: the marker suppressed a notify", name)
		}
	}
	if got := envvars.ManagedPolicy(codexNotifyChainedEnv); got != envvars.ManagedIgnore {
		t.Fatalf("registry managed policy = %q, want %q", got, envvars.ManagedIgnore)
	}
	envvars.SetManagedStandalone(true)
	t.Cleanup(func() { envvars.SetManagedStandalone(false) })
	if got := envvars.Getenv(codexNotifyChainedEnv); got != "" {
		t.Fatalf("managed standalone read %q, want unset", got)
	}
}
