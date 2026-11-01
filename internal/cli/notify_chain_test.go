// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
			if got := codexNotifyChainEnded(payload); got != tc.want {
				t.Fatalf("chain ended = %v, want %v", got, tc.want)
			}
		})
	}
}

// The notify command builds its options with buildHookOptions, which never
// marks them managed or Secure Client, so every host that reaches the command
// reads the marker and chains. Run the real command end to end: a notifier it
// chains runs unless the marker is the digest of this payload.
func TestNotifyCommandChainsUnlessTheMarkerIsThePayloadDigest(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	opts := buildHookOptions("codex", "notify", "", "open")
	if opts.ManagedEnterprise || opts.SecureClient {
		t.Fatalf("buildHookOptions marked the notify options managed=%v secureClient=%v", opts.ManagedEnterprise, opts.SecureClient)
	}
	if filepath.Clean(opts.Home) != filepath.Clean(dataDir) {
		t.Skipf("the hook home %q is not the test data dir", opts.Home)
	}
	out := filepath.Join(dataDir, "chained.log")
	t.Setenv("DC_NOTIFY_HELPER_OUT", out)
	original, _ := json.Marshal([]string{os.Args[0], "-test.run=^TestNotifyChainHelperProcess$", "--"})
	backup, _ := json.Marshal(map[string]interface{}{"had_notify": true, "original_notify": json.RawMessage(original)})
	if err := os.WriteFile(filepath.Join(dataDir, "codex_config_backup.json"), backup, 0o600); err != nil {
		t.Fatal(err)
	}
	forwarded := 0
	prev := forwardCodexNotify
	forwardCodexNotify = func(_ context.Context, _ hookexec.Options, _ []byte) int { forwarded++; return 0 }
	t.Cleanup(func() { forwardCodexNotify = prev })

	payload := `{"type":"agent-turn-complete","turn-id":"t1"}`
	other := `{"type":"agent-turn-complete","turn-id":"t2"}`
	for _, tc := range []struct {
		name       string
		marker     string
		wantChain  bool
		wantForwar int
	}{
		{"unset", "", true, 1},
		{"constant", "1", true, 1},
		{"digest of another turn", codexNotifyPayloadDigest(other), true, 1},
		{"digest of this payload", codexNotifyPayloadDigest(payload), false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.Remove(out)
			forwarded = 0
			if tc.marker == "" {
				_ = os.Unsetenv(codexNotifyChainedEnv)
			} else {
				t.Setenv(codexNotifyChainedEnv, tc.marker)
			}
			cmd := newNotifyCmd()
			if err := cmd.RunE(cmd, []string{payload}); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(out)
			chained := err == nil
			if chained != tc.wantChain {
				t.Fatalf("chained notifier ran = %v, want %v", chained, tc.wantChain)
			}
			if chained && string(data) != payload {
				t.Fatalf("chained notifier got %q, want the payload unchanged", data)
			}
			if forwarded != tc.wantForwar {
				t.Fatalf("gateway forwards = %d, want %d", forwarded, tc.wantForwar)
			}
		})
	}
}

// TestNotifyChainHelperProcess is the notifier the test above chains: the
// test binary itself, which writes the payload it was handed.
func TestNotifyChainHelperProcess(t *testing.T) {
	out := os.Getenv("DC_NOTIFY_HELPER_OUT")
	if out == "" || len(os.Args) < 2 || os.Args[len(os.Args)-2] != "--" {
		t.Skip("helper process of TestNotifyCommandChainsUnlessTheMarkerIsThePayloadDigest")
	}
	_ = os.WriteFile(out, []byte(os.Args[len(os.Args)-1]), 0o600)
}
