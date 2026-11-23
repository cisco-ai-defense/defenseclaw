// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// gap0364Fill is prefix, then unit(i) for i = 0, 1, ... while the command
// stays within limit bytes with tail, then tail (the review's fill,
// evidence/substrate-1/rkguest2/rkguest2_probe_test.go TestRKGuest2GuardCost).
func gap0364Fill(prefix string, unit func(int) string, tail string, limit int) string {
	var b strings.Builder
	b.WriteString(prefix)
	for i := 0; ; i++ {
		u := unit(i)
		if b.Len()+len(u)+len(tail) > limit {
			break
		}
		b.WriteString(u)
	}
	b.WriteString(tail)
	return b.String()
}

// TestGAP0364SandboxHookConfigGuardAllocationIsBounded: at the guard's 8 KB
// bound, a cd and ~1,500 ':N' statements allocated ~129 MB per call
// (substrate-1 GAP-0364): the guard read every placed statement. It now
// reads only a statement that may name a hook file, and still finds the
// settings write at the end of the same call.
func TestGAP0364SandboxHookConfigGuardAllocationIsBounded(t *testing.T) {
	colon := func(i int) string { return fmt.Sprintf(":%d\n", i) }
	measure := func(f func()) uint64 {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		f()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	for _, row := range []struct{ name, command, want string }{
		{"colon-8192", gap0364Fill("cd .cache\n", colon, "ls", 8192), ""},
		{"colon-8192-settings-last", gap0364Fill("cd .cache\n", colon, "echo '{}' > ../.claude/settings.json", 8192),
			sandboxauth.SandboxHome + "/.claude/settings.json"},
		{"colon-8192-quoted-settings-last", gap0364Fill("cd .cache\n", colon, "echo '{}' > ../.claude/'settings'.json", 8192),
			sandboxauth.SandboxHome + "/.claude/settings.json"},
		{"colon-8192-variable-settings-last", gap0364Fill("cd .cache\nf=settings.json\n", colon, "echo '{}' > ../.claude/$f", 8192), ""},
	} {
		input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: sandboxauth.SandboxHome, ActiveHome: sandboxauth.SandboxHome}
		// One reading of the whole call, which the dispatch makes anyway.
		reading := measure(func() { actionfacts.Analyze(input) })
		var target string
		allocated := measure(func() {
			_, _, target = sandboxAgentHookConfigChange(context.Background(), trustedActionRequest{Input: input})
		})
		if row.want != "" && target != row.want {
			t.Errorf("%s: guard target %q, want %q", row.name, target, row.want)
		}
		// The guard reads the whole call, splits it into its placed
		// statements and reads only those that may name a hook file: 32 MB
		// on go1.26 linux/amd64, where reading every statement took 133 MB.
		if allocated > 48<<20 {
			t.Errorf("%s: guard allocated %.1f MB, want at most 48 MB (one reading of the call %.1f MB)",
				row.name, float64(allocated)/(1<<20), float64(reading)/(1<<20))
		}
		t.Logf("%s: %d bytes, target %q, guard %.1f MB, one reading %.1f MB", row.name, len(row.command), target,
			float64(allocated)/(1<<20), float64(reading)/(1<<20))
	}
	for _, statement := range []string{
		"echo x > settings.json", "cp a ~/.codex/config.toml", "tee 'settings.local.json'", "echo > s\"ettings\".json",
		"echo > $F", "echo > set*.json", "echo > `f`", "echo > settings.{json,x}", "echo > ~/.claude/settings.jso?",
		"echo > settings.js\\\non", "echo > se\\ttings.json",
	} {
		if !sandboxStatementMayNameHookConfig(statement) {
			t.Errorf("%q: skipped, but it may write a hook file", statement)
		}
	}
	for _, statement := range []string{":12", "touch f1", "ls -la", "mkdir -p d1", "cd sub"} {
		if sandboxStatementMayNameHookConfig(statement) {
			t.Errorf("%q: read, but it names no hook file", statement)
		}
	}
}

// TestGAP0366GAP0380GAP0381ActorGuardResiduals pins three residual rows of
// the sandbox guard and statement budget (RKGUEST2/RKGUEST3) against the
// laptop in every pack:
//   - substrate-1 GAP-0366: the write inside a brace group or subshell past
//     the statement budget keeps tamper.agent_hook_config_write;
//   - substrate-1 GAP-0380: a here-string call with 131 statements gets the
//     laptop's answer (both allow), not an actor-only ACTION-COMPOUND-LIMIT;
//   - substrate-1 GAP-0381: an 8 KB call with $CMD after cd keeps
//     tamper.agent_hook_config_write next to the limit.
//
// The actor's verdict and rules equal the laptop's.
func TestGAP0366GAP0380GAP0381ActorGuardResiduals(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	repeat := func(n int, f func(int) string) string {
		var b strings.Builder
		for i := range n {
			b.WriteString(f(i))
		}
		return b.String()
	}
	touch := func(i int) string { return fmt.Sprintf("touch f%d; ", i) }
	settings := "echo '{}' > ../.claude/settings.json"
	rows := []struct{ name, command string }{
		{"GAP-0366 in-brace-140-settings", "cd .cache && { " + repeat(140, touch) + settings + "; }"},
		{"GAP-0366 in-subshell-140-settings", "cd .cache && ( " + repeat(140, touch) + settings + " )"},
		{"GAP-0366 brace-140-then-settings", "cd .cache\n{ " + repeat(140, touch) + "}\n" + settings},
		{"GAP-0380 herestr-130", "bash <<< 'true'\n" + repeat(130, func(i int) string { return fmt.Sprintf("touch f%d\n", i) })},
		{"GAP-0380 herestr-126", "bash <<< 'true'\n" + repeat(126, func(i int) string { return fmt.Sprintf("touch f%d\n", i) })},
		{"GAP-0381 dyn-cd-colon-settings", gap0364Fill("cd .cache\n$CMD\n", func(i int) string { return fmt.Sprintf(":%d\n", i) }, settings, 8192)},
		{"GAP-0381 dyn-cd-colon", gap0364Fill("cd .cache\n$CMD\n", func(i int) string { return fmt.Sprintf(":%d\n", i) }, "ls", 8192)},
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", pack)
			home := filepath.Join(t.TempDir(), "home", "alice")
			for _, dir := range []string{".cache/sub", ".claude", ".ssh"} {
				if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", home)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePack = pack
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			binding := sandboxTestBinding("claudecode")
			actor := withProfilePath(withAuthenticatedHookConnector(sandboxauth.WithRequest(context.Background(), binding, nil), binding.Connector), profilePathHook)
			for _, row := range rows {
				la, lr := gap0304Verdict(t, api, context.Background(), home, row.command)
				ca, cr := gap0304Verdict(t, api, actor, sandboxauth.SandboxHome, row.command)
				if ca != la || !slices.Equal(cr, lr) {
					t.Errorf("%s: copy-mode actor %s %v, laptop %s %v", row.name, ca, cr, la, lr)
				}
				t.Logf("%s: laptop %s %v, actor %s %v", row.name, la, lr, ca, cr)
			}
		})
	}
}
