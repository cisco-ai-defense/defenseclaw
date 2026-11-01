// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gap0568Assignments is a0=1; a1=1; ... a<n-1>=1, the benign form that
// missed the Windows hook window (rel-1-0-2:GAP-0568).
func gap0568Assignments(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("a%d=1", i)
	}
	return strings.Join(parts, "; ")
}

func gap0568Dispatch(t *testing.T, command, cwd, home string) ([]RuleFinding, *hookpaths.TargetMemo) {
	t.Helper()
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	memo := hookpaths.NewTargetMemo()
	input := actionfacts.Input{Tool: "Bash", Args: args, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: string(args), Connector: "claudecode", EnforcementCapable: true, targetMemo: memo,
	})
	return findings, memo
}

// TestGAP0568StatementBudgetWork is rel-1-0-2:GAP-0568 measured with the
// evaluation's work counter (hookpaths.TargetMemo.Work), not a clock. Under
// the statement budget the gateway's evaluation, the call and each of its
// statements alone, shares one memo, so its file system work grows linearly
// with a small constant; a 100-statement call missed the Windows hook
// window when every reading walked the directories again. Over the budget
// the call is refused with ACTION-COMPOUND-LIMIT before the twins, readers
// and per-statement passes run; only the whole-call state check runs, so
// the work stays linear (about one unit per statement) and a state tail
// also takes tamper.detector_state_write, the finding observe mode still
// blocks on.
func TestGAP0568StatementBudgetWork(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	gap0568StateFile(t, home)
	work := map[int]int{}
	for _, n := range []int{32, 64, 128} {
		findings, memo := gap0568Dispatch(t, gap0568Assignments(n), cwd, home)
		if verdict := buildVerdict(findings, "tool_call").Action; verdict == guardrailActionBlock {
			t.Fatalf("%d benign assignments blocked: %v", n, findingIDs(findings))
		}
		work[n] = memo.Work()
	}
	t.Logf("work: n=32 %d, n=64 %d, n=128 %d", work[32], work[64], work[128])
	if first, second := work[64]-work[32], work[128]-work[64]; second > 2*first+16 {
		t.Errorf("work grew faster than linear: +%d for 32 more statements, then +%d for 64 more", first, second)
	}
	if limit := 8*128 + 256; work[128] > limit {
		t.Errorf("128 statements cost %d units of work, want at most %d", work[128], limit)
	}
	const limit, tamper = "ACTION-COMPOUND-LIMIT", "tamper.detector_state_write"
	stateTail := "; printf changed >> ~/.defenseclaw/config.yaml"
	for _, tc := range []struct {
		command    string
		statements int
		want       []string
	}{
		{gap0568Assignments(129), 129, []string{limit}},
		{gap0568Assignments(1100), 1100, []string{limit}},
		{gap0568Assignments(3000), 3000, []string{limit}},
		{gap0568Assignments(600) + "; echo k >> ~/.ssh/authorized_keys", 601, []string{limit}},
		{strings.Repeat("echo x | ", 200) + "cat", 201, []string{limit}},
		{gap0568Assignments(200) + stateTail, 201, []string{limit, tamper}},
		{gap0568Assignments(3000) + stateTail, 3001, []string{limit, tamper}},
	} {
		findings, memo := gap0568Dispatch(t, tc.command, cwd, home)
		ids := findingIDs(findings)
		slices.Sort(ids)
		ids = slices.Compact(ids)
		if buildVerdict(findings, "tool_call").Action != guardrailActionBlock || !slices.Equal(ids, tc.want) {
			t.Errorf("%.40q... (%d statements): findings %v, want %v", tc.command, tc.statements, ids, tc.want)
		}
		if bound := 2*tc.statements + 64; memo.Work() > bound {
			t.Errorf("%.40q... (%d statements): %d units of work over the budget, want at most %d (the whole-call state check only)", tc.command, tc.statements, memo.Work(), bound)
		}
	}
}

// gap0568StateFile makes the active state file ~/.defenseclaw/config.yaml.
func gap0568StateFile(t testing.TB, home string) string {
	t.Helper()
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(state), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte("guardrail:\n  mode: observe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return state
}

// BenchmarkGAP0568HookAssignmentChain times one per-user hook answer (the
// client header and the gateway) for a chain of n assignments, the
// rel-1-0-2:GAP-0568 form, for both connectors.
func BenchmarkGAP0568HookAssignmentChain(b *testing.B) {
	home := b.TempDir()
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		b.Fatal(err)
	}
	b.Setenv("HOME", home)
	b.Setenv("USERPROFILE", home)
	for _, n := range []int{100, 500, 3000} {
		for _, connector := range []string{"claudecode", "codex"} {
			payload, err := json.Marshal(map[string]any{"session_id": "gap0568", "hook_event_name": "PreToolUse", "cwd": project,
				"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_gap0568",
				"tool_input": map[string]any{"command": gap0568Assignments(n)}})
			if err != nil {
				b.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			b.Run(fmt.Sprintf("n=%d/%s", n, connector), func(b *testing.B) {
				for b.Loop() {
					req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
					if header := hookpaths.Resolve(payload); header != "" {
						req.Header.Set(hookpaths.Header, header)
					}
					if connector == "codex" {
						setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
					}
					api.handleAgentHook(connector).ServeHTTP(httptest.NewRecorder(), req)
				}
			})
		}
	}
}

// TestGAP0318StatementBudgetOnEveryDialectRoute is rel-1-0-6:GAP-0318: a
// call that PowerShell may run (Codex on Windows sends no dialect hint; a
// PowerShell hint or tool here, so the test reads the same on every OS)
// past the 64 KiB analysis bound with more than 128 statements is refused
// by the statement budget before the readers run, as Claude Code's Bash
// call is; only the whole-call state check runs (linear work), so a state
// tail also takes tamper.detector_state_write. Before, no reading finished, no budget applied, and the call was
// allowed after about 4 s of reading on Windows. One long PowerShell
// statement past the bound is not over the statement budget.
func TestGAP0318StatementBudgetOnEveryDialectRoute(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	var writes strings.Builder
	for i := range 3000 {
		if i > 0 {
			writes.WriteString("; ")
		}
		fmt.Fprintf(&writes, "echo line%d >> ordinary/n%d.txt", i, i)
	}
	long := "Set-Content notes.txt -Value @'\n" + strings.Repeat("ordinary text line\n", 4000) + "'@"
	gap0568StateFile(t, home)
	const stateWrite = "echo changed > ~/.defenseclaw/config.yaml"
	stateTail := writes.String() + "; " + stateWrite
	for _, route := range []struct {
		name, tool string
		hint       actionfacts.Dialect
	}{
		{"Bash tool, PowerShell hint", "Bash", actionfacts.DialectPowerShell},
		{"PowerShell tool", "powershell", ""},
	} {
		dispatch := func(command string, memo *hookpaths.TargetMemo) []RuleFinding {
			args, err := json.Marshal(map[string]string{"command": command})
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{Tool: route.tool, Args: args, CWD: cwd, ActiveHome: home, DialectHint: route.hint}
			return dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: "codex", EnforcementCapable: true, targetMemo: memo,
			})
		}
		// Over the budget the call keeps the state proof the route forms for
		// the state write alone (none for a PowerShell hint on this host's
		// POSIX home, at any size).
		stateWants := []string{"ACTION-COMPOUND-LIMIT"}
		if findingWithID(dispatch(stateWrite, nil), "tamper.detector_state_write") != nil {
			stateWants = append(stateWants, "tamper.detector_state_write")
		}
		for _, tc := range []struct {
			command string
			over    bool
			want    []string
		}{
			{writes.String(), true, []string{"ACTION-COMPOUND-LIMIT"}},
			{stateTail, true, stateWants},
			{long, false, nil},
		} {
			args, err := json.Marshal(map[string]string{"command": tc.command})
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{Tool: route.tool, Args: args, CWD: cwd, ActiveHome: home, DialectHint: route.hint}
			if facts := actionfacts.Analyze(input); facts.Parse.Status != actionfacts.StatusLimitExceeded {
				t.Fatalf("%s: %d-byte call analysis status %q, want limit_exceeded", route.name, len(tc.command), facts.Parse.Status)
			}
			memo := hookpaths.NewTargetMemo()
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: "codex", EnforcementCapable: true, targetMemo: memo,
			})
			limited := findingWithID(findings, "ACTION-COMPOUND-LIMIT") != nil
			ids := findingIDs(findings)
			slices.Sort(ids)
			ids = slices.Compact(ids)
			switch {
			case tc.over && (!slices.Equal(ids, tc.want) || memo.Work() > 2*3001+64):
				t.Errorf("%s: 3000 statements: findings %v after %d units of work, want %v with linear work", route.name, ids, memo.Work(), tc.want)
			case !tc.over && limited:
				t.Errorf("%s: one long statement took the statement budget: %v", route.name, findingIDs(findings))
			}
		}
	}
}
