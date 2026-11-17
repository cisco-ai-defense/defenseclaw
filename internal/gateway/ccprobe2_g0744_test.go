// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0744: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha b78d35a3ec lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"context"
	"encoding/json"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Every GAP-0526 row blocks in all five tiers on the Claude Code and Codex
// hook routes, /inspect/tool (OpenClaw), ACP and the proxy's tool-call check,
// where the control blocks alone, and names the control's rule.
func TestCCP2G0744_GAP0526BlockedCommandWithSyntaxErrorStillBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text; OpenClaw exec is PowerShell on native Windows")
	}
	cases := gap0526Cases()
	for _, id := range gap0526SortedIDs(cases) {
		gap0526HasSyntaxError(t, id, cases[id].command)
	}
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			hook := gap0437Server(t, p, "claudecode", "action")
			codex := gap0437Server(t, p, "codex", "action")
			inspect := gap0437Server(t, p, "openclaw", "action")
			// A loaded -race box can pass the product scan window on these
			// many calls; the verdict, not the window, is under test.
			inspect.inspectToolScanTimeout = time.Minute
			acpEnv := gap0526ACPEnv(t, p)
			cwd := t.TempDir()
			routes := map[string]func(id, command string) map[string]any{
				"hook-claudecode": func(id, command string) map[string]any { return gap0437Hook(t, hook, cwd, p.name+id, command) },
				"hook-codex":      func(id, command string) map[string]any { return gap0526Codex(t, codex, cwd, p.name+id, command) },
				"inspect-tool":    func(_, command string) map[string]any { return gap0437Inspect(t, inspect, cwd, command) },
				"acp":             func(_, command string) map[string]any { return gap0526ACP(t, acpEnv, p.managed, command) },
			}
			for _, route := range gap0526SortedIDs(routes) {
				decide := routes[route]
				controls := map[string]string{}
				for id, command := range gap0486Blocked {
					controls[id] = gap0526ControlRule(t, route+" "+p.name+" "+id, decide(id, command))
				}
				for _, id := range gap0526SortedIDs(cases) {
					k := cases[id]
					out := decide(id, k.command)
					where := route + " " + p.name + " " + id
					if out["action"] != "block" {
						t.Errorf("%s: action %v, want block (%s blocks alone): %v", where, out["action"], k.control, out)
						continue
					}
					if !gap0526Names(out, controls[k.control]) {
						t.Errorf("%s: the answer lost the control's rule %s: %v", where, controls[k.control], out)
					}
				}
			}
		})
	}
	// The proxy's tool-call check reads the same dispatch.
	rank := map[string]int{"": 0, "allow": 0, "alert": 1, "confirm": 1, "block": 2}
	for _, mode := range gap0437Modes {
		proxy := ccp2g0744_newTestProxy(t, &mockProvider{}, newMockInspector(), mode)
		verdictOf := func(command string) string {
			args, _ := json.Marshal(map[string]string{"command": command})
			calls, _ := json.Marshal([]map[string]any{{"type": "function", "function": map[string]string{"name": "Bash", "arguments": string(args)}}})
			if v := proxy.inspectToolCalls(context.Background(), calls); v != nil {
				return v.Action
			}
			return "allow"
		}
		for _, id := range gap0526SortedIDs(cases) {
			k := cases[id]
			if control, combined := verdictOf(gap0486Blocked[k.control]), verdictOf(k.command); !ccp2g0744_gap0825ProxyHolds(id, control, combined, rank, verdictOf) {
				t.Errorf("/llm %s %s: %s alone, %s with the syntax error", mode, id, control, combined)
			}
		}
	}
}

// The GAP-0526 sweep: each blocking control (B1 and B3 as written, and as
// eval and bash -c bodies) with random plain syntax errors from a small
// grammar (unbalanced quotes and brackets, closing keywords without an
// opener, dangling operators), put after the control (outside the body) or
// at the end of the body. At least 500 combinations per command, in the
// default, permissive and strict packs: none may be allowed or alerted where
// the command alone blocks.
func TestCCP2G0744_GAP0526SyntaxErrorSweepNeverAllowsABlockedCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	// The full sweep (500 suffixes per command, about two and a half
	// minutes) runs with DEFENSECLAW_FULL_SWEEP set; the package run reads
	// 100, the race build and -short 50.
	perCommand := 100
	switch {
	case os.Getenv("DEFENSECLAW_FULL_SWEEP") != "":
		perCommand = 500
	case testing.Short() || hookAnswerRaceBuild:
		perCommand = 50
	}
	suffixes := gap0526SyntaxSuffixes(perCommand)
	type shaped struct {
		name string
		with func(suffix string) string
	}
	var commands []shaped
	for _, id := range gap0526SortedIDs(gap0486Blocked) {
		blocked := gap0486Blocked[id]
		commands = append(commands,
			shaped{id, func(s string) string { return blocked + s }},
			shaped{"E" + id, func(s string) string { return "eval " + gap0526Quote(blocked+s) }},
			shaped{"N" + id, func(s string) string { return "bash -c " + gap0526Quote(blocked+s) }},
		)
	}
	for _, name := range []string{"default", "permissive", "strict"} {
		p := gap0437Pack{name: name, pack: name}
		t.Run(name, func(t *testing.T) {
			hook := gap0437Server(t, p, "claudecode", "action")
			cwd := t.TempDir()
			allowed := 0
			for _, c := range commands {
				if out := gap0437Hook(t, hook, cwd, name+c.name, c.with("")); out["action"] != "block" {
					t.Fatalf("%s %s: the control must block alone: %v", name, c.name, out)
				}
				for i, suffix := range suffixes {
					command := c.with(suffix)
					out := gap0437Hook(t, hook, cwd, name+c.name+"-"+string(rune('a'+i%26)), command)
					if out["action"] != "block" {
						allowed++
						if allowed <= 200 {
							t.Errorf("%s %s suffix %d %q: action %v, want block (rules %v)", name, c.name, i, suffix, out["action"], out["rule_ids"])
						}
					}
				}
			}
			if allowed != 0 {
				t.Errorf("%s: %d of %d combinations not blocked", name, allowed, len(commands)*len(suffixes))
			}
			t.Logf("GAP0526SWEEP pack=%s commands=%d suffixes=%d combinations=%d not_blocked=%d",
				name, len(commands), len(suffixes), len(commands)*len(suffixes), allowed)
		})
	}
}

// The part of a command with a syntax error that was not read is recorded
// on the answer (ACTION-PARSE-FAILURE, detection-only), so the call is never
// a silent allow; it does not raise the verdict by itself (owner traces:
// unreadPartFindings). A reading cut at a cap of shellparse.ReadSyntaxTail
// takes the evaluation-limit path: at least the unknown tier of the pack,
// alert in default, permissive and managed, block in strict and managed
// strict (the bound rule).
func TestCCP2G0744_GAP0526UnreadSyntaxErrorIsRecordedAndCapsTakeTheUnknownTier(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	capped := strings.Repeat("ls\nfi\n", shellparse.MaxSyntaxTailStatements+8)
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			hook := gap0437Server(t, p, "claudecode", "action")
			inspect := gap0437Server(t, p, "openclaw", "action")
			cwd := t.TempDir()
			for _, command := range []string{"ls\nfi", "eval " + gap0526Quote("ls\nfi"), "ls; done", "ls\necho 'x"} {
				for route, out := range map[string]map[string]any{
					"hook":    gap0437Hook(t, hook, cwd, p.name+command, command),
					"inspect": gap0437Inspect(t, inspect, cwd, command),
				} {
					if !gap0526Names(out, parseFailureRuleID) {
						t.Errorf("%s %s %q: the answer does not record %s: %v", route, p.name, command, parseFailureRuleID, out)
					}
				}
			}
			want := "alert"
			if p.pack == "strict" {
				want = "block"
			}
			for route, out := range map[string]map[string]any{
				"hook":    gap0437Hook(t, hook, cwd, p.name+"capped", capped),
				"inspect": gap0437Inspect(t, inspect, cwd, capped),
			} {
				if out["action"] != want && out["action"] != "block" {
					t.Errorf("%s %s capped: action %v, want %s: %v", route, p.name, out["action"], want, out)
				}
			}
		})
	}
}

// The GAP-0535 sweep: every spelling of the -c option x {bash, sh, zsh,
// dash} x {direct, env, sudo, nice, timeout, command} x the B1 and EB1
// (eval) bodies, in the default, permissive and strict packs. The body
// blocks alone; none of the calls may be allowed or only alerted.
func TestCCP2G0744_GAP0535QuotedShellOptionSweepNeverAllowsABlockedBody(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	bodies := map[string]string{"B1": gap0486Blocked["B1"], "EB1": "eval " + gap0526Quote(gap0486Blocked["B1"]), "B3": gap0486Blocked["B3"]}
	// The full sweep (all 60 spellings, about seven minutes) runs with
	// DEFENSECLAW_FULL_SWEEP set; the package run reads the first 10
	// spellings of -c with every wrapper, shell and body, the race build and
	// -short the first 3, so the gateway package stays inside its gate
	// timeout.
	options := gap0535OptionWords()
	switch {
	case os.Getenv("DEFENSECLAW_FULL_SWEEP") != "":
	case testing.Short() || hookAnswerRaceBuild:
		options = options[:3]
	default:
		options = options[:10]
	}
	for _, name := range []string{"default", "permissive", "strict"} {
		p := gap0437Pack{name: name, pack: name}
		t.Run(name, func(t *testing.T) {
			hook := gap0437Server(t, p, "claudecode", "action")
			cwd := t.TempDir()
			total, notBlocked := 0, 0
			for _, bodyID := range gap0526SortedIDs(bodies) {
				body := bodies[bodyID]
				if out := gap0437Hook(t, hook, cwd, name+bodyID, body); out["action"] != "block" {
					t.Fatalf("%s %s: the body must block alone: %v", name, bodyID, out)
				}
				for _, wrapperID := range gap0526SortedIDs(gap0535Wrappers) {
					for _, shell := range gap0535Shells {
						for i, option := range options {
							command := gap0535Wrappers[wrapperID] + shell + " " + option + " " + gap0526Quote(body)
							total++
							out := gap0437Hook(t, hook, cwd, name+bodyID+wrapperID+shell+string(rune('a'+i%26)), command)
							if out["action"] != "block" {
								notBlocked++
								if notBlocked <= 40 {
									t.Errorf("%s %s %s %s option %q: action %v, want block (rules %v)", name, bodyID, wrapperID, shell, option, out["action"], out["rule_ids"])
								}
							}
						}
					}
				}
			}
			t.Logf("GAP0535SWEEP pack=%s combinations=%d not_blocked=%d", name, total, notBlocked)
		})
	}
}

// A shell call whose option word or -c body the walk cannot resolve is the
// unknown tier as an alert in every pack (ACTION-PARSE-FAILURE, never a
// block): what the body runs is not known.
func TestCCP2G0744_GAP0535UnresolvedShellBodyIsRecorded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			hook := gap0437Server(t, p, "claudecode", "action")
			cwd := t.TempDir()
			for _, command := range []string{`bash "$o" 'ls'`, `bash -c "$(cat f)"`, `env bash "$o" 'ls'`} {
				out := gap0437Hook(t, hook, cwd, p.name+command, command)
				if !gap0526Names(out, parseFailureRuleID) {
					t.Errorf("%s %q: the answer does not record %s: %v", p.name, command, parseFailureRuleID, out)
				}
				// The unknown tier as an alert in every pack, never a block.
				if out["action"] != "alert" {
					t.Errorf("%s %q: action %v, want alert", p.name, command, out["action"])
				}
			}
			// A shell running a script whose path is dynamic has no -c body.
			if out := gap0437Hook(t, hook, cwd, p.name+"script", `bash "$f"`); gap0526Names(out, unresolvedBodyTitle) {
				t.Errorf("%s: a script run is recorded as an unresolved body: %v", p.name, out)
			}
		})
	}
}

// rel-1-0-10:GAP-0548. A proven finding on the readable text of a call the
// parser rejects decides, at every filler size (the listing rows of the gap
// belong to lane s7-sshfp, GAP-0570); and text the parser rejects but
// a shell runs, writing the DefenseClaw state, is recorded in every pack and
// alerted by the strict and managed raw-text check of the unread part.
func TestCCP2G0744_GAP0548ProvenFindingSurvivesAParseFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			hook := gap0437Server(t, p, "claudecode", "action")
			home := t.TempDir()
			for _, n := range []int{3, 128, 256} {
				command := boundedShellSeen + "; " + gap0548Filler(n)
				if out := gap0437Hook(t, hook, home, p.name+"seen"+string(rune('a'+n%26)), command); out["action"] != "block" {
					t.Errorf("%s state write + filler %d: action %v, want block: %v", p.name, n, out["action"], out["rule_ids"])
				}
			}
			// The strict and managed raw-text check of the unread part ships
			// alert-only in 1.0.10 (owner traces: a blocking check added 150
			// false blocks of 56,443 calls in strict): an alert there, the
			// detection-only record elsewhere.
			differential := gap0437Hook(t, hook, home, p.name+"diff", gap0548Differential())
			want := "allow"
			if p.pack == "strict" || p.managed {
				want = "alert"
			}
			if got := differential["action"]; got != want {
				t.Errorf("%s parser differential: action %v, want %s: %v", p.name, got, want, differential["rule_ids"])
			}
			if !gap0526Names(differential, parseFailureRuleID) {
				t.Errorf("%s parser differential: no %s record: %v", p.name, parseFailureRuleID, differential)
			}
		})
	}
}

// rel-1-0-10:GAP-0643. The listing skip of 90e6605b8a dropped the keys file
// named by a listing and read back through $_ by the next statement; it is
// reverted (the listing class is lane s7-sshfp, GAP-0570). The row of
// TestGAP0570SSHFolderReadsLinksAndCheckoutAreNotKeyOrHookWrites (s7/sshfp)
// blocks in every tier, as on rel.
func TestCCP2G0744_GAP0643ListedKeysNameReadBackStillBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	command := "ls ~/.ssh/authorized_keys; echo marker >> $_"
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		if out := gap0437Hook(t, hook, t.TempDir(), p.name+"g643", command); out["action"] != "block" {
			t.Errorf("%s: action %v, want block: %v", p.name, out["action"], out["rule_ids"])
		}
	}
}

// gap0825ProxyHolds reports that a row's combined /llm verdict is not lower
// than its no-fault control, or, for a GAP-0825 row, not lower than its
// unreadable text alone.
func ccp2g0744_gap0825ProxyHolds(id, control, combined string, rank map[string]int, verdictOf func(string) string) bool {
	if rank[combined] >= rank[control] {
		return true
	}
	unread, ok := ccp2g0744_gap0825ProxyUnreadFirst(id)
	return ok && rank[combined] >= rank[verdictOf(unread)]
}

// gap0825ProxyUnreadFirst returns, for a row whose unreadable text comes
// before the control statement (K..b: the fault text first; GP: a lone fi
// first), that text. The /llm proxy sends no cwd or home, so it reads no
// parser fault and no syntax-error remainder (rel-1-0-10:GAP-0825, for
// T-BOUNDS after push 3): on that route such a row is held to the verdict of
// its unreadable text alone, never below it, until GAP-0825 lands. The hook
// and inspect/tool routes read those rows in full and block them in every
// pack (TestGAP0486BlockedCommandWithFaultTextStillBlocks,
// TestGAP0526BlockedCommandWithSyntaxErrorStillBlocks).
func ccp2g0744_gap0825ProxyUnreadFirst(id string) (string, bool) {
	switch {
	case strings.HasPrefix(id, "K") && strings.HasSuffix(id, "b"):
		return gap0437Fault, true
	case strings.HasPrefix(id, "GP"):
		return "fi", true
	}
	return "", false
}

func ccp2g0744_newTestProxy(t *testing.T, prov LLMProvider, insp ContentInspector, mode string) *GuardrailProxy {
	t.Helper()
	// A test proxy has no gateway generation of its own, so guardrail
	// profiles another test left in liveGuardrailProfiles (NewAPIServer
	// publishes its set there) are not its profiles: with a default profile
	// in action mode they turned this proxy's observe mode into action, but
	// only when such a test ran earlier in the same binary (Windows shard
	// gw14, push 12). It starts with none; the previous set comes back after.
	previousProfiles := liveGuardrailProfiles.Load()
	liveGuardrailProfiles.Store(nil)
	t.Cleanup(func() { liveGuardrailProfiles.Store(previousProfiles) })
	cfg := &config.GuardrailConfig{
		Enabled:   true,
		Model:     "openai/gpt-4",
		ModelName: "gpt-4",
		Port:      0,
		Mode:      mode,
	}
	store, logger := testStoreAndLogger(t)
	health := NewSidecarHealth()

	p := &GuardrailProxy{
		cfg:       cfg,
		logger:    logger,
		health:    health,
		store:     store,
		dataDir:   t.TempDir(),
		inspector: insp,
		mode:      mode,
		// Plan B2 / S0.2: production paths fail closed when the
		// gateway token is empty. The legacy fixtures in this file
		// construct a proxy directly without going through
		// NewGuardrailProxy (no token synthesis), so flip the
		// test-only bypass; the auth behavior itself is covered by
		// dedicated TestTokenAuth_* / TestProxyAuth_* tests that
		// leave skipAuthForTest false.
		skipAuthForTest: true,
	}
	// Inject the mock provider — bypasses header-based resolution.
	p.resolveProviderFn = func(_ *ChatRequest) LLMProvider { return prov }
	return p
}
