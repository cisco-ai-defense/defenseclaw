// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// rel-1-0-10:GAP-0526. A command that blocks on its own (the controls B1 and
// B3 of the s7-panicrev differential, gap0486Blocked) still blocks, and names
// the rule that blocks it alone, when a plain syntax error is put after,
// before or beside it, or inside the eval or bash -c body that holds it. The
// structured parse of such a text fails; its readable statements are judged
// (shellparse.ReadSyntaxTail), and the rest is judged at the unknown tier of
// the pack. Every case is a transformation of the existing fixtures in code.

// gap0526Quote is a POSIX single-quoted word of s (test text only).
func gap0526Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// gap0526Cases are the GAP-0526 rows: G (a trailing line holding only fi),
// NG (G as a bash -c body), EG (G as an eval body), EK..a (the control and
// the GAP-0437 fault text as an eval body: the recovering parse never reads
// an eval body, so it is a plain syntax error there), and the shapes of the
// token fallback: the error on the same line (GS), after a list operator
// (GA), before the control (GP), and an unbalanced quote after it (GQ).
func gap0526Cases() map[string]struct{ control, command string } {
	out := map[string]struct{ control, command string }{}
	for id, blocked := range gap0486Blocked {
		n := id[1:]
		g := blocked + "\nfi"
		for name, command := range map[string]string{
			"G" + n:        g,
			"NG" + n:       "bash -c " + gap0526Quote(g),
			"EG" + n:       "eval " + gap0526Quote(g),
			"EK" + n + "a": "eval " + gap0526Quote(blocked+"\n"+gap0437Fault),
			"GS" + n:       blocked + "; fi",
			"GA" + n:       blocked + " && fi",
			"GP" + n:       "fi\n" + blocked,
			"GQ" + n:       blocked + "\necho 'x",
		} {
			out[name] = struct{ control, command string }{id, command}
		}
	}
	return out
}

func gap0526SortedIDs[V any](m map[string]V) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// gap0526HasSyntaxError checks that a row is the shape under test: a text
// the structured parse rejects with a plain syntax error, not a parser fault.
func gap0526HasSyntaxError(t *testing.T, id, command string) {
	t.Helper()
	if _, parsed := shellparse.Parse(command); parsed && !strings.HasPrefix(id, "N") && !strings.HasPrefix(id, "E") {
		t.Fatalf("%s: the row parses; it must hold a syntax error", id)
	}
}

func gap0526Codex(t *testing.T, a *APIServer, cwd, id, command string) map[string]any {
	t.Helper()
	body := map[string]any{"session_id": "gap0526-" + id, "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "cwd": cwd, "tool_input": map[string]any{"command": command}}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.Resolve(raw))
	setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	w := httptest.NewRecorder()
	a.handleAgentHook("codex").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("codex hook: status %d body %s", w.Code, w.Body.String())
	}
	out := map[string]any{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("codex hook answer %q: %v", w.Body.String(), err)
	}
	return out
}

// gap0526ACP runs command as the bash -c body of a terminal/create frame in
// action mode and returns the verdict as a map.
func gap0526ACP(t *testing.T, env *acpActionEnv, managedRequest bool, command string) map[string]any {
	t.Helper()
	frame := acpFrameJSON(t, 1, "terminal/create",
		map[string]any{"sessionId": "s", "command": "bash", "args": []string{"-c", command}, "cwd": env.project})
	verdict := gap0486ACPEvaluate(t, env, acp.AgentToClient, frame, managedRequest)
	raw, _ := json.Marshal(verdict)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	out["action"] = verdict.Action
	return out
}

func gap0526ACPEnv(t *testing.T, p gap0437Pack) *acpActionEnv {
	t.Helper()
	env := newACPActionEnv(t, p.pack)
	policies, err := filepath.Abs(filepath.Join("..", "..", "policies"))
	if err != nil {
		t.Fatal(err)
	}
	env.acpAPI.scannerCfg.PolicyDir = policies
	if p.managed {
		env.acpAPI.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		env.acpAPI.scannerCfg.Enterprise.Profile = managed.ProfileStandalone
	}
	env.setMode(acp.ModeAction)
	return env
}

// gap0526RuleInReason is the first rule id a block reason names, the
// upper-case catalog ids and the dotted semantic ids alike.
var gap0526RuleInReason = regexp.MustCompile(`\brules? ([A-Za-z][A-Za-z0-9_]*(?:[-.][A-Za-z0-9_]+)+)`)

// gap0526ControlRule is the rule id that blocks a control alone on a route.
func gap0526ControlRule(t *testing.T, where string, out map[string]any) string {
	t.Helper()
	reason, _ := out["reason"].(string)
	match := gap0526RuleInReason.FindStringSubmatch(reason)
	if out["action"] != "block" || match == nil {
		t.Fatalf("%s: the control must block alone with a rule: %v", where, out)
	}
	return match[1]
}

func gap0526Names(out map[string]any, rule string) bool {
	raw, _ := json.Marshal(out)
	return strings.Contains(string(raw), rule)
}

// Every GAP-0526 row blocks in all five tiers on the Claude Code and Codex
// hook routes, /inspect/tool (OpenClaw), ACP and the proxy's tool-call check,
// where the control blocks alone, and names the control's rule.
func TestGAP0526BlockedCommandWithSyntaxErrorStillBlocks(t *testing.T) {
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
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), mode)
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
			if control, combined := verdictOf(gap0486Blocked[k.control]), verdictOf(k.command); !gap0825ProxyHolds(control, combined, rank) {
				t.Errorf("/llm %s %s: %s alone, %s with the syntax error", mode, id, control, combined)
			}
		}
	}
}

// The part of a command with a syntax error that was not read is recorded
// on the answer (ACTION-PARSE-FAILURE, detection-only), so the call is never
// a silent allow; it does not raise the verdict by itself (owner traces:
// unreadPartFindings). A reading cut at a cap of shellparse.ReadSyntaxTail
// takes the evaluation-limit path: at least the unknown tier of the pack,
// alert in default, permissive and managed, block in strict and managed
// strict (the bound rule).
func TestGAP0526UnreadSyntaxErrorIsRecordedAndCapsTakeTheUnknownTier(t *testing.T) {
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

// The GAP-0526 sweep: each blocking control (B1 and B3 as written, and as
// eval and bash -c bodies) with random plain syntax errors from a small
// grammar (unbalanced quotes and brackets, closing keywords without an
// opener, dangling operators), put after the control (outside the body) or
// at the end of the body. At least 500 combinations per command, in the
// default, permissive and strict packs: none may be allowed or alerted where
// the command alone blocks.
func TestGAP0526SyntaxErrorSweepNeverAllowsABlockedCommand(t *testing.T) {
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

// gap0526SyntaxSuffixes generates n distinct suffixes, each a plain syntax
// error after any of the controls (checked: the control with it fails the
// structured parse and is no parser fault), from a fixed seed.
func gap0526SyntaxSuffixes(n int) []string {
	joiners := []string{"\n", "; ", " ", " && ", " | ", "\n\n"}
	breakers := []string{"'", "\"", "`", "(", ")", "{", "}", "$(", "((", "fi", "done", "esac", "then", "do", "else",
		"elif", "&&", "||", "|", ";;", "<", ">", "<<<", "[[", "]]", "if", "for", "while", "case"}
	words := []string{"x", "echo y", "ls", "true", "z=1", "cat f", "\n", ";"}
	rng := rand.New(rand.NewPCG(526, 1))
	seen := map[string]bool{}
	var out []string
	for attempts := 0; len(out) < n && attempts < 200*n; attempts++ {
		var b strings.Builder
		b.WriteString(joiners[rng.IntN(len(joiners))])
		for parts := 1 + rng.IntN(4); parts > 0; parts-- {
			if rng.IntN(3) == 0 {
				b.WriteString(words[rng.IntN(len(words))])
			} else {
				b.WriteString(breakers[rng.IntN(len(breakers))])
			}
			if parts > 1 {
				b.WriteString(joiners[rng.IntN(len(joiners))])
			}
		}
		suffix := b.String()
		if seen[suffix] {
			continue
		}
		plain := true
		for _, blocked := range gap0486Blocked {
			if _, ok := shellparse.ReadSyntaxTail(blocked + suffix); !ok {
				plain = false
				break
			}
		}
		if plain && !slices.Contains(out, suffix) {
			seen[suffix] = true
			out = append(out, suffix)
		}
	}
	return out
}

// rel-1-0-10:GAP-0535. A shell's -c option is the word the shell sees, not
// its spelling: quoted, ANSI-C quoted, concatenated, escaped or combined
// with other short options, the body after it runs. gap0535OptionWords
// spells the option in each of those ways (built in code from "-c" and the
// short options the -c readers accept).
func gap0535OptionWords() []string {
	var out []string
	for _, option := range []string{"-c", "-lc", "-ic", "-xc", "-ec", "-ce"} {
		flags := option[1:]
		out = append(out,
			option,
			"'"+option+"'",
			`"`+option+`"`,
			"$'"+option+"'",
			"-'"+flags+"'",
			`"-"`+flags,
			`\`+option,
			"-"+`\`+flags,
			"$'\\x2d"+flags+"'",
			"'-'\""+flags+"\"",
		)
	}
	return out
}

// gap0535Wrappers runs a shell directly or behind a wrapper.
var gap0535Wrappers = map[string]string{
	"direct": "", "env": "env ", "env-assign": "env A=1 ", "sudo": "sudo ", "nice": "nice ",
	"nice-n": "nice -n 5 ", "timeout": "timeout 5 ", "command": "command ",
}

var gap0535Shells = []string{"bash", "sh", "zsh", "dash"}

// The GAP-0535 sweep: every spelling of the -c option x {bash, sh, zsh,
// dash} x {direct, env, sudo, nice, timeout, command} x the B1 and EB1
// (eval) bodies, in the default, permissive and strict packs. The body
// blocks alone; none of the calls may be allowed or only alerted.
func TestGAP0535QuotedShellOptionSweepNeverAllowsABlockedBody(t *testing.T) {
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
func TestGAP0535UnresolvedShellBodyIsRecorded(t *testing.T) {
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

// gap0548Filler is the GAP-0548 filler: n units of a, a background
// ampersand, a line continuation and an ampersand. Bash joins the
// continuation (a && a ...); the shell parser here rejects it.
func gap0548Filler(n int) string { return strings.Repeat("a&\\\n&", n) + "a" }

// gap0548Differential is the bound-rule state-write fixture
// (boundedShellSeen) with its append operator split by a line continuation:
// real bash 5.2 runs it as the plain append (checked on dev in a scratch
// home with dummy files, s7-syntail 2026-11-14), the shell parser here
// rejects it.
func gap0548Differential() string { return strings.Replace(boundedShellSeen, ">>", ">\\\n>", 1) }

// rel-1-0-10:GAP-0548. A proven finding on the readable text of a call the
// parser rejects decides, at every filler size (the listing rows of the gap
// belong to lane s7-sshfp, GAP-0570); and text the parser rejects but
// a shell runs, writing the DefenseClaw state, is recorded in every pack and
// alerted by the strict and managed raw-text check of the unread part.
func TestGAP0548ProvenFindingSurvivesAParseFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			hook := gap0437Server(t, p, "claudecode", "action")
			home := t.TempDir()
			// A proven state write alerts outside strict (GAP-0747).
			wantStateWrite := "alert"
			if p.pack == "strict" {
				wantStateWrite = "block"
			}
			for _, n := range []int{3, 128, 256} {
				command := boundedShellSeen + "; " + gap0548Filler(n)
				if out := gap0437Hook(t, hook, home, p.name+"seen"+string(rune('a'+n%26)), command); out["action"] != wantStateWrite {
					t.Errorf("%s state write + filler %d: action %v, want %s: %v", p.name, n, out["action"], wantStateWrite, out["rule_ids"])
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
func TestGAP0643ListedKeysNameReadBackStillBlocks(t *testing.T) {
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
