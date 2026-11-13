// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// The cross-lane property test of the bound rule (internal/guardrail/bounded):
// for every cap of every lane in boundedLanes, an input just past the cap,
// and one far past it, is judged at least as strictly as the same shape at
// the cap and at least at the unknown tier, in every tier; and an element
// the lane judges on its own, placed before the cap, still decides past it.
//
// A lane registers its caps from its own test file, so a new lane is covered
// by adding one file:
//
//	func init() {
//		registerBoundedLane(boundedLaneCap{lane: "s7/nonshell mcp-mapper", cap: bounded.Paths,
//			limit: maxPaths, adopted: true, gen: nonShellPathsCall})
//	}
//
// Inputs come from generator functions of size and shape, never from literal
// attack text.

// boundedLaneCap is one cap of one lane.
type boundedLaneCap struct {
	lane  string
	cap   bounded.Cap
	limit int
	// gen builds the lane's input of the given size (limit is at the cap,
	// limit+1 just past it). shape.seen puts the lane's seen element (an
	// element it judges on its own, from its existing fixtures) before the
	// part the cap measures.
	gen func(size int, shape boundedShape) boundedLaneCall
	// adopted lanes reach withBoundedTruncation or floorBoundedTruncated:
	// past the cap the answer names the bounded reason with this cap.
	adopted bool
	// decide runs one call through the lane's hook decision and returns the
	// action and finding strings; nil runs it through the Claude Code hook.
	decide func(t *testing.T, api *APIServer, env boundedEnv, call boundedLaneCall) (string, []string)
	// open names, by tier name ("*" for every tier), the gap of a known
	// violation not yet fixed in this tree: its failures are logged, not
	// failed. A lane deletes the entry in its fix.
	open map[string]string
}

// boundedShape is the shape of a generated input.
type boundedShape struct {
	seen bool
}

// boundedLaneCall is one generated tool call.
type boundedLaneCall struct {
	tool  string
	input map[string]any
}

// boundedEnv is the home and working folder the calls run in.
type boundedEnv struct {
	home, cwd string
}

var boundedLanes []boundedLaneCap

func registerBoundedLane(caps ...boundedLaneCap) { boundedLanes = append(boundedLanes, caps...) }

// The shell reading bounds on rel/1.0.10 (lane s7/parselimits). Nesting is a
// cap of the reading budget and reaches the helper (withBudgetTruncation);
// the statement and operand budgets take the evaluation-limit path of their
// own (the managed floor of both follows rel-1-0-6:GAP-0675: alert).
func init() {
	registerBoundedLane(
		boundedLaneCap{lane: "shell-parse nesting", cap: bounded.Depth, limit: shellparse.MaxNestingDepth,
			adopted: true, gen: boundedShellCall(boundedNestedSubshells)},
		boundedLaneCap{lane: "shell-parse statements", cap: bounded.Items, limit: boundedShellStatements,
			gen: boundedShellCall(gap0568Assignments)},
		boundedLaneCap{lane: "shell operands", cap: bounded.Items, limit: actionfacts.MaxOperandsPerCall,
			gen: boundedShellCall(boundedListOperands), open: map[string]string{"*": "rel-1-0-10:GAP-0313"}},
	)
}

// boundedShellStatements is the statement budget of one POSIX call
// (actionfacts.maxStatementsAlone).
const boundedShellStatements = 128

// boundedShellSeen is the lane's seen element: a write the reader resolves
// into the DefenseClaw state folder, which blocks in every tier (fixture of
// TestEvaluationLimitOnlyCallAlertsOutsideStrict).
const boundedShellSeen = "printf changed >> ~/.defenseclaw/config.yaml"

// boundedShellCall is a Bash call of the command fill(size), after the seen
// element when the shape asks for it.
func boundedShellCall(fill func(size int) string) func(int, boundedShape) boundedLaneCall {
	return func(size int, shape boundedShape) boundedLaneCall {
		command := fill(size)
		if shape.seen {
			command = boundedShellSeen + "; " + command
		}
		return boundedLaneCall{tool: "Bash", input: map[string]any{"command": command}}
	}
}

// boundedNestedSubshells is a true command nested in size subshells.
func boundedNestedSubshells(size int) string {
	return strings.Repeat("(", size) + "true" + strings.Repeat(")", size)
}

// boundedListOperands lists size operands of the working folder.
func boundedListOperands(size int) string {
	var b strings.Builder
	b.WriteString("ls")
	for i := range size {
		b.WriteString(" o")
		b.WriteString(strings.Repeat("x", i%7+1))
	}
	return b.String()
}

// boundedDecideClaudeCode sends one PreToolUse call through the Claude Code
// hook with the hook client's resolved writes and the tier mark of the hook
// route (safeEvaluateHook), as a per-user gateway does.
func boundedDecideClaudeCode(t *testing.T, api *APIServer, env boundedEnv, call boundedLaneCall) (string, []string) {
	t.Helper()
	base := context.Background()
	ctx := withShareBodyStrict(base, func() bool { return api.shareBodyStrictTier(base, "claudecode") })
	body := mustJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": "bounded", "cwd": env.cwd,
		"tool_name": call.tool, "tool_input": call.input})
	if targets, ok := hookpaths.Decode(hookpaths.Resolve(body)); ok {
		ctx = context.WithValue(ctx, resolvedWritesContextKey{}, targets)
	}
	resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		HookEventName: "PreToolUse", CWD: env.cwd, ToolName: call.tool, ToolInput: call.input,
	})
	return resp.Action, resp.Findings
}

// boundedTestTiers are the tiers every lane cap is checked in.
var boundedTestTiers = []struct {
	name, posture string
	managed       bool
	tier          bounded.Tier
}{
	{"default", "default", false, bounded.TierDefault},
	{"permissive", "permissive", false, bounded.TierPermissive},
	{"strict", "strict", false, bounded.TierStrict},
	{"managed", "default", true, bounded.TierManaged},
	{"managed strict", "strict", true, bounded.TierStrict},
}

func boundedHasLimit(findings []string, c bounded.Cap, adopted bool) bool {
	return slices.ContainsFunc(findings, func(f string) bool {
		if !strings.HasPrefix(f, evaluationLimitRuleID) {
			return false
		}
		return !adopted || strings.Contains(f, bounded.ReasonCode) && boundedReasonNames(f, c)
	})
}

// boundedReasonNames reports that the reason in finding names cap c.
func boundedReasonNames(finding string, c bounded.Cap) bool {
	_, list, ok := strings.Cut(finding, bounded.ReasonCode+" cap=")
	if !ok {
		return false
	}
	list, _, _ = strings.Cut(list, ")")
	return slices.Contains(strings.Split(list, ","), c.String())
}

func TestBoundRuleEveryLaneCap(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	if len(boundedLanes) == 0 {
		t.Fatal("no lane registered a cap")
	}
	homes := filepath.Join(t.TempDir(), "homes")
	env := boundedEnv{home: filepath.Join(homes, "alice")}
	env.cwd = filepath.Join(env.home, "project")
	if err := os.MkdirAll(env.cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	gap0568StateFile(t, env.home)
	t.Setenv("HOME", env.home)
	t.Setenv("USERPROFILE", env.home)
	for _, tier := range boundedTestTiers {
		api := instructionProtectionTestAPIWithPack(t, "claudecode", "action", "", tier.posture)
		if tier.managed {
			// A managed enterprise install whose local rules decide (the
			// Secure Client profile hands every decision to AI Defense).
			api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
			api.scannerCfg.Enterprise.Profile = managed.ProfileStandalone
		}
		for _, lane := range boundedLanes {
			name := tier.name + "/" + lane.lane + "/" + lane.cap.String()
			decide := lane.decide
			if decide == nil {
				decide = boundedDecideClaudeCode
			}
			report := t.Errorf
			open := lane.open[tier.name]
			if open == "" {
				open = lane.open["*"]
			}
			if open != "" {
				report = func(format string, args ...any) { t.Logf("OPEN %s: "+format, append([]any{open}, args...)...) }
			}
			floor := bounded.Unknown(tier.tier)
			for _, shape := range []boundedShape{{}, {seen: true}} {
				atAction, atFindings := decide(t, api, env, lane.gen(lane.limit, shape))
				at := bounded.ParseAction(atAction)
				if !shape.seen && boundedHasLimit(atFindings, lane.cap, false) {
					t.Errorf("%s: the input at the cap (%d) is already truncated: %v", name, lane.limit, atFindings)
				}
				for _, size := range []int{lane.limit + 1, 2 * lane.limit} {
					action, findings := decide(t, api, env, lane.gen(size, shape))
					got := bounded.ParseAction(action)
					if got < floor || got < at {
						report("%s seen=%t size=%d: action=%s, want at least %s (unknown tier) and %s (at the cap); findings=%v",
							name, shape.seen, size, got, floor, at, findings)
					}
					if !shape.seen && !boundedHasLimit(findings, lane.cap, lane.adopted) {
						report("%s size=%d: no %s finding naming the cap: %v", name, size, evaluationLimitRuleID, findings)
					}
				}
			}
		}
	}
}
