// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// The cross-lane property test of the bound rule (internal/guardrail/bounded).
// For every cap of every lane in boundedLanes, in every tier the hook route
// judges in (the tier is asserted at the route):
//   - the input at the cap is not truncated, and past it (limit+1, 2*limit)
//     the answer carries the evaluation-limit finding, naming the cap for an
//     adopted lane;
//   - past the cap the action is at least the unknown tier of the pack and at
//     least the action of the same shape at the cap;
//   - with the lane's seen element before the capped part, the action is at
//     least that of the seen element judged alone (what was read before the
//     cap is still judged); after the capped part, nested in a sub-reader,
//     or with two caps hit at once, at least the unknown tier;
//   - with a regex_judge judge configured (TestBoundRuleJudgeStillDecides),
//     a truncated call still goes to the judge, and the floor stands when the
//     judge fails.
//
// A lane registers its caps from its own test file, so a new lane is covered
// by adding one file:
//
//	func init() {
//		registerBoundedLane(boundedLaneCap{lane: "s7/nonshell mcp-mapper", cap: bounded.Paths,
//			limit: maxPaths, gen: nonShellPathsCall, seen: nonShellSeenCall})
//	}
//
// Inputs come from generator functions of size and shape, never from literal
// attack text. A known violation is an OPEN entry: it is logged, the case
// must still fail (an OPEN entry that passes fails the test: delete it), and
// it names one tier and an open gap id.

// boundedLaneCap is one cap of one lane.
type boundedLaneCap struct {
	lane  string
	cap   bounded.Cap
	limit int
	// gen builds the lane's input of the given size (limit is at the cap,
	// limit+1 just past it) and shape. ok is false for a shape the lane has
	// no form for; plain and seen are required.
	gen func(size int, shape boundedShape) (call boundedLaneCall, ok bool)
	// seen is the lane's seen element alone: an element it judges on its own,
	// from its existing fixtures, that gen places before or after the
	// capped part.
	seen func() boundedLaneCall
	// legacy names the lane that will move a cap still on the old
	// evaluation-limit path to the helper. Only the rel shell rows have one;
	// every other lane is adopted: past the cap its reason names the cap.
	legacy string
	// work marks a Time cap counted in work units: size is the units, never
	// wall-clock time (which no generator can drive reliably).
	work bool
	// decide runs one call through the lane's route; nil is the Claude Code
	// PreToolUse hook.
	decide func(t *testing.T, api *APIServer, env boundedEnv, call boundedLaneCall) (string, []string)
	// open maps a tier name to the gap of a known violation not yet fixed in
	// this tree. The lane's fix deletes the entry.
	open map[string]string
}

// boundedShape is the shape of a generated input.
type boundedShape struct {
	seen, seenAfter, nested, multi bool
}

var boundedShapes = []struct {
	name     string
	shape    boundedShape
	required bool
}{
	{"plain", boundedShape{}, true},
	{"seen", boundedShape{seen: true}, true},
	{"seen-after", boundedShape{seenAfter: true}, false},
	{"nested", boundedShape{nested: true}, false},
	{"multi", boundedShape{multi: true}, false},
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

// The shell reading bounds on rel/1.0.10, all through withBoundedTruncation:
// nesting and the statement budget (lane s7/parselimits), and the operand
// bound (rel-1-0-10:GAP-0313).
func init() {
	registerBoundedLane(
		boundedLaneCap{lane: "shell-parse nesting", cap: bounded.Depth, limit: shellparse.MaxNestingDepth,
			gen:  boundedShellLane(boundedNestedSubshells, boundedNestedAssignments),
			seen: boundedShellSeenCall},
		boundedLaneCap{lane: "shell-parse statements", cap: bounded.Items, limit: boundedShellStatements,
			gen:  boundedShellLane(gap0568Assignments, boundedListStatements),
			seen: boundedShellSeenCall},
		boundedLaneCap{lane: "shell operands", cap: bounded.Items, limit: actionfacts.MaxOperandsPerCall,
			gen:  boundedShellLane(boundedListOperands, boundedSplitOperands),
			seen: boundedShellSeenCall},
	)
}

// boundedShellStatements is the statement budget of one POSIX call
// (actionfacts.maxStatementsAlone).
const boundedShellStatements = 128

// boundedShellSeen is the shell lanes' seen element: a write the reader
// resolves into the DefenseClaw state folder, which blocks in every tier
// (fixture of TestEvaluationLimitOnlyCallAlertsOutsideStrict).
const boundedShellSeen = "printf changed >> ~/.defenseclaw/config.yaml"

func boundedShellSeenCall() boundedLaneCall { return boundedShellCommand(boundedShellSeen) }

func boundedShellCommand(command string) boundedLaneCall {
	return boundedLaneCall{tool: "Bash", input: map[string]any{"command": command}}
}

// boundedShellLane is a Bash generator: fill(size) (multi(size) for the
// multi-cap shape), wrapped in a bash -c body when nested, with the seen
// element before or after it.
func boundedShellLane(fill, multi func(size int) string) func(int, boundedShape) (boundedLaneCall, bool) {
	return func(size int, shape boundedShape) (boundedLaneCall, bool) {
		command := fill(size)
		if shape.multi {
			command = multi(size)
		}
		if shape.nested {
			command = "bash -c '" + command + "'"
		}
		if shape.seen {
			command = boundedShellSeen + "; " + command
		}
		if shape.seenAfter {
			command += "; " + boundedShellSeen
		}
		return boundedShellCommand(command), true
	}
}

// boundedNestedSubshells is a true command nested in size subshells.
func boundedNestedSubshells(size int) string {
	return strings.Repeat("(", size) + "true" + strings.Repeat(")", size)
}

// boundedNestedAssignments nests past the statement budget too (depth and
// items at once).
func boundedNestedAssignments(size int) string {
	return strings.Repeat("(", size) + gap0568Assignments(2*boundedShellStatements) + strings.Repeat(")", size)
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

// boundedListStatements is size statements of nine operands each: past the
// statement budget, and past the operand bound too from 114 statements.
func boundedListStatements(size int) string {
	parts := make([]string, size)
	for i := range parts {
		parts[i] = "ls" + strings.Repeat(" ox", 9)
	}
	return strings.Join(parts, "; ")
}

// boundedSplitOperands spreads size operands over statements of eight:
// past the operand bound and, from 1025 operands, the statement budget.
func boundedSplitOperands(size int) string {
	var parts []string
	for done := 0; done < size; done += 8 {
		parts = append(parts, "ls"+strings.Repeat(" oy", min(8, size-done)))
	}
	return strings.Join(parts, "; ")
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
		HookEventName: "PreToolUse", SessionID: "bounded", CWD: env.cwd, ToolName: call.tool, ToolInput: call.input,
	})
	return resp.Action, resp.Findings
}

// boundedTestTiers are the tiers every lane cap is checked in. The unknown
// tier follows the pack: a managed install that runs the default pack is in
// the default tier (rel-1-0-6:GAP-0675).
var boundedTestTiers = []struct {
	name, posture string
	managed       bool
	tier          bounded.Tier
}{
	{"default", "default", false, bounded.TierDefault},
	{"permissive", "permissive", false, bounded.TierPermissive},
	{"strict", "strict", false, bounded.TierStrict},
	{"managed", "default", true, bounded.TierDefault},
	{"managed strict", "strict", true, bounded.TierStrict},
}

var boundedOpenGap = regexp.MustCompile(`^rel-1-0-10:GAP-\d{4}$`)

// boundedHasLimit reports the evaluation-limit finding; for an adopted lane
// it must carry the bounded reason naming cap c.
func boundedHasLimit(findings []string, c bounded.Cap, adopted bool) bool {
	return slices.ContainsFunc(findings, func(f string) bool {
		if !strings.HasPrefix(f, evaluationLimitRuleID+":") {
			return false
		}
		return !adopted || boundedReasonNames(f, c)
	})
}

// boundedReasonNames reports that a bounded reason in finding names cap c.
func boundedReasonNames(finding string, c bounded.Cap) bool {
	for _, part := range strings.Split(finding, bounded.ReasonCode+" cap=")[1:] {
		end := strings.IndexAny(part, ") ;")
		if end < 0 {
			end = len(part)
		}
		if slices.Contains(strings.Split(part[:end], ","), c.String()) {
			return true
		}
	}
	return false
}

func boundedParse(action string) bounded.Action {
	a, _ := bounded.ParseAction(action)
	return a
}

// boundedLaneEnv is the POSIX home the shell lanes run in.
func boundedLaneEnv(t *testing.T) boundedEnv {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
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
	return env
}

// boundedTierAPI is the test API of one tier, its tier asserted at the
// route.
func boundedTierAPI(t *testing.T, posture string, managedInstall bool, want bounded.Tier) *APIServer {
	t.Helper()
	api := instructionProtectionTestAPIWithPack(t, "claudecode", "action", "", posture)
	if managedInstall {
		// A managed enterprise install whose local rules decide (the Secure
		// Client profile hands every decision to AI Defense).
		api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		api.scannerCfg.Enterprise.Profile = managed.ProfileStandalone
	}
	if got := api.scannerCfg.HookPolicyTierForConnector("claudecode"); got != posture {
		t.Fatalf("pack %s: the route reads posture %q", posture, got)
	}
	if got := api.boundedTier(context.Background(), "claudecode"); got != want {
		t.Fatalf("pack %s managed=%t: the route judges in tier %d, want %d", posture, managedInstall, got, want)
	}
	return api
}

func TestBoundRuleEveryLaneCap(t *testing.T) {
	if len(boundedLanes) == 0 {
		t.Fatal("no lane registered a cap")
	}
	env := boundedLaneEnv(t)
	tierNames := map[string]bool{}
	for _, tier := range boundedTestTiers {
		tierNames[tier.name] = true
	}
	for _, lane := range boundedLanes {
		if lane.gen == nil || lane.seen == nil || lane.limit <= 0 {
			t.Errorf("%s/%s: a lane registers gen, seen and a positive limit", lane.lane, lane.cap)
		}
		if lane.cap == bounded.Time && !lane.work {
			t.Errorf("%s: a time cap is registered in work units (work: true), never wall-clock", lane.lane)
		}
		for key, gap := range lane.open {
			if !tierNames[key] || !boundedOpenGap.MatchString(gap) {
				t.Errorf("%s/%s: OPEN entry %q: %q needs a tier name and one open gap id", lane.lane, lane.cap, key, gap)
			}
		}
	}
	if t.Failed() {
		return
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		floor := bounded.Unknown(tier.tier)
		for _, lane := range boundedLanes {
			name := tier.name + "/" + lane.lane + "/" + lane.cap.String()
			decide := lane.decide
			if decide == nil {
				decide = boundedDecideClaudeCode
			}
			adopted := lane.legacy == ""
			var violations []string
			fail := func(format string, args ...any) { violations = append(violations, fmt.Sprintf(format, args...)) }
			seenAlone := boundedParse(first(decide(t, api, env, lane.seen())))
			for _, s := range boundedShapes {
				at, ok := lane.gen(lane.limit, s.shape)
				if !ok {
					if s.required {
						t.Errorf("%s: no %s shape (required)", name, s.name)
					}
					continue
				}
				atAction, atFindings := decide(t, api, env, at)
				if s.shape == (boundedShape{}) && boundedHasLimit(atFindings, lane.cap, false) {
					t.Errorf("%s: the input at the cap (%d) is already truncated: %v", name, lane.limit, atFindings)
				}
				for _, size := range []int{lane.limit + 1, 2 * lane.limit} {
					call, _ := lane.gen(size, s.shape)
					action, findings := decide(t, api, env, call)
					got := boundedParse(action)
					want := floor
					switch {
					case s.shape == (boundedShape{}):
						want = bounded.Stricter(want, boundedParse(atAction))
					case s.shape.seen:
						want = bounded.Stricter(want, seenAlone)
					}
					if got < want {
						fail("%s %s size=%d: action=%s, want at least %s; findings=%v", name, s.name, size, got, want, findings)
					}
					if (s.shape == (boundedShape{}) || s.shape.multi) && !boundedHasLimit(findings, lane.cap, adopted) {
						fail("%s %s size=%d: no %s finding naming the cap: %v", name, s.name, size, evaluationLimitRuleID, findings)
					}
				}
			}
			switch gap := lane.open[tier.name]; {
			case gap != "" && len(violations) == 0:
				t.Errorf("%s: OPEN entry %s passes: delete it", name, gap)
			case gap != "":
				for _, v := range violations {
					t.Logf("OPEN %s: %s", gap, v)
				}
			default:
				for _, v := range violations {
					t.Error(v)
				}
			}
		}
	}
}

func first(action string, _ []string) string { return action }

// boundedJudgeAPI is a tier's test API with a regex_judge tool-call judge
// for claudecode whose provider fails, so the test sees both that the judge
// is asked and that the floor stands when it gives no verdict.
func boundedJudgeAPI(t *testing.T, posture string, managedInstall bool, tier bounded.Tier) (*APIServer, *mockLLMProvider) {
	t.Helper()
	api := boundedTierAPI(t, posture, managedInstall, tier)
	api.scannerCfg.DataDir = t.TempDir()
	api.scannerCfg.Guardrail.DetectionStrategy = "regex_judge"
	api.scannerCfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, ToolInjection: true, HookConnectors: []string{"claudecode"}}
	mock := &mockLLMProvider{err: errors.New("judge down")}
	api.SetHookJudge(&LLMJudge{cfg: &api.scannerCfg.Guardrail.Judge, model: "test-model", provider: mock, rp: &guardrail.RulePack{}})
	return api, mock
}

// Under regex_judge (the default strategy) a truncated call is not decisive:
// it goes to the judge where the floor only alerts, and when the judge fails
// the call keeps the floor, a managed install's closed fail mode included
// (rel-1-0-10:GAP-0320). In strict the floor blocks.
func TestBoundRuleJudgeStillDecides(t *testing.T) {
	env := boundedLaneEnv(t)
	for _, tier := range boundedTestTiers {
		api, mock := boundedJudgeAPI(t, tier.posture, tier.managed, tier.tier)
		floor := bounded.Unknown(tier.tier)
		for _, lane := range boundedLanes {
			if lane.decide != nil {
				continue // a lane on another route brings its own judge row
			}
			call, _ := lane.gen(lane.limit+1, boundedShape{})
			asked := boundedJudgeCalls(mock)
			action, findings := boundedDecideClaudeCode(t, api, env, call)
			got := boundedParse(action)
			name := tier.name + "/" + lane.lane
			// Where the floor alerts the judge must be asked (this also proves
			// the stub is wired); where it blocks the call is decisive.
			if floor == bounded.Alert && boundedJudgeCalls(mock) == asked {
				t.Errorf("%s: a truncated call skipped the judge (decisive); findings=%v", name, findings)
			}
			if got != floor {
				t.Errorf("%s: the judge failed and the call is %s, want the floor %s; findings=%v", name, got, floor, findings)
			}
		}
	}
}

func boundedJudgeCalls(mock *mockLLMProvider) int {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	return len(mock.captured)
}
