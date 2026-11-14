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
// attack text. A known violation is an OPEN entry keyed "<tier>/<shape>": it
// waives that tier and shape only, the case must still fail (an OPEN entry
// that passes fails the test: delete it), and it names an open gap id.

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
	// path is boundedAdopted (past the cap the reason names the cap) or, for
	// the rel shell reading bounds only (boundedLegacyLanes), the old
	// evaluation-limit path that s7/parselimits moves to the helper.
	path boundedPath
	// work marks a Time cap counted in work units: size is the units, never
	// wall-clock time (which no generator can drive reliably). The test
	// checks that the answer is the same on a second run.
	work bool
	// connector is the connector the lane's route judges for (claudecode
	// when empty; required with decide); its tier is asserted at the route
	// and the judge stub is enabled for it.
	connector string
	// decide runs one call through the lane's route; nil is the Claude Code
	// PreToolUse hook.
	decide func(t *testing.T, api *APIServer, env boundedEnv, call boundedLaneCall) (string, []string)
	// judge is the lane's judge row, required with decide: it runs one call
	// through the lane's route on an API with the regex_judge stub
	// (boundedJudgeAPI). TestBoundRuleJudgeStillDecides checks that a
	// truncated call reaches the judge where the floor alerts and keeps the
	// floor when the judge fails.
	judge func(t *testing.T, api *APIServer, env boundedEnv, call boundedLaneCall) (string, []string)
	// open maps "<tier>/<shape>" to the gap of a known violation not yet
	// fixed in this tree. The lane's fix deletes the entry.
	open map[string]string
}

// boundedPath is how a lane's cap reaches the decision.
type boundedPath uint8

const (
	boundedAdopted boundedPath = iota
	// boundedLegacyShellReading: trustedActionLimitFindings, to be moved to
	// withBoundedTruncation by s7/parselimits.
	boundedLegacyShellReading
)

// boundedLegacyLanes are the only lanes allowed on the legacy path.
var boundedLegacyLanes = map[string]bool{"shell-parse nesting": true, "shell-parse statements": true}

func (lane boundedLaneCap) connectorName() string {
	if lane.connector == "" {
		return "claudecode"
	}
	return lane.connector
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

// The shell reading bounds on rel/1.0.10. Nesting and statements (lane
// s7/parselimits) still take the evaluation-limit path
// (trustedActionLimitFindings); the operand bound goes through
// withBoundedTruncation (rel-1-0-10:GAP-0313).
func init() {
	registerBoundedLane(
		boundedLaneCap{lane: "shell-parse nesting", cap: bounded.Depth, limit: shellparse.MaxNestingDepth,
			gen:  boundedShellLane(boundedNestedSubshells, boundedNestedAssignments),
			seen: boundedShellSeenCall,
			path: boundedLegacyShellReading,
			open: map[string]string{"default/seen": "rel-1-0-10:GAP-0312", "permissive/seen": "rel-1-0-10:GAP-0312",
				"managed/seen": "rel-1-0-10:GAP-0312"}},
		boundedLaneCap{lane: "shell-parse statements", cap: bounded.Items, limit: boundedShellStatements,
			gen:  boundedShellLane(gap0568Assignments, boundedListStatements),
			seen: boundedShellSeenCall,
			path: boundedLegacyShellReading},
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
	for _, connector := range boundedTierConnectors() {
		if got := api.scannerCfg.HookPolicyTierForConnector(connector); got != posture {
			t.Fatalf("pack %s: the %s route reads posture %q", posture, connector, got)
		}
		if got := api.boundedTier(context.Background(), connector); got != want {
			t.Fatalf("pack %s managed=%t: the %s route judges in tier %d, want %d", posture, managedInstall, connector, got, want)
		}
	}
	return api
}

// boundedTierConnectors are the connectors whose route tier is asserted:
// claudecode and codex always, and every lane's own connector.
func boundedTierConnectors() []string {
	connectors := []string{"claudecode", "codex"}
	for _, lane := range boundedLanes {
		if !slices.Contains(connectors, lane.connectorName()) {
			connectors = append(connectors, lane.connectorName())
		}
	}
	return connectors
}

// boundedValidateLanes checks the lane table itself.
func boundedValidateLanes(t *testing.T) {
	t.Helper()
	for _, err := range boundedLaneTableErrors(boundedLanes) {
		t.Error(err)
	}
}

// boundedLaneTableErrors are the misuses of a lane table.
func boundedLaneTableErrors(lanes []boundedLaneCap) []string {
	var errs []string
	tierNames, shapeNames := map[string]bool{}, map[string]bool{}
	for _, tier := range boundedTestTiers {
		tierNames[tier.name] = true
	}
	for _, s := range boundedShapes {
		shapeNames[s.name] = true
	}
	for _, lane := range lanes {
		name := lane.lane + "/" + lane.cap.String()
		if lane.gen == nil || lane.seen == nil || lane.limit <= 0 {
			errs = append(errs, fmt.Sprintf("%s: a lane registers gen, seen and a positive limit", name))
		}
		if lane.path == boundedLegacyShellReading && !boundedLegacyLanes[lane.lane] {
			errs = append(errs, fmt.Sprintf("%s: only the rel shell reading bounds may stay on the legacy path; adopt withBoundedTruncation", name))
		}
		if lane.path > boundedLegacyShellReading {
			errs = append(errs, fmt.Sprintf("%s: unknown path %d", name, lane.path))
		}
		if (lane.cap == bounded.Time) != lane.work {
			errs = append(errs, fmt.Sprintf("%s: a time cap, and only a time cap, is registered in work units (work: true)", name))
		}
		if lane.decide != nil && lane.judge == nil {
			errs = append(errs, fmt.Sprintf("%s: lane %s has its own route and no judge row", name, lane.lane))
		}
		if lane.decide == nil && lane.judge != nil {
			errs = append(errs, fmt.Sprintf("%s: a judge row without its own route (decide) would never run", name))
		}
		if lane.decide != nil && lane.connector == "" {
			errs = append(errs, fmt.Sprintf("%s: a lane with its own route names its connector", name))
		}
		for key, gap := range lane.open {
			tier, shape, ok := strings.Cut(key, "/")
			if !ok || !tierNames[tier] || !shapeNames[shape] || !boundedOpenGap.MatchString(gap) {
				errs = append(errs, fmt.Sprintf("%s: OPEN entry %q: %q needs a \"<tier>/<shape>\" key and one open gap id", name, key, gap))
			}
		}
	}
	return errs
}

func TestBoundRuleEveryLaneCap(t *testing.T) {
	if len(boundedLanes) == 0 {
		t.Fatal("no lane registered a cap")
	}
	env := boundedLaneEnv(t)
	if boundedValidateLanes(t); t.Failed() {
		return
	}
	// A lane that ships in shadow does not decide: it has its own contract
	// (bounded_shadow_lanes_test.go).
	t.Run("shadow lanes", func(t *testing.T) { boundedCheckShadowLanes(t) })
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		floor := bounded.Unknown(tier.tier)
		for _, lane := range boundedLanes {
			name := tier.name + "/" + lane.lane + "/" + lane.cap.String()
			decide := lane.decide
			if decide == nil {
				decide = boundedDecideClaudeCode
			}
			adopted := lane.path == boundedAdopted
			violations := map[string][]string{} // by shape name
			var shapeName string
			fail := func(format string, args ...any) {
				violations[shapeName] = append(violations[shapeName], fmt.Sprintf(format, args...))
			}
			seenAlone := boundedParse(first(decide(t, api, env, lane.seen())))
			for _, s := range boundedShapes {
				shapeName = s.name
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
					if lane.work {
						// Work units, not wall-clock: the same input gives the same answer.
						if again, againFindings := decide(t, api, env, call); again != action || !slices.Equal(againFindings, findings) {
							fail("%s %s size=%d: a work-unit cap answered %s then %s: not counted in work units", name, s.name, size, action, again)
						}
					}
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
			for _, s := range boundedShapes {
				gap := lane.open[tier.name+"/"+s.name]
				switch {
				case gap != "" && len(violations[s.name]) == 0:
					t.Errorf("%s %s: OPEN entry %s passes: delete it", name, s.name, gap)
				case gap != "":
					for _, v := range violations[s.name] {
						t.Logf("OPEN %s: %s", gap, v)
					}
				default:
					for _, v := range violations[s.name] {
						t.Error(v)
					}
				}
			}
		}
	}
}

func first(action string, _ []string) string { return action }

// boundedJudgeAPI is a tier's test API with a regex_judge tool-call judge
// for claudecode whose provider fails, so the test sees both that the judge
// is asked and that the floor stands when it gives no verdict.
func boundedJudgeAPI(t *testing.T, posture string, managedInstall bool, tier bounded.Tier,
) (*APIServer, *mockLLMProvider) {
	t.Helper()
	api := boundedTierAPI(t, posture, managedInstall, tier)
	api.scannerCfg.DataDir = t.TempDir()
	api.scannerCfg.Guardrail.DetectionStrategy = "regex_judge"
	api.scannerCfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, ToolInjection: true,
		HookConnectors: boundedTierConnectors()}
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
			judge := lane.judge
			if lane.decide == nil {
				judge = boundedDecideClaudeCode
			}
			if judge == nil {
				continue // the lane table check reports it
			}
			call, _ := lane.gen(lane.limit+1, boundedShape{})
			asked := boundedJudgeCalls(mock)
			action, findings := judge(t, api, env, call)
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

// The lane table rejects each misuse the review named: a legacy path outside
// the rel shell rows, an own route without a judge row, a work flag on a
// non-time cap (and a time cap without it), an OPEN entry for a whole tier
// or with no gap id, a missing seen element.
func TestBoundRuleLaneTableRejectsMisuse(t *testing.T) {
	// A valid lane built here, not taken from the live table, so a lane an
	// adopter registers does not change what each edit tests.
	good := boundedLaneCap{lane: "table check", cap: bounded.Items, limit: 8,
		gen: boundedShellLane(boundedListOperands, boundedSplitOperands), seen: boundedShellSeenCall}
	if errs := boundedLaneTableErrors([]boundedLaneCap{good}); len(errs) != 0 {
		t.Fatalf("a valid lane is rejected: %v", errs)
	}
	route := func(*testing.T, *APIServer, boundedEnv, boundedLaneCall) (string, []string) { return "", nil }
	// Each edit is one defect, matched by the error it must raise.
	for _, tc := range []struct {
		name, want string
		edit       func(*boundedLaneCap)
	}{
		{"legacy outside the shell rows", "only the rel shell reading bounds", func(l *boundedLaneCap) { l.path = boundedLegacyShellReading }},
		{"unknown path", "unknown path", func(l *boundedLaneCap) { l.path = boundedLegacyShellReading + 1 }},
		{"own route, no judge row", "has its own route and no judge row", func(l *boundedLaneCap) { l.decide, l.connector = route, "codex" }},
		{"own route, no connector", "names its connector", func(l *boundedLaneCap) { l.decide, l.judge = route, route }},
		{"judge row without own route", "judge row without its own route", func(l *boundedLaneCap) { l.judge = route }},
		{"work on a non-time cap", "only a time cap", func(l *boundedLaneCap) { l.work = true }},
		{"time cap without work", "only a time cap", func(l *boundedLaneCap) { l.cap = bounded.Time }},
		{"OPEN for a whole tier", "OPEN entry", func(l *boundedLaneCap) { l.open = map[string]string{"default": "rel-1-0-10:GAP-0312"} }},
		{"OPEN wildcard", "OPEN entry", func(l *boundedLaneCap) { l.open = map[string]string{"*/seen": "rel-1-0-10:GAP-0312"} }},
		{"OPEN without a gap id", "OPEN entry", func(l *boundedLaneCap) { l.open = map[string]string{"default/seen": "later"} }},
		{"no seen element", "registers gen, seen and a positive limit", func(l *boundedLaneCap) { l.seen = nil }},
	} {
		lane := good
		tc.edit(&lane)
		errs := boundedLaneTableErrors([]boundedLaneCap{lane})
		if len(errs) != 1 || !strings.Contains(errs[0], tc.want) {
			t.Errorf("%s: errors %q, want exactly one containing %q", tc.name, errs, tc.want)
		}
	}
}
