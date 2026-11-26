// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// DET111 step 3, class R1 (nested and staged bodies, the frontends and the
// walker of internal/effects): verdict-level rows for the R1 gaps. The rows
// are the DET111 gap corpus copies the effects package judges at the IR
// (internal/effects/testdata/det111_r1*.cases.jsonl), read here so no attack
// spelling is written by hand. Each POSIX row runs on the hook path of two
// connectors and on the content route (/inspect/tool, OpenClaw exec) in all
// five tiers, with the shipped effects lane and with the lane off (the
// a64bfdb931 verdicts):
//   - an attack row reaches at least the unknown tier (alert in default,
//     permissive and managed; block in strict and managed strict) and is never
//     below its lane-off verdict;
//   - a benign row is never stricter than its lane-off verdict (the lane adds
//     no benign raise).
// With the lane off (DET111_R1_LANE=off) the attack rows allow: the fail-before.

// det111R1VerdictPending are attack rows whose verdict does not reach the
// unknown tier yet, with the lane that closes each (the IR table's
// det111Pending, plus rows whose IR is green but whose verdict is decided
// elsewhere). A pending row is still held to its lane-off (1.0.10) verdict;
// one that reaches the unknown tier in every cell fails the test (finish).
var det111R1VerdictPending = map[string]string{
	"GAP-1538/var":   "$SHELL stays unknown until the hook account's login shell is supplied (S3-R1, ruling 04:25Z)",
	"GAP-1502/var2":  "the file a staged curl -d @FILE sends is not graded (send source, S3-PRE flow lane)",
	"GAP-1508/seed":  "fetch piped to a shell is the remote-code verdict, not an effect target (decision side)",
	"GAP-1508/var":   "fetch piped to a shell under coproc: remote-code verdict, not an effect target (decision side)",
	"GAP-1508/var2":  "fetch piped to a shell under coproc { }: remote-code verdict, not an effect target (decision side)",
	"GAP-1561/seed5": ".git/config is not a protected set (decision side)",
	"GAP-1640/var":   "the written script's text (os.system) is a content verdict, not an effect target (R7 / content scanners)",
	"GAP-1640/var2":  "the written script's text (os.system) is a content verdict, not an effect target (R7 / content scanners)",
	"GAP-1653/seed":  ".env read: .env is not a protected set (decision side)",
	"GAP-1653/seed2": ".env read: .env is not a protected set (decision side)",
	"GAP-1653/var":   ".env read through an alias of open: .env is not a protected set (decision side)",
}

// det111R1WindowsPending are the Windows host rows (managed cells) whose
// verdict does not reach the unknown tier yet, with the lane that closes each.
var det111R1WindowsPending = map[string]string{
	"GAP-0998/seed":  "$env:USERPROFILE as one PowerShell bareword stays dynamic (S3-R1)",
	"GAP-0998/seed2": "$env:USERPROFILE as one PowerShell bareword stays dynamic (S3-R1)",
	"GAP-1550/seed":  "the automatic PowerShell $HOME stays dynamic (S3-R1)",
	"GAP-0998/var":   "codex shell on a Windows host: the effects call gets no PowerShell dialect (S3-PRE effectCall); claudecode PowerShell reaches",
	"GAP-0998/var2":  "codex shell on a Windows host: no PowerShell dialect for the effects call (S3-PRE effectCall)",
	"GAP-0998/var3":  "codex shell on a Windows host: no PowerShell dialect for the effects call (S3-PRE effectCall)",
	"GAP-1550/seed2": "codex shell on a Windows host: no PowerShell dialect for the effects call (S3-PRE effectCall)",
	"GAP-1550/var":   "codex shell on a Windows host: no PowerShell dialect for the effects call (S3-PRE effectCall)",
	"GAP-1173/var6":  "inline-code folder literal: the classifier grades a folder only for mutations (S4-R3)",
	"GAP-1173/var4":  "Expand-Archive has no program row (S4-R2)",
	"GAP-1173/var5":  "tar in PowerShell on Windows has no program row (S4-R2)",
	"GAP-1667/var":   "cmd /c on Git Bash: tar on Windows has no program row (S4-R2)",
	"GAP-1667/var2":  "cmd copy /y and tar on Windows have no program rows (S4-R2)",
	"GAP-1561/seed":  "an lsass dump is not an effect target (decision side)",
	"GAP-1561/seed2": "an lsass dump is not an effect target (decision side)",
	"GAP-1561/seed4": "icacls C:\\ /grant Everyone:F is a permission change on the system root (decision side)",
	"GAP-1561/var":   "an lsass dump is not an effect target (decision side)",
	"GAP-1561/var2":  "an lsass dump is not an effect target (decision side)",
	"GAP-1561/var4":  "icacls on the system root (decision side)",
	"GAP-1588/seed":  "an lsass dump is not an effect target; legacy dialect placement on Git Bash (decision side)",
	"GAP-1588/var":   "an lsass dump is not an effect target (decision side)",
	"GAP-1588/var2":  "an lsass dump is not an effect target (decision side)",
	"GAP-1588/var3":  "an lsass dump is not an effect target (decision side)",
	"GAP-1588/var4":  "fsutil usn deletejournal is not an effect target (decision side)",
	"GAP-1588/var5":  "icacls on the system root (decision side)",
}

// det111R1RuledInert are corpus attack rows DET111 ruled are not attacks
// (the IR table's det111RuledInert): judged as benign rows.
var det111R1RuledInert = map[string]string{
	"GAP-0662/var6": "RULING 2026-11-22T01:47Z: watch's joined body is a shell syntax error, nothing runs",
}

type det111R1Row struct {
	id, gap, role, platform, dialect, tool, command string
	attack, benign                                  bool
	// expect is the corpus action per tier (tier:<tier>=<action>), the
	// gap's own bar; the test asserts the unknown tier and reports this.
	expect map[string]string
}

func loadDET111R1Rows(t *testing.T, keep func(platform, dialect string) bool) []det111R1Row {
	t.Helper()
	var rows []det111R1Row
	for _, fn := range []string{"det111_r1.cases.jsonl", "det111_r1_launch.cases.jsonl"} {
		f, err := os.Open(filepath.Join("..", "effects", "testdata", fn))
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var c struct {
				ID      string `json:"id"`
				Payload struct {
					Args     map[string]any `json:"args"`
					Dialect  string         `json:"dialect"`
					ToolName string         `json:"tool_name"`
				} `json:"payload"`
				Strata struct {
					Platform string `json:"platform"`
				} `json:"strata"`
				Truth struct {
					Categories []string `json:"categories"`
					Truth      string   `json:"deterministic_truth"`
				} `json:"truth"`
			}
			if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
				t.Fatal(err)
			}
			r := det111R1Row{expect: map[string]string{}, id: strings.TrimPrefix(c.ID, "gap/det111-b_"), platform: c.Strata.Platform, tool: c.Payload.ToolName}
			r.command, _ = c.Payload.Args["command"].(string)
			cost := false
			for _, k := range c.Truth.Categories {
				switch {
				case strings.HasPrefix(k, "gap:"):
					r.gap = strings.TrimPrefix(k, "gap:")
				case strings.HasPrefix(k, "role:"):
					r.role = strings.TrimPrefix(k, "role:")
				case strings.HasPrefix(k, "tier:") && strings.Contains(k, "="):
					kv := strings.SplitN(strings.TrimPrefix(k, "tier:"), "=", 2)
					r.expect[kv[0]] = kv[1]
				case k == "kind:parity":
					cost = true // judged by its own parity test
				case k == "kind:cost":
					cost = true // a raise the corpus expects on a benign row: judged by its own tier test
				}
			}
			// every malicious row is an attack row: the gap corpus marks them
			// kind:attack-miss, the launcher copies carry no kind.
			r.attack = c.Truth.Truth == "deterministic_malicious"
			r.benign = c.Truth.Truth == "benign" && !cost
			if _, inert := det111R1RuledInert[r.id]; inert {
				// ruled not an attack: it may not raise more than 1.0.10 does
				r.attack, r.benign = false, true
			}
			r.dialect = c.Payload.Dialect
			if r.command == "" || !keep(r.platform, r.dialect) {
				continue
			}
			rows = append(rows, r)
		}
		f.Close()
	}
	return rows
}

// det111R1Home lays out the test home the rows name (/home/alice on Linux,
// /Users/alice on macOS, rewritten to it).
func det111R1Home(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for _, f := range []string{".ssh/authorized_keys", ".ssh/id_rsa", ".aws/credentials", ".claude/settings.json",
		".defenseclaw/config.yaml", ".bashrc", "proj/notes.txt", "proj/out.txt"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	return home
}

type det111R1Route struct {
	name, connector string
	decide          func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) string
}

func det111R1Routes() []det111R1Route {
	return []det111R1Route{
		{"claudecode Bash", "claudecode", func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) string {
			return api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "det111-r1", CWD: cwd, ToolName: "Bash",
				ToolInput: map[string]interface{}{"command": command},
			}).Action
		}},
		{"codex shell", "codex", func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) string {
			return api.evaluateCodexHook(ctx, codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
				ToolInput: map[string]interface{}{"command": command},
			}).Action
		}},
		{"openclaw inspect/tool", "openclaw", func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) string {
			start := processWork(t)
			out := gap0437Inspect(t, api, cwd, command)
			work := processWork(t) - start
			det111R1MostInspectWork = max(det111R1MostInspectWork, work)
			if work > det111R1InspectWork {
				t.Errorf("openclaw inspect/tool did %s of work on one call, want under %s: %.120q", work.Round(time.Millisecond), det111R1InspectWork, command)
			}
			// the content route reports the pack's action; observe never applies here (action mode)
			a, _ := out["action"].(string)
			return a
		}},
	}
}

// det111R1API is the server of one route and tier (rel-1-0-10:GAP-1998).
// These tests judge verdicts, so the inspect route gets no wall-clock deadline
// (inspectToolScanTimeout a minute): the 504 of a call past the production
// 200 ms is the defined fail-closed cell of a busy gateway (audited, the plugin
// blocks it, GAP-0919), proven by its own tests, and it is not a verdict of a
// row. The first openclaw inspect/tool row of the default tier answered 504
// under -race in 3 runs out of 3 because that call built the default rule
// generation and its rules' literal plans inside its deadline; the gateway now
// builds them before the deadline starts (inspectScanBudget,
// TestGAP1998ScanBudgetIsReadAfterTheOneTimeRuleBuild). Under 64 CPU burners
// the heaviest row (a 4 KiB body) still ran past 800 ms of wall clock with the
// same work. What the deadline is about, the work of one call, is bounded
// instead: det111R1InspectWork of CPU time (processWork) per inspect call.
func det111R1API(t *testing.T, connector, posture string, managedInstall bool, tier bounded.Tier) *APIServer {
	t.Helper()
	api := gap0589TierAPI(t, connector, posture, managedInstall, tier)
	api.inspectToolScanTimeout = time.Minute
	return api
}

// det111R1InspectWork bounds the CPU time of one openclaw inspect/tool call of
// these tests: the production scan budget, scaled under -race
// (raceScanBudgetScale), times 2 for the rule scans that run in parallel
// goroutines and for a core shared with a busy sibling thread.
const det111R1InspectWork = 2 * inspectScanTimeout * raceScanBudgetScale

// det111R1MostInspectWork is the most work of one inspect call seen so far
// in the test process (logged, for the bound above).
var det111R1MostInspectWork time.Duration

func TestDET111R1BodiesVerdictFiveTiers(t *testing.T) {
	home := det111R1Home(t)
	rows := loadDET111R1Rows(t, func(platform, dialect string) bool {
		return dialect == "posix" && (platform == "linux" || platform == "macos")
	})
	if len(rows) < 60 {
		t.Fatalf("only %d POSIX rows: the corpus copy lost rows", len(rows))
	}
	laneOff := os.Getenv("DET111_R1_LANE") == "off"
	probe := os.Getenv("DET111_R1_PROBE") != ""
	cwd := filepath.Join(home, "proj")
	rewrite := strings.NewReplacer("/home/alice", home, "/Users/alice", home)
	j := newDET111R1Judge(t)
	for _, tier := range boundedTestTiers {
		for _, route := range det111R1Routes() {
			api := det111R1API(t, route.connector, tier.posture, tier.managed, tier.tier)
			for _, row := range rows {
				j.judge(t, api, t.Context(), tier.name, bounded.Unknown(tier.tier), route, cwd, row, rewrite.Replace(row.command), laneOff, probe)
			}
		}
	}
	j.finish(t)
	t.Logf("most work of one openclaw inspect/tool call: %s (bound %s)", det111R1MostInspectWork.Round(time.Millisecond), det111R1InspectWork)
}

// det111R1Judge judges rows cell by cell and keeps the pending rows honest.
type det111R1Judge struct {
	attacks int
	failed  map[string]bool
	pending map[string]bool // pending attack rows judged in this run
}

func newDET111R1Judge(t *testing.T) *det111R1Judge {
	return &det111R1Judge{failed: map[string]bool{}, pending: map[string]bool{}}
}

func (j *det111R1Judge) judge(t *testing.T, api *APIServer, ctx context.Context, tierName string, floor bounded.Action, route det111R1Route, cwd string, row det111R1Row, command string, laneOff, probe bool) {
	t.Helper()
	useEffectsRulesMode(t, "off")
	off := boundedParse(route.decide(t, api, ctx, cwd, command))
	on := off
	if !laneOff {
		useDefaultEffectsLane(t)
		on = boundedParse(route.decide(t, api, ctx, cwd, command))
	}
	if probe {
		t.Logf("ROW\t%s\t%s\t%s\t%s\toff=%s\ton=%s\texpect=%s", tierName, route.name, row.id, row.role, off, on, row.expect[strings.ReplaceAll(tierName, " ", "-")])
	}
	where := tierName + " " + route.name + " " + row.id
	switch {
	case row.attack:
		j.attacks++
		if _, pending := det111R1VerdictPending[row.id]; pending && !laneOff {
			j.pending[row.id] = true
		}
		if bounded.Stricter(on, off) != on {
			t.Errorf("%s: lane on %s is below lane off %s (raise-only)", where, on, off)
		}
		if bounded.Stricter(on, floor) != on {
			j.failed[row.id] = true
			if _, pending := det111R1VerdictPending[row.id]; !pending {
				t.Errorf("%s %q: %s, want at least %s", where, command, on, floor)
			}
		}
	case row.benign:
		if bounded.Stricter(on, off) != off {
			t.Errorf("%s %q: benign row raised by the lane: %s, lane off %s", where, command, on, off)
		}
	}
}

// finish keeps the pending table honest (DET111 ruling 2026-11-22 04:21Z: the
// verdict tests are ratchets): every row is held to at least its lane-off
// (1.0.10) verdict in judge, and a pending row that now reaches the unknown
// tier in every cell of the run must leave the table.
func (j *det111R1Judge) finish(t *testing.T) {
	t.Helper()
	if j.attacks == 0 {
		t.Fatal("no attack rows judged")
	}
	for id := range j.pending {
		if !j.failed[id] {
			t.Errorf("%s reaches the unknown tier in every cell now: remove it from the pending table (%s)", id, det111R1VerdictPending[id])
		}
	}
}

// det111R1WindowsRoutes are the routes of a Windows hook host: the
// PowerShell tool of claudecode and the codex shell for PowerShell rows, the
// claudecode Bash tool (Git Bash) for POSIX rows.
func det111R1WindowsRoutes(dialect string) []det111R1Route {
	if dialect == "posix" {
		return []det111R1Route{{"claudecode Bash (Git Bash)", "claudecode", func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) string {
			return api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "det111-r1w", CWD: cwd, ToolName: "Bash",
				ToolInput: map[string]interface{}{"command": command},
			}).Action
		}}}
	}
	return []det111R1Route{
		{"claudecode PowerShell", "claudecode", func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) string {
			return api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "det111-r1w", CWD: cwd, ToolName: "PowerShell",
				ToolInput: map[string]interface{}{"command": command},
			}).Action
		}},
		{"codex shell", "codex", func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) string {
			return api.evaluateCodexHook(ctx, codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
				ToolInput: map[string]interface{}{"command": command},
			}).Action
		}},
	}
}

// TestDET111R1BodiesVerdictWindowsHost runs the Windows rows on a Windows
// hook host in the managed cells, where the managed hook peer carries the
// account's profile (C:\Users\alice, the rows' home). A Linux test gateway
// has no Windows profile of its own, so the per-user Windows cells run
// natively (s7-winslot).
func TestDET111R1BodiesVerdictWindowsHost(t *testing.T) {
	gap0589WindowsHost(t)
	rows := loadDET111R1Rows(t, func(platform, dialect string) bool {
		return platform == "windows" && (dialect == "posix" || dialect == "powershell")
	})
	if len(rows) < 40 {
		t.Fatalf("only %d Windows rows: the corpus copy lost rows", len(rows))
	}
	defer func(saved map[string]string) { det111R1VerdictPending = saved }(det111R1VerdictPending)
	det111R1VerdictPending = det111R1WindowsPending
	laneOff := os.Getenv("DET111_R1_LANE") == "off"
	probe := os.Getenv("DET111_R1_PROBE") != ""
	ctx := withManagedHookPeer(t.Context(), managedHookPeer{Home: `C:\Users\alice`})
	j := newDET111R1Judge(t)
	for _, tier := range boundedTestTiers {
		if !tier.managed {
			continue
		}
		for _, dialect := range []string{"posix", "powershell"} {
			for _, route := range det111R1WindowsRoutes(dialect) {
				api := det111R1API(t, route.connector, tier.posture, tier.managed, tier.tier)
				for _, row := range rows {
					if row.dialect != dialect {
						continue
					}
					j.judge(t, api, ctx, tier.name, bounded.Unknown(tier.tier), route, `C:\Users\alice\proj`, row, row.command, laneOff, probe)
				}
			}
		}
	}
	j.finish(t)
}
