// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

type d1ReplayRow struct {
	ID       string            `json:"id"`
	Kind     string            `json:"kind"`
	ToolName string            `json:"tool_name"`
	CCTool   string            `json:"cc_tool"`
	Command  string            `json:"command"`
	Args     map[string]any    `json:"args"`
	Expected map[string]string `json:"expected,omitempty"`
}

type d1ReplayVerdict struct {
	Decision string
	RuleID   string
}

type d1PendingProductDecision struct {
	Gap     string
	Want    string
	Current d1ReplayVerdict
}

// The public corpus keeps the intended verdicts in its rows. These entries
// pin peer-owned decisions until their product fixes reach this branch. A
// changed result, including the intended result, requires removing the entry.
// The archive cells belong to rel-1-0-6 GAP-0675 (gas-ux-r1 GAP-0054 was
// folded into it). The GAP-0055 lookup cells left the list when its fix
// reached rel/1.0.9.
func d1PendingProductDecisions() map[string]d1PendingProductDecision {
	pending := make(map[string]d1PendingProductDecision)
	for _, id := range []string{
		"d1-0041", "d1-0063", "d1-0065", "d1-0070", "d1-0075",
		"d1-0104", "d1-0105", "d1-0158", "d1-0263", "d1-0297",
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			pending[id+" "+connector+"/managed-balanced"] = d1PendingProductDecision{
				Gap: "GAP-0675", Want: "alert",
				Current: d1ReplayVerdict{Decision: "block", RuleID: "persistence.ssh_authorized_keys_command"},
			}
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		pending["d1-0043 "+connector+"/managed-balanced"] = d1PendingProductDecision{
			Gap: "GAP-0675", Want: "allow",
			Current: d1ReplayVerdict{Decision: "block", RuleID: "persistence.ssh_authorized_keys_command"},
		}
		for _, cell := range []string{connector + "/oss", connector + "/managed-balanced"} {
			pending["d1-0081 "+cell] = d1PendingProductDecision{
				Gap: "GAP-0675", Want: "allow",
				Current: d1ReplayVerdict{Decision: "block", RuleID: "persistence.ssh_authorized_keys_command"},
			}
		}
	}
	return pending
}

func d1CheckPublicVerdict(row d1ReplayRow, cell string, got d1ReplayVerdict, pending map[string]d1PendingProductDecision) error {
	want, ok := row.Expected[cell]
	if !ok {
		return fmt.Errorf("missing expected verdict")
	}
	if item, listed := pending[row.ID+" "+cell]; listed {
		if want != item.Want {
			return fmt.Errorf("%s intended verdict changed: got %s, want %s", item.Gap, want, item.Want)
		}
		if got.Decision == want {
			return fmt.Errorf("%s pending decision resolved; remove its inventory entry", item.Gap)
		}
		if got != item.Current {
			return fmt.Errorf("%s pending decision changed: got %s (%s), pinned %s (%s)",
				item.Gap, got.Decision, got.RuleID, item.Current.Decision, item.Current.RuleID)
		}
		return nil
	}
	if got.Decision != want || got.Decision == "error" {
		return fmt.Errorf("got %s (%s), want %s", got.Decision, got.RuleID, want)
	}
	return nil
}

func d1FirstRule(ids, findings []string) string {
	if len(ids) > 0 {
		return ids[0]
	}
	for _, finding := range findings {
		if before, _, ok := strings.Cut(finding, ":"); ok && before != "" && len(before) < 100 && !strings.ContainsAny(before, " \t\n") {
			return before
		}
	}
	return "-"
}

func d1ReadRows(t *testing.T, path string) []d1ReplayRow {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var rows []d1ReplayRow
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	seen := make(map[string]bool)
	for scanner.Scan() {
		var row d1ReplayRow
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatalf("invalid D1 row %d: %v", len(rows)+1, err)
		}
		if row.ID == "" || seen[row.ID] || row.Kind == "" {
			t.Fatalf("missing or repeated D1 row identity at %d", len(rows)+1)
		}
		seen[row.ID] = true
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("empty D1 corpus")
	}
	return rows
}

func d1TestAPI(t *testing.T, connector string) *APIServer {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.BlockAt = "HIGH"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
	return &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
}

func d1Input(row d1ReplayRow, connector string) (string, map[string]any) {
	if row.Kind == "shell" {
		if connector == "codex" {
			return "exec_command", map[string]any{"cmd": row.Command}
		}
		if strings.EqualFold(row.ToolName, "powershell") {
			return "PowerShell", map[string]any{"command": row.Command}
		}
		return "Bash", map[string]any{"command": row.Command}
	}
	tool := row.CCTool
	if tool == "" {
		tool = map[string]string{"read": "Read", "write": "Write", "edit": "Edit", "glob": "Glob", "grep": "Grep"}[row.Kind]
	}
	return tool, row.Args
}

func d1EvidenceContext(t *testing.T, ctx context.Context, cwd, tool string, args map[string]any) context.Context {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "d1", "cwd": cwd,
		"tool_name": tool, "tool_input": args,
	})
	if err != nil {
		t.Fatal(err)
	}
	if targets, ok := hookpaths.Decode(hookpaths.Resolve(payload)); ok && len(targets) != 0 {
		ctx = context.WithValue(ctx, resolvedWritesContextKey{}, targets)
	}
	return ctx
}

func d1Evaluate(t *testing.T, api *APIServer, row d1ReplayRow, connector string, managed bool, home, cwd string) (result d1ReplayVerdict) {
	t.Helper()
	defer func() {
		if recover() != nil {
			result = d1ReplayVerdict{Decision: "error", RuleID: "-"}
		}
	}()
	tool, args := d1Input(row, connector)
	if connector == "codex" && row.Kind == "shell" && strings.EqualFold(row.ToolName, "powershell") {
		previous := codexShellRunsPowerShell
		codexShellRunsPowerShell = true
		defer func() { codexShellRunsPowerShell = previous }()
	}
	ctx := d1EvidenceContext(t, t.Context(), cwd, tool, args)
	ctx = withAuthenticatedHookConnector(ctx, connector)
	if managed {
		ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
	}
	if connector == "claudecode" {
		response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "d1", CWD: cwd,
			ToolName: tool, ToolInput: args,
		})
		result.Decision = response.Action
		result.RuleID = d1FirstRule(response.RuleIDs, response.Findings)
	} else {
		response := api.evaluateCodexHook(ctx, codexHookRequest{
			HookEventName: "PreToolUse", SessionID: "d1", CWD: cwd,
			ToolName: tool, ToolInput: args,
		})
		result.Decision = response.Action
		result.RuleID = d1FirstRule(response.RuleIDs, response.Findings)
	}
	if result.Decision == "" {
		result.Decision = "error"
	}
	return result
}

// d1CellLimit bounds one private replay cell (DC_D1_CELL_TIMEOUT, default
// one minute), so a single evaluator that never returns (rel-1-0-6
// GAP-0700) is recorded as a timeout cell instead of stopping the replay.
func d1CellLimit(t *testing.T) time.Duration {
	t.Helper()
	text := os.Getenv("DC_D1_CELL_TIMEOUT")
	if text == "" {
		return time.Minute
	}
	limit, err := time.ParseDuration(text)
	if err != nil || limit <= 0 {
		t.Fatalf("invalid DC_D1_CELL_TIMEOUT %q", text)
	}
	return limit
}

// d1EvaluateBounded returns a timeout verdict when the evaluation outlives
// limit. The evaluation keeps running in its goroutine until the test binary
// exits, so the replay stops after the row and a later run resumes.
func d1EvaluateBounded(t *testing.T, api *APIServer, row d1ReplayRow, connector string, managed bool, home, cwd string, limit time.Duration) d1ReplayVerdict {
	t.Helper()
	done := make(chan d1ReplayVerdict, 1)
	go func() { done <- d1Evaluate(t, api, row, connector, managed, home, cwd) }()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case verdict := <-done:
		return verdict
	case <-timer.C:
		return d1ReplayVerdict{Decision: "timeout", RuleID: "-"}
	}
}

// d1ReplayRun is one replay's output and resume state.
type d1ReplayRun struct {
	// Output receives one verdict line per cell; nil records nothing.
	Output *os.File
	// Check compares every cell with the row's expected verdict.
	Check bool
	// Done lists rows an earlier run already recorded completely.
	Done map[string]bool
	// Stalled names the marker file written when a cell outlives its limit.
	// The replay then stops cleanly and the caller starts a new run, which
	// resumes after that row. Empty means a timed-out cell fails the test.
	Stalled string
}

// d1StartRun opens the verdict TSV. With resume it keeps the rows an earlier
// run recorded completely (the four cells of a row), drops a partial row
// left by a killed run, and appends; otherwise it starts the file anew. It
// removes a stale stall marker.
func d1StartRun(path string, resume bool) (d1ReplayRun, error) {
	run := d1ReplayRun{Done: make(map[string]bool), Stalled: path + ".stalled"}
	if err := os.Remove(run.Stalled); err != nil && !os.IsNotExist(err) {
		return run, err
	}
	var kept []string
	if data, err := os.ReadFile(path); resume && err == nil {
		cells := make(map[string]map[string]bool)
		lines := make(map[string][]string)
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) != 4 || fields[0] == "" {
				continue
			}
			if cells[fields[0]] == nil {
				cells[fields[0]] = make(map[string]bool)
			}
			cells[fields[0]][fields[1]] = true
			lines[fields[0]] = append(lines[fields[0]], line)
		}
		for id, rowLines := range lines {
			if len(rowLines) == 4 && len(cells[id]) == 4 {
				run.Done[id] = true
				kept = append(kept, rowLines...)
			}
		}
		sort.Strings(kept)
	} else if resume && !os.IsNotExist(err) {
		return run, err
	}
	content := ""
	if len(kept) > 0 {
		content = strings.Join(kept, "\n") + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return run, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	run.Output = file
	return run, err
}

// d1Replay evaluates the rows in four cells each and reports whether it
// stopped early after a cell outlived its limit. An unfinished cell (error
// or timeout) is recorded, not failed here: scripts/d1diff.py is the gate for
// the private replay and fails it unless the owner ratified that exact cell.
func d1Replay(t *testing.T, rows []d1ReplayRow, run d1ReplayRun) (stalled bool) {
	t.Helper()
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	apis := map[string]*APIServer{
		"claudecode": d1TestAPI(t, "claudecode"),
		"codex":      d1TestAPI(t, "codex"),
	}
	pending := d1PendingProductDecisions()
	seenPending := make(map[string]bool)
	cellLimit := d1CellLimit(t)
	unfinished := 0
	for _, row := range rows {
		if run.Done[row.ID] {
			continue
		}
		rowTimedOut := false
		for _, connector := range []string{"claudecode", "codex"} {
			for _, managed := range []bool{false, true} {
				cell := connector + "/oss"
				if managed {
					cell = connector + "/managed-balanced"
				}
				var verdict d1ReplayVerdict
				switch {
				case run.Check:
					verdict = d1Evaluate(t, apis[connector], row, connector, managed, home, cwd)
				case rowTimedOut:
					// Not evaluated again: each run would leave one more
					// evaluator running.
					verdict = d1ReplayVerdict{Decision: "timeout", RuleID: "-"}
				default:
					verdict = d1EvaluateBounded(t, apis[connector], row, connector, managed, home, cwd, cellLimit)
					rowTimedOut = verdict.Decision == "timeout"
				}
				if run.Output != nil {
					if _, err := fmt.Fprintf(run.Output, "%s\t%s\t%s\t%s\n", row.ID, cell, verdict.Decision, verdict.RuleID); err != nil {
						t.Fatal(err)
					}
				}
				if run.Check {
					key := row.ID + " " + cell
					if _, listed := pending[key]; listed {
						seenPending[key] = true
					}
					if err := d1CheckPublicVerdict(row, cell, verdict, pending); err != nil {
						t.Errorf("D1 %s %s: %v", row.ID, cell, err)
					}
				} else if verdict.Decision == "error" || verdict.Decision == "timeout" {
					unfinished++
				}
			}
		}
		// An evaluator that outlived its limit keeps running and allocating
		// (GAP-0700 reached the host memory limit), so the replay stops
		// after its row, which is recorded as timeout in every cell. A new
		// run resumes after it.
		if rowTimedOut {
			if run.Stalled == "" {
				t.Fatalf("D1 %s: evaluation did not return within %s", row.ID, cellLimit)
			}
			if err := os.WriteFile(run.Stalled, []byte(row.ID+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Logf("D1: a row outlived the %s cell limit; stopping so a new run resumes after it", cellLimit)
			return true
		}
	}
	if unfinished > 0 {
		t.Logf("D1: %d unfinished cells recorded; d1diff decides", unfinished)
	}
	if run.Check {
		for key := range pending {
			if !seenPending[key] {
				t.Errorf("D1 pending decision absent from public corpus: %s", key)
			}
		}
	}
	return false
}

func TestD1PendingProductDecisionInventory(t *testing.T) {
	row := d1ReplayRow{ID: "d1-0081", Expected: map[string]string{"codex/oss": "allow"}}
	cell := "codex/oss"
	pending := map[string]d1PendingProductDecision{"d1-0081 codex/oss": {
		Gap: "GAP-0675", Want: "allow",
		Current: d1ReplayVerdict{Decision: "block", RuleID: "persistence.ssh_authorized_keys_command"},
	}}
	if err := d1CheckPublicVerdict(row, cell, d1ReplayVerdict{Decision: "block", RuleID: "persistence.ssh_authorized_keys_command"}, pending); err != nil {
		t.Fatal(err)
	}
	if err := d1CheckPublicVerdict(row, cell, d1ReplayVerdict{Decision: "allow"}, pending); err == nil {
		t.Fatal("resolved product decision must require inventory review")
	}
	if err := d1CheckPublicVerdict(row, cell, d1ReplayVerdict{Decision: "alert"}, pending); err == nil {
		t.Fatal("unreviewed product decision must fail")
	}
	row.ID = "d1-0030"
	if err := d1CheckPublicVerdict(row, cell, d1ReplayVerdict{Decision: "allow"}, pending); err != nil {
		t.Fatal(err)
	}
}

func TestD1PublicShapes(t *testing.T) {
	rows := d1ReadRows(t, "testdata/d1-shapes.jsonl")
	if len(rows) < 250 {
		t.Fatalf("public D1 shape set has %d rows, want at least 250", len(rows))
	}
	if os.Getenv("DC_D1_RECORD") == "1" {
		d1Replay(t, rows, d1ReplayRun{Output: os.Stdout})
		return
	}
	d1Replay(t, rows, d1ReplayRun{Check: true})
}

func TestD1StrictArchiveShape(t *testing.T) {
	var row d1ReplayRow
	for _, candidate := range d1ReadRows(t, "testdata/d1-shapes.jsonl") {
		if candidate.ID == "d1-0081" {
			row = candidate
			break
		}
	}
	if row.ID == "" {
		t.Fatal("missing strict archive shape")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, connector := range []string{"claudecode", "codex"} {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = connector
		cfg.Guardrail.RulePack = "strict"
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		for _, managed := range []bool{false, true} {
			got := d1Evaluate(t, api, row, connector, managed, home, cwd)
			if got.Decision != "block" || got.RuleID != "persistence.ssh_authorized_keys_command" {
				t.Errorf("D1 strict %s managed=%t: got %s (%s), want the archive block", connector, managed, got.Decision, got.RuleID)
			}
		}
	}
}
