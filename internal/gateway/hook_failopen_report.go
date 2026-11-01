// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// The hooks append one line to <home>/logs/hook-failures.jsonl for every
// call that got no verdict from the gateway (_hardening.sh
// defenseclaw_log_hook_failure, hookexec logHookFailure). A fail-open call
// then ran without a DefenseClaw check, and the gateway that would have
// recorded it was down, so nothing in the alerts or the audit history said so
// (GAP-0414). On start, and about once a minute while it runs, the gateway
// reads the lines it has not reported yet and records one guardrail-degraded
// alert per connector.
//
// A call the hook blocked itself (outcome fail_closed) gets its own audit
// row too. Under load a per-user hook gives up at its answer budget and
// blocks the call, while its gateway still decides it, records allow and
// answers a hook that has left: in an 18000-call flood, 16 calls the agent
// saw denied were recorded as 17999 allow and 1 block (GAP-0271). The
// guardrail-block row names the call's session, call and tool id and the
// hook event, so the audit holds the block the agent received beside the
// gateway's decision. Only a block of a pre-execution event (PreToolUse,
// PermissionRequest, the connectors' before-* events: hookexec.ToolGateEvent)
// is the call's own block; a post-execution event's tool had already run
// (GAP-0271 review). A report run writes at most hookFailureRowsPerReport
// rows one by one and one summary row for the rest, so a long outage's
// backlog does not hold the audit writer the resuming hooks need.
const (
	hookFailuresFile         = "hook-failures.jsonl"
	hookFailuresReportedFile = "hook-failures.reported"
	// hookFailOpenReportMaxBytes bounds what one start reads. With more
	// unread, the report reads the newest lines (readHookFailureCalls).
	hookFailOpenReportMaxBytes = 16 << 20
	// hookFailuresHeadBytes bounds the first line the report fingerprints.
	hookFailuresHeadBytes = 4096
	// hookFailOpenReportMaxAge leaves out calls older than the default
	// audit retention when the report has no position in the file (its
	// first read, or a replaced file), so the first start of an upgraded
	// gateway does not report a months-old file. Lines after a recorded
	// position are new and are reported whatever their age: a gateway that
	// stayed stopped for more than 7 days dropped them (rel-1-0-2 GAP-0446
	// item 3).
	hookFailOpenReportMaxAge = 7 * 24 * time.Hour
)

// hookFailureRowsPerReport bounds the per-call audit rows one report run
// writes; the rest get one summary row. A variable for tests.
var hookFailureRowsPerReport = 1000

// hookFailOpenReportInterval is how often a running per-user gateway looks
// for new hook-failure lines. A call that ran fail-open while the gateway
// was up but did not answer it (busy, a server error, a hook that timed
// out) was reported only at the next start (rel-1-0-2 GAP-0446 item 3).
// One stat per folder when nothing changed. A variable for tests.
var hookFailOpenReportInterval = time.Minute

// hookFailuresHooksHome is the data directory the hooks write their
// hook-failure log to (hookFailOpenLogDirs). The gateway tests' TestMain
// sets it to "", so no test reads or writes the host account's logs.
var hookFailuresHooksHome = config.DefaultDataPath

// hookFailOpenReportMu keeps the start-up report and a write-recovery report
// from reading the same lines.
var hookFailOpenReportMu sync.Mutex

type hookFailureLine struct {
	TS        string `json:"ts"`
	Connector string `json:"connector"`
	SessionID string `json:"session_id"`
	CallID    string `json:"call_id"`
	// ToolID is CallID when the hook took it from the agent's tool call id
	// (tool_use_id, tool_call_id, callID). Empty in lines of hooks before
	// 1.0.7.
	ToolID string `json:"tool_id"`
	// Event is the hook event (PreToolUse, PostToolUse, ...). Empty in the
	// shell hooks' lines before 1.0.7.
	Event    string `json:"event"`
	Reason   string `json:"reason"`
	Category string `json:"category"`
	FailMode string `json:"fail_mode"`
	// Outcome is what the call got: fail_open (it ran unchecked),
	// fail_closed (it was blocked) or diagnostic (a record that is no
	// delivery decision, such as a rejected traceparent: the call still went
	// to the gateway). A call that strict availability or an event contract
	// blocked is logged with the connector's fail mode open and outcome
	// fail_closed: it did not run.
	Outcome string `json:"outcome"`
}

// ranUnchecked reports whether the logged call went ahead without a check.
// The 1.0.4 hooks write the outcome they applied on every line. A line
// without one (the OpenCode plugin, which logs only the calls it lets
// through, and hooks before 1.0.3) or with outcome unknown (the 1.0.3 shell
// hooks' Hermes, Devin, Kiro, Antigravity, Copilot and inspect-* branches,
// read by the first start after an upgrade) keeps the fail-mode rule: open
// counts, so an upgrade never hides a call that ran unchecked.
func (l hookFailureLine) ranUnchecked() bool {
	switch strings.TrimSpace(l.Outcome) {
	case "fail_open":
		return true
	case "fail_closed", "diagnostic":
		return false
	}
	return strings.TrimSpace(l.FailMode) == "open"
}

// blockedByHook reports whether the hook blocked the logged call itself:
// the agent got a block that no gateway decision row records (GAP-0271).
// Only the outcome the hook wrote counts; a line without one is no proof.
func (l hookFailureLine) blockedByHook() bool {
	return strings.TrimSpace(l.Outcome) == "fail_closed"
}

// hookFailOpenSummary is the fail-open calls of one connector. One call can
// write several lines (a Hermes turn wrote 16: one per hook event), so the
// alert counts distinct calls (session and call id; a line without a call id
// is one call) and names the hook events and sessions apart (rel-1-0-2
// GAP-0446 item 8).
type hookFailOpenSummary struct {
	Connector   string
	Calls       int
	Events      int
	Sessions    int
	First, Last time.Time
	LastReason  string
	callKeys    map[string]struct{}
	sessionKeys map[string]struct{}
}

// count adds one fail-open line, which ends at offset end, to the summary.
func (sum *hookFailOpenSummary) count(entry hookFailureLine, end int64) {
	sum.Events++
	key := "line\x00" + strconv.FormatInt(end, 10)
	session := strings.TrimSpace(entry.SessionID)
	if id := strings.TrimSpace(entry.CallID); id != "" {
		key = "call\x00" + session + "\x00" + id
	}
	if sum.callKeys == nil {
		sum.callKeys, sum.sessionKeys = map[string]struct{}{}, map[string]struct{}{}
	}
	if _, seen := sum.callKeys[key]; !seen {
		sum.callKeys[key] = struct{}{}
		sum.Calls++
	}
	if session != "" {
		sum.sessionKeys[session] = struct{}{}
		sum.Sessions = len(sum.sessionKeys)
	}
}

// hookFailuresReported is the report's position in hook-failures.jsonl.
type hookFailuresReported struct {
	Offset int64 `json:"offset"`
	// The summary alert and the per-call audit progress independently. A
	// failed summary write must not duplicate already recorded call rows.
	AuditOffset int64 `json:"audit_offset,omitempty"`
	// Head fingerprints the file's first line at Offset: a file replaced by
	// another one, even a longer one, is read again from its start instead
	// of from the middle of a line (rel-1-0-2 GAP-0446). Empty in a state
	// an older gateway wrote.
	Head string `json:"head,omitempty"`
	// Done holds, per connector, the end of the lines already recorded
	// when a later connector's audit write failed, so the next report,
	// which reads from Offset again, does not record them twice.
	Done map[string]int64 `json:"done,omitempty"`
}

// reportHookFailureCalls records the hook calls written to
// hook-failures.jsonl since the last report (hookFailOpenLogDirs): one audit
// row per call that ran unchecked (fail-open) or that the hook blocked
// itself (fail-closed), and one alert per connector for the fail-open ones.
// Per-user gateways only: a managed hook's failures are not in the gateway's
// data directory, and managed hooks fail closed (the block is visible in the
// agent).
func (s *Sidecar) reportHookFailureCalls() {
	if s == nil || s.logger == nil || ManagedEnterpriseActive() {
		return
	}
	cfg := s.currentConfig()
	if !hookFailOpenReportApplies(cfg) {
		return
	}
	for _, logDir := range hookFailOpenLogDirs(cfg.DataDir) {
		if err := reportHookFailureCallsIn(logDir, s.logger, time.Now().UTC()); err != nil {
			fmt.Fprintf(os.Stderr, "[gateway] hook failure report: %v\n", err)
		}
	}
}

func hookFailOpenReportApplies(cfg *config.Config) bool {
	return cfg != nil && !cfg.StandaloneEnterprise() && strings.TrimSpace(cfg.DataDir) != ""
}

// hookFailOpenLogDirs are the folders whose hook-failures.jsonl the report
// reads: the gateway's data directory and the one the hooks write to
// (DEFENSECLAW_HOME, else ~/.defenseclaw: _hardening.sh, the native hook
// and the OpenCode plugin's credential folder). They differ only with a
// custom data_dir, whose hook calls that ran fail-open were never reported
// (rel-1-0-2 GAP-0446 item 9). A folder is listed once, also through a
// symbolic link.
func hookFailOpenLogDirs(dataDir string) []string {
	var dirs []string
	seen := map[string]bool{}
	for _, home := range []string{dataDir, hookFailuresHooksHome()} {
		home = strings.TrimSpace(home)
		if home == "" {
			continue
		}
		key := filepath.Clean(home)
		if resolved, err := filepath.EvalSymlinks(home); err == nil {
			key = resolved
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		dirs = append(dirs, filepath.Join(home, "logs"))
	}
	return dirs
}

// watchHookFailureCalls reports new hook-failure lines while the gateway
// runs (hookFailOpenReportInterval), so a call that ran fail-open while the
// gateway was up is not left for the next start. It reads a folder only when
// its file's size or time changed. A managed gateway starts no timer.
func (s *Sidecar) watchHookFailureCalls(ctx context.Context) {
	if s == nil || s.logger == nil || ManagedEnterpriseActive() {
		return
	}
	ticker := time.NewTicker(hookFailOpenReportInterval)
	defer ticker.Stop()
	type stamp struct {
		size int64
		mod  time.Time
	}
	seen := map[string]stamp{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cfg := s.currentConfig()
		if !hookFailOpenReportApplies(cfg) {
			continue
		}
		changed := false
		for _, dir := range hookFailOpenLogDirs(cfg.DataDir) {
			var now stamp
			if info, err := os.Stat(filepath.Join(dir, hookFailuresFile)); err == nil {
				now = stamp{size: info.Size(), mod: info.ModTime()}
			}
			if seen[dir] != now {
				seen[dir], changed = now, true
			}
		}
		if changed {
			s.reportHookFailureCalls()
		}
	}
}

func reportHookFailureCallsIn(logDir string, logger *audit.Logger, now time.Time) error {
	hookFailOpenReportMu.Lock()
	defer hookFailOpenReportMu.Unlock()
	summaries, read, err := readHookFailureCalls(logDir, now)
	if err != nil {
		return err
	}
	if !read.found {
		// No file: a later one is read from its start. Never create the
		// logs folder (or the DefenseClaw folder a purge removed) for the
		// position alone (GAP-0654).
		if err := os.Remove(filepath.Join(logDir, hookFailuresReportedFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	written, skipped, skippedBlocked := 0, 0, 0
	for _, call := range read.calls {
		if call.end <= read.start.AuditOffset {
			// Recorded by a run whose later write failed (it kept Offset).
			continue
		}
		if written >= hookFailureRowsPerReport {
			skipped++
			if call.blocked {
				skippedBlocked++
			}
			continue
		}
		env := audit.CorrelationEnvelope{Connector: call.entry.Connector,
			SessionID: call.entry.SessionID, RequestID: call.entry.CallID}
		if call.blocked {
			env.ToolID = strings.TrimSpace(call.entry.ToolID)
		}
		ctx := audit.ContextWithEnvelope(context.Background(), env)
		action, target, details, severity := hookFailureRow(call)
		if err := logger.LogActionCtxSeverity(ctx, action, target, details, severity); err != nil {
			_ = writeHookFailuresReported(logDir, read.start)
			return fmt.Errorf("record %s hook call %s: %w", call.entry.Connector, action, err)
		}
		read.start.AuditOffset = call.end
		written++
	}
	if skipped > 0 {
		details := fmt.Sprintf("hook failure report: %d more hook calls (%d blocked by the hook, %d unchecked) are not "+
			"recorded one by one; this run recorded %d; see logs/%s", skipped, skippedBlocked, skipped-skippedBlocked,
			written, hookFailuresFile)
		if err := logger.LogActionSeverityConnector(string(audit.ActionGuardrailWarn), "hook-failures",
			details, "MEDIUM", ""); err != nil {
			_ = writeHookFailuresReported(logDir, read.start)
			return fmt.Errorf("record the hook failure report summary: %w", err)
		}
	}
	read.start.AuditOffset = read.next
	for _, sum := range summaries {
		if err := logger.LogActionSeverityConnector(string(audit.ActionGuardrailDegraded), sum.Connector,
			describeHookFailOpenCalls(sum), "HIGH", sum.Connector); err != nil {
			// Keep the offset, so the next report reads these lines again,
			// but not the connectors recorded before this one.
			_ = writeHookFailuresReported(logDir, read.start)
			return fmt.Errorf("record %s fail-open calls: %w", sum.Connector, err)
		}
		if read.start.Done == nil {
			read.start.Done = map[string]int64{}
		}
		read.start.Done[sum.Connector] = read.next
	}
	return writeHookFailuresReported(logDir, hookFailuresReported{Offset: read.next, Head: read.start.Head,
		AuditOffset: read.start.AuditOffset})
}

// hookFailureRow is the audit row of one hook-failure line: a fail-open
// call ran unchecked (guardrail-warn, HIGH); a fail-closed one was blocked by
// the hook (guardrail-block, MEDIUM, target connector:event). Only the
// block of a pre-execution event is the call's own block, the answer the
// agent got for it; a post-execution event's tool had already run, and a
// line that names no event (a shell hook before 1.0.7) is not claimed as
// either.
func hookFailureRow(call hookFailureCall) (action, target, details, severity string) {
	reason := strings.TrimSpace(call.entry.Reason)
	if len(reason) > 300 {
		reason = reason[:300]
	}
	connectorName := call.entry.Connector
	if !call.blocked {
		return string(audit.ActionGuardrailWarn), connectorName,
			fmt.Sprintf("unchecked hook call during gateway outage: %s; see logs/%s", strconv.Quote(reason), hookFailuresFile), "HIGH"
	}
	event := strings.Join(strings.Fields(call.entry.Event), "")
	if len(event) > 64 {
		event = event[:64]
	}
	target = connectorName
	if event != "" {
		target = connectorName + ":" + event
	}
	var what string
	switch {
	case event == "":
		what = "hook blocked a hook event itself (fail-closed; the line names no event, so this is not claimed as the call's verdict)"
	case hookexec.ToolGateEvent(connectorName, event):
		what = fmt.Sprintf("hook blocked the call itself (fail-closed, %s): the agent got this block, "+
			"not a gateway decision recorded for the call", event)
	case postExecutionHookEvent(event):
		what = fmt.Sprintf("the tool had already run; the hook blocked its result (fail-closed, %s), "+
			"not the call", event)
	default:
		what = fmt.Sprintf("hook blocked its %s event itself (fail-closed), not a tool call", event)
	}
	return string(audit.ActionGuardrailBlock), target,
		fmt.Sprintf("%s: %s; see logs/%s", what, strconv.Quote(reason), hookFailuresFile), "MEDIUM"
}

// postExecutionHookEvent reports a hook event that runs after its tool
// call ran: PostToolUse, postToolUse, post_tool_call, tool.execute.after,
// afterShellExecution, tool.result and the like.
func postExecutionHookEvent(event string) bool {
	lower := strings.ToLower(event)
	return strings.HasPrefix(lower, "post") || strings.HasPrefix(lower, "after") ||
		strings.HasSuffix(lower, ".after") || lower == "tool.result"
}

// hookFailureRead is where one report read: the state it started from
// (the offset it read at, the file's head and the connectors already
// recorded) and the offset after its last complete line.
type hookFailureRead struct {
	start hookFailuresReported
	next  int64
	calls []hookFailureCall
	// found is false when there is no hook-failures.jsonl.
	found bool
}

type hookFailureCall struct {
	entry hookFailureLine
	end   int64
	// blocked: the hook blocked the call itself (blockedByHook); it gets a
	// guardrail-block row and no place in the fail-open alert.
	blocked bool
}

// readHookFailureCalls returns the fail-open calls after the reported
// offset, grouped by connector, and where it read. A file shorter than the
// offset, or whose first line changed, was replaced and is read again from
// the start. With more than hookFailOpenReportMaxBytes unread (a first start
// after an upgrade with a large file), it reads the newest lines, from the
// first line that starts in the last hookFailOpenReportMaxBytes.
func readHookFailureCalls(logDir string, now time.Time) ([]hookFailOpenSummary, hookFailureRead, error) {
	state := readHookFailuresReported(logDir)
	read := hookFailureRead{start: state, next: state.Offset, found: true}
	f, err := os.Open(filepath.Join(logDir, hookFailuresFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, hookFailureRead{}, nil
	}
	if err != nil {
		return nil, read, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, read, err
	}
	head := hookFailuresHead(f)
	offset := state.Offset
	// A recorded position in this file: what follows it is new, whatever
	// its age (hookFailOpenReportMaxAge).
	positioned := state.Offset > 0 || state.Head != ""
	if offset > info.Size() || offset < 0 || (state.Head != "" && state.Head != head) {
		offset, state.Done = 0, nil
		state.AuditOffset = 0
		positioned = false
	}
	skipPartial := false
	if info.Size()-offset > hookFailOpenReportMaxBytes {
		offset, skipPartial = info.Size()-hookFailOpenReportMaxBytes, true
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, read, err
	}
	byConnector := map[string]*hookFailOpenSummary{}
	reader := bufio.NewReader(io.LimitReader(f, hookFailOpenReportMaxBytes))
	next := offset
	if skipPartial && offset > 0 {
		// The window starts inside a line unless the byte before it ends one.
		previous := make([]byte, 1)
		if _, err := f.ReadAt(previous, offset-1); err == nil && previous[0] != '\n' {
			partial, _ := reader.ReadBytes('\n')
			next += int64(len(partial))
		}
	}
	read.start = hookFailuresReported{Offset: next, Head: head, Done: state.Done, AuditOffset: state.AuditOffset}
	for {
		line, _ := reader.ReadBytes('\n')
		if len(line) == 0 || line[len(line)-1] != '\n' {
			// The end, or a last line still being written: read it next time.
			break
		}
		next += int64(len(line))
		var entry hookFailureLine
		if json.Unmarshal(line, &entry) != nil {
			continue
		}
		blocked := entry.blockedByHook()
		if !blocked && !entry.ranUnchecked() {
			continue
		}
		at, perr := time.Parse(time.RFC3339, strings.TrimSpace(entry.TS))
		connectorName := strings.ToLower(strings.TrimSpace(entry.Connector))
		if perr != nil || connectorName == "" || (!positioned && now.Sub(at) > hookFailOpenReportMaxAge) {
			continue
		}
		entry.Connector = connectorName
		read.calls = append(read.calls, hookFailureCall{entry: entry, end: next, blocked: blocked})
		if blocked || next <= state.Done[connectorName] {
			continue
		}
		sum := byConnector[connectorName]
		if sum == nil {
			sum = &hookFailOpenSummary{Connector: connectorName, First: at}
			byConnector[connectorName] = sum
		}
		sum.count(entry, next)
		if at.Before(sum.First) {
			sum.First = at
		}
		if !at.Before(sum.Last) {
			sum.Last = at
			sum.LastReason = entry.Reason
		}
	}
	out := make([]hookFailOpenSummary, 0, len(byConnector))
	for _, sum := range byConnector {
		out = append(out, *sum)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Connector < out[j].Connector })
	read.next = next
	return out, read, nil
}

// hookFailuresHead fingerprints the first line of the hook-failure log (at
// most hookFailuresHeadBytes of it).
func hookFailuresHead(f *os.File) string {
	buf := make([]byte, hookFailuresHeadBytes)
	n, _ := f.ReadAt(buf, 0)
	line := buf[:n]
	if i := strings.IndexByte(string(line), '\n'); i >= 0 {
		line = line[:i+1]
	}
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// describeHookFailOpenCalls is the alert text, for example "2 hermes hook
// calls (16 hook events) in 1 session ran without a DefenseClaw check
// (fail-open) while the gateway was unreachable or did not answer (first
// 2026-10-13T09:49:01Z, last 2026-10-13T09:49:40Z; last reason: gateway
// unreachable); see logs/hook-failures.jsonl". The hook events are named
// only when there are more of them than calls, the sessions only when the
// lines name one.
func describeHookFailOpenCalls(sum hookFailOpenSummary) string {
	noun := "calls"
	if sum.Calls == 1 {
		noun = "call"
	}
	if sum.Events > sum.Calls {
		noun += fmt.Sprintf(" (%d hook events)", sum.Events)
	}
	switch {
	case sum.Sessions == 1:
		noun += " in 1 session"
	case sum.Sessions > 1:
		noun += fmt.Sprintf(" in %d sessions", sum.Sessions)
	}
	reason := strings.Join(strings.Fields(sum.LastReason), " ")
	if len(reason) > 200 {
		reason = strings.ToValidUTF8(reason[:200], "") + "…"
	}
	if reason == "" {
		reason = "unknown"
	}
	return fmt.Sprintf("%d %s hook %s ran without a DefenseClaw check (fail-open) while the gateway was "+
		"unreachable or did not answer (first %s, last %s; last reason: %s); see logs/%s",
		sum.Calls, sum.Connector, noun, sum.First.Format(time.RFC3339), sum.Last.Format(time.RFC3339),
		reason, hookFailuresFile)
}

func readHookFailuresReported(logDir string) hookFailuresReported {
	raw, err := os.ReadFile(filepath.Join(logDir, hookFailuresReportedFile))
	if err != nil {
		return hookFailuresReported{}
	}
	var state hookFailuresReported
	if json.Unmarshal(raw, &state) != nil {
		return hookFailuresReported{}
	}
	return state
}

func writeHookFailuresReported(logDir string, state hookFailuresReported) error {
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return err
	}
	raw, _ := json.Marshal(state)
	tmp, err := os.CreateTemp(logDir, hookFailuresReportedFile+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(append(raw, '\n'))
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(name)
		return errors.Join(werr, cerr)
	}
	if err := os.Rename(name, filepath.Join(logDir, hookFailuresReportedFile)); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
