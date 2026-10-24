// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// The hooks append one line to <home>/logs/hook-failures.jsonl for every
// call that got no verdict from the gateway (_hardening.sh
// defenseclaw_log_hook_failure, hookexec logHookFailure). A fail-open call
// then ran without a DefenseClaw check, and the gateway that would have
// recorded it was down, so nothing in the alerts or the audit history said so
// (GAP-0414). On start the gateway reads the lines it has not reported yet
// and records one guardrail-degraded alert per connector.
const (
	hookFailuresFile         = "hook-failures.jsonl"
	hookFailuresReportedFile = "hook-failures.reported"
	// hookFailOpenReportMaxBytes bounds what one start reads. With more
	// unread, the report reads the newest lines (readHookFailOpenCalls).
	hookFailOpenReportMaxBytes = 16 << 20
	// hookFailuresHeadBytes bounds the first line the report fingerprints.
	hookFailuresHeadBytes = 4096
	// hookFailOpenReportMaxAge leaves out calls older than the default
	// audit retention, so the first start of an upgraded gateway does not
	// report a months-old file.
	hookFailOpenReportMaxAge = 7 * 24 * time.Hour
)

// hookFailOpenReportMu keeps the start-up report and a write-recovery report
// from reading the same lines.
var hookFailOpenReportMu sync.Mutex

type hookFailureLine struct {
	TS        string `json:"ts"`
	Connector string `json:"connector"`
	Reason    string `json:"reason"`
	Category  string `json:"category"`
	FailMode  string `json:"fail_mode"`
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

// hookFailOpenSummary is the fail-open calls of one connector.
type hookFailOpenSummary struct {
	Connector   string
	Calls       int
	First, Last time.Time
	LastReason  string
}

// hookFailuresReported is the report's position in hook-failures.jsonl.
type hookFailuresReported struct {
	Offset int64 `json:"offset"`
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

// reportHookFailOpenCalls records the fail-open hook calls written to
// dataDir/logs/hook-failures.jsonl since the last report. Per-user gateways
// only: a managed hook's failures are not in the gateway's data directory,
// and managed hooks fail closed (the block is visible in the agent).
func (s *Sidecar) reportHookFailOpenCalls() {
	if s == nil || s.logger == nil || ManagedEnterpriseActive() {
		return
	}
	cfg := s.currentConfig()
	if cfg == nil || cfg.StandaloneEnterprise() || strings.TrimSpace(cfg.DataDir) == "" {
		return
	}
	if err := reportHookFailOpenCallsIn(filepath.Join(cfg.DataDir, "logs"), s.logger, time.Now().UTC()); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] fail-open hook call report: %v\n", err)
	}
}

func reportHookFailOpenCallsIn(logDir string, logger *audit.Logger, now time.Time) error {
	hookFailOpenReportMu.Lock()
	defer hookFailOpenReportMu.Unlock()
	summaries, read, err := readHookFailOpenCalls(logDir, now)
	if err != nil {
		return err
	}
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
	return writeHookFailuresReported(logDir, hookFailuresReported{Offset: read.next, Head: read.start.Head})
}

// hookFailOpenRead is where one report read: the state it started from
// (the offset it read at, the file's head and the connectors already
// recorded) and the offset after its last complete line.
type hookFailOpenRead struct {
	start hookFailuresReported
	next  int64
}

// readHookFailOpenCalls returns the fail-open calls after the reported
// offset, grouped by connector, and where it read. A file shorter than the
// offset, or whose first line changed, was replaced and is read again from
// the start. With more than hookFailOpenReportMaxBytes unread (a first start
// after an upgrade with a large file), it reads the newest lines, from the
// first line that starts in the last hookFailOpenReportMaxBytes.
func readHookFailOpenCalls(logDir string, now time.Time) ([]hookFailOpenSummary, hookFailOpenRead, error) {
	state := readHookFailuresReported(logDir)
	read := hookFailOpenRead{start: state, next: state.Offset}
	f, err := os.Open(filepath.Join(logDir, hookFailuresFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, hookFailOpenRead{}, nil
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
	if offset > info.Size() || offset < 0 || (state.Head != "" && state.Head != head) {
		offset, state.Done = 0, nil
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
	read.start = hookFailuresReported{Offset: next, Head: head, Done: state.Done}
	for {
		line, _ := reader.ReadBytes('\n')
		if len(line) == 0 || line[len(line)-1] != '\n' {
			// The end, or a last line still being written: read it next time.
			break
		}
		next += int64(len(line))
		var entry hookFailureLine
		if json.Unmarshal(line, &entry) != nil || !entry.ranUnchecked() {
			continue
		}
		at, perr := time.Parse(time.RFC3339, strings.TrimSpace(entry.TS))
		connectorName := strings.ToLower(strings.TrimSpace(entry.Connector))
		if perr != nil || connectorName == "" || now.Sub(at) > hookFailOpenReportMaxAge ||
			next <= state.Done[connectorName] {
			continue
		}
		sum := byConnector[connectorName]
		if sum == nil {
			sum = &hookFailOpenSummary{Connector: connectorName, First: at}
			byConnector[connectorName] = sum
		}
		sum.Calls++
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
// calls ran without a DefenseClaw check (fail-open) while the gateway was
// unreachable or did not answer (first 2026-10-13T09:49:01Z, last
// 2026-10-13T09:49:40Z; last reason: gateway unreachable); see
// logs/hook-failures.jsonl".
func describeHookFailOpenCalls(sum hookFailOpenSummary) string {
	noun := "calls"
	if sum.Calls == 1 {
		noun = "call"
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
