// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
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
	// hookFailOpenReportMaxBytes bounds what one start reads.
	hookFailOpenReportMaxBytes = 16 << 20
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
}

// hookFailOpenSummary is the fail-open calls of one connector.
type hookFailOpenSummary struct {
	Connector   string
	Calls       int
	First, Last time.Time
	LastReason  string
}

type hookFailuresReported struct {
	Offset int64 `json:"offset"`
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
	summaries, next, err := readHookFailOpenCalls(logDir, now)
	if err != nil {
		return err
	}
	for _, sum := range summaries {
		if err := logger.LogActionSeverityConnector(string(audit.ActionGuardrailDegraded), sum.Connector,
			describeHookFailOpenCalls(sum), "HIGH", sum.Connector); err != nil {
			// Keep the offset: the next start reports these calls again.
			return fmt.Errorf("record %s fail-open calls: %w", sum.Connector, err)
		}
	}
	return writeHookFailuresReported(logDir, next)
}

// readHookFailOpenCalls returns the fail-open calls after the reported
// offset, grouped by connector, and the offset to store once they are
// recorded. A file shorter than the offset was replaced and is read again
// from the start.
func readHookFailOpenCalls(logDir string, now time.Time) ([]hookFailOpenSummary, int64, error) {
	offset := readHookFailuresReported(logDir)
	f, err := os.Open(filepath.Join(logDir, hookFailuresFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, offset, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, offset, err
	}
	if offset > info.Size() || offset < 0 {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, err
	}
	byConnector := map[string]*hookFailOpenSummary{}
	reader := bufio.NewReader(io.LimitReader(f, hookFailOpenReportMaxBytes))
	next := offset
	for {
		line, _ := reader.ReadBytes('\n')
		if len(line) == 0 || line[len(line)-1] != '\n' {
			// The end, or a last line still being written: read it next time.
			break
		}
		next += int64(len(line))
		var entry hookFailureLine
		if json.Unmarshal(line, &entry) != nil || strings.TrimSpace(entry.FailMode) != "open" {
			continue
		}
		at, perr := time.Parse(time.RFC3339, strings.TrimSpace(entry.TS))
		connectorName := strings.ToLower(strings.TrimSpace(entry.Connector))
		if perr != nil || connectorName == "" || now.Sub(at) > hookFailOpenReportMaxAge {
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
	return out, next, nil
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

func readHookFailuresReported(logDir string) int64 {
	raw, err := os.ReadFile(filepath.Join(logDir, hookFailuresReportedFile))
	if err != nil {
		return 0
	}
	var state hookFailuresReported
	if json.Unmarshal(raw, &state) != nil {
		return 0
	}
	return state.Offset
}

func writeHookFailuresReported(logDir string, offset int64) error {
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return err
	}
	raw, _ := json.Marshal(hookFailuresReported{Offset: offset})
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
