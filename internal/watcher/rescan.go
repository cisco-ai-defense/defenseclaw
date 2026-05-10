// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// DriftType classifies the kind of change detected between re-scans.
type DriftType string

const (
	DriftNewFinding       DriftType = "new_finding"
	DriftRemovedFinding   DriftType = "resolved_finding"
	DriftSeverityChange   DriftType = "severity_escalation"
	DriftContentChange    DriftType = "content_change"
	DriftDependencyChange DriftType = "dependency_change"
	DriftConfigMutation   DriftType = "config_mutation"
	DriftNewEndpoint      DriftType = "new_endpoint"
	DriftRemovedEndpoint  DriftType = "removed_endpoint"
)

// DriftDelta represents a single detected change between baseline and current state.
type DriftDelta struct {
	Type        DriftType `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Previous    string    `json:"previous,omitempty"`
	Current     string    `json:"current,omitempty"`
}

// rescanLoop runs periodic re-scans of all installed skills, plugins, and MCPs,
// compares against baseline snapshots, and emits drift alerts.
func (w *InstallWatcher) rescanLoop(ctx context.Context) {
	interval := time.Duration(w.cfg.Watch.RescanIntervalMin) * time.Minute
	if interval <= 0 {
		interval = 60 * time.Minute
	}

	fmt.Fprintf(os.Stderr, "[rescan] periodic re-scan enabled (interval=%s)\n", interval)
	_ = w.logger.LogAction("rescan-start", "", fmt.Sprintf("interval=%s", interval))

	// Bootstrap a baseline immediately so already-installed targets are not
	// blind for the first full interval after startup.
	w.runRescanCycle(ctx)

	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			w.runRescanCycle(ctx)
			timer.Reset(interval)
		}
	}
}

// runRescanCycle enumerates all installed targets and re-scans each one.
func (w *InstallWatcher) runRescanCycle(ctx context.Context) {
	targets := w.enumerateTargets()
	if len(targets) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "[rescan] starting periodic re-scan of %d targets\n", len(targets))
	_ = w.logger.LogAction("rescan", "", fmt.Sprintf("targets=%d", len(targets)))

	for _, evt := range targets {
		if ctx.Err() != nil {
			return
		}
		w.rescanTarget(ctx, evt)
	}
}

// enumerateTargets lists all direct child directories under watched roots plus
// configured MCP servers from openclaw.json.
func (w *InstallWatcher) enumerateTargets() []InstallEvent {
	var targets []InstallEvent

	for _, dir := range w.skillDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rescan] enumerate skills dir %s: %v\n", dir, err)
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			targets = append(targets, InstallEvent{
				Type:      InstallSkill,
				Name:      e.Name(),
				Path:      filepath.Join(dir, e.Name()),
				Timestamp: time.Now().UTC(),
			})
		}
	}

	for _, dir := range w.pluginDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rescan] enumerate plugins dir %s: %v\n", dir, err)
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			targets = append(targets, InstallEvent{
				Type:      InstallPlugin,
				Name:      e.Name(),
				Path:      filepath.Join(dir, e.Name()),
				Timestamp: time.Now().UTC(),
			})
		}
	}

	servers, err := w.cfg.ReadMCPServers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[rescan] enumerate mcp servers: %v\n", err)
		return targets
	}
	for _, server := range servers {
		if strings.TrimSpace(server.Name) == "" {
			continue
		}
		targets = append(targets, InstallEvent{
			Type:      InstallMCP,
			Name:      server.Name,
			Path:      server.Name,
			Timestamp: time.Now().UTC(),
		})
	}

	return targets
}

// rescanTarget scans a single target, compares with baseline, and emits drift alerts.
//
// DeepSec hardening (S2.watcher, "Rescan findings are baselined without
// admission enforcement"): both the initial-baseline path
// (no prior baseline) and the drift-detected path now route the fresh
// scan result through the same admission/enforcement gate as
// runAdmission via evaluatePostScanForRescan. The baseline is only
// updated when the verdict is NOT rejected/blocked, so a malicious
// component that appears while the watcher is down -- or one that
// mutates after a clean admission -- cannot become the accepted
// baseline by relying on the periodic rescan path being alert-only.
func (w *InstallWatcher) rescanTarget(ctx context.Context, evt InstallEvent) {
	currentSnap, err := w.snapshotForEvent(evt)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[rescan] snapshot %s: %v\n", evt.Path, err)
		return
	}

	baseline, err := w.store.GetTargetSnapshot(string(evt.Type), evt.Path)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.storeBaseline(ctx, evt, currentSnap)
			return
		}
		fmt.Fprintf(os.Stderr, "[rescan] get baseline %s: %v\n", evt.Path, err)
		return
	}

	var deltas []DriftDelta

	// If a previous baseline exists but never recorded a scan result, keep
	// retrying scan persistence so finding-based drift detection can recover.
	if baseline.ScanID == "" {
		w.storeBaseline(ctx, evt, currentSnap)
	}

	// Compare content-level drift (deps, config, endpoints).
	deltas = append(deltas, compareSnapshots(baseline, currentSnap)...)

	// Run scanner and compare findings against last stored scan. We
	// also retain the freshly computed ScanResult so we can route it
	// through admission below without paying for a second scan.
	scanDeltas, freshResult := w.compareScanResults(ctx, evt)
	deltas = append(deltas, scanDeltas...)

	if len(deltas) == 0 {
		return
	}

	w.emitDriftAlerts(evt, deltas)

	// DeepSec hardening: route drift through admission. If the fresh
	// scan would be rejected/blocked by current policy, refuse to
	// promote the new snapshot to the baseline so we keep alerting on
	// every subsequent rescan (and any operator-configured auto-block
	// gets applied via applyPostScanEnforcement).
	if freshResult != nil {
		decision := w.evaluatePostScanForRescan(ctx, evt, freshResult)
		if decision != nil && shouldRejectAdmissionVerdict(decision.Verdict) {
			_ = w.logger.LogAction("rescan-rejected", evt.Path,
				fmt.Sprintf("type=%s verdict=%s reason=%s",
					evt.Type, decision.Verdict, decision.Reason))
			return
		}
	}

	w.storeBaseline(ctx, evt, currentSnap)
}

// storeBaseline runs a scan, routes the result through the admission
// gate, and persists the snapshot as the new baseline only when the
// verdict is not rejected/blocked.
//
// DeepSec hardening (S2.watcher): a scanner failure or a
// rejected/blocked verdict must not become the accepted baseline. See
// the matching comment on rescanTarget and finding "Rescan findings
// are baselined without admission enforcement".
func (w *InstallWatcher) storeBaseline(ctx context.Context, evt InstallEvent, snap *TargetSnapshot) {
	s := w.scannerFor(evt)
	scanID := ""
	if s != nil {
		scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()

		result, err := s.Scan(scanCtx, w.scanTargetFor(evt))
		if err != nil {
			// The scanner Scan() now fails closed on any
			// non-zero subprocess exit. Refuse to baseline so we
			// keep retrying on the next rescan rather than
			// silently accepting an unscanned target.
			_ = w.logger.LogAction("baseline-rejected", evt.Path,
				fmt.Sprintf("type=%s reason=scan-error error=%v", evt.Type, err))
			return
		}
		if result != nil {
			decision := w.evaluatePostScanForRescan(ctx, evt, result)
			if decision != nil && shouldRejectAdmissionVerdict(decision.Verdict) {
				_ = w.logger.LogAction("baseline-rejected", evt.Path,
					fmt.Sprintf("type=%s verdict=%s reason=%s",
						evt.Type, decision.Verdict, decision.Reason))
				return
			}
			scanID = w.persistScanResult(result)
		}
	}

	depJSON, _ := json.Marshal(snap.DependencyHashes)
	cfgJSON, _ := json.Marshal(snap.ConfigHashes)
	epJSON, _ := json.Marshal(snap.NetworkEndpoints)

	_ = w.store.SetTargetSnapshot(
		string(evt.Type), evt.Path, snap.ContentHash,
		string(depJSON), string(cfgJSON), string(epJSON), scanID,
	)
}

// evaluatePostScanForRescan runs the same OPA -> fallback -> enforcement
// pipeline as runAdmission's post-scan phase, but for a result that was
// produced by the rescan/baseline path rather than an install event.
//
// The returned AdmissionOutput tells the caller whether the fresh scan
// is acceptable as a new baseline (clean/warning/allowed) or whether it
// must be rejected (rejected/blocked). Side-effects like quarantine,
// disable, and audit logging are performed via applyPostScanEnforcement
// so rescan parity with the install path is automatic.
func (w *InstallWatcher) evaluatePostScanForRescan(ctx context.Context, evt InstallEvent, result *scanner.ScanResult) *policy.AdmissionOutput {
	if result == nil {
		return nil
	}
	targetType := string(evt.Type)
	pe := enforce.NewPolicyEngine(w.store)
	blockList := w.buildListEntries(pe, "block")
	allowList := w.buildListEntries(pe, "allow")
	fallbackProfile := policy.LoadFallbackProfile(w.cfg.PolicyDir)

	scanInput := &policy.ScanResultInput{
		MaxSeverity:   string(result.MaxSeverity()),
		TotalFindings: len(result.Findings),
		ScannerName:   result.Scanner,
		Findings:      toFindingInputs(result.Findings),
		ExitCode:      result.ExitCode,
		ScanError:     result.ScanError,
	}
	input := policy.AdmissionInput{
		TargetType: targetType,
		TargetName: evt.Name,
		Path:       evt.Path,
		BlockList:  blockList,
		AllowList:  allowList,
		ScanResult: scanInput,
	}

	var out *policy.AdmissionOutput
	if w.opa != nil {
		if rOut, err := w.opa.Evaluate(ctx, input); err == nil {
			out = rOut
		}
	}
	if out == nil {
		out = policy.EvaluateAdmissionFallback(input, fallbackProfile)
	}

	w.applyPostScanEnforcement(ctx, pe, out, evt, targetType, result, result.Scanner)
	_ = w.logger.LogScanWithVerdict(result, out.Verdict)
	w.recordAdmission(ctx, out.Verdict, targetType)
	return out
}

// shouldRejectAdmissionVerdict returns true for verdicts that must NOT
// be accepted as a new rescan/baseline. Anything else (clean, warning,
// allowed, or unknown verdict) is treated as acceptable so we don't
// accidentally over-block on a verdict the policy engine introduced
// after a code update.
func shouldRejectAdmissionVerdict(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "blocked", "rejected":
		return true
	}
	return false
}

// compareScanResults runs a fresh scan, diffs findings against the
// last stored scan, and returns both the drift deltas and the fresh
// result so callers can route it through admission without paying for
// a second scan.
func (w *InstallWatcher) compareScanResults(ctx context.Context, evt InstallEvent) ([]DriftDelta, *scanner.ScanResult) {
	s := w.scannerFor(evt)
	if s == nil {
		return nil, nil
	}

	baseline, err := w.store.GetTargetSnapshot(string(evt.Type), evt.Path)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			fmt.Fprintf(os.Stderr, "[rescan] compareScanResults: get baseline %s: %v\n", evt.Path, err)
		}
		return nil, nil
	}
	if baseline.ScanID == "" {
		return nil, nil
	}

	prevScan, err := w.loadScanResult(baseline.ScanID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[rescan] compareScanResults: load baseline scan %s: %v\n", baseline.ScanID, err)
		return nil, nil
	}
	if prevScan == nil {
		return nil, nil
	}

	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	current, err := s.Scan(scanCtx, w.scanTargetFor(evt))
	if err != nil {
		// DeepSec hardening (S2.watcher): scanner Scan() now
		// fails closed on non-zero exit. Surface that as a
		// drift signal so the operator can act, but do NOT
		// silently swap the baseline; a nil result here causes
		// rescanTarget to skip the baseline update path.
		fmt.Fprintf(os.Stderr, "[rescan] compareScanResults: scan %s: %v\n", evt.Path, err)
		return []DriftDelta{{
			Type:        DriftContentChange,
			Severity:    "HIGH",
			Description: fmt.Sprintf("rescan failed: %v", err),
		}}, nil
	}
	if current == nil {
		return nil, nil
	}

	deltas := diffFindings(prevScan.Findings, current.Findings)

	prevMax := string(prevScan.MaxSeverity())
	curMax := string(current.MaxSeverity())
	if audit.SeverityRank(curMax) > audit.SeverityRank(prevMax) {
		deltas = append(deltas, DriftDelta{
			Type:        DriftSeverityChange,
			Severity:    curMax,
			Description: fmt.Sprintf("max severity escalated from %s to %s", prevMax, curMax),
			Previous:    prevMax,
			Current:     curMax,
		})
	}

	return deltas, current
}

// loadScanResult retrieves a past scan result from the audit store.
func (w *InstallWatcher) loadScanResult(scanID string) (*scanner.ScanResult, error) {
	rawJSON, err := w.store.GetScanRawJSON(scanID)
	if err != nil {
		return nil, err
	}
	var result scanner.ScanResult
	if err := json.Unmarshal([]byte(rawJSON), &result); err != nil {
		return nil, fmt.Errorf("parse scan result: %w", err)
	}
	return &result, nil
}

// compareSnapshots diffs dependency hashes, config hashes, and network endpoints.
func compareSnapshots(baseline *audit.SnapshotRow, current *TargetSnapshot) []DriftDelta {
	var deltas []DriftDelta
	if baseline == nil || current == nil {
		return deltas
	}

	var prevDeps map[string]string
	if err := json.Unmarshal([]byte(baseline.DependencyHashes), &prevDeps); err != nil && baseline.DependencyHashes != "" {
		fmt.Fprintf(os.Stderr, "[rescan] corrupt baseline dependency_hashes for %s: %v\n", baseline.TargetPath, err)
	}
	for file, hash := range current.DependencyHashes {
		prev, exists := prevDeps[file]
		if !exists {
			deltas = append(deltas, DriftDelta{
				Type:        DriftDependencyChange,
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("new dependency manifest: %s", file),
				Current:     hash,
			})
		} else if prev != hash {
			deltas = append(deltas, DriftDelta{
				Type:        DriftDependencyChange,
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("dependency manifest modified: %s", file),
				Previous:    prev,
				Current:     hash,
			})
		}
	}
	for file, hash := range prevDeps {
		if _, exists := current.DependencyHashes[file]; !exists {
			deltas = append(deltas, DriftDelta{
				Type:        DriftDependencyChange,
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("dependency manifest removed: %s", file),
				Previous:    hash,
			})
		}
	}

	var prevCfg map[string]string
	if err := json.Unmarshal([]byte(baseline.ConfigHashes), &prevCfg); err != nil && baseline.ConfigHashes != "" {
		fmt.Fprintf(os.Stderr, "[rescan] corrupt baseline config_hashes for %s: %v\n", baseline.TargetPath, err)
	}
	for file, hash := range current.ConfigHashes {
		prev, exists := prevCfg[file]
		if !exists {
			deltas = append(deltas, DriftDelta{
				Type:        DriftConfigMutation,
				Severity:    "HIGH",
				Description: fmt.Sprintf("new config file: %s", file),
				Current:     hash,
			})
		} else if prev != hash {
			deltas = append(deltas, DriftDelta{
				Type:        DriftConfigMutation,
				Severity:    "HIGH",
				Description: fmt.Sprintf("config file modified: %s", file),
				Previous:    prev,
				Current:     hash,
			})
		}
	}
	for file, hash := range prevCfg {
		if _, exists := current.ConfigHashes[file]; !exists {
			deltas = append(deltas, DriftDelta{
				Type:        DriftConfigMutation,
				Severity:    "HIGH",
				Description: fmt.Sprintf("config file removed: %s", file),
				Previous:    hash,
			})
		}
	}

	var prevEndpoints []string
	if err := json.Unmarshal([]byte(baseline.NetworkEndpoints), &prevEndpoints); err != nil && baseline.NetworkEndpoints != "" {
		fmt.Fprintf(os.Stderr, "[rescan] corrupt baseline network_endpoints for %s: %v\n", baseline.TargetPath, err)
	}
	prevSet := make(map[string]bool, len(prevEndpoints))
	for _, ep := range prevEndpoints {
		prevSet[ep] = true
	}
	curSet := make(map[string]bool, len(current.NetworkEndpoints))
	for _, ep := range current.NetworkEndpoints {
		curSet[ep] = true
	}

	for _, ep := range current.NetworkEndpoints {
		if !prevSet[ep] {
			deltas = append(deltas, DriftDelta{
				Type:        DriftNewEndpoint,
				Severity:    "HIGH",
				Description: fmt.Sprintf("new network endpoint detected: %s", ep),
				Current:     ep,
			})
		}
	}
	for _, ep := range prevEndpoints {
		if !curSet[ep] {
			deltas = append(deltas, DriftDelta{
				Type:        DriftRemovedEndpoint,
				Severity:    "INFO",
				Description: fmt.Sprintf("network endpoint removed: %s", ep),
				Previous:    ep,
			})
		}
	}

	// Fall back to the whole-tree content hash so code-only mutations that do
	// not alter dependencies, config files, or endpoints still surface as drift.
	if baseline.ContentHash != "" && current.ContentHash != "" &&
		baseline.ContentHash != current.ContentHash && len(deltas) == 0 {
		deltas = append(deltas, DriftDelta{
			Type:        DriftContentChange,
			Severity:    "MEDIUM",
			Description: "directory contents changed outside tracked dependency/config/endpoint surfaces",
			Previous:    baseline.ContentHash,
			Current:     current.ContentHash,
		})
	}

	return deltas
}

func findingDriftKey(f scanner.Finding) string {
	return strings.Join([]string{
		f.Scanner,
		f.Title,
		f.Location,
	}, "\x00")
}

func findingLabel(f scanner.Finding) string {
	if f.Location == "" {
		return f.Title
	}
	return fmt.Sprintf("%s (%s)", f.Title, f.Location)
}

// diffFindings compares two sets of findings and returns drift deltas.
func diffFindings(prev, curr []scanner.Finding) []DriftDelta {
	prevByKey := make(map[string]scanner.Finding, len(prev))
	for _, f := range prev {
		prevByKey[findingDriftKey(f)] = f
	}
	currByKey := make(map[string]scanner.Finding, len(curr))
	for _, f := range curr {
		currByKey[findingDriftKey(f)] = f
	}

	var deltas []DriftDelta

	for key, f := range currByKey {
		prevFinding, exists := prevByKey[key]
		if !exists {
			deltas = append(deltas, DriftDelta{
				Type:        DriftNewFinding,
				Severity:    string(f.Severity),
				Description: fmt.Sprintf("new finding: %s (%s)", findingLabel(f), f.Severity),
				Current:     findingLabel(f),
			})
			continue
		}
		if prevFinding.Severity != f.Severity {
			sev := prevFinding.Severity
			if audit.SeverityRank(string(f.Severity)) > audit.SeverityRank(string(prevFinding.Severity)) {
				sev = f.Severity
			}
			deltas = append(deltas, DriftDelta{
				Type:        DriftSeverityChange,
				Severity:    string(sev),
				Description: fmt.Sprintf("finding severity changed: %s (%s -> %s)", findingLabel(f), prevFinding.Severity, f.Severity),
				Previous:    string(prevFinding.Severity),
				Current:     string(f.Severity),
			})
		}
	}

	for key, f := range prevByKey {
		if _, exists := currByKey[key]; !exists {
			deltas = append(deltas, DriftDelta{
				Type:        DriftRemovedFinding,
				Severity:    "INFO",
				Description: fmt.Sprintf("finding resolved: %s (was %s)", findingLabel(f), f.Severity),
				Previous:    findingLabel(f),
			})
		}
	}

	return deltas
}

// emitDriftAlerts logs drift deltas as alert events in the audit store.
func (w *InstallWatcher) emitDriftAlerts(evt InstallEvent, deltas []DriftDelta) {
	maxSev := "INFO"
	for _, d := range deltas {
		if audit.SeverityRank(d.Severity) > audit.SeverityRank(maxSev) {
			maxSev = d.Severity
		}
	}

	summary := summarizeDrift(deltas)
	detailsJSON, _ := json.Marshal(deltas)

	fmt.Fprintf(os.Stderr, "[rescan] drift detected in %s %s: %s\n", evt.Type, evt.Name, summary)

	event := audit.Event{
		Timestamp: time.Now().UTC(),
		Action:    "drift",
		Target:    evt.Path,
		Actor:     "defenseclaw-rescan",
		Details:   string(detailsJSON),
		Severity:  maxSev,
	}
	if err := w.logger.LogEvent(event); err != nil {
		fmt.Fprintf(os.Stderr, "[rescan] drift alert LogEvent failed for %s: %v\n", evt.Path, err)
	}

	if w.otel != nil {
		w.otel.RecordWatcherEvent(context.Background(), "drift", string(evt.Type))
	}

	if w.webhooks != nil {
		w.webhooks.Dispatch(event)
	}
}

func summarizeDrift(deltas []DriftDelta) string {
	counts := make(map[DriftType]int)
	for _, d := range deltas {
		counts[d.Type]++
	}

	var parts []string
	types := make([]DriftType, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return string(types[i]) < string(types[j]) })

	for _, t := range types {
		parts = append(parts, fmt.Sprintf("%s=%d", t, counts[t]))
	}
	return strings.Join(parts, " ")
}

func (w *InstallWatcher) snapshotForEvent(evt InstallEvent) (*TargetSnapshot, error) {
	switch evt.Type {
	case InstallMCP:
		return w.snapshotMCPServer(evt.Name)
	default:
		if _, err := os.Stat(evt.Path); err != nil {
			return nil, err
		}
		return SnapshotTarget(evt.Path)
	}
}

func (w *InstallWatcher) snapshotMCPServer(name string) (*TargetSnapshot, error) {
	entry, err := w.lookupMCPServer(name)
	if err != nil {
		return nil, err
	}

	raw, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshal mcp server %s: %w", name, err)
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])

	snap := &TargetSnapshot{
		ContentHash:      hash,
		DependencyHashes: map[string]string{},
		ConfigHashes: map[string]string{
			fmt.Sprintf("mcp.servers.%s", name): hash,
		},
		Timestamp: time.Now().UTC(),
	}
	if entry.URL != "" {
		snap.NetworkEndpoints = []string{entry.URL}
	}
	return snap, nil
}

func (w *InstallWatcher) lookupMCPServer(name string) (*config.MCPServerEntry, error) {
	servers, err := w.cfg.ReadMCPServers()
	if err != nil {
		return nil, err
	}
	for _, server := range servers {
		if server.Name == name {
			serverCopy := server
			return &serverCopy, nil
		}
	}
	return nil, os.ErrNotExist
}

func (w *InstallWatcher) scanTargetFor(evt InstallEvent) string {
	if evt.Type != InstallMCP {
		return evt.Path
	}
	entry, err := w.lookupMCPServer(evt.Name)
	if err != nil {
		return evt.Name
	}
	if entry.URL != "" {
		return entry.URL
	}
	return entry.Name
}

// persistScanResult stores a scan result in the audit DB and returns the generated scan ID.
func (w *InstallWatcher) persistScanResult(result *scanner.ScanResult) string {
	if result == nil {
		return ""
	}
	scanID := uuid.New().String()
	raw, _ := result.JSON()
	err := w.store.InsertScanResult(
		scanID, result.Scanner, result.Target, result.Timestamp,
		result.Duration.Milliseconds(), len(result.Findings),
		string(result.MaxSeverity()), string(raw),
	)
	if err != nil {
		return ""
	}
	return scanID
}
