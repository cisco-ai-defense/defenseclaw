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
	"database/sql"
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

// rescanLoop runs periodic re-scans of all installed skills and MCPs,
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

	running := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if running {
				fmt.Fprintf(os.Stderr, "[rescan] previous cycle still running, skipping\n")
				timer.Reset(interval)
				continue
			}
			running = true
			w.runRescanCycle(ctx)
			running = false
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

// enumerateTargets lists all direct child directories under watched roots.
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

	return targets
}

// rescanTarget scans a single target, compares with baseline, and emits drift alerts.
func (w *InstallWatcher) rescanTarget(ctx context.Context, evt InstallEvent) {
	if _, err := os.Stat(evt.Path); os.IsNotExist(err) {
		return
	}

	currentSnap, err := SnapshotTarget(evt.Path)
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

	// Run scanner and compare findings against last stored scan.
	scanDeltas := w.compareScanResults(ctx, evt)
	deltas = append(deltas, scanDeltas...)

	if len(deltas) == 0 {
		return
	}

	w.emitDriftAlerts(evt, deltas)
	w.storeBaseline(ctx, evt, currentSnap)
}

// storeBaseline runs a scan and persists the snapshot as the new baseline.
func (w *InstallWatcher) storeBaseline(ctx context.Context, evt InstallEvent, snap *TargetSnapshot) {
	s := w.scannerFor(evt)
	scanID := ""
	if s != nil {
		scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()

		result, err := s.Scan(scanCtx, evt.Path)
		if err == nil && result != nil {
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

// compareScanResults runs a fresh scan and diffs findings against the last stored scan.
func (w *InstallWatcher) compareScanResults(ctx context.Context, evt InstallEvent) []DriftDelta {
	s := w.scannerFor(evt)
	if s == nil {
		return nil
	}

	baseline, err := w.store.GetTargetSnapshot(string(evt.Type), evt.Path)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			fmt.Fprintf(os.Stderr, "[rescan] compareScanResults: get baseline %s: %v\n", evt.Path, err)
		}
		return nil
	}
	if baseline.ScanID == "" {
		return nil
	}

	prevScan, err := w.loadScanResult(baseline.ScanID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[rescan] compareScanResults: load baseline scan %s: %v\n", baseline.ScanID, err)
		return nil
	}
	if prevScan == nil {
		return nil
	}

	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	current, err := s.Scan(scanCtx, evt.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[rescan] compareScanResults: scan %s: %v\n", evt.Path, err)
		return nil
	}
	if current == nil {
		return nil
	}

	deltas := diffFindings(prevScan.Findings, current.Findings)

	prevMax := string(prevScan.MaxSeverity())
	curMax := string(current.MaxSeverity())
	if severityRank(curMax) > severityRank(prevMax) {
		deltas = append(deltas, DriftDelta{
			Type:        DriftSeverityChange,
			Severity:    curMax,
			Description: fmt.Sprintf("max severity escalated from %s to %s", prevMax, curMax),
			Previous:    prevMax,
			Current:     curMax,
		})
	}

	return deltas
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
			if severityRank(string(f.Severity)) > severityRank(string(prevFinding.Severity)) {
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
		if severityRank(d.Severity) > severityRank(maxSev) {
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
	if err := w.store.LogEvent(event); err != nil {
		fmt.Fprintf(os.Stderr, "[rescan] drift alert LogEvent failed for %s: %v\n", evt.Path, err)
	}

	if w.otel != nil {
		w.otel.RecordWatcherEvent(context.Background(), "drift", string(evt.Type))
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

func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
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
