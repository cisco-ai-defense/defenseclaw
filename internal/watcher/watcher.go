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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// InstallType distinguishes between skill and MCP install events.
type InstallType string

const (
	InstallSkill  InstallType = "skill"
	InstallMCP    InstallType = "mcp"
	InstallPlugin InstallType = "plugin"
)

// String returns the string representation of the InstallType.
func (t InstallType) String() string { return string(t) }

// InstallEvent is emitted when the watcher detects a new skill or MCP server.
type InstallEvent struct {
	Type InstallType
	Name string
	Path string
	// Connector is the owning connector for this install, used to scope
	// per-connector enforcement on the admit path (most-specific-wins:
	// connector-scoped state, then the bare global state). Empty ⇒ resolve the
	// connector from the watcher config (watcherConnectorName) — preserves the
	// pre-existing global behavior for events that do not tag a connector.
	Connector string
	Timestamp time.Time
}

// Verdict is the outcome of running the admission gate on an install.
type Verdict string

const (
	VerdictBlocked   Verdict = "blocked"
	VerdictAllowed   Verdict = "allowed"
	VerdictClean     Verdict = "clean"
	VerdictRejected  Verdict = "rejected"
	VerdictWarning   Verdict = "warning"
	VerdictScanError Verdict = "scan-error"
)

// AdmissionResult captures the outcome for a single install event.
type AdmissionResult struct {
	Event         InstallEvent
	Verdict       Verdict
	Reason        string
	MaxSeverity   string
	FindingCount  int
	InstallAction string
	FileAction    string
	RuntimeAction string
}

// OnAdmission is called after each install event is processed.
type OnAdmission func(AdmissionResult)

// InstallWatcher monitors OpenClaw skill directories for new installs
// and runs the admission gate (block → allow → scan) on each detection.
// MCP servers are managed via “defenseclaw mcp set/unset“ rather than
// filesystem watching.
// WebhookDispatcher is implemented by gateway.WebhookDispatcher. Declared as
// an interface here to avoid an import cycle (watcher → gateway).
type WebhookDispatcher interface {
	Dispatch(event audit.Event)
}

type InstallWatcher struct {
	cfg        *config.Config
	skillDirs  []string
	pluginDirs []string
	store      *audit.Store
	logger     *audit.Logger
	shell      *sandbox.OpenShell
	opa        *policy.Engine
	webhooks   WebhookDispatcher
	debounce   time.Duration
	onAdmit    OnAdmission

	mu      sync.Mutex
	pending map[string]time.Time // path → first-seen, for debounce

	observabilityV8Mu sync.RWMutex
	observabilityV8   ObservabilityV8Runtime

	policyFileMu     sync.Mutex
	policyFileHashes map[string]string   // path → sha256 hex of file contents (policy / list YAML watch)
	policyListSnap   map[string][]string // path → sorted rule keys for list YAML diffs

	// scannerFactory resolves the scanner for an event. Defaults to
	// scannerFor; tests inject a fake to observe scan invocations without
	// shelling out to the real scanner binaries.
	scannerFactory func(InstallEvent) scanner.Scanner
}

// newScanner resolves the scanner for evt via the injectable factory, falling
// back to the config-driven scannerFor when no factory is installed.
func (w *InstallWatcher) newScanner(evt InstallEvent) scanner.Scanner {
	if w.scannerFactory != nil {
		return w.scannerFactory(evt)
	}
	return w.scannerFor(evt)
}

// New creates an InstallWatcher. The opa parameter may be nil to fall back
// to the built-in Go admission logic. Watcher observability is exclusively
// emitted through the audit logger's generated v8 runtime.
func New(cfg *config.Config, skillDirs, pluginDirs []string, store *audit.Store, logger *audit.Logger, shell *sandbox.OpenShell, opa *policy.Engine, onAdmit OnAdmission) *InstallWatcher {
	debounce := time.Duration(cfg.Watch.DebounceMs) * time.Millisecond
	if debounce <= 0 {
		debounce = 500 * time.Millisecond
	}
	return &InstallWatcher{
		cfg:              cfg,
		skillDirs:        skillDirs,
		pluginDirs:       pluginDirs,
		store:            store,
		logger:           logger,
		shell:            shell,
		opa:              opa,
		debounce:         debounce,
		onAdmit:          onAdmit,
		pending:          make(map[string]time.Time),
		policyFileHashes: make(map[string]string),
		policyListSnap:   make(map[string][]string),
	}
}

// SetWebhookDispatcher attaches a webhook dispatcher for outbound notifications.
func (w *InstallWatcher) SetWebhookDispatcher(d WebhookDispatcher) {
	w.webhooks = d
}

// Run starts watching configured directories. It blocks until ctx is cancelled.
func (w *InstallWatcher) Run(ctx context.Context) error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watcher: create fsnotify watcher: %w", err)
	}
	defer fsw.Close()

	watched := 0
	for _, dir := range w.skillDirs {
		if err := ensureAndWatch(fsw, dir); err != nil {
			fmt.Fprintf(os.Stderr, "[watch] skill dir %s: %v (skipping)\n", dir, err)
			continue
		}
		watched++
		fmt.Printf("[watch] monitoring skill dir: %s\n", dir)
	}
	for _, dir := range w.pluginDirs {
		if err := ensureAndWatch(fsw, dir); err != nil {
			fmt.Fprintf(os.Stderr, "[watch] plugin dir %s: %v (skipping)\n", dir, err)
			continue
		}
		watched++
		fmt.Printf("[watch] monitoring plugin dir: %s\n", dir)
	}

	if watched == 0 {
		return fmt.Errorf("watcher: no directories to watch — check claw.mode and claw.home_dir")
	}

	_ = w.logger.LogAction(string(audit.ActionWatchStart), "", fmt.Sprintf("dirs=%d debounce=%s", watched, w.debounce))

	go w.watchPolicyListsAndYAML(ctx)

	if w.cfg.Watch.RescanEnabled {
		go w.rescanLoop(ctx)
	}

	ticker := time.NewTicker(w.debounce)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = w.logger.LogAction(string(audit.ActionWatchStop), "", "context cancelled")
			return ctx.Err()

		case event, ok := <-fsw.Events:
			if !ok {
				return nil
			}
			if event.Op&(fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			if !w.isDirectChildDir(event.Name) {
				continue
			}
			evtType := "create"
			if event.Op&fsnotify.Rename != 0 {
				evtType = "rename"
			}
			w.recordWatcherEvent(ctx, evtType, w.classifyEvent(event.Name).Type.String(), "")
			w.mu.Lock()
			if _, exists := w.pending[event.Name]; !exists {
				w.pending[event.Name] = time.Now()
			}
			w.mu.Unlock()

		case err, ok := <-fsw.Errors:
			if !ok {
				return nil
			}
			w.recordWatcherError(ctx)
			fmt.Fprintf(os.Stderr, "[watch] fsnotify error: %v\n", err)

		case <-ticker.C:
			w.processPending(ctx)
		}
	}
}

func (w *InstallWatcher) processPending(ctx context.Context) {
	w.mu.Lock()
	now := time.Now()
	var ready []string
	for path, firstSeen := range w.pending {
		if now.Sub(firstSeen) >= w.debounce {
			ready = append(ready, path)
		}
	}
	for _, p := range ready {
		delete(w.pending, p)
	}
	w.mu.Unlock()

	for _, path := range ready {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		evt := w.classifyEvent(path)
		result := w.runAdmission(ctx, evt)
		if w.onAdmit != nil {
			w.onAdmit(result)
		}
	}
}

func (w *InstallWatcher) classifyEvent(path string) InstallEvent {
	installType := InstallSkill
	pathAbs, _ := filepath.Abs(path)
	for _, dir := range w.pluginDirs {
		abs, _ := filepath.Abs(dir)
		if strings.HasPrefix(pathAbs, abs) {
			installType = InstallPlugin
			break
		}
	}

	return InstallEvent{
		Type:      installType,
		Name:      filepath.Base(path),
		Path:      path,
		Connector: watcherConnectorName(w.cfg),
		Timestamp: time.Now().UTC(),
	}
}

// eventConnector resolves the connector that owns an install event: the
// connector tagged on the event when present, otherwise the watcher's own
// connector (watcherConnectorName). This keeps the admit path correct for
// events that do not carry a Connector (e.g. the rescan enumerator), which
// previously always resolved via watcherConnectorName.
func (w *InstallWatcher) eventConnector(evt InstallEvent) string {
	if c := strings.TrimSpace(evt.Connector); c != "" {
		return c
	}
	return watcherConnectorName(w.cfg)
}

// runAdmission applies the full admission gate: block → allow → scan.
// When the OPA engine is available it delegates the verdict decision to
// Rego policy; otherwise it falls back to the built-in Go logic.
func (w *InstallWatcher) runAdmission(ctx context.Context, evt InstallEvent) (res AdmissionResult) {
	pe := enforce.NewPolicyEngine(w.store)
	targetType := string(evt.Type)
	policyID := enforce.PolicyStableID(w.cfg.PolicyDir)
	ctx, admissionTrace := w.startAdmissionTraceV8(ctx, evt, targetType, policyID)
	// SLO timer: measure watcher-detection → admission-decision wall
	// time so every run feeds defenseclaw.slo.block.latency. Blocked
	// verdicts drive the <2000ms SLO dashboard; allowed/clean still
	// populate the histogram so operators can compare distributions.
	admissionStart := time.Now()
	defer func() {
		_ = admissionTrace.end(res)
		w.recordBlockSLO(ctx, targetType, float64(time.Since(admissionStart).Milliseconds()))
	}()

	w.logAssetDiscovered(
		ctx, evt,
		fmt.Sprintf("type=%s name=%s", targetType, evt.Name), "detected",
	)

	// Avarice F-2867: an explicit operator allow that recorded a
	// source_path MUST NOT auto-allow a different on-disk asset
	// just because it presents the same target name. We consult
	// the stored entry first; if its source_path differs from
	// evt.Path we drop the allow and force a fresh scan/decision.
	if existing, _ := pe.GetAction(targetType, evt.Name); existing != nil {
		if existing.Actions.Install == "allow" && existing.SourcePath != "" && existing.SourcePath != evt.Path {
			_ = w.logger.LogAction("install-allow-path-mismatch", evt.Path,
				fmt.Sprintf("type=%s name=%s allowed_path=%q presented_path=%q (F-2867)",
					targetType, evt.Name, existing.SourcePath, evt.Path))
			w.enforceBlock(ctx, evt)
			w.recordAdmission(ctx, "blocked", targetType)
			res = AdmissionResult{
				Event:   evt,
				Verdict: VerdictBlocked,
				Reason:  "allow entry pinned to different source_path; failing closed (F-2867)",
			}
			return res
		}
	}

	// Build block/allow lists from the SQLite store for the OPA input.
	blockList := w.buildListEntries(pe, "block")
	allowList := w.buildListEntries(pe, "allow")
	fallbackProfile := policy.LoadFallbackProfile(w.cfg.PolicyDir)

	assetDecision := w.cfg.EvaluateAssetPolicy(config.AssetPolicyInput{
		TargetType:     targetType,
		Name:           evt.Name,
		Connector:      w.eventConnector(evt),
		SourcePath:     evt.Path,
		RuntimeSurface: "watcher",
	})
	if assetDecision.Enabled && assetDecision.RawAction == "block" {
		if assetDecision.Action == "block" {
			_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
				fmt.Sprintf("type=%s reason=%s source=%s", targetType, assetDecision.Reason, assetDecision.Source))
			w.enforceBlock(ctx, evt)
			w.recordAdmission(ctx, "blocked", targetType)
			res = AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: assetDecision.Reason}
			return res
		}
	}

	// Phase 1: pre-scan OPA evaluation (no scan_result yet).
	if w.opa != nil {
		input := policy.AdmissionInput{
			TargetType: targetType,
			TargetName: evt.Name,
			Path:       evt.Path,
			BlockList:  blockList,
			AllowList:  allowList,
		}
		out, err := w.opa.Evaluate(ctx, input)
		if err == nil {
			switch out.Verdict {
			case "blocked":
				_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
					fmt.Sprintf("type=%s reason=blocked", targetType))
				w.enforceBlock(ctx, evt)
				w.recordAdmission(ctx, "blocked", targetType)
				res = AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: out.Reason}
				return res
			case "rejected":
				_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
					fmt.Sprintf("type=%s reason=policy-rejected", targetType))
				w.enforceBlock(ctx, evt)
				w.recordAdmission(ctx, "rejected", targetType)
				res = AdmissionResult{Event: evt, Verdict: VerdictRejected, Reason: out.Reason}
				return res
			case "allowed":
				_ = w.logger.LogAction(string(audit.ActionInstallAllowed), evt.Path,
					fmt.Sprintf("type=%s reason=allow-listed", targetType))
				w.recordAdmission(ctx, "allowed", targetType)
				res = AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: out.Reason}
				return res
			}
			// verdict == "scan" → proceed to scanning below
		}
		// On OPA error, fall back to the built-in pre-scan gate so explicit
		// block/allow semantics still hold even when Rego is unavailable.
		fallbackOut := policy.EvaluateAdmissionFallback(input, fallbackProfile)
		switch fallbackOut.Verdict {
		case "blocked":
			_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
				fmt.Sprintf("type=%s reason=blocked", targetType))
			w.enforceBlock(ctx, evt)
			w.recordAdmission(ctx, "blocked", targetType)
			res = AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: fallbackOut.Reason}
			return res
		case "allowed":
			_ = w.logger.LogAction(string(audit.ActionInstallAllowed), evt.Path,
				fmt.Sprintf("type=%s reason=allow-listed", targetType))
			w.recordAdmission(ctx, "allowed", targetType)
			res = AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: fallbackOut.Reason}
			return res
		}
	} else {
		input := policy.AdmissionInput{
			TargetType: targetType,
			TargetName: evt.Name,
			Path:       evt.Path,
			BlockList:  blockList,
			AllowList:  allowList,
		}
		out := policy.EvaluateAdmissionFallback(input, fallbackProfile)
		switch out.Verdict {
		case "blocked":
			_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
				fmt.Sprintf("type=%s reason=blocked", targetType))
			w.enforceBlock(ctx, evt)
			w.recordAdmission(ctx, "blocked", targetType)
			res = AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: out.Reason}
			return res
		case "allowed":
			_ = w.logger.LogAction(string(audit.ActionInstallAllowed), evt.Path,
				fmt.Sprintf("type=%s reason=allow-listed", targetType))
			w.recordAdmission(ctx, "allowed", targetType)
			res = AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: out.Reason}
			return res
		}
	}

	// Phase 2: Scan.
	s := w.newScanner(evt)
	if s == nil {
		w.recordAdmission(ctx, "scan-error", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictScanError, Reason: "no scanner available"}
		return res
	}

	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	result, err := s.Scan(scanCtx, evt.Path)
	if err != nil {
		_ = w.logger.LogAction(string(audit.ActionInstallScanError), evt.Path,
			fmt.Sprintf("type=%s scanner=%s error=%v", targetType, s.Name(), err))
		w.recordScanError(ctx, s.Name(), targetType, classifyWatcherScanError(err))
		// Avarice F-3187: a scanner error must NOT leave the
		// freshly-detected install in place. The legacy code
		// recorded `scan-error` and returned without quarantine,
		// blocking, or disabling the artifact, so a malicious
		// skill/plugin that crashed its scanner stayed installed.
		// Treat scanner failures as fail-closed: enforce a block
		// (which quarantines + disables per fallback policy) before
		// surfacing the verdict to the sidecar.
		w.enforceBlock(ctx, evt)
		_ = w.logger.LogAction("install-blocked", evt.Path,
			fmt.Sprintf("type=%s reason=scanner-error scanner=%s (F-3187)",
				targetType, s.Name()))
		w.recordAdmission(ctx, "scan-error", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictBlocked,
			Reason:        fmt.Sprintf("scanner failure (fail-closed): %v", err),
			InstallAction: "block",
		}
		return res
	}

	// Manual block/allow entries should win even if they were added while the
	// scan was running.
	if blocked, bErr := pe.IsBlocked(targetType, evt.Name); bErr == nil && blocked {
		reason := fmt.Sprintf("%s %q is on the block list — rejected", targetType, evt.Name)
		_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
			fmt.Sprintf("type=%s reason=blocked-post-scan", targetType))
		_ = w.logScan(ctx, evt, result, "blocked")
		w.enforceBlock(ctx, evt)
		w.recordAdmission(ctx, "blocked", targetType)
		res = AdmissionResult{
			Event: evt, Verdict: VerdictBlocked, Reason: reason,
			MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
			InstallAction: "block",
		}
		return res
	}
	if allowed, aErr := pe.IsAllowed(targetType, evt.Name); aErr == nil && allowed {
		reason := fmt.Sprintf("scan found findings but %s %q is allow-listed — skipping enforcement", targetType, evt.Name)
		_ = w.logger.LogAction(string(audit.ActionInstallAllowed), evt.Path,
			fmt.Sprintf("type=%s reason=allow-listed-post-scan", targetType))
		_ = w.logScan(ctx, evt, result, "allowed")
		w.recordAdmission(ctx, "allowed", targetType)
		res = AdmissionResult{
			Event: evt, Verdict: VerdictAllowed, Reason: reason,
			MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
			InstallAction: "allow",
		}
		return res
	}

	// Phase 3: post-scan OPA evaluation with scan_result.
	if w.opa != nil {
		scanInput := &policy.ScanResultInput{
			MaxSeverity:   string(result.MaxSeverity()),
			TotalFindings: len(result.Findings),
			ScannerName:   s.Name(),
			Findings:      toFindingInputs(result.Findings),
		}
		input := policy.AdmissionInput{
			TargetType: targetType,
			TargetName: evt.Name,
			Path:       evt.Path,
			BlockList:  blockList,
			AllowList:  allowList,
			ScanResult: scanInput,
		}
		out, evalErr := w.opa.Evaluate(ctx, input)
		if evalErr == nil {
			w.applyPostScanEnforcement(ctx, pe, out, evt, targetType, result, s.Name())
			_ = w.logScan(ctx, evt, result, out.Verdict)
			w.recordAdmission(ctx, out.Verdict, targetType)
			res = AdmissionResult{
				Event: evt, Verdict: toVerdict(out.Verdict), Reason: out.Reason,
				MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
				InstallAction: out.InstallAction,
				FileAction:    out.FileAction,
				RuntimeAction: out.RuntimeAction,
			}
			return res
		}
		// On OPA error, fall through to built-in logic.
	}

	scanInput := &policy.ScanResultInput{
		MaxSeverity:   string(result.MaxSeverity()),
		TotalFindings: len(result.Findings),
		ScannerName:   s.Name(),
		Findings:      toFindingInputs(result.Findings),
	}
	out := policy.EvaluateAdmissionFallback(policy.AdmissionInput{
		TargetType: targetType,
		TargetName: evt.Name,
		Path:       evt.Path,
		BlockList:  blockList,
		AllowList:  allowList,
		ScanResult: scanInput,
	}, fallbackProfile)
	w.applyPostScanEnforcement(ctx, pe, out, evt, targetType, result, s.Name())
	_ = w.logScan(ctx, evt, result, out.Verdict)
	w.recordAdmission(ctx, out.Verdict, targetType)
	res = AdmissionResult{
		Event: evt, Verdict: toVerdict(out.Verdict), Reason: out.Reason,
		MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
		InstallAction: out.InstallAction,
		FileAction:    out.FileAction,
		RuntimeAction: out.RuntimeAction,
	}
	return res
}

// applyPostScanEnforcement takes the OPA verdict after scanning and executes
// the enforcement side-effects (block, quarantine, disable) that OPA cannot
// perform itself. It respects file_action and install_action from OPA output.
//
// Allow-listed items are exempt from auto-enforcement; only a manual block
// can override an allow entry.
func (w *InstallWatcher) applyPostScanEnforcement(ctx context.Context, pe *enforce.PolicyEngine, out *policy.AdmissionOutput, evt InstallEvent, targetType string, result *scanner.ScanResult, scannerName string) {
	// Re-check allow list to guard against races where the item became
	// allowed between the pre-scan check and post-scan enforcement.
	if allowed, err := pe.IsAllowed(targetType, evt.Name); err == nil && allowed {
		_ = w.logger.LogAction(string(audit.ActionInstallAllowedSkipEnforce), evt.Path,
			fmt.Sprintf("type=%s %s is allow-listed — skipping auto-enforcement", targetType, evt.Name))
		return
	}

	switch out.Verdict {
	case "clean":
		_ = w.logger.LogAction(string(audit.ActionInstallClean), evt.Path,
			fmt.Sprintf("type=%s scanner=%s", targetType, scannerName))
	case "rejected":
		_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
			fmt.Sprintf("type=%s severity=%s scanner=%s install_action=%s file_action=%s",
				targetType, result.MaxSeverity(), scannerName, out.InstallAction, out.FileAction))

		if w.takeActionFor(evt) {
			blockReason := fmt.Sprintf("auto-block: watch detected %s findings (scanner=%s)", result.MaxSeverity(), scannerName)

			installAction := coalesce(out.InstallAction, "block")
			runtimeAction := coalesce(out.RuntimeAction, "allow")
			fileAction := coalesce(out.FileAction, "none")

			if installAction == "block" {
				_ = pe.Block(targetType, evt.Name, blockReason)
			}
			pe.SetSourcePath(targetType, evt.Name, evt.Path)

			enforcement := map[string]string{
				"source_path": evt.Path,
				"install":     installAction,
				"runtime":     runtimeAction,
				"file":        fileAction,
			}

			if fileAction == "quarantine" {
				_ = pe.Quarantine(targetType, evt.Name, blockReason)
			}
			if runtimeAction == "block" {
				_ = pe.Disable(targetType, evt.Name, blockReason)
			}

			_ = w.logger.LogActionWithEnforcement(string(audit.ActionWatcherBlock), evt.Name,
				fmt.Sprintf("type=%s reason=%s", targetType, blockReason), enforcement)

			if fileAction == "quarantine" || runtimeAction == "block" {
				w.enforceBlock(ctx, evt)
			}
		}
	case "warning":
		_ = w.logger.LogAction(string(audit.ActionInstallWarning), evt.Path,
			fmt.Sprintf("type=%s severity=%s scanner=%s", targetType, result.MaxSeverity(), scannerName))
	}
}

func (w *InstallWatcher) logAssetDiscovered(
	ctx context.Context,
	evt InstallEvent,
	details, reason string,
) {
	_ = w.logger.LogAssetDiscoveredCtx(ctx, evt.Path, details, audit.AssetLifecycleInput{
		AssetID: evt.Name, AssetType: string(evt.Type), TargetPath: evt.Path,
		Reason: reason, Initiator: "watcher",
	})
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// buildListEntries queries the SQLite store for block or allow entries.
func (w *InstallWatcher) buildListEntries(pe *enforce.PolicyEngine, action string) []policy.ListEntry {
	var entries []audit.ActionEntry
	var err error
	switch action {
	case "block":
		entries, err = pe.ListBlocked()
	case "allow":
		entries, err = pe.ListAllowed()
	}
	if err != nil || entries == nil {
		return nil
	}
	out := make([]policy.ListEntry, len(entries))
	for i, e := range entries {
		out[i] = policy.ListEntry{
			TargetType: e.TargetType,
			TargetName: e.TargetName,
			Reason:     e.Reason,
		}
	}
	return out
}

func toVerdict(s string) Verdict {
	switch s {
	case "blocked":
		return VerdictBlocked
	case "allowed":
		return VerdictAllowed
	case "clean":
		return VerdictClean
	case "rejected":
		return VerdictRejected
	case "warning":
		return VerdictWarning
	default:
		return VerdictScanError
	}
}

func (w *InstallWatcher) scannerFor(evt InstallEvent) scanner.Scanner {
	// Each scanner kind gets its own resolved LLMConfig so
	// ``scanners.{skill,mcp}.llm`` overrides layered on top of the
	// global ``llm:`` block take effect. Resolving per-event (rather
	// than caching once at watcher startup) means a config reload is
	// picked up automatically on the next install.
	switch evt.Type {
	case InstallSkill:
		return scanner.NewSkillScannerFromLLM(
			w.cfg.Scanners.SkillScanner,
			w.cfg.ResolveLLM("scanners.skill"),
			w.cfg.CiscoAIDefense,
		)
	case InstallMCP:
		return scanner.NewMCPScannerFromLLM(
			w.cfg.Scanners.MCPScanner,
			w.cfg.ResolveLLM("scanners.mcp"),
			w.cfg.CiscoAIDefense,
		)

	case InstallPlugin:
		return scanner.NewPluginScanner(w.cfg.Scanners.PluginScanner)
	default:
		return nil
	}
}

// takeActionFor returns whether enforcement actions should be applied for the
// given event type, using the per-type gateway watcher config with a fallback
// to the legacy watch.auto_block flag.
func (w *InstallWatcher) takeActionFor(evt InstallEvent) bool {
	switch evt.Type {
	case InstallSkill:
		return w.cfg.Gateway.Watcher.Skill.TakeAction
	case InstallPlugin:
		return w.cfg.Gateway.Watcher.Plugin.TakeAction
	case InstallMCP:
		return w.cfg.Gateway.Watcher.MCP.TakeAction
	default:
		return w.cfg.Watch.AutoBlock
	}
}

func (w *InstallWatcher) enforceBlock(ctx context.Context, evt InstallEvent) {
	switch evt.Type {
	case InstallMCP:
		me := enforce.NewMCPEnforcer(w.shell)
		_ = me.BlockEndpoint(evt.Name)
	case InstallSkill, InstallPlugin:
		w.quarantineAsset(ctx, evt)
	}
}

func (w *InstallWatcher) quarantineAsset(ctx context.Context, evt InstallEvent) {
	if w == nil || w.cfg == nil || w.store == nil {
		w.emitQuarantineFailure(ctx, evt.Path, fmt.Errorf("watcher: quarantine provenance store is unavailable"))
		return
	}
	if w.preserveRestoredBlockedAsset(evt) {
		_ = w.logger.LogAction(string(audit.ActionWatcherBlock), evt.Path,
			fmt.Sprintf("type=%s restored physical files retained while install block remains", evt.Type))
		return
	}
	connector := w.eventConnector(evt)
	plan, err := enforce.NewAssetQuarantinePlan(
		w.cfg.QuarantineDir, w.sourceRootsFor(evt.Type), evt.Type.String(),
		evt.Name, connector, evt.Path,
	)
	if err != nil {
		w.emitQuarantineFailure(ctx, evt.Path, err)
		return
	}
	record, err := w.store.CreateQuarantineRecord(ctx, audit.CreateQuarantineRecordInput{
		TargetType: evt.Type.String(), TargetName: evt.Name,
		OriginalPath: plan.SourcePath, QuarantinePath: plan.QuarantinePath,
		ContentHash: plan.ContentHash, Reason: "watcher enforcement",
		State: audit.QuarantineStatePending, OwnershipJSON: plan.OwnershipJSON,
		// The physical owner and global action scope are committed together so
		// either Go or Python restore clears the exact logical file decision.
		Connectors: []string{connector, ""},
	})
	if err != nil {
		w.emitQuarantineFailure(ctx, evt.Path, err)
		return
	}
	if record.State == audit.QuarantineStateRestoring &&
		sameWatcherPath(record.RestorePath, plan.SourcePath) {
		matches, hashErr := enforce.AssetContentHashMatches(plan.SourcePath, record.ContentHash)
		if hashErr == nil && matches {
			_ = w.logger.LogAction(string(audit.ActionWatcherBlock), evt.Path,
				fmt.Sprintf("type=%s restore in progress; physical files retained", evt.Type))
			return
		}
	}
	if err := enforce.ExecuteAssetQuarantine(plan, record.ID); err != nil {
		// Roll back only an unmaterialized journal. A verified destination is
		// authoritative recovery data and must retain its pending provenance.
		if _, statErr := os.Lstat(plan.QuarantinePath); os.IsNotExist(statErr) {
			_ = w.store.DeleteQuarantineRecord(ctx, record.ID)
		}
		w.emitQuarantineFailure(ctx, evt.Path, err)
		return
	}
	if err := w.store.UpdateQuarantineRecordState(
		ctx, record.ID, audit.QuarantineStateActive, "",
	); err != nil {
		// The pending write-ahead record is intentionally retained and can be
		// finalized or restored after restart.
		fmt.Fprintf(os.Stderr, "[watch] quarantine provenance remains pending for %s: %v\n", evt.Path, err)
	}
	w.recordQuarantineAudit(ctx, audit.ActionQuarantine, evt, plan.QuarantinePath)
}

// RestoreQuarantined restores one connector-owned watcher quarantine. The
// physical file action is cleared transactionally at completion, while an
// install block or runtime disable remains intact.
func (w *InstallWatcher) RestoreQuarantined(
	ctx context.Context,
	targetType, targetName, connector, restorePath string,
) error {
	if w == nil || w.cfg == nil || w.store == nil {
		return fmt.Errorf("watcher: quarantine provenance store is unavailable")
	}
	if ctx == nil {
		return fmt.Errorf("watcher: restore context is required")
	}
	targetType = strings.TrimSpace(targetType)
	targetName = strings.TrimSpace(targetName)
	connector = strings.TrimSpace(connector)
	if targetType != InstallSkill.String() && targetType != InstallPlugin.String() {
		return fmt.Errorf("watcher: unsupported restore target type %q", targetType)
	}
	records, err := w.store.ListQuarantineRecordsForConnector(
		ctx, targetType, targetName, connector,
	)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return fmt.Errorf("watcher: %s %q is not quarantined for connector %q", targetType, targetName, connector)
	}
	if len(records) != 1 {
		return fmt.Errorf("watcher: restore is ambiguous for %s %q connector %q", targetType, targetName, connector)
	}
	record := records[0]
	requestedRestorePath := strings.TrimSpace(restorePath)
	boundRestorePath := strings.TrimSpace(record.RestorePath)
	if record.State == audit.QuarantineStateRestoring && boundRestorePath != "" {
		if requestedRestorePath == "" {
			restorePath = boundRestorePath
		} else if !sameWatcherPath(requestedRestorePath, boundRestorePath) {
			return fmt.Errorf(
				"watcher: explicit restore path does not match durable restoring destination",
			)
		} else {
			restorePath = requestedRestorePath
		}
	} else if requestedRestorePath == "" {
		restorePath = record.OriginalPath
	} else {
		restorePath = requestedRestorePath
	}
	if err := w.store.UpdateQuarantineRecordState(
		ctx, record.ID, audit.QuarantineStateRestoring, restorePath,
	); err != nil {
		return fmt.Errorf("watcher: journal quarantine restore: %w", err)
	}
	plan := enforce.AssetRestorePlan{
		RecordID: record.ID, TargetType: record.TargetType, TargetName: record.TargetName,
		QuarantineRoot: w.cfg.QuarantineDir, QuarantinePath: record.QuarantinePath,
		RestorePath: restorePath, AllowedRoots: w.sourceRootsFor(InstallType(record.TargetType)),
		ContentHash: record.ContentHash,
	}
	if err := enforce.ExecuteAssetRestore(plan); err != nil {
		if matches, matchErr := enforce.AssetContentHashMatches(
			record.QuarantinePath, record.ContentHash,
		); matchErr == nil && matches {
			_ = w.store.UpdateQuarantineRecordState(
				ctx, record.ID, audit.QuarantineStateActive, "",
			)
		}
		if w.logger != nil {
			_ = w.logger.RecordQuarantineActionMetric(ctx, "move_out", "error")
		}
		return fmt.Errorf("watcher: restore quarantined asset: %w", err)
	}
	if err := w.store.CompleteQuarantineRestore(ctx, record.ID, restorePath); err != nil {
		return fmt.Errorf("watcher: finalize quarantine restore: %w", err)
	}
	if w.logger != nil {
		_ = w.logger.RecordQuarantineActionMetric(ctx, "move_out", "ok")
		w.recordQuarantineAudit(ctx, audit.ActionRestore, InstallEvent{
			Type: InstallType(targetType), Name: targetName, Path: restorePath,
			Connector: connector, Timestamp: time.Now().UTC(),
		}, restorePath)
	}
	return nil
}

func (w *InstallWatcher) sourceRootsFor(targetType InstallType) []string {
	switch targetType {
	case InstallSkill:
		return w.skillDirs
	case InstallPlugin:
		return w.pluginDirs
	default:
		return nil
	}
}

func (w *InstallWatcher) preserveRestoredBlockedAsset(evt InstallEvent) bool {
	if w == nil || w.store == nil {
		return false
	}
	connector := w.eventConnector(evt)
	pe := enforce.NewPolicyEngine(w.store)
	blocked, err := pe.IsBlockedForConnector(evt.Type.String(), evt.Name, connector)
	if err != nil || !blocked {
		return false
	}
	connectors := []string{connector}
	if connector != "" {
		connectors = append(connectors, "")
	}
	for _, scope := range connectors {
		entry, err := w.store.GetActionForConnector(evt.Type.String(), evt.Name, scope)
		if err != nil || entry == nil {
			continue
		}
		if entry.Actions.File == "" && entry.SourcePath != "" &&
			sameWatcherPath(entry.SourcePath, evt.Path) {
			return true
		}
	}
	return false
}

func sameWatcherPath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(strings.TrimSpace(left))
	rightAbs, rightErr := filepath.Abs(strings.TrimSpace(right))
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftAbs = filepath.Clean(leftAbs)
	rightAbs = filepath.Clean(rightAbs)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(leftAbs, rightAbs)
	}
	return leftAbs == rightAbs
}

func (w *InstallWatcher) emitQuarantineFailure(ctx context.Context, path string, err error) {
	if w != nil && w.logger != nil {
		_ = w.logger.RecordQuarantineActionMetric(ctx, "move_in", "error")
	}
	fmt.Fprintf(os.Stderr, "[watch] quarantine %s: %v\n", path, err)
}

func (w *InstallWatcher) recordQuarantineAudit(ctx context.Context, action audit.Action, evt InstallEvent, destPath string) {
	event := audit.Event{
		Action:   string(action),
		Target:   evt.Path,
		Actor:    "defenseclaw",
		Details:  fmt.Sprintf("dest=%s", destPath),
		Severity: "INFO",
	}
	if action != audit.ActionQuarantine {
		_ = w.logger.LogEventCtx(ctx, event)
		return
	}
	_ = w.logger.LogEnforcementQuarantineApplied(ctx, event, audit.EnforcementQuarantineAppliedInput{
		EnforcementID:   uuid.NewString(),
		RequestedAction: "quarantine",
		EffectiveAction: "quarantine",
		Initiator:       "defenseclaw",
		ResultingState:  "quarantined",
		AssetID:         evt.Name,
		AssetType:       evt.Type.String(),
		SourcePath:      evt.Path,
		DestinationPath: destPath,
	})
}

// isDirectChildDir returns true if path is a directory and a direct child
// of one of the watched skill or MCP directories. Files and nested
// subdirectories inside a skill are ignored — a skill is always a top-level
// directory under a skill dir.
func (w *InstallWatcher) isDirectChildDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}

	parent := filepath.Dir(path)
	parentAbs, _ := filepath.Abs(parent)

	for _, dir := range w.skillDirs {
		dirAbs, _ := filepath.Abs(dir)
		if parentAbs == dirAbs {
			return true
		}
	}
	for _, dir := range w.pluginDirs {
		dirAbs, _ := filepath.Abs(dir)
		if parentAbs == dirAbs {
			return true
		}
	}
	return false
}

func (w *InstallWatcher) recordAdmission(ctx context.Context, decision, targetType string) {
	if w != nil && w.logger != nil {
		_ = w.logger.RecordAdmissionDecisionMetric(ctx, decision, targetType, "watcher")
	}
}

func (w *InstallWatcher) recordWatcherEvent(
	ctx context.Context,
	eventType, targetType, connector string,
) {
	if w != nil && w.logger != nil {
		_ = w.logger.RecordWatcherEventMetric(ctx, eventType, targetType, connector)
	}
}

func (w *InstallWatcher) recordWatcherError(ctx context.Context) {
	if w != nil && w.logger != nil {
		_ = w.logger.RecordWatcherErrorMetric(ctx)
	}
}

func (w *InstallWatcher) recordBlockSLO(ctx context.Context, targetType string, latencyMS float64) {
	if w != nil && w.logger != nil {
		_ = w.logger.RecordBlockSLOMetric(ctx, targetType, latencyMS)
	}
}

func (w *InstallWatcher) recordScanError(
	ctx context.Context,
	scannerName, targetType, errorType string,
) {
	if w != nil && w.logger != nil {
		_ = w.logger.RecordWatcherScanErrorMetric(ctx, scannerName, targetType, errorType)
	}
}

func (w *InstallWatcher) logScan(
	ctx context.Context,
	evt InstallEvent,
	result *scanner.ScanResult,
	verdict string,
) error {
	if w == nil || w.logger == nil {
		return fmt.Errorf("watcher: v8 scan logger is unavailable")
	}
	return w.logger.LogScanWithCorrelation(
		ctx, result, verdict,
		watcherScanCorrelation(ctx, "", w.eventConnector(evt)),
	)
}

func watcherScanCorrelation(
	ctx context.Context,
	runID, connector string,
) audit.ScanCorrelation {
	envelope := audit.EnvelopeFromContext(ctx)
	if runID == "" {
		runID = envelope.RunID
	}
	correlation := audit.ScanCorrelation{
		RunID: runID, RequestID: envelope.RequestID, SessionID: envelope.SessionID,
		TraceID: envelope.TraceID, AgentID: envelope.AgentID, AgentName: envelope.AgentName,
		AgentInstanceID: envelope.AgentInstanceID, Connector: connector,
		EvaluationID: watcherAdmissionEvaluationID(ctx),
	}
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.IsValid() {
		if correlation.TraceID == "" {
			correlation.TraceID = spanContext.TraceID().String()
			correlation.SpanID = spanContext.SpanID().String()
		}
		if correlation.TraceID == spanContext.TraceID().String() && correlation.SpanID == "" {
			correlation.SpanID = spanContext.SpanID().String()
		}
	}
	return correlation
}

func watcherConnectorName(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	if strings.TrimSpace(cfg.Guardrail.Connector) != "" {
		return strings.ToLower(strings.TrimSpace(cfg.Guardrail.Connector))
	}
	return strings.ToLower(strings.TrimSpace(string(cfg.Claw.Mode)))
}

func classifyWatcherScanError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found") || strings.Contains(msg, "executable file not found"):
		return "not_found"
	case strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "timeout"):
		return "timeout"
	case strings.Contains(msg, "parse") || strings.Contains(msg, "unmarshal") || strings.Contains(msg, "json"):
		return "parse"
	default:
		return "crash"
	}
}

func toFindingInputs(findings []scanner.Finding) []policy.FindingInput {
	if len(findings) == 0 {
		return nil
	}
	out := make([]policy.FindingInput, 0, len(findings))
	for _, f := range findings {
		out = append(out, policy.FindingInput{
			Severity: string(f.Severity),
			Scanner:  f.Scanner,
			Title:    f.Title,
		})
	}
	return out
}

func ensureAndWatch(fsw *fsnotify.Watcher, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	if err := fsw.Add(dir); err != nil {
		return fmt.Errorf("watch: %w", err)
	}

	return nil
}
