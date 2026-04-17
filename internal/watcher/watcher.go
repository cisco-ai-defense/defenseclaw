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
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
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
	Type      InstallType
	Name      string
	Path      string
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
	otel       *telemetry.Provider
	webhooks   WebhookDispatcher
	debounce   time.Duration
	onAdmit    OnAdmission

	mu      sync.Mutex
	pending map[string]time.Time // path → first-seen, for debounce
}

// New creates an InstallWatcher. The opa parameter may be nil to fall back
// to the built-in Go admission logic. The otel parameter may be nil when
// telemetry is disabled.
func New(cfg *config.Config, skillDirs, pluginDirs []string, store *audit.Store, logger *audit.Logger, shell *sandbox.OpenShell, opa *policy.Engine, otel *telemetry.Provider, onAdmit OnAdmission) *InstallWatcher {
	debounce := time.Duration(cfg.Watch.DebounceMs) * time.Millisecond
	if debounce <= 0 {
		debounce = 500 * time.Millisecond
	}
	return &InstallWatcher{
		cfg:        cfg,
		skillDirs:  skillDirs,
		pluginDirs: pluginDirs,
		store:      store,
		logger:     logger,
		shell:      shell,
		opa:        opa,
		otel:       otel,
		debounce:   debounce,
		onAdmit:    onAdmit,
		pending:    make(map[string]time.Time),
	}
}

// SetOTelProvider attaches the OTel provider for watcher metrics.
func (w *InstallWatcher) SetOTelProvider(p *telemetry.Provider) {
	w.otel = p
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

	_ = w.logger.LogAction("watch-start", "", fmt.Sprintf("dirs=%d debounce=%s", watched, w.debounce))

	if w.cfg.Watch.RescanEnabled {
		go w.rescanLoop(ctx)
	}

	ticker := time.NewTicker(w.debounce)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = w.logger.LogAction("watch-stop", "", "context cancelled")
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
			if w.otel != nil {
				evtType := "create"
				if event.Op&fsnotify.Rename != 0 {
					evtType = "rename"
				}
				w.otel.RecordWatcherEvent(ctx, evtType, w.classifyEvent(event.Name).Type.String())
			}
			w.mu.Lock()
			if _, exists := w.pending[event.Name]; !exists {
				w.pending[event.Name] = time.Now()
			}
			w.mu.Unlock()

		case err, ok := <-fsw.Errors:
			if !ok {
				return nil
			}
			if w.otel != nil {
				w.otel.RecordWatcherError(ctx)
			}
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
		Timestamp: time.Now().UTC(),
	}
}

// runAdmission applies the full admission gate: block → allow → scan.
// When the OPA engine is available it delegates the verdict decision to
// Rego policy; otherwise it falls back to the built-in Go logic.
func (w *InstallWatcher) runAdmission(ctx context.Context, evt InstallEvent) AdmissionResult {
	pe := enforce.NewPolicyEngine(w.store)
	targetType := string(evt.Type)

	_ = w.logger.LogAction("install-detected", evt.Path,
		fmt.Sprintf("type=%s name=%s", targetType, evt.Name))

	// Build block/allow lists from the SQLite store for the OPA input.
	blockList := w.buildListEntries(pe, "block")
	allowList := w.buildListEntries(pe, "allow")
	fallbackProfile := policy.LoadFallbackProfile(w.cfg.PolicyDir)

	// Phase 1: pre-scan OPA evaluation (no scan_result yet).
	if w.opa != nil {
		input := policy.AdmissionInput{
			TargetType: targetType,
			TargetName: evt.Name,
			Path:       evt.Path,
			BlockList:  blockList,
			AllowList:  allowList,
		}
		preScanStart := time.Now()
		out, err := w.opa.Evaluate(ctx, input)
		if err == nil {
			if w.otel != nil {
				w.otel.EndPolicySpan(nil, "admission", out.Verdict, out.Reason, preScanStart)
			}
			switch out.Verdict {
			case "blocked":
				_ = w.logger.LogAction("install-rejected", evt.Path,
					fmt.Sprintf("type=%s reason=blocked", targetType))
				if w.otel != nil {
					w.otel.EmitPolicyDecision("admission", "blocked", evt.Name, targetType, out.Reason, nil)
				}
				w.enforceBlock(evt)
				w.recordAdmission(ctx, "blocked", targetType)
				return AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: out.Reason}
			case "allowed":
				_ = w.logger.LogAction("install-allowed", evt.Path,
					fmt.Sprintf("type=%s reason=allow-listed", targetType))
				w.recordAdmission(ctx, "allowed", targetType)
				return AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: out.Reason}
			}
			// verdict == "scan" → proceed to scanning below
		}
		// On OPA error, fall back to the built-in pre-scan gate so explicit
		// block/allow semantics still hold even when Rego is unavailable.
		fallbackOut := policy.EvaluateAdmissionFallback(input, fallbackProfile)
		switch fallbackOut.Verdict {
		case "blocked":
			_ = w.logger.LogAction("install-rejected", evt.Path,
				fmt.Sprintf("type=%s reason=blocked", targetType))
			w.enforceBlock(evt)
			w.recordAdmission(ctx, "blocked", targetType)
			return AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: fallbackOut.Reason}
		case "allowed":
			_ = w.logger.LogAction("install-allowed", evt.Path,
				fmt.Sprintf("type=%s reason=allow-listed", targetType))
			w.recordAdmission(ctx, "allowed", targetType)
			return AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: fallbackOut.Reason}
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
			_ = w.logger.LogAction("install-rejected", evt.Path,
				fmt.Sprintf("type=%s reason=blocked", targetType))
			w.enforceBlock(evt)
			w.recordAdmission(ctx, "blocked", targetType)
			return AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: out.Reason}
		case "allowed":
			_ = w.logger.LogAction("install-allowed", evt.Path,
				fmt.Sprintf("type=%s reason=allow-listed", targetType))
			w.recordAdmission(ctx, "allowed", targetType)
			return AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: out.Reason}
		}
	}

	// Phase 2: Scan.
	s := w.scannerFor(evt)
	if s == nil {
		w.recordAdmission(ctx, "scan-error", targetType)
		return AdmissionResult{Event: evt, Verdict: VerdictScanError, Reason: "no scanner available"}
	}

	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	result, err := s.Scan(scanCtx, evt.Path)
	if err != nil {
		_ = w.logger.LogAction("install-scan-error", evt.Path,
			fmt.Sprintf("type=%s scanner=%s error=%v", targetType, s.Name(), err))
		if w.otel != nil {
			w.otel.RecordScanError(ctx, s.Name(), targetType, classifyWatcherScanError(err))
		}
		w.recordAdmission(ctx, "scan-error", targetType)
		return AdmissionResult{Event: evt, Verdict: VerdictScanError, Reason: err.Error()}
	}

	// Manual block/allow entries should win even if they were added while the
	// scan was running.
	if blocked, bErr := pe.IsBlocked(targetType, evt.Name); bErr == nil && blocked {
		reason := fmt.Sprintf("%s %q is on the block list — rejected", targetType, evt.Name)
		_ = w.logger.LogAction("install-rejected", evt.Path,
			fmt.Sprintf("type=%s reason=blocked-post-scan", targetType))
		_ = w.logger.LogScanWithVerdict(result, "blocked")
		w.enforceBlock(evt)
		w.recordAdmission(ctx, "blocked", targetType)
		return AdmissionResult{
			Event: evt, Verdict: VerdictBlocked, Reason: reason,
			MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
			InstallAction: "block",
		}
	}
	if allowed, aErr := pe.IsAllowed(targetType, evt.Name); aErr == nil && allowed {
		reason := fmt.Sprintf("scan found findings but %s %q is allow-listed — skipping enforcement", targetType, evt.Name)
		_ = w.logger.LogAction("install-allowed", evt.Path,
			fmt.Sprintf("type=%s reason=allow-listed-post-scan", targetType))
		_ = w.logger.LogScanWithVerdict(result, "allowed")
		w.recordAdmission(ctx, "allowed", targetType)
		return AdmissionResult{
			Event: evt, Verdict: VerdictAllowed, Reason: reason,
			MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
			InstallAction: "allow",
		}
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
		postScanStart := time.Now()
		out, evalErr := w.opa.Evaluate(ctx, input)
		if evalErr == nil {
			if w.otel != nil {
				w.otel.EndPolicySpan(nil, "admission", out.Verdict, out.Reason, postScanStart)
				if out.Verdict == "rejected" || out.Verdict == "blocked" {
					w.otel.EmitPolicyDecision("admission", out.Verdict, evt.Name, targetType, out.Reason, map[string]string{
						"scanner":      s.Name(),
						"max_severity": string(result.MaxSeverity()),
					})
				}
			}
			w.applyPostScanEnforcement(pe, out, evt, targetType, result, s.Name())
			_ = w.logger.LogScanWithVerdict(result, out.Verdict)
			w.recordAdmission(ctx, out.Verdict, targetType)
			return AdmissionResult{
				Event: evt, Verdict: toVerdict(out.Verdict), Reason: out.Reason,
				MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
				InstallAction: out.InstallAction,
				FileAction:    out.FileAction,
				RuntimeAction: out.RuntimeAction,
			}
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
	w.applyPostScanEnforcement(pe, out, evt, targetType, result, s.Name())
	_ = w.logger.LogScanWithVerdict(result, out.Verdict)
	w.recordAdmission(ctx, out.Verdict, targetType)
	return AdmissionResult{
		Event: evt, Verdict: toVerdict(out.Verdict), Reason: out.Reason,
		MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
		InstallAction: out.InstallAction,
		FileAction:    out.FileAction,
		RuntimeAction: out.RuntimeAction,
	}
}

// applyPostScanEnforcement takes the OPA verdict after scanning and executes
// the enforcement side-effects (block, quarantine, disable) that OPA cannot
// perform itself. It respects file_action and install_action from OPA output.
//
// Allow-listed items are exempt from auto-enforcement; only a manual block
// can override an allow entry.
func (w *InstallWatcher) applyPostScanEnforcement(pe *enforce.PolicyEngine, out *policy.AdmissionOutput, evt InstallEvent, targetType string, result *scanner.ScanResult, scannerName string) {
	// Re-check allow list to guard against races where the item became
	// allowed between the pre-scan check and post-scan enforcement.
	if allowed, err := pe.IsAllowed(targetType, evt.Name); err == nil && allowed {
		_ = w.logger.LogAction("install-allowed-skip-enforce", evt.Path,
			fmt.Sprintf("type=%s %s is allow-listed — skipping auto-enforcement", targetType, evt.Name))
		return
	}

	switch out.Verdict {
	case "clean":
		_ = w.logger.LogAction("install-clean", evt.Path,
			fmt.Sprintf("type=%s scanner=%s", targetType, scannerName))
	case "rejected":
		_ = w.logger.LogAction("install-rejected", evt.Path,
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

			_ = w.logger.LogActionWithEnforcement("watcher-block", evt.Name,
				fmt.Sprintf("type=%s reason=%s", targetType, blockReason), enforcement)

			if fileAction == "quarantine" || runtimeAction == "block" {
				w.enforceBlock(evt)
			}
		}
	case "warning":
		_ = w.logger.LogAction("install-warning", evt.Path,
			fmt.Sprintf("type=%s severity=%s scanner=%s", targetType, result.MaxSeverity(), scannerName))
	}
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
	llm := w.cfg.EffectiveInspectLLM()
	switch evt.Type {
	case InstallSkill:
		return scanner.NewSkillScanner(w.cfg.Scanners.SkillScanner, llm, w.cfg.CiscoAIDefense)
	case InstallMCP:
		return scanner.NewMCPScanner(w.cfg.Scanners.MCPScanner, llm, w.cfg.CiscoAIDefense)

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

func (w *InstallWatcher) enforceBlock(evt InstallEvent) {
	switch evt.Type {
	case InstallSkill:
		se := enforce.NewSkillEnforcer(w.cfg.QuarantineDir)
		if _, err := se.Quarantine(evt.Path); err != nil {
			fmt.Fprintf(os.Stderr, "[watch] quarantine %s: %v\n", evt.Path, err)
		}
	case InstallMCP:
		me := enforce.NewMCPEnforcer(w.shell)
		_ = me.BlockEndpoint(evt.Name)
	case InstallPlugin:
		pe := enforce.NewPluginEnforcer(w.cfg.QuarantineDir, w.shell)
		if _, err := pe.Quarantine(evt.Path); err != nil {
			fmt.Fprintf(os.Stderr, "[watch] quarantine plugin %s: %v\n", evt.Path, err)
		}
	}
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
	if w.otel != nil {
		w.otel.RecordAdmissionDecision(ctx, decision, targetType, "watcher")
	}
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
