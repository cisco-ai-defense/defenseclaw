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
)

// InstallType distinguishes between skill and MCP install events.
type InstallType string

const (
	InstallSkill InstallType = "skill"
	InstallMCP   InstallType = "mcp"
)

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
	VerdictBlocked    Verdict = "blocked"
	VerdictAllowed    Verdict = "allowed"
	VerdictClean      Verdict = "clean"
	VerdictRejected   Verdict = "rejected"
	VerdictWarning    Verdict = "warning"
	VerdictScanError  Verdict = "scan-error"
)

// AdmissionResult captures the outcome for a single install event.
type AdmissionResult struct {
	Event   InstallEvent
	Verdict Verdict
	Reason  string
}

// OnAdmission is called after each install event is processed.
type OnAdmission func(AdmissionResult)

// InstallWatcher monitors OpenClaw skill and MCP directories for new installs
// and runs the admission gate (block → allow → scan) on each detection.
type InstallWatcher struct {
	cfg       *config.Config
	skillDirs []string
	mcpDirs   []string
	store     *audit.Store
	logger    *audit.Logger
	shell     *sandbox.OpenShell
	opa       *policy.Engine
	debounce  time.Duration
	onAdmit   OnAdmission

	mu      sync.Mutex
	pending map[string]time.Time // path → first-seen, for debounce
}

// New creates an InstallWatcher. The opa parameter may be nil to fall back
// to the built-in Go admission logic.
func New(cfg *config.Config, skillDirs, mcpDirs []string, store *audit.Store, logger *audit.Logger, shell *sandbox.OpenShell, opa *policy.Engine, onAdmit OnAdmission) *InstallWatcher {
	debounce := time.Duration(cfg.Watch.DebounceMs) * time.Millisecond
	if debounce <= 0 {
		debounce = 500 * time.Millisecond
	}
	return &InstallWatcher{
		cfg:       cfg,
		skillDirs: skillDirs,
		mcpDirs:   mcpDirs,
		store:     store,
		logger:    logger,
		shell:     shell,
		opa:       opa,
		debounce:  debounce,
		onAdmit:   onAdmit,
		pending:   make(map[string]time.Time),
	}
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
	for _, dir := range w.mcpDirs {
		if err := ensureAndWatch(fsw, dir); err != nil {
			fmt.Fprintf(os.Stderr, "[watch] mcp dir %s: %v (skipping)\n", dir, err)
			continue
		}
		watched++
		fmt.Printf("[watch] monitoring MCP dir:   %s\n", dir)
	}

	if watched == 0 {
		return fmt.Errorf("watcher: no directories to watch — check claw.mode and claw.home_dir")
	}

	_ = w.logger.LogAction("watch-start", "", fmt.Sprintf("dirs=%d debounce=%s", watched, w.debounce))

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
			w.mu.Lock()
			if _, exists := w.pending[event.Name]; !exists {
				w.pending[event.Name] = time.Now()
			}
			w.mu.Unlock()

		case err, ok := <-fsw.Errors:
			if !ok {
				return nil
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
	for _, dir := range w.mcpDirs {
		abs, _ := filepath.Abs(dir)
		pathAbs, _ := filepath.Abs(path)
		if strings.HasPrefix(pathAbs, abs) {
			installType = InstallMCP
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
				_ = w.logger.LogAction("install-rejected", evt.Path,
					fmt.Sprintf("type=%s reason=blocked", targetType))
				w.enforceBlock(evt)
				return AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: out.Reason}
			case "allowed":
				_ = w.logger.LogAction("install-allowed", evt.Path,
					fmt.Sprintf("type=%s reason=allow-listed", targetType))
				return AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: out.Reason}
			}
			// verdict == "scan" → proceed to scanning below
		}
		// On OPA error fall through to scan (best-effort).
	} else {
		// Fallback: built-in Go block/allow check when OPA is unavailable.
		blocked, err := pe.IsBlocked(targetType, evt.Name)
		if err == nil && blocked {
			reason := fmt.Sprintf("%s %q is on the block list — rejected", targetType, evt.Name)
			_ = w.logger.LogAction("install-rejected", evt.Path,
				fmt.Sprintf("type=%s reason=blocked", targetType))
			w.enforceBlock(evt)
			return AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: reason}
		}

		allowed, err := pe.IsAllowed(targetType, evt.Name)
		if err == nil && allowed {
			reason := fmt.Sprintf("%s %q is on the allow list — skipping scan", targetType, evt.Name)
			_ = w.logger.LogAction("install-allowed", evt.Path,
				fmt.Sprintf("type=%s reason=allow-listed", targetType))
			return AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: reason}
		}
	}

	// Phase 2: Scan.
	s := w.scannerFor(evt)
	if s == nil {
		return AdmissionResult{Event: evt, Verdict: VerdictScanError, Reason: "no scanner available"}
	}

	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	result, err := s.Scan(scanCtx, evt.Path)
	if err != nil {
		_ = w.logger.LogAction("install-scan-error", evt.Path,
			fmt.Sprintf("type=%s scanner=%s error=%v", targetType, s.Name(), err))
		return AdmissionResult{Event: evt, Verdict: VerdictScanError, Reason: err.Error()}
	}

	_ = w.logger.LogScan(result)

	// Phase 3: post-scan OPA evaluation with scan_result.
	if w.opa != nil {
		scanInput := &policy.ScanResultInput{
			MaxSeverity:   string(result.MaxSeverity()),
			TotalFindings: len(result.Findings),
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
			w.applyPostScanEnforcement(pe, out, evt, targetType, result, s.Name())
			return AdmissionResult{Event: evt, Verdict: toVerdict(out.Verdict), Reason: out.Reason}
		}
		// On OPA error, fall through to built-in logic.
	}

	// Fallback: built-in Go post-scan logic.
	if result.IsClean() {
		_ = w.logger.LogAction("install-clean", evt.Path,
			fmt.Sprintf("type=%s scanner=%s", targetType, s.Name()))
		return AdmissionResult{Event: evt, Verdict: VerdictClean, Reason: "scan clean"}
	}

	maxSev := result.MaxSeverity()
	if maxSev == scanner.SeverityHigh || maxSev == scanner.SeverityCritical {
		reason := fmt.Sprintf("scan found %s findings — auto-blocking", maxSev)
		_ = w.logger.LogAction("install-rejected", evt.Path,
			fmt.Sprintf("type=%s severity=%s scanner=%s", targetType, maxSev, s.Name()))

		if w.cfg.Watch.AutoBlock {
			blockReason := fmt.Sprintf("auto-block: watch detected %s findings (scanner=%s)", maxSev, s.Name())
			_ = pe.Block(targetType, evt.Name, blockReason)
			pe.SetSourcePath(targetType, evt.Name, evt.Path)

			action := w.cfg.SkillActions.ForSeverity(string(maxSev))
			if action.File == config.FileActionQuarantine {
				_ = pe.Quarantine(targetType, evt.Name, blockReason)
			}
			if action.Runtime == config.RuntimeDisable {
				_ = pe.Disable(targetType, evt.Name, blockReason)
			}

			w.enforceBlock(evt)
		}
		return AdmissionResult{Event: evt, Verdict: VerdictRejected, Reason: reason}
	}

	reason := fmt.Sprintf("scan found %s findings — installed with warning", maxSev)
	_ = w.logger.LogAction("install-warning", evt.Path,
		fmt.Sprintf("type=%s severity=%s scanner=%s", targetType, maxSev, s.Name()))
	return AdmissionResult{Event: evt, Verdict: VerdictWarning, Reason: reason}
}

// applyPostScanEnforcement takes the OPA verdict after scanning and executes
// the enforcement side-effects (block, quarantine, disable) that OPA cannot
// perform itself.
func (w *InstallWatcher) applyPostScanEnforcement(pe *enforce.PolicyEngine, out *policy.AdmissionOutput, evt InstallEvent, targetType string, result *scanner.ScanResult, scannerName string) {
	switch out.Verdict {
	case "clean":
		_ = w.logger.LogAction("install-clean", evt.Path,
			fmt.Sprintf("type=%s scanner=%s", targetType, scannerName))
	case "rejected":
		_ = w.logger.LogAction("install-rejected", evt.Path,
			fmt.Sprintf("type=%s severity=%s scanner=%s", targetType, result.MaxSeverity(), scannerName))

		if w.cfg.Watch.AutoBlock {
			blockReason := fmt.Sprintf("auto-block: watch detected %s findings (scanner=%s)", result.MaxSeverity(), scannerName)
			_ = pe.Block(targetType, evt.Name, blockReason)
			pe.SetSourcePath(targetType, evt.Name, evt.Path)

			if out.FileAction == "quarantine" {
				_ = pe.Quarantine(targetType, evt.Name, blockReason)
			}
			_ = pe.Disable(targetType, evt.Name, blockReason)
			w.enforceBlock(evt)
		}
	case "warning":
		_ = w.logger.LogAction("install-warning", evt.Path,
			fmt.Sprintf("type=%s severity=%s scanner=%s", targetType, result.MaxSeverity(), scannerName))
	}
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
	switch evt.Type {
	case InstallSkill:
		return scanner.NewSkillScanner(w.cfg.Scanners.SkillScanner)
	case InstallMCP:
		return scanner.NewMCPScanner(w.cfg.Scanners.MCPScanner)
	default:
		return nil
	}
}

func (w *InstallWatcher) enforceBlock(evt InstallEvent) {
	switch evt.Type {
	case InstallSkill:
		se := enforce.NewSkillEnforcer(w.cfg.QuarantineDir, w.shell)
		if _, err := se.Quarantine(evt.Path); err != nil {
			fmt.Fprintf(os.Stderr, "[watch] quarantine %s: %v\n", evt.Path, err)
		}
		_ = se.UpdateSandboxPolicy(evt.Name, true)
	case InstallMCP:
		me := enforce.NewMCPEnforcer(w.shell)
		_ = me.BlockEndpoint(evt.Name)
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
	for _, dir := range w.mcpDirs {
		dirAbs, _ := filepath.Abs(dir)
		if parentAbs == dirAbs {
			return true
		}
	}
	return false
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
