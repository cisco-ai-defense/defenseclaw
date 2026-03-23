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
	debounce  time.Duration
	onAdmit   OnAdmission

	mu      sync.Mutex
	pending map[string]time.Time // path → first-seen, for debounce
}

func New(cfg *config.Config, skillDirs, mcpDirs []string, store *audit.Store, logger *audit.Logger, shell *sandbox.OpenShell, onAdmit OnAdmission) *InstallWatcher {
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
			w.mu.Lock()
			if _, exists := w.pending[event.Name]; !exists {
				w.pending[event.Name] = time.Now()
			}
			w.mu.Unlock()

			// When a new subdirectory appears, start watching it too
			// so we catch nested installs.
			if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
				_ = fsw.Add(event.Name)
			}

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
func (w *InstallWatcher) runAdmission(ctx context.Context, evt InstallEvent) AdmissionResult {
	pe := enforce.NewPolicyEngine(w.store)
	targetType := string(evt.Type)

	_ = w.logger.LogAction("install-detected", evt.Path,
		fmt.Sprintf("type=%s name=%s", targetType, evt.Name))

	// 1. Block list check
	blocked, err := pe.IsBlocked(targetType, evt.Name)
	if err == nil && blocked {
		reason := fmt.Sprintf("%s %q is on the block list — rejected", targetType, evt.Name)
		_ = w.logger.LogAction("install-rejected", evt.Path,
			fmt.Sprintf("type=%s reason=blocked", targetType))
		w.enforceBlock(evt)
		return AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: reason}
	}

	// 2. Allow list check
	allowed, err := pe.IsAllowed(targetType, evt.Name)
	if err == nil && allowed {
		reason := fmt.Sprintf("%s %q is on the allow list — skipping scan", targetType, evt.Name)
		_ = w.logger.LogAction("install-allowed", evt.Path,
			fmt.Sprintf("type=%s reason=allow-listed", targetType))
		return AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: reason}
	}

	// 3. Scan
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
			w.enforceBlock(evt)
		}
		return AdmissionResult{Event: evt, Verdict: VerdictRejected, Reason: reason}
	}

	// MEDIUM/LOW: install with warning
	reason := fmt.Sprintf("scan found %s findings — installed with warning", maxSev)
	_ = w.logger.LogAction("install-warning", evt.Path,
		fmt.Sprintf("type=%s severity=%s scanner=%s", targetType, maxSev, s.Name()))
	return AdmissionResult{Event: evt, Verdict: VerdictWarning, Reason: reason}
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

func ensureAndWatch(fsw *fsnotify.Watcher, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	if err := fsw.Add(dir); err != nil {
		return fmt.Errorf("watch: %w", err)
	}

	// Watch existing subdirectories so nested installs are caught immediately.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.IsDir() {
			sub := filepath.Join(dir, e.Name())
			_ = fsw.Add(sub)
		}
	}

	return nil
}
