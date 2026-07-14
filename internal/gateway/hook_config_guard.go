// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const (
	// defaultHookGuardDebounce coalesces a burst of filesystem events
	// (editors often emit several writes/renames per save) into a single
	// presence check.
	defaultHookGuardDebounce = 500 * time.Millisecond

	// hookGuardHealSuppressWindow is how long the guard ignores events
	// after it re-runs Setup. Setup rewrites the connector config file,
	// which would otherwise re-trigger the guard; the presence check
	// already prevents a sustained loop, but suppressing the immediate
	// self-write keeps the audit trail clean.
	hookGuardHealSuppressWindow = 3 * time.Second

	// hookGuardSetupTimeout bounds a single re-install so a wedged
	// connector Setup cannot block the guard goroutine forever.
	hookGuardSetupTimeout = 15 * time.Second

	// hookGuardSwitchSuppressWindow pauses self-heal across a runtime
	// connector hot-swap. Tearing down the outgoing connector removes its
	// hook entries; without this pause the guard (still pointed at the old
	// connector until Repoint) could re-install them mid-swap, leaving
	// stale enforcement for a connector that was deliberately deactivated.
	// Sized to comfortably cover a teardown+Setup cycle plus a debounce
	// tick; Repoint at the end of the swap re-targets the guard.
	hookGuardSwitchSuppressWindow = 5 * time.Second

	// defaultHookGuardPolicyAuditInterval catches effective-policy changes
	// that do not produce a filesystem event (notably Windows registry policy)
	// and retries watches for policy directories created after startup.
	defaultHookGuardPolicyAuditInterval = 30 * time.Second
)

// HookConfigGuard watches the active connector's agent config file(s) and
// auto-heals (re-installs) the DefenseClaw hook block when a user deletes or
// strips it while the gateway is running. Without it, enforcement silently
// lapses until the next sidecar restart or connector switch.
//
// The guard watches the parent directory of each resolved config path (so
// editor atomic rename/replace saves are caught) and filters events down to
// the exact target files. On a debounced event it checks whether the owned
// hook command still appears in the config; only when it is gone does it
// re-run conn.Setup, which idempotently re-patches the hook entries.
//
// The GuardrailProxy owns one guard and calls Repoint when it hot-swaps
// connectors so the watcher follows the active connector.
type HookConfigGuard struct {
	logger   *audit.Logger
	otel     *telemetry.Provider
	debounce time.Duration
	// policyAudit is separate from debounce so tests can shorten effective-
	// policy polling without changing filesystem event coalescing.
	policyAudit time.Duration

	// onHealed is an optional fan-out hook (webhook / desktop
	// notification) invoked after a successful re-install. nil is safe.
	onHealed func(connectorName string, paths []string)

	mu            sync.Mutex
	started       bool
	ctx           context.Context
	cancel        context.CancelFunc
	fsw           *fsnotify.Watcher
	conn          connector.Connector
	opts          connector.SetupOpts
	targets       map[string]struct{} // cleaned absolute config file paths
	watchedDirs   map[string]struct{} // cleaned absolute parent dirs added to fsw
	pending       map[string]time.Time
	suppressUntil time.Time
	// lastPolicyFailure suppresses an identical permanent policy diagnostic on
	// every audit tick while still reporting a changed failure immediately.
	lastPolicyFailure string
	done              chan struct{}
}

// NewHookConfigGuard constructs a guard. debounce <= 0 falls back to the
// default. logger and otel may be nil (observability becomes a no-op).
func NewHookConfigGuard(logger *audit.Logger, otel *telemetry.Provider, debounce time.Duration) *HookConfigGuard {
	if debounce <= 0 {
		debounce = defaultHookGuardDebounce
	}
	return &HookConfigGuard{
		logger:      logger,
		otel:        otel,
		debounce:    debounce,
		policyAudit: defaultHookGuardPolicyAuditInterval,
		targets:     map[string]struct{}{},
		watchedDirs: map[string]struct{}{},
		pending:     map[string]time.Time{},
	}
}

// SetHealNotifier wires an optional callback fired after a successful
// re-install, used to fan out to webhooks / desktop notifications. Safe to
// leave unset.
func (g *HookConfigGuard) SetHealNotifier(fn func(connectorName string, paths []string)) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.onHealed = fn
	g.mu.Unlock()
}

func (g *HookConfigGuard) SetOTelProvider(p *telemetry.Provider) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.otel = p
	g.mu.Unlock()
}

// Start begins watching the given connector's config files. It launches a
// background goroutine bound to ctx and returns immediately. Starting a guard
// for a connector with no hook config paths (proxy/plugin connectors) is
// allowed: the goroutine runs idle until a later Repoint adds targets.
func (g *HookConfigGuard) Start(ctx context.Context, conn connector.Connector, opts connector.SetupOpts) {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.started {
		g.mu.Unlock()
		g.Repoint(conn, opts)
		return
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		g.mu.Unlock()
		fmt.Fprintf(os.Stderr, "[hook-guard] create fsnotify watcher: %v (self-heal disabled)\n", err)
		return
	}

	gctx, cancel := context.WithCancel(ctx)
	g.ctx = gctx
	g.cancel = cancel
	g.fsw = fsw
	g.done = make(chan struct{})
	g.started = true
	g.applyTargetsLocked(conn, opts)
	g.mu.Unlock()

	go g.run()
}

// Repoint switches the guard to a new connector (e.g. after a runtime
// connector hot-swap). It re-resolves config paths and adjusts the watched
// directories. No-op until Start has been called.
func (g *HookConfigGuard) Repoint(conn connector.Connector, opts connector.SetupOpts) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.started || g.fsw == nil {
		// Remember the latest target so a future Start picks it up.
		g.conn = conn
		g.opts = opts
		return
	}
	g.applyTargetsLocked(conn, opts)
	// A connector switch invalidates any pending events for the old
	// connector's files; drop them so we never heal the wrong connector.
	g.pending = map[string]time.Time{}
}

// SuppressHealing pauses heal evaluation for at least d and drops any events
// already queued for processing. Used during a runtime connector hot-swap so
// the guard does not re-install the connector being torn down: the proxy calls
// this before teardown and Repoint afterward. Nil-safe and a no-op for d <= 0.
func (g *HookConfigGuard) SuppressHealing(d time.Duration) {
	if g == nil || d <= 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if until := time.Now().Add(d); until.After(g.suppressUntil) {
		g.suppressUntil = until
	}
	// Drop in-flight events for the connector being swapped out so a
	// pending teardown write cannot mature into a heal once the window
	// elapses.
	g.pending = map[string]time.Time{}
}

// Stop cancels the guard goroutine and releases the fsnotify watcher. Safe to
// call multiple times.
func (g *HookConfigGuard) Stop() {
	if g == nil {
		return
	}
	g.mu.Lock()
	if !g.started {
		g.mu.Unlock()
		return
	}
	cancel := g.cancel
	done := g.done
	g.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// applyTargetsLocked recomputes the watched config paths + parent dirs for the
// given connector and syncs the fsnotify watch set. Caller must hold g.mu.
func (g *HookConfigGuard) applyTargetsLocked(conn connector.Connector, opts connector.SetupOpts) {
	g.conn = conn
	g.opts = opts

	newTargets := map[string]struct{}{}
	newDirs := map[string]struct{}{}
	for _, p := range connector.HookPolicyWatchPathsForConnector(conn, opts) {
		clean := filepath.Clean(p)
		newTargets[clean] = struct{}{}
		newDirs[filepath.Dir(clean)] = struct{}{}
	}
	g.targets = newTargets

	if g.fsw == nil {
		g.watchedDirs = newDirs
		return
	}
	// Add newly required directories.
	for dir := range newDirs {
		if _, ok := g.watchedDirs[dir]; ok {
			continue
		}
		if err := g.fsw.Add(dir); err != nil {
			// Optional project/managed policy directories commonly do not exist
			// yet. Their nearest existing parent remains watched and the periodic
			// audit retries them after creation; absence is not a degraded state.
			if !errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(os.Stderr, "[hook-guard] watch %s: %v (skipping)\n", dir, err)
			}
			continue
		}
		g.watchedDirs[dir] = struct{}{}
	}
	// Drop directories we no longer need.
	for dir := range g.watchedDirs {
		if _, ok := newDirs[dir]; ok {
			continue
		}
		_ = g.fsw.Remove(dir)
		delete(g.watchedDirs, dir)
	}
}

// resyncTargetsLocked force-refreshes directory watches after Setup. A
// directory watch is tied to the underlying directory object, so a path that
// Setup recreated can look unchanged in watchedDirs while fsnotify still
// references the deleted object. Rebuilding the watcher avoids inode/file-ID
// reuse making a remove/add cycle silently retain the stale OS handle. Caller
// must hold g.mu.
func (g *HookConfigGuard) resyncTargetsLocked(conn connector.Connector, opts connector.SetupOpts) {
	if g.fsw == nil {
		g.applyTargetsLocked(conn, opts)
		return
	}

	fresh, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[hook-guard] refresh fsnotify watcher: %v (keeping existing watcher)\n", err)
		return
	}
	previous := g.fsw
	g.fsw = fresh
	g.watchedDirs = map[string]struct{}{}
	g.applyTargetsLocked(conn, opts)
	_ = previous.Close()
}

func (g *HookConfigGuard) run() {
	defer close(g.done)
	defer func() {
		g.mu.Lock()
		if g.fsw != nil {
			_ = g.fsw.Close()
		}
		g.started = false
		g.mu.Unlock()
	}()

	ticker := time.NewTicker(g.debounce)
	defer ticker.Stop()
	var policyTicker *time.Ticker
	var policyAudit <-chan time.Time
	if g.policyAudit > 0 {
		policyTicker = time.NewTicker(g.policyAudit)
		policyAudit = policyTicker.C
		defer policyTicker.Stop()
	}

	for {
		g.mu.Lock()
		ctx := g.ctx
		watcher := g.fsw
		g.mu.Unlock()
		if ctx == nil || watcher == nil {
			return
		}
		select {
		case <-ctx.Done():
			return

		case event, ok := <-watcher.Events:
			if !ok {
				if g.watcherWasReplaced(watcher) {
					continue
				}
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}
			name := filepath.Clean(event.Name)
			g.mu.Lock()
			_, isTarget := g.targets[name]
			if isTarget {
				if _, exists := g.pending[name]; !exists {
					g.pending[name] = time.Now()
				}
			}
			g.mu.Unlock()

		case err, ok := <-watcher.Errors:
			if !ok {
				if g.watcherWasReplaced(watcher) {
					continue
				}
				return
			}
			if g.otel != nil {
				g.otel.RecordWatcherError(g.ctx)
			}
			fmt.Fprintf(os.Stderr, "[hook-guard] fsnotify error: %v\n", err)

		case <-ticker.C:
			g.processPending()

		case <-policyAudit:
			g.processPolicyAudit()
		}
	}
}

// watcherWasReplaced distinguishes the expected channel closure caused by a
// resync from a terminal closure of the active watcher.
func (g *HookConfigGuard) watcherWasReplaced(observed *fsnotify.Watcher) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.started && g.fsw != nil && g.fsw != observed
}

// processPending evaluates debounced events: if any guarded config file no
// longer references the owned hook, re-install via Setup.
func (g *HookConfigGuard) processPending() {
	g.mu.Lock()
	now := time.Now()
	suppressed := now.Before(g.suppressUntil)
	var ready []string
	for path, firstSeen := range g.pending {
		if now.Sub(firstSeen) >= g.debounce {
			ready = append(ready, path)
		}
	}
	for _, p := range ready {
		delete(g.pending, p)
	}
	conn := g.conn
	opts := g.opts
	g.mu.Unlock()

	if suppressed || len(ready) == 0 || conn == nil {
		return
	}
	// A policy event can be the first creation of a previously absent .claude
	// or managed-settings.d directory. Rebind before evaluating so later files
	// inside that directory cannot escape the effective-policy guardian.
	g.mu.Lock()
	g.resyncTargetsLocked(conn, opts)
	g.mu.Unlock()

	present, err := connector.OwnedHooksPresent(conn, opts)
	if err != nil {
		g.reportPolicyFailure(conn, err)
		return
	}
	g.clearPolicyFailure()
	if present {
		// The owned hook still exists — the operator edited unrelated
		// keys, or a previous heal already restored it. Do not fight
		// legitimate edits.
		return
	}

	g.heal(conn, opts, ready)
}

// processPolicyAudit re-evaluates Claude's full effective settings chain even
// when no file event occurs. Windows registry policy and administrator-created
// policy roots otherwise remain invisible to fsnotify until an unrelated edit.
func (g *HookConfigGuard) processPolicyAudit() {
	g.mu.Lock()
	conn := g.conn
	opts := g.opts
	suppressed := time.Now().Before(g.suppressUntil)
	if !suppressed && conn != nil && conn.Name() == "claudecode" {
		// Recompute targets so newly created managed/project directories and
		// drop-ins join the watcher without replacing its live OS handle.
		g.applyTargetsLocked(conn, opts)
	}
	g.mu.Unlock()
	if suppressed || conn == nil || conn.Name() != "claudecode" {
		return
	}

	present, err := connector.OwnedHooksPresent(conn, opts)
	if err != nil {
		g.reportPolicyFailure(conn, err)
		return
	}
	g.clearPolicyFailure()
	if !present {
		g.heal(conn, opts, []string{"periodic effective-policy audit"})
	}
}

func (g *HookConfigGuard) reportPolicyFailure(conn connector.Connector, err error) {
	message := err.Error()
	g.mu.Lock()
	if g.lastPolicyFailure == message {
		g.mu.Unlock()
		return
	}
	g.lastPolicyFailure = message
	logger := g.logger
	baseCtx := g.ctx
	g.mu.Unlock()

	connName := conn.Name()
	fmt.Fprintf(os.Stderr, "[hook-guard] effective-policy check for %s: %v\n", connName, err)
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	emitErrorConnector(baseCtx, "hook_guard", "effective-policy-blocked", connName,
		fmt.Sprintf("%s effective hook policy is not enforcing", connName), err)
	if logger != nil {
		_ = logger.LogActionSeverityConnector(string(audit.ActionGuardrailDegraded), connName,
			fmt.Sprintf("effective hook policy is not enforcing: %v", err), "", connName)
	}
}

func (g *HookConfigGuard) clearPolicyFailure() {
	g.mu.Lock()
	g.lastPolicyFailure = ""
	g.mu.Unlock()
}

// heal re-runs the connector Setup to re-install the hook block, emits audit
// + telemetry, and suppresses the resulting self-write.
func (g *HookConfigGuard) heal(conn connector.Connector, opts connector.SetupOpts, changed []string) {
	connName := conn.Name()
	detail := strings.Join(changed, ", ")

	g.mu.Lock()
	g.suppressUntil = time.Now().Add(hookGuardHealSuppressWindow)
	baseCtx := g.ctx
	g.mu.Unlock()
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	if g.logger != nil {
		// Connector is the multi-connector dimension we add; severity is left
		// at the logger's default (empty -> INFO) — the original severity of
		// these rows is not ours to redesign.
		_ = g.logger.LogActionSeverityConnector(string(audit.ActionConnectorHookTampered), connName,
			fmt.Sprintf("hook config missing owned entries: %s", detail), "", connName)
	}
	emitLifecycle(baseCtx, "hook_guard", "tampered", map[string]string{
		"connector": connName,
		"paths":     detail,
	})

	hctx, cancel := context.WithTimeout(context.WithoutCancel(baseCtx), hookGuardSetupTimeout)
	defer cancel()

	setupErr := conn.Setup(hctx, opts)

	// Setup may have recreated a deleted parent directory even when a later
	// verification step fails. Rebind before handling its result so the guard
	// never remains attached to the deleted inode.
	g.mu.Lock()
	g.resyncTargetsLocked(conn, opts)
	g.mu.Unlock()

	if setupErr != nil {
		err := setupErr
		fmt.Fprintf(os.Stderr, "[hook-guard] re-install %s hooks failed: %v\n", connName, err)
		emitErrorConnector(baseCtx, "hook_guard", "self-heal-failed", connName,
			fmt.Sprintf("failed to re-install %s hook config", connName), err)
		if g.logger != nil {
			_ = g.logger.LogActionSeverityConnector(string(audit.ActionGuardrailDegraded), connName,
				fmt.Sprintf("hook self-heal Setup failed: %v", err), "", connName)
		}
		return
	}

	present, err := connector.OwnedHooksPresent(conn, opts)
	if err != nil || !present {
		if err == nil {
			err = fmt.Errorf("effective hook contract is still inactive")
		}
		fmt.Fprintf(os.Stderr, "[hook-guard] re-install %s hooks did not restore enforcement: %v\n", connName, err)
		emitErrorConnector(baseCtx, "hook_guard", "self-heal-failed", connName,
			fmt.Sprintf("re-installed %s hook config but enforcement is still inactive", connName), err)
		if g.logger != nil {
			_ = g.logger.LogActionSeverityConnector(string(audit.ActionGuardrailDegraded), connName,
				fmt.Sprintf("hook self-heal verification failed: %v", err), "", connName)
		}
		return
	}

	fmt.Fprintf(os.Stderr, "[hook-guard] re-installed %s hook config after manual removal (%s)\n", connName, detail)
	if g.otel != nil {
		g.otel.RecordWatcherEvent(baseCtx, "hook-heal", connName, connName)
	}
	if g.logger != nil {
		_ = g.logger.LogActionSeverityConnector(string(audit.ActionConnectorHookRepaired), connName,
			fmt.Sprintf("re-installed hook entries removed from: %s", detail), "", connName)
	}
	emitLifecycle(baseCtx, "hook_guard", "repaired", map[string]string{
		"connector": connName,
		"paths":     detail,
	})

	g.mu.Lock()
	notify := g.onHealed
	g.mu.Unlock()
	if notify != nil {
		notify(connName, changed)
	}
}
