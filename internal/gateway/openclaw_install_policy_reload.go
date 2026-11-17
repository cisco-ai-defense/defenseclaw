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

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// openClawInstallPolicyInputs is what the DefenseClaw security.installPolicy
// block in openclaw.json is written from.
type openClawInstallPolicyInputs struct {
	on          bool
	timeoutMs   int
	failsClosed bool
}

func openClawInstallPolicyInputsOf(cfg *config.Config) openClawInstallPolicyInputs {
	return openClawInstallPolicyInputs{
		on:          cfg.OpenClawInstallPolicyOn(),
		timeoutMs:   cfg.OpenClawInstallPolicyTimeoutMs(),
		failsClosed: cfg.OpenClawInstallPolicyFailsClosed(),
	}
}

// openClawInstallPolicyRefresher rewrites the install policy block and
// returns the state it left; tests replace it.
var openClawInstallPolicyRefresher = func(opts connector.SetupOpts) (string, error) {
	conn, ok := connector.NewDefaultRegistry().Get("openclaw")
	if !ok {
		return connector.OpenClawInstallPolicyNotChanged + "no openclaw connector", nil
	}
	refresher, ok := conn.(interface {
		RefreshInstallPolicy(connector.SetupOpts) (string, error)
	})
	if !ok {
		return connector.OpenClawInstallPolicyNotChanged + "the openclaw connector cannot refresh it", nil
	}
	return refresher.RefreshInstallPolicy(opts)
}

// openClawInstallPolicyRefreshMu runs one refresh at a time.
var openClawInstallPolicyRefreshMu sync.Mutex

// A refresh that fails (the openclaw.json lock held past its wait, a write
// error) is retried after each delay in turn; while one is still owed,
// openClawInstallPolicyPending makes the next reload refresh again even when
// it changes nothing for the install policy. A refresh that kept the policy
// under an unknown OpenClaw version is still owed too, and the watcher runs
// it once the cached version parses (GAP-1236). Tests replace the delays.
var (
	openClawInstallPolicyRetryDelays = []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second, 2 * time.Minute, 5 * time.Minute}
	openClawInstallPolicyPending     atomic.Bool
	openClawInstallPolicyRetrying    atomic.Bool
)

// The retry timer is kept so the gateway can stop it at shutdown: a timer
// left armed past the context keeps its closure (and the sidecar) alive and
// fires a refresh into a gateway that is gone. A restarted gateway starts
// with the refresh still owed in memory, and setup at its start writes the
// install policy again, so nothing is persisted for the owed state. A retry
// that fired before the stop is counted in openClawInstallPolicyRetryRuns,
// and the stop waits for it, so no retry refresh runs once it returned.
var (
	openClawInstallPolicyRetryTimerMu sync.Mutex
	openClawInstallPolicyRetryTimer   *time.Timer
	openClawInstallPolicyStopped      atomic.Bool
	openClawInstallPolicyRetryRuns    sync.WaitGroup
)

// openClawObservation is an OpenClaw version (normalized) and the
// executable discovery read it from ("" when it names none).
type openClawObservation struct {
	version    string
	binaryPath string
}

// openClawInstallPolicyWrittenUnder is the OpenClaw version and executable
// the install policy was last decided under: the state file's when the watch
// starts (else the cached version), then those of each refresh that decided
// (connector.OpenClawInstallPolicyDecided). A refresh that returned before
// it looked at the version, or found it unknown, moves nothing (GAP-1234).
// The watcher compares the cached version with it, not with the last one it
// saw, so a refresh that failed past every retry runs again at its next
// look while the policy is still judged under the old version (GAP-1198).
//
// openClawInstallPolicyLastSeen is the last cached OpenClaw the watcher
// parsed and acts on, recorded at every look, also while a retry is armed. A
// watcher refresh and its retries judge under it when the cache no longer
// parses, so a retry never goes back to an older version the watcher has
// since seen replaced (GAP-1235).
var (
	openClawInstallPolicyWrittenMu    sync.Mutex
	openClawInstallPolicyWrittenUnder openClawObservation
	openClawInstallPolicyLastSeen     openClawObservation
)

func openClawInstallPolicySeen() openClawObservation {
	openClawInstallPolicyWrittenMu.Lock()
	defer openClawInstallPolicyWrittenMu.Unlock()
	return openClawInstallPolicyLastSeen
}

func setOpenClawInstallPolicySeen(seen openClawObservation) {
	openClawInstallPolicyWrittenMu.Lock()
	openClawInstallPolicyLastSeen = seen
	openClawInstallPolicyWrittenMu.Unlock()
}

func openClawInstallPolicyWritten() openClawObservation {
	openClawInstallPolicyWrittenMu.Lock()
	defer openClawInstallPolicyWrittenMu.Unlock()
	return openClawInstallPolicyWrittenUnder
}

// setOpenClawInstallPolicyWritten moves written-under, and the last seen
// OpenClaw with it: a refresh that decided, or a setup the watcher follows,
// is newer than what the watcher last saw, and a refresh that falls back to
// the last seen one must not go back to an older version (GAP-1237 review).
func setOpenClawInstallPolicyWritten(written openClawObservation) {
	openClawInstallPolicyWrittenMu.Lock()
	openClawInstallPolicyWrittenUnder = written
	openClawInstallPolicyLastSeen = written
	openClawInstallPolicyWrittenMu.Unlock()
}

// openClawExecutableMatch says how a cache read from one openclaw relates
// to the one the install policy was written under (GAP-1237).
type openClawExecutableMatch int

const (
	// openClawExecutableSame: the same executable, or one of the two is not
	// known (a state file from before it was recorded, a cache that names
	// none): acted on as before.
	openClawExecutableSame openClawExecutableMatch = iota
	// openClawExecutableOther: another executable while the recorded one is
	// there (or cannot be looked at): another openclaw on some PATH.
	openClawExecutableOther
	// openClawExecutableGone: another executable and the recorded one is
	// gone: a reinstall to another folder, once the watcher has seen it gone
	// on openClawInstallPolicyGoneLooks looks in a row.
	openClawExecutableGone
)

// openClawInstallPolicyGoneLooks is how many looks in a row the watcher must
// find the recorded executable gone before it follows another one: an
// upgrade in place (npm rewrites the shim, openclaw.cmd on Windows) removes
// it for a moment. Tests replace it.
var openClawInstallPolicyGoneLooks = 2

// openClawInstallPolicyExecutable classifies a cache read from seenPath while
// the policy was written under writtenPath. Doctor, agent discover, the TUI
// and init rewrite the cache from the shell they run in, so a run whose PATH
// finds another trusted openclaw removed and re-added the block within 30
// seconds although the OpenClaw the user runs did not change.
func openClawInstallPolicyExecutable(seenPath, writtenPath string) openClawExecutableMatch {
	if writtenPath == "" || seenPath == "" || openClawSameExecutable(seenPath, writtenPath) {
		return openClawExecutableSame
	}
	if _, err := os.Stat(writtenPath); errors.Is(err, os.ErrNotExist) {
		return openClawExecutableGone
	}
	return openClawExecutableOther
}

// openClawSameExecutable compares two executable paths as the file system
// does: case-insensitively on Windows.
func openClawSameExecutable(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// openClawInstallPolicyVersionPoll is how often the gateway looks at the
// OpenClaw version the last discovery cached. Discovery runs in the CLI and
// the gateway, not in this process, so a changed version has no event.
var openClawInstallPolicyVersionPoll = 30 * time.Second

// stopOpenClawInstallPolicyRetries stops the armed retry and any later one,
// and waits for a retry that already fired. The refresh stays owed
// (openClawInstallPolicyPending).
func stopOpenClawInstallPolicyRetries() {
	openClawInstallPolicyStopped.Store(true)
	openClawInstallPolicyRetryTimerMu.Lock()
	if openClawInstallPolicyRetryTimer != nil {
		openClawInstallPolicyRetryTimer.Stop()
		openClawInstallPolicyRetryTimer = nil
	}
	openClawInstallPolicyRetrying.Store(false)
	openClawInstallPolicyRetryTimerMu.Unlock()
	openClawInstallPolicyRetryRuns.Wait()
}

// scheduleOpenClawInstallPolicyRetry arms the retry unless the gateway is
// stopping or one is already armed. watch says the failed refresh came from
// the watcher (see openClawInstallPolicyRefreshOpts); the retry judges under
// what the cache, or the watcher, holds when it fires, not under a version
// captured now (GAP-1235).
func (s *Sidecar) scheduleOpenClawInstallPolicyRetry(attempt int, reason string, watch bool, delay time.Duration) bool {
	openClawInstallPolicyRetryTimerMu.Lock()
	defer openClawInstallPolicyRetryTimerMu.Unlock()
	if openClawInstallPolicyStopped.Load() || !openClawInstallPolicyRetrying.CompareAndSwap(false, true) {
		return false
	}
	openClawInstallPolicyRetryTimer = time.AfterFunc(delay, func() {
		// Stopped is checked under the timer lock the stop takes, and the
		// run is counted before the lock is let go, so a stop either sees
		// this retry and waits for it or this retry sees the stop.
		openClawInstallPolicyRetryTimerMu.Lock()
		if openClawInstallPolicyStopped.Load() {
			openClawInstallPolicyRetryTimerMu.Unlock()
			return
		}
		openClawInstallPolicyRetrying.Store(false)
		openClawInstallPolicyRetryTimer = nil
		openClawInstallPolicyRetryRuns.Add(1)
		openClawInstallPolicyRetryTimerMu.Unlock()
		defer openClawInstallPolicyRetryRuns.Done()
		s.refreshOpenClawInstallPolicyAttempt(attempt+1, reason, watch)
	})
	return true
}

// startOpenClawInstallPolicyWatch starts the watch of the cached OpenClaw
// version (GAP-1198) and returns the function that stops it and the retry
// timers; Run defers it.
func (s *Sidecar) startOpenClawInstallPolicyWatch(ctx context.Context) (stop func()) {
	openClawInstallPolicyStopped.Store(false)
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	// What the policy was written under is read here, not in the
	// goroutine, so a change right after start is a change.
	cfg := s.currentConfig()
	written := openClawObservation{version: openClawCachedObservation(cfg).version}
	if cfg != nil {
		version, binaryPath, err := connector.OpenClawInstallPolicyStateWritten(cfg.DataDir)
		switch {
		case err != nil:
			// A state file that is there but cannot be read says nothing
			// about the version: the first version that parses refreshes.
			written = openClawObservation{}
		case version != "":
			written = openClawObservation{version: version, binaryPath: binaryPath}
		}
	}
	setOpenClawInstallPolicyWritten(written)
	go func() {
		defer close(done)
		s.watchOpenClawInstallPolicy(wctx, written)
	}()
	return func() {
		cancel()
		<-done
		stopOpenClawInstallPolicyRetries()
	}
}

// openClawCachedObservation is the OpenClaw version the last discovery
// cached, normalized ("" when there is none or it does not parse), and the
// executable it was read from.
func openClawCachedObservation(cfg *config.Config) openClawObservation {
	if cfg == nil {
		return openClawObservation{}
	}
	version, binaryPath := connector.LoadCachedOpenClawSignal(cfg.DataDir)
	return openClawObservation{version: connector.NormalizeAgentVersion("openclaw", version), binaryPath: binaryPath}
}

// watchOpenClawInstallPolicy re-checks the install policy when the cached
// OpenClaw version differs from the one it was written under. Setup wrote
// the policy under one version: a reinstall below 2026.8.35, or below
// 2026.11.3 on a hardened Windows root, leaves a registered command OpenClaw
// refuses, and the reload refresh only follows config changes (GAP-1198).
// recorded is what the state file named at the start.
func (s *Sidecar) watchOpenClawInstallPolicy(ctx context.Context, recorded openClawObservation) {
	if s == nil {
		return
	}
	ticker := time.NewTicker(openClawInstallPolicyVersionPoll)
	defer ticker.Stop()
	goneLooks, goneOf := 0, ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg := s.currentConfig()
			// A setup that ran outside this watch (the CLI, the gateway's
			// own connector setup) records what it wrote the policy under
			// in the state file: follow it, or a new executable it chose
			// reads as another openclaw (GAP-1237). Read under the refresh
			// lock, so a refresh that runs meanwhile is not overwritten with
			// the state from before it; a look that finds a refresh running
			// follows at the next one.
			if cfg != nil && openClawInstallPolicyRefreshMu.TryLock() {
				if version, binaryPath, err := connector.OpenClawInstallPolicyStateWritten(cfg.DataDir); err == nil && version != "" {
					if state := (openClawObservation{version: version, binaryPath: binaryPath}); state != recorded {
						recorded = state
						setOpenClawInstallPolicyWritten(state)
					}
				}
				openClawInstallPolicyRefreshMu.Unlock()
			}
			seen := openClawCachedObservation(cfg)
			// An empty or unparsable version is no evidence about OpenClaw
			// (the connector keeps a registered policy under it), and a
			// cache from another openclaw than the one the policy was
			// written under is not the OpenClaw the user runs (GAP-1237).
			if seen.version == "" {
				goneLooks = 0
				continue
			}
			written := openClawInstallPolicyWritten()
			match := openClawInstallPolicyExecutable(seen.binaryPath, written.binaryPath)
			if match != openClawExecutableGone || goneOf != written.binaryPath {
				goneLooks, goneOf = 0, written.binaryPath
			}
			if match == openClawExecutableGone {
				goneLooks++
			}
			if match == openClawExecutableOther || (match == openClawExecutableGone && goneLooks < openClawInstallPolicyGoneLooks) {
				continue
			}
			otherExecutable := match == openClawExecutableGone
			// Recorded also while a retry is armed: the retry judges under
			// it when the cache reads "" by the time it fires (GAP-1235).
			// Until a refresh decided, written-under keeps the old version
			// and the next look tries again.
			setOpenClawInstallPolicySeen(seen)
			if openClawInstallPolicyRetrying.Load() || !openClawInstallPolicyGuarded(cfg) {
				continue
			}
			// An owed refresh (one that failed past its retries, or kept the
			// policy under an unknown version) runs once the version parses,
			// also when it is the one the policy was written under (GAP-1236).
			reason := "an OpenClaw version change to " + seen.version
			switch {
			case otherExecutable:
				reason = "an OpenClaw executable change to " + seen.binaryPath
			case seen.version != written.version:
			case openClawInstallPolicyPending.Load():
				reason = "an owed refresh under OpenClaw " + seen.version
			default:
				continue
			}
			s.refreshOpenClawInstallPolicyAttempt(0, reason, true)
		}
	}
}

// openClawInstallPolicyReloadWanted reports a reload that should refresh
// the OpenClaw install policy: its inputs changed, or an earlier refresh
// failed and is still owed.
func openClawInstallPolicyReloadWanted(oldCfg, newCfg *config.Config) bool {
	return openClawInstallPolicyNeedsRefresh(oldCfg, newCfg) ||
		(openClawInstallPolicyPending.Load() && openClawInstallPolicyGuarded(newCfg))
}

// openClawInstallPolicyNeedsRefresh reports a reload that changes the
// OpenClaw install admission of a configured, guarded OpenClaw: a rule pack
// switched to or from strict turns install_policy auto on or off, and the
// outage answer and scan timeout follow config too. The guardrail proxy and
// hook guards do not run OpenClaw setup again, so without this the block in
// openclaw.json kept the old answer until the next setup (GAP-1128). Managed
// installs take their config from a signed bundle and run setup with it.
func openClawInstallPolicyNeedsRefresh(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || !openClawInstallPolicyGuarded(newCfg) {
		return false
	}
	return openClawInstallPolicyInputsOf(oldCfg) != openClawInstallPolicyInputsOf(newCfg)
}

// openClawInstallPolicyGuarded reports a configured, guarded, unmanaged
// OpenClaw whose install policy the gateway keeps.
func openClawInstallPolicyGuarded(cfg *config.Config) bool {
	return cfg != nil && cfg.Guardrail.Enabled &&
		!managed.IsManagedEnterprise(cfg.DeploymentMode) &&
		slices.Contains(cfg.ActiveConnectors(), "openclaw") &&
		cfg.EffectiveGuardrailEnabledForConnector("openclaw") &&
		!connector.ConnectorExplicitlyInactive(cfg.DataDir, "openclaw")
}

// openClawInstallPolicyRefreshOpts is the part of the OpenClaw SetupOpts
// that the install policy block is written from. The OpenClaw version and
// executable are the cached ones (one read of the cache). A cache that names
// another openclaw than the one the policy was written under is not judged
// under, by the watcher or by a reload: they judge under the last one the
// watcher acted on, else under what the policy was written under, so a
// reload cannot adopt another shell's openclaw (GAP-1237). When the version
// does not parse, a refresh of the watcher (watch, also its retries) judges
// under the last one the watcher saw: the cache can change between the
// watcher's look and this one, or by the time a retry fires (GAP-1235). A
// reload refresh passes an unparsable cache as it is; the connector keeps a
// registered policy under an unknown version.
func openClawInstallPolicyRefreshOpts(cfg *config.Config, watch bool) connector.SetupOpts {
	agentVersion, agentExecutable := connector.LoadCachedOpenClawSignal(cfg.DataDir)
	written, seen := openClawInstallPolicyWritten(), openClawInstallPolicySeen()
	var instead openClawObservation
	switch {
	case openClawInstallPolicyExecutable(agentExecutable, written.binaryPath) != openClawExecutableSame:
		instead = seen
		if instead.version == "" {
			instead = written
		}
	case watch && connector.NormalizeAgentVersion("openclaw", agentVersion) == "":
		instead = seen
	case agentExecutable == "":
		// A cache that names no executable is taken for the recorded one
		// (openClawExecutableSame); keep it recorded, or the next decided
		// refresh would drop it and the guard with it.
		agentExecutable = written.binaryPath
	}
	if instead.version != "" {
		agentVersion, agentExecutable = instead.version, instead.binaryPath
	}
	return connector.SetupOpts{
		DataDir:                          cfg.DataDir,
		OpenClawHome:                     cfg.OpenClawHome(),
		OpenClawConfigPath:               cfg.OpenClawConfigPath(),
		OpenClawPluginDir:                cfg.OpenClawExternalPluginDir(),
		OpenClawPluginAccount:            strings.TrimSpace(cfg.Connectors.OpenClaw.PluginAccount),
		OpenClawPluginTokenFile:          strings.TrimSpace(cfg.Connectors.OpenClaw.PluginTokenFile),
		APIAddr:                          apiListenAddr(cfg),
		AgentVersion:                     agentVersion,
		AgentExecutable:                  agentExecutable,
		OpenClawInstallPolicy:            cfg.OpenClawInstallPolicyOn(),
		OpenClawInstallPolicyTimeoutMs:   cfg.OpenClawInstallPolicyTimeoutMs(),
		OpenClawInstallPolicyFailsClosed: cfg.OpenClawInstallPolicyFailsClosed(),
	}
}

// refreshOpenClawInstallPolicy applies a reload to the OpenClaw install
// admission (see openClawInstallPolicyNeedsRefresh). The reload starts it in
// a goroutine; refreshes run one at a time and each writes from the config
// the gateway holds when it runs, not the one of its reload, so quick
// reloads (strict, default, strict) cannot apply out of order and leave the
// admission off. Every refresh logs the state it left and why. OpenClaw
// reads openclaw.json at each install, so no restart is needed.
func (s *Sidecar) refreshOpenClawInstallPolicy() {
	s.refreshOpenClawInstallPolicyAttempt(0, "the config reload", false)
}

// openClawInstallPolicyLastUndecided is the last log line of a refresh that
// decided nothing. The watcher runs such a refresh again at each look until
// one decides; the same line is not logged again. Guarded by
// openClawInstallPolicyRefreshMu.
var openClawInstallPolicyLastUndecided string

// refreshOpenClawInstallPolicyAttempt is one try; reason says what asked for
// the refresh in the log, watch says the watcher asked (see
// openClawInstallPolicyRefreshOpts).
func (s *Sidecar) refreshOpenClawInstallPolicyAttempt(attempt int, reason string, watch bool) {
	if s == nil {
		return
	}
	openClawInstallPolicyRefreshMu.Lock()
	defer openClawInstallPolicyRefreshMu.Unlock()
	delays := openClawInstallPolicyRetryDelays
	cfg := s.currentConfig()
	if !openClawInstallPolicyGuarded(cfg) {
		openClawInstallPolicyPending.Store(false)
		return
	}
	setting := "off"
	if cfg.OpenClawInstallPolicyOn() {
		setting = "on"
	}
	opts := openClawInstallPolicyRefreshOpts(cfg, watch)
	state, err := openClawInstallPolicyRefresher(opts)
	if err == nil {
		// An unknown version kept the policy as it was: what changed in
		// config is still owed (GAP-1236).
		openClawInstallPolicyPending.Store(state == connector.OpenClawInstallPolicyVersionUnknown)
		line := fmt.Sprintf("[connector] openclaw: install admission after %s (install_policy %s): %s\n", reason, setting, state)
		if !connector.OpenClawInstallPolicyDecided(state) {
			if line != openClawInstallPolicyLastUndecided {
				fmt.Fprint(os.Stderr, line)
			}
			openClawInstallPolicyLastUndecided = line
			return
		}
		openClawInstallPolicyLastUndecided = ""
		if version := connector.NormalizeAgentVersion("openclaw", opts.AgentVersion); version != "" {
			setOpenClawInstallPolicyWritten(openClawObservation{version: version, binaryPath: strings.TrimSpace(opts.AgentExecutable)})
		}
		fmt.Fprint(os.Stderr, line)
		return
	}
	openClawInstallPolicyPending.Store(true)
	if attempt < len(delays) && s.scheduleOpenClawInstallPolicyRetry(attempt, reason, watch, delays[attempt]) {
		fmt.Fprintf(os.Stderr, "[connector] openclaw: install admission (install_policy %s) was not updated: %v; retrying in %s\n", setting, err, delays[attempt])
		return
	}
	if openClawInstallPolicyRetrying.Load() {
		fmt.Fprintf(os.Stderr, "[connector] openclaw: install admission (install_policy %s) was not updated: %v; a retry is already scheduled\n", setting, err)
		return
	}
	fmt.Fprintf(os.Stderr, "[connector] openclaw: install admission (install_policy %s) was not updated: %v; the gateway tries again at its next version look or config reload, or run defenseclaw setup openclaw\n", setting, err)
}
