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
	"fmt"
	"os"
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
		return "not changed: no openclaw connector", nil
	}
	refresher, ok := conn.(interface {
		RefreshInstallPolicy(connector.SetupOpts) (string, error)
	})
	if !ok {
		return "not changed: the openclaw connector cannot refresh it", nil
	}
	return refresher.RefreshInstallPolicy(opts)
}

// openClawInstallPolicyRefreshMu runs one refresh at a time.
var openClawInstallPolicyRefreshMu sync.Mutex

// A refresh that fails (the openclaw.json lock held past its wait, a write
// error) is retried after each delay in turn; while one is still owed,
// openClawInstallPolicyPending makes the next reload refresh again even when
// it changes nothing for the install policy. Tests replace the delays.
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

// openClawInstallPolicyWrittenUnder is the OpenClaw version the install
// policy was last written under: the state file's when the watch starts
// (else the cached one), then the version of each refresh that ran. The
// watcher compares the cached version with it, not with the last one it
// saw, so a refresh that failed past every retry runs again at its next
// look while the policy is still judged under the old version (GAP-1198).
var (
	openClawInstallPolicyWrittenMu    sync.Mutex
	openClawInstallPolicyWrittenUnder string
)

func openClawInstallPolicyWrittenVersion() string {
	openClawInstallPolicyWrittenMu.Lock()
	defer openClawInstallPolicyWrittenMu.Unlock()
	return openClawInstallPolicyWrittenUnder
}

func setOpenClawInstallPolicyWrittenVersion(version string) {
	openClawInstallPolicyWrittenMu.Lock()
	openClawInstallPolicyWrittenUnder = version
	openClawInstallPolicyWrittenMu.Unlock()
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
// stopping or one is already armed. version is the one the failed refresh
// was asked to judge under (see openClawInstallPolicyRefreshOpts).
func (s *Sidecar) scheduleOpenClawInstallPolicyRetry(attempt int, reason, version string, delay time.Duration) bool {
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
		s.refreshOpenClawInstallPolicyAttempt(attempt+1, reason, version)
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
	// The version the policy was written under is read here, not in the
	// goroutine, so a change right after start is a change.
	cfg := s.currentConfig()
	written := openClawCachedVersion(cfg)
	if cfg != nil {
		if recorded := connector.OpenClawInstallPolicyStateVersion(cfg.DataDir); recorded != "" {
			written = recorded
		}
	}
	setOpenClawInstallPolicyWrittenVersion(written)
	go func() {
		defer close(done)
		s.watchOpenClawInstallPolicy(wctx)
	}()
	return func() {
		cancel()
		<-done
		stopOpenClawInstallPolicyRetries()
	}
}

// openClawCachedVersion is the OpenClaw version the last discovery cached,
// normalized; "" when there is none.
func openClawCachedVersion(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return connector.NormalizeAgentVersion("openclaw", connector.LoadCachedAgentVersion(cfg.DataDir, "openclaw"))
}

// watchOpenClawInstallPolicy re-checks the install policy when the cached
// OpenClaw version differs from the one it was written under. Setup wrote
// the policy under one version: a reinstall below 2026.8.35, or below
// 2026.11.3 on a hardened Windows root, leaves a registered command OpenClaw
// refuses, and the reload refresh only follows config changes (GAP-1198).
func (s *Sidecar) watchOpenClawInstallPolicy(ctx context.Context) {
	if s == nil {
		return
	}
	ticker := time.NewTicker(openClawInstallPolicyVersionPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg := s.currentConfig()
			version := openClawCachedVersion(cfg)
			// An empty or unparsable version is no evidence about OpenClaw
			// (the connector keeps a registered policy under it). An armed
			// retry refreshes from the cache when it fires; until a refresh
			// ran, written-under keeps the old version and the next look
			// tries again.
			if version == "" || version == openClawInstallPolicyWrittenVersion() ||
				openClawInstallPolicyRetrying.Load() || !openClawInstallPolicyGuarded(cfg) {
				continue
			}
			// The version is passed on: the cache can read "" again by the
			// time the refresh holds its lock.
			s.refreshOpenClawInstallPolicyAttempt(0, "an OpenClaw version change to "+version, version)
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
// that the install policy block is written from. The OpenClaw version is the
// cached one when it parses, else version (the one the watcher saw; "" from
// a reload): the cache can read "" between the watcher's look and this one.
func openClawInstallPolicyRefreshOpts(cfg *config.Config, version string) connector.SetupOpts {
	agentVersion := connector.LoadCachedAgentVersion(cfg.DataDir, "openclaw")
	if connector.NormalizeAgentVersion("openclaw", agentVersion) == "" && version != "" {
		agentVersion = version
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
	s.refreshOpenClawInstallPolicyAttempt(0, "the config reload", "")
}

// refreshOpenClawInstallPolicyAttempt is one try; reason says what asked for
// the refresh in the log, version is the OpenClaw version to judge under when
// the cache no longer parses ("" for none).
func (s *Sidecar) refreshOpenClawInstallPolicyAttempt(attempt int, reason, version string) {
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
	opts := openClawInstallPolicyRefreshOpts(cfg, version)
	state, err := openClawInstallPolicyRefresher(opts)
	if err == nil {
		openClawInstallPolicyPending.Store(false)
		if written := connector.NormalizeAgentVersion("openclaw", opts.AgentVersion); written != "" {
			setOpenClawInstallPolicyWrittenVersion(written)
		}
		fmt.Fprintf(os.Stderr, "[connector] openclaw: install admission after %s (install_policy %s): %s\n", reason, setting, state)
		return
	}
	openClawInstallPolicyPending.Store(true)
	if attempt < len(delays) && s.scheduleOpenClawInstallPolicyRetry(attempt, reason, version, delays[attempt]) {
		fmt.Fprintf(os.Stderr, "[connector] openclaw: install admission (install_policy %s) was not updated: %v; retrying in %s\n", setting, err, delays[attempt])
		return
	}
	if openClawInstallPolicyRetrying.Load() {
		fmt.Fprintf(os.Stderr, "[connector] openclaw: install admission (install_policy %s) was not updated: %v; a retry is already scheduled\n", setting, err)
		return
	}
	fmt.Fprintf(os.Stderr, "[connector] openclaw: install admission (install_policy %s) was not updated: %v; the next config reload tries again, or run defenseclaw setup openclaw\n", setting, err)
}
