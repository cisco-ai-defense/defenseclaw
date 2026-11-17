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
// that the install policy block is written from.
func openClawInstallPolicyRefreshOpts(cfg *config.Config) connector.SetupOpts {
	return connector.SetupOpts{
		DataDir:                          cfg.DataDir,
		OpenClawHome:                     cfg.OpenClawHome(),
		OpenClawConfigPath:               cfg.OpenClawConfigPath(),
		OpenClawPluginDir:                cfg.OpenClawExternalPluginDir(),
		OpenClawPluginAccount:            strings.TrimSpace(cfg.Connectors.OpenClaw.PluginAccount),
		OpenClawPluginTokenFile:          strings.TrimSpace(cfg.Connectors.OpenClaw.PluginTokenFile),
		APIAddr:                          apiListenAddr(cfg),
		AgentVersion:                     connector.LoadCachedAgentVersion(cfg.DataDir, "openclaw"),
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
	s.refreshOpenClawInstallPolicyAttempt(0)
}

func (s *Sidecar) refreshOpenClawInstallPolicyAttempt(attempt int) {
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
	state, err := openClawInstallPolicyRefresher(openClawInstallPolicyRefreshOpts(cfg))
	if err == nil {
		openClawInstallPolicyPending.Store(false)
		fmt.Fprintf(os.Stderr, "[connector] openclaw: install admission after the config reload (install_policy %s): %s\n", setting, state)
		return
	}
	if attempt < len(delays) && openClawInstallPolicyRetrying.CompareAndSwap(false, true) {
		openClawInstallPolicyPending.Store(true)
		delay := delays[attempt]
		fmt.Fprintf(os.Stderr, "[connector] openclaw: install admission (install_policy %s) was not updated: %v; retrying in %s\n", setting, err, delay)
		time.AfterFunc(delay, func() {
			openClawInstallPolicyRetrying.Store(false)
			s.refreshOpenClawInstallPolicyAttempt(attempt + 1)
		})
		return
	}
	openClawInstallPolicyPending.Store(true)
	if openClawInstallPolicyRetrying.Load() {
		fmt.Fprintf(os.Stderr, "[connector] openclaw: install admission (install_policy %s) was not updated: %v; a retry is already scheduled\n", setting, err)
		return
	}
	fmt.Fprintf(os.Stderr, "[connector] openclaw: install admission (install_policy %s) was not updated: %v; the next config reload tries again, or run defenseclaw setup openclaw\n", setting, err)
}
