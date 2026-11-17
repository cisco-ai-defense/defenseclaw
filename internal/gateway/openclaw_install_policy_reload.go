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

// openClawInstallPolicyRefresher rewrites the install policy block; tests
// replace it.
var openClawInstallPolicyRefresher = func(opts connector.SetupOpts) error {
	conn, ok := connector.NewDefaultRegistry().Get("openclaw")
	if !ok {
		return nil
	}
	refresher, ok := conn.(interface {
		RefreshInstallPolicy(connector.SetupOpts) error
	})
	if !ok {
		return nil
	}
	return refresher.RefreshInstallPolicy(opts)
}

// openClawInstallPolicyNeedsRefresh reports a reload that changes the
// OpenClaw install admission of a configured, guarded OpenClaw: a rule pack
// switched to or from strict turns install_policy auto on or off, and the
// outage answer and scan timeout follow config too. The guardrail proxy and
// hook guards do not run OpenClaw setup again, so without this the block in
// openclaw.json kept the old answer until the next setup (GAP-1128). Managed
// installs take their config from a signed bundle and run setup with it.
func openClawInstallPolicyNeedsRefresh(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil || !newCfg.Guardrail.Enabled ||
		managed.IsManagedEnterprise(newCfg.DeploymentMode) ||
		!slices.Contains(newCfg.ActiveConnectors(), "openclaw") ||
		!newCfg.EffectiveGuardrailEnabledForConnector("openclaw") ||
		connector.ConnectorExplicitlyInactive(newCfg.DataDir, "openclaw") {
		return false
	}
	return openClawInstallPolicyInputsOf(oldCfg) != openClawInstallPolicyInputsOf(newCfg)
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
// admission (see openClawInstallPolicyNeedsRefresh). OpenClaw reads
// openclaw.json at each install, so no restart is needed.
func (s *Sidecar) refreshOpenClawInstallPolicy(oldCfg, newCfg *config.Config) {
	if s == nil || !openClawInstallPolicyNeedsRefresh(oldCfg, newCfg) {
		return
	}
	state := "off"
	if newCfg.OpenClawInstallPolicyOn() {
		state = "on"
	}
	if err := openClawInstallPolicyRefresher(openClawInstallPolicyRefreshOpts(newCfg)); err != nil {
		fmt.Fprintf(os.Stderr, "[connector] openclaw: install admission (install_policy %s) was not updated: %v; run defenseclaw setup openclaw\n", state, err)
		return
	}
	fmt.Fprintf(os.Stderr, "[connector] openclaw: install admission updated for the reloaded config (install_policy %s)\n", state)
}
