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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1128: a reload that turns the OpenClaw install admission on (guardrail
// use-pack strict with install_policy auto, here install_policy on) writes
// it now, not at the next setup; a reload that changes nothing for it does
// not touch openclaw.json.
func TestRefreshOpenClawInstallPolicyFollowsReload(t *testing.T) {
	prev := openClawInstallPolicyRefresher
	t.Cleanup(func() { openClawInstallPolicyRefresher = prev })
	var calls []connector.SetupOpts
	openClawInstallPolicyRefresher = func(opts connector.SetupOpts) error {
		calls = append(calls, opts)
		return nil
	}
	newCfg := func(policy string) *config.Config {
		cfg := &config.Config{DataDir: t.TempDir()}
		cfg.Guardrail.Enabled = true
		cfg.Guardrail.Connector = "openclaw"
		cfg.Connectors.OpenClaw.InstallPolicy = policy
		return cfg
	}
	s := &Sidecar{}
	off, on := newCfg("off"), newCfg("on")
	on.DataDir = off.DataDir

	s.refreshOpenClawInstallPolicy(off, off)
	if len(calls) != 0 {
		t.Fatalf("an unchanged install admission must not be rewritten: %d calls", len(calls))
	}
	s.refreshOpenClawInstallPolicy(off, on)
	if len(calls) != 1 || !calls[0].OpenClawInstallPolicy || calls[0].DataDir != on.DataDir {
		t.Fatalf("turning install admission on must rewrite it from the new config: %+v", calls)
	}
	s.refreshOpenClawInstallPolicy(on, off)
	if len(calls) != 2 || calls[1].OpenClawInstallPolicy {
		t.Fatalf("turning install admission off must remove it: %+v", calls)
	}

	other := newCfg("on")
	other.Guardrail.Connector = "codex"
	s.refreshOpenClawInstallPolicy(off, other)
	if len(calls) != 2 {
		t.Fatalf("a host without the openclaw connector must not touch openclaw.json: %d calls", len(calls))
	}
}
