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

package cli

// R12 review probe (not for commit).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/configwatch"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// The gateway's own reload refuses managed_downgrade (config_manager.go);
// a live ConfigMap edit through configwatch must not drop managed_enterprise
// behaviour either, and must not apply a key it reports as restart-only.
func TestGAP0294ManagedDowngradeThroughConfigMap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("boot"), 0o600); err != nil {
		t.Fatal(err)
	}
	boot := &config.Config{DeploymentMode: "managed_enterprise"}
	boot.Substrate.Enabled = true
	w := configwatch.New(path, boot, []byte("boot"))
	oss := "config_version: 9\nsubstrate:\n  enabled: true\n  identity:\n    issuer: https://idp.ate-system.svc\n    audience: defenseclaw\n    token_lifetime_seconds: 300\n"
	w.Fetch = func(context.Context) ([]byte, bool, error) { return []byte(oss), true, nil }
	w.Load = func(string, []byte) (*config.Config, error) {
		c := &config.Config{}
		c.Substrate.Enabled = true
		return c, nil // the edit drops deployment_mode managed_enterprise
	}
	ch := w.Refresh(context.Background())
	if ch.Refused == nil || !strings.Contains(ch.Refused.Error(), "managed_downgrade") || ch.Changed {
		t.Fatalf("a managed downgrade through the ConfigMap was not refused as managed_downgrade: %+v", ch)
	}
	cur, _ := w.Current()
	t.Logf("in force deployment_mode=%q changed=%v restart-only=%v", cur.DeploymentMode, ch.Changed, substrateRestartOnly(boot, cur))
	before := substrateBlocksUnscannedSkills(boot)("claudecode")
	after := substrateBlocksUnscannedSkills(cur)("claudecode")
	if before && !after {
		t.Fatalf("R12: a ConfigMap edit dropped deployment_mode managed_enterprise live: unscanned skills blocked before=%v, after=%v (follower reports deployment_mode as restart-only)", before, after)
	}
}

// TestGAP0297ControllerKeepsBootIdentityAndServices: an audience, token
// lifetime or service edit is restart-only in the controller as in the
// gateway: the rendered policy keeps the boot values, and a warning names
// the keys and the restart.
func TestGAP0297ControllerKeepsBootIdentityAndServices(t *testing.T) {
	boot := &config.Config{}
	boot.Substrate.Enabled = true
	boot.Substrate.Egress.Allow = []string{"github.com"}
	next := &config.Config{}
	next.Substrate = boot.Substrate
	next.Substrate.Identity.Audience = "other-audience"
	next.Substrate.Identity.TokenLifetimeSeconds = 900
	next.Substrate.Egress.Allow = nil
	var sink controllerfakeSink
	live := substrateControllerLiveFunc(boot, false, nil, &sink)
	b, n := live(boot), live(next)
	if n.Settings.Audience != b.Settings.Audience || n.Settings.TokenLifetimeSeconds != b.Settings.TokenLifetimeSeconds ||
		n.Settings.ActorService != b.Settings.ActorService || n.Settings.AdminService != b.Settings.AdminService {
		t.Fatalf("restart-only render inputs applied live: boot %+v next %+v", b.Settings, n.Settings)
	}
	if len(n.Settings.AllowHosts) != 0 {
		t.Fatalf("the live part (egress allow) did not apply: %v", n.Settings.AllowHosts)
	}
	if !strings.Contains(sink.msgs, "substrate.identity") || !strings.Contains(sink.msgs, "deploy/defenseclaw-gateway-leader") {
		t.Fatalf("warning = %q", sink.msgs)
	}
}

type controllerfakeSink struct{ msgs string }

func (s *controllerfakeSink) Emit(e controller.Event) { s.msgs += e.Message + "\n" }

// TestGAP0306ControllerKeepsBootMCPAndProviderHosts: substrate.extproc
// mcp_hosts and the llm_providers hosts change only with the callout and
// the gateway (helm upgrade, restart), so the controller keeps the boot
// ones; a live edit opens no egress the callout does not inspect.
func TestGAP0306ControllerKeepsBootMCPAndProviderHosts(t *testing.T) {
	boot := &config.Config{}
	boot.Substrate.Enabled = true
	boot.Substrate.Extproc.MCPHosts = []string{"mcp.boot.example"}
	next := &config.Config{}
	next.Substrate = boot.Substrate
	next.Substrate.Extproc.MCPHosts = []string{"mcp.boot.example", "mcp.added.example"}
	next.LLMProviders.Custom = append(next.LLMProviders.Custom, config.LLMCustomProvider{Domains: []string{"llm.added.example"}})
	var sink controllerfakeSink
	live := substrateControllerLiveFunc(boot, false, nil, &sink)
	n := live(next)
	for _, h := range append(append([]string{}, n.Settings.MCPHosts...), n.Settings.ProviderHosts...) {
		if strings.Contains(h, "added.example") {
			t.Fatalf("host %s from a live edit is rendered before the callout and gateway take it", h)
		}
	}
	if !strings.Contains(sink.msgs, "substrate.extproc") || !strings.Contains(sink.msgs, "llm_providers") {
		t.Fatalf("warning = %q", sink.msgs)
	}
}
