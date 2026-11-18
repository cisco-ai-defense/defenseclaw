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

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/configwatch"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// gap0276Watcher follows an in-memory ConfigMap whose sources decode to
// the given configs.
func gap0276Watcher(t *testing.T, boot *config.Config, configs map[string]*config.Config, raw *string, now *time.Time) *configwatch.Watcher {
	t.Helper()
	w := configwatch.New("/etc/defenseclaw/config.yaml", boot, []byte("boot"))
	w.Fetch = func(context.Context) ([]byte, bool, error) { return []byte(*raw), true, nil }
	w.Load = func(_ string, b []byte) (*config.Config, error) {
		if c, ok := configs[string(b)]; ok {
			return c, nil
		}
		return nil, errors.New("does not load")
	}
	w.Now = func() time.Time { return *now }
	return w
}

func gap0276Config(action string, mut func(*config.Config)) *config.Config {
	c := &config.Config{}
	c.Substrate.Enabled = true
	c.Substrate.ChainEgressAction = action
	if mut != nil {
		mut(c)
	}
	return c
}

// TestGAP0276GatewayAndLeaderFollowChainEgressAction: a chain egress
// action change reaches the gateway's hook disposition and the leader's
// callout verdict without a restart, from the same ConfigMap.
func TestGAP0276GatewayAndLeaderFollowChainEgressAction(t *testing.T) {
	prev := gateway.SubstrateChainEgressAction()
	t.Cleanup(func() { _ = gateway.SetSubstrateChainEgressAction(prev) })
	boot := gap0276Config(chainstate.EgressAlert, nil)
	if err := applyGatewayChainEgress(boot); err != nil {
		t.Fatal(err)
	}
	chains, err := chainstate.New(chainstate.Options{Dir: t.TempDir(), EgressAction: chainstate.EgressAlert})
	if err != nil {
		t.Fatal(err)
	}
	defer chains.Close()
	raw, now := "boot", time.Date(2026, 11, 14, 17, 0, 0, 0, time.UTC)
	configs := map[string]*config.Config{"boot": boot, "v2": gap0276Config(chainstate.EgressBlock, func(c *config.Config) {
		c.Substrate.Identity.AdminGroups = []string{"dc-admins"}
	})}
	var gwOut, ldOut bytes.Buffer
	gw := newSubstrateFollower(gap0276Watcher(t, boot, configs, &raw, &now), "gateway", &gwOut, applyGatewayChainEgress)
	ld := newSubstrateFollower(gap0276Watcher(t, boot, configs, &raw, &now), "leader", &ldOut, func(c *config.Config) error {
		action, _ := leaderChainEgressAction(c)
		return chains.SetEgressAction(action)
	})
	raw = "v2"
	now = now.Add(configwatch.DefaultInterval)
	gw.step(context.Background())
	ld.step(context.Background())
	if got := gateway.SubstrateChainEgressAction(); got != chainstate.EgressBlock {
		t.Fatalf("gateway chain egress action = %q after the edit", got)
	}
	if got := chains.EgressAction(); got != chainstate.EgressBlock {
		t.Fatalf("leader chain egress action = %q after the edit", got)
	}
	if !strings.Contains(gwOut.String(), "deploy/defenseclaw-gateway)") || !strings.Contains(ldOut.String(), "deploy/defenseclaw-gateway-leader)") {
		t.Fatalf("the restart hint names a Deployment the chart does not have: %q / %q", gwOut.String(), ldOut.String())
	}
	// The gateway's guardrail follows the mounted file, so its follower says
	// seen, not in force (GAP-0590).
	for out, word := range map[string]string{gwOut.String(): " seen", ldOut.String(): " in force"} {
		if !strings.Contains(out, configwatch.Digest([]byte("v2"))+word) || !strings.Contains(out, "substrate.identity") ||
			!strings.Contains(out, "rollout restart") {
			t.Fatalf("follower log = %q", out)
		}
	}
	// A source that does not load changes nothing and is logged once.
	raw = "broken"
	for i := 0; i < 2; i++ {
		now = now.Add(configwatch.DefaultInterval)
		gw.step(context.Background())
	}
	if got := gateway.SubstrateChainEgressAction(); got != chainstate.EgressBlock || strings.Count(gwOut.String(), "not applied") != 1 {
		t.Fatalf("bad edit: action %q, log %q", got, gwOut.String())
	}
}

// TestGAP0276RestartOnlyKeys names what a running pod keeps until restart
// and nothing it applies live.
func TestGAP0276RestartOnlyKeys(t *testing.T) {
	boot := gap0276Config("", nil)
	live := gap0276Config(chainstate.EgressAlert, func(c *config.Config) {
		c.Substrate.Egress.Allow = []string{"github.com"}
		c.Substrate.LauncherAtespaces = map[string][]string{"eng": {"eng-web"}}
		c.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "eng"}}
	})
	if got := substrateRestartOnly(boot, live); len(got) != 0 {
		t.Fatalf("live keys reported as restart-only: %v", got)
	}
	later := gap0276Config("", func(c *config.Config) {
		c.Substrate.RateLimits.PerActorRPS = 3
		c.Substrate.Extproc.FailureMode = "open"
	})
	got := strings.Join(substrateRestartOnly(boot, later), "|")
	if !strings.Contains(got, "substrate.rate_limits") || !strings.Contains(got, "substrate.extproc") {
		t.Fatalf("restart-only = %s", got)
	}
}

type gap0276Kube struct {
	cm  *setup.ConfigMap
	err error
}

func (k gap0276Kube) GetConfigMap(context.Context, string, string) (*setup.ConfigMap, error) {
	return k.cm, k.err
}

func TestGAP0276ConfigMapFetch(t *testing.T) {
	ok := substrateConfigMapFetch(gap0276Kube{cm: &setup.ConfigMap{Data: map[string]string{"config.yaml": "x: 1"}}}, "dc", substrateConfigMap)
	if b, found, err := ok(context.Background()); err != nil || !found || string(b) != "x: 1" {
		t.Fatalf("fetch = %q %v %v", b, found, err)
	}
	for name, k := range map[string]gap0276Kube{
		"gone":    {},
		"no key":  {cm: &setup.ConfigMap{Data: map[string]string{"other": "y"}}},
		"refused": {err: errors.New("forbidden")},
	} {
		b, found, err := substrateConfigMapFetch(k, "dc", substrateConfigMap)(context.Background())
		if found || len(b) != 0 || (name == "refused") != (err != nil) {
			t.Fatalf("%s: %q %v %v", name, b, found, err)
		}
	}
}
