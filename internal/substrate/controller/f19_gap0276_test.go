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

package controller_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/configwatch"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0276: an edit of the defenseclaw-config ConfigMap must reach running
// actors without a controller restart. The rig's ConfigMap is in memory;
// the controller reads it through a real configwatch.Watcher on the rig's
// clock, the way the controller deployment reads it through the API.

const j9Host = "j9.example.net"

// cmFake is the defenseclaw-config ConfigMap: its current source, and the
// config each source decodes to (a source not in the map does not load).
type cmFake struct {
	mu      sync.Mutex
	raw     string
	configs map[string]*config.Config
}

func (f *cmFake) set(raw string, cfg *config.Config) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.raw = raw
	if cfg != nil {
		f.configs[raw] = cfg
	}
}

func (f *cmFake) fetch(context.Context) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []byte(f.raw), true, nil
}

func (f *cmFake) load(_ string, raw []byte) (*config.Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.configs[string(raw)]; ok {
		return c, nil
	}
	return nil, errors.New("config_version: field is required")
}

// j9Config is the rig's config with j9Host on the allow list, changed by mut.
func j9Config(mut func(*config.Config)) *config.Config {
	cfg := &config.Config{}
	cfg.Substrate = config.SubstrateConfig{
		Enabled:           true,
		LauncherAtespaces: map[string][]string{"eng": {"eng-web"}},
		Egress:            config.SubstrateEgressConfig{Allow: []string{"github.com", j9Host}, EcosystemPacks: []string{"pypi"}},
	}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"eng": {}, "ci": {}}
	if mut != nil {
		mut(cfg)
	}
	return cfg
}

func without(list []string, drop string) []string {
	var out []string
	for _, s := range list {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}

type liveRig struct {
	*rig
	cm *cmFake
	w  *configwatch.Watcher
}

// newLiveRig is newRig with the controller following the fake ConfigMap.
func newLiveRig(t *testing.T) *liveRig {
	t.Helper()
	boot := j9Config(nil)
	cm := &cmFake{raw: "v1", configs: map[string]*config.Config{"v1": boot}}
	w := configwatch.New("/etc/defenseclaw/config.yaml", boot, []byte("v1"))
	w.Fetch, w.Load = cm.fetch, cm.load
	var r *rig
	r = newRig(t, func(cfg *config.Config, o *controller.Options) {
		*cfg = *boot
		o.Resolver = &controller.ConfigResolver{Config: boot}
		o.Config = w
		o.Live = func(c *config.Config) controller.Live {
			return controller.Live{Settings: controller.SettingsFromConfig(c), Secrets: controller.SecretsFromConfig(c),
				LauncherAtespaces: controller.LauncherSet(c), RequireAttestation: true, Templates: c.Substrate.Templates,
				Attestor: o.Attestor, Resolver: &controller.ConfigResolver{Config: c}, IdleSuspendAfter: 30 * time.Minute}
		}
	})
	w.Now = r.clk.Now
	return &liveRig{rig: r, cm: cm, w: w}
}

func (r *liveRig) policyHas(ref *ateapi.ObjectRef, host string) bool {
	r.t.Helper()
	p := r.api.Policy(ref)
	return p != nil && strings.Contains(p.String(), host)
}

// TestGAP0276RemovedHostDeniedForRunningActor is SMK J9: a host removed
// from substrate.egress.allow leaves a running actor's policy within one
// read interval plus one pass, and comes back when it is restored.
func TestGAP0276RemovedHostDeniedForRunningActor(t *testing.T) {
	r := newLiveRig(t)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	if !r.policyHas(ref, j9Host) {
		t.Fatal("baseline: the running actor's policy does not allow the host")
	}
	r.cm.set("v2", j9Config(func(c *config.Config) { c.Substrate.Egress.Allow = without(c.Substrate.Egress.Allow, j9Host) }))
	r.clk.Add(configwatch.DefaultInterval)
	r.pass()
	if r.policyHas(ref, j9Host) {
		t.Fatalf("the removed host is still allowed one read interval (%s) and one pass after the ConfigMap edit", configwatch.DefaultInterval)
	}
	ev := r.sink.Events(controller.EventConfigReloaded)
	if len(ev) != 1 || ev[0].Detail["config_digest"] != configwatch.Digest([]byte("v2")) || ev[0].Detail["previous_digest"] != configwatch.Digest([]byte("v1")) {
		t.Fatalf("reload events = %+v", ev)
	}
	writes := r.sink.Events(controller.EventPolicyWritten)
	if last := writes[len(writes)-1]; last.Detail["config_digest"] != configwatch.Digest([]byte("v2")) {
		t.Fatalf("the policy write names config %v, not the new one", last.Detail["config_digest"])
	}
	if got := r.ctl.Digest(); got != configwatch.Digest([]byte("v2")) {
		t.Fatalf("Digest() = %q", got)
	}
	// Restored: allowed again on the next read.
	r.cm.set("v1", nil)
	r.clk.Add(configwatch.DefaultInterval)
	r.pass()
	if !r.policyHas(ref, j9Host) {
		t.Fatal("the restored host is not allowed again")
	}
}

// TestGAP0276ReadIntervalBoundsTheChange: the source is read at most every
// interval; the change is in force at the first pass after it.
func TestGAP0276ReadIntervalBoundsTheChange(t *testing.T) {
	r := newLiveRig(t)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	r.cm.set("v2", j9Config(func(c *config.Config) { c.Substrate.Egress.Allow = without(c.Substrate.Egress.Allow, j9Host) }))
	r.clk.Add(configwatch.DefaultInterval / 2)
	r.pass()
	if !r.policyHas(ref, j9Host) {
		t.Fatal("the source was read again inside the interval")
	}
	r.clk.Add(configwatch.DefaultInterval / 2)
	r.pass()
	if r.policyHas(ref, j9Host) {
		t.Fatal("not applied after one interval")
	}
}

// TestGAP0276PerInput: every config input the controller renders from
// reaches a running actor on the same reload.
func TestGAP0276PerInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*config.Config)
		// gone: the actor keeps no DefenseClaw policy at all.
		gone bool
	}{
		{name: "egress allow list", mut: func(c *config.Config) { c.Substrate.Egress.Allow = without(c.Substrate.Egress.Allow, j9Host) }},
		{name: "profile egress_block", mut: func(c *config.Config) {
			c.Guardrail.Profiles["eng"] = config.GuardrailProfile{Sandbox: &config.OpenShellAdminConfig{EgressBlock: []string{j9Host}}}
		}},
		{name: "substrate.admin egress_block (the floor)", mut: func(c *config.Config) {
			c.Substrate.Admin.EgressBlock = []string{j9Host}
		}},
		{name: "profile egress_allow_only", mut: func(c *config.Config) {
			c.Guardrail.Profiles["eng"] = config.GuardrailProfile{Sandbox: &config.OpenShellAdminConfig{EgressAllowOnly: []string{"github.com"}}}
		}},
		{name: "launcher atespace removed", mut: func(c *config.Config) {
			c.Substrate.LauncherAtespaces = map[string][]string{"eng": {"eng-other"}}
		}, gone: true},
		{name: "profile no longer allows sandboxes", mut: func(c *config.Config) {
			no := false
			c.Guardrail.Profiles["eng"] = config.GuardrailProfile{Sandbox: &config.OpenShellAdminConfig{Allowed: &no}}
		}, gone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newLiveRig(t)
			a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
			ref := ateapi.RefOf(a.GetMetadata())
			r.pass()
			if !r.policyHas(ref, j9Host) {
				t.Fatal("baseline: host not allowed")
			}
			r.cm.set("v2", j9Config(tc.mut))
			r.clk.Add(configwatch.DefaultInterval)
			r.pass()
			if tc.gone {
				if p := r.api.Policy(ref); p != nil {
					t.Fatalf("the actor kept a policy: %v", p)
				}
				return
			}
			if r.policyHas(ref, j9Host) {
				t.Fatal("the tightened host is still allowed")
			}
			if !r.policyHas(ref, "github.com") {
				t.Fatal("the tightening removed more than it names")
			}
		})
	}
}

// TestGAP0276BadEditKeepsConfigInForce: a source that does not load is
// refused once, alerts, and changes no policy; a fixed edit then applies.
func TestGAP0276BadEditKeepsConfigInForce(t *testing.T) {
	r := newLiveRig(t)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	before := len(r.api.PolicyWrites())
	r.cm.set("broken", nil)
	for i := 0; i < 3; i++ {
		r.clk.Add(configwatch.DefaultInterval)
		r.pass()
	}
	if n := len(r.api.PolicyWrites()); n != before || !r.policyHas(ref, j9Host) {
		t.Fatalf("a source that does not load changed the policy (%d writes, was %d)", n, before)
	}
	ev := r.sink.Events(controller.EventConfigRefused)
	if len(ev) != 1 || ev[0].Severity != controller.SeverityAlert || !strings.Contains(ev[0].Message, "does not load") {
		t.Fatalf("refused events = %+v", ev)
	}
	r.cm.set("v2", j9Config(func(c *config.Config) { c.Substrate.Egress.Allow = without(c.Substrate.Egress.Allow, j9Host) }))
	r.clk.Add(configwatch.DefaultInterval)
	r.pass()
	if r.policyHas(ref, j9Host) {
		t.Fatal("the fixed edit did not apply")
	}
}

// TestGAP0276CreatePathReadsTheEdit: the gateway's create path writes a new
// actor's first policy from the edited config, not the boot one.
func TestGAP0276CreatePathReadsTheEdit(t *testing.T) {
	r := newLiveRig(t)
	r.cm.set("v2", j9Config(func(c *config.Config) { c.Substrate.Egress.Allow = without(c.Substrate.Egress.Allow, j9Host) }))
	r.clk.Add(configwatch.DefaultInterval)
	a := r.actor("eng-web", "alice-2", ateapi.ActorStateSuspended, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	if err := r.ctl.EnsurePolicy(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if r.policyHas(ref, j9Host) {
		t.Fatal("a new actor got the boot allow list")
	}
}

// TestGAP0276ReloadReattestsTemplates: a config change expires the cached
// template verdicts, so a tightened attestation applies on the next pass
// instead of after the cache TTL.
func TestGAP0276ReloadReattestsTemplates(t *testing.T) {
	r := newLiveRig(t)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	r.att.Set("eng-web/claude", controller.Attestation{Reason: "key revoked"})
	r.cm.set("v2", j9Config(func(c *config.Config) { c.Substrate.Templates.MinPolicyGeneration = 7 }))
	r.clk.Add(configwatch.DefaultInterval)
	r.pass()
	if r.api.Policy(ref) != nil {
		t.Fatal("the cached verdict outlived the config change")
	}
}
