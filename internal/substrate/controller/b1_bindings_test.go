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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

type cmBindings struct {
	mu  sync.Mutex
	raw []byte
}

func (m *cmBindings) Get(context.Context) ([]byte, string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.raw...), "1", m.raw != nil, nil
}

func (m *cmBindings) Put(_ context.Context, raw []byte, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.raw = append([]byte(nil), raw...)
	return nil
}

// TestB1BindingOwnerFilter: a person's self-service binding reaches only
// the policy of an actor bound to that person, a waiting binding reaches
// none, and the rendered source names the owner's own value Secret.
func TestB1BindingOwnerFilter(t *testing.T) {
	store := secretbind.New(&cmBindings{})
	now := time.Date(2026, 11, 12, 20, 0, 0, 0, time.UTC)
	if err := store.Update(context.Background(), func(d *secretbind.Doc) error {
		d.Bindings = append(d.Bindings,
			secretbind.Binding{ID: "b-00000000a1", Name: "gl-work", Owner: render.PersonKey("sub-alice"), Template: "gitlab",
				Hosts: []string{"gitlab.com"}, State: secretbind.Active, Created: now},
			secretbind.Binding{ID: "b-00000000a2", Name: "gl-lab", Owner: render.PersonKey("sub-alice"), Template: "gitlab",
				Hosts: []string{"git.lab.example"}, State: secretbind.Waiting, Created: now})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	src := &scriptedSource{}
	r := newRig(t, func(cfg *config.Config, o *controller.Options) {
		cfg.Substrate.Egress.Allow = append(cfg.Substrate.Egress.Allow, "gitlab.com", "git.lab.example")
		src.cur, src.dig = cfg, "d1"
		o.Config = src
		o.Live = func(c *config.Config) controller.Live {
			return controller.Live{Settings: controller.SettingsFromConfig(c), Secrets: controller.SecretsFromConfig(c),
				LauncherAtespaces: controller.LauncherSet(c), RequireAttestation: true, Templates: c.Substrate.Templates,
				Attestor: o.Attestor, Resolver: &controller.ConfigResolver{Config: c}, IdleSuspendAfter: 30 * time.Minute,
				Bindings: controller.BindingsFrom(store, c, func() time.Time { return now })}
		}
		// The first Live comes from Options (no config change yet).
		o.Bindings = controller.BindingsFrom(store, cfg, func() time.Time { return now })
	})
	alice := ateapi.RefOf(r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice").GetMetadata())
	bob := ateapi.RefOf(r.actor("eng-web", "bob-1", ateapi.ActorStateRunning, "sub-bob").GetMetadata())
	r.pass()
	pa, pb := r.api.Policy(alice), r.api.Policy(bob)
	if pa == nil || pb == nil {
		t.Fatalf("no policy: alice %v bob %v", pa != nil, pb != nil)
	}
	value := secretbind.ValueSecretName(render.PersonKey("sub-alice"))
	if s := pa.String(); !strings.Contains(s, value) {
		t.Fatalf("alice's policy lacks her binding's value Secret %s:\n%s", value, s)
	}
	if s := pb.String(); strings.Contains(s, "dc-b-") {
		t.Fatalf("bob's policy carries a self-service binding:\n%s", s)
	}
	if n := strings.Count(pa.String(), value); n != 1 {
		t.Fatalf("alice's policy names her value Secret %d times; the waiting binding must not render", n)
	}
	// A binding approved (or added) later reaches the running actor on the
	// next pass, without a config change.
	if err := store.Update(context.Background(), func(d *secretbind.Doc) error {
		for i := range d.Bindings {
			if d.Bindings[i].ID == "b-00000000a2" {
				// Approval keeps the ask id: an approved host outside the
				// template stays (RV3 P2-2 drops it only without one).
				d.Bindings[i].State, d.Bindings[i].AskID = secretbind.Active, "A-1"
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if n := strings.Count(r.api.Policy(alice).String(), value); n != 2 {
		t.Fatalf("after approval alice's policy names her value Secret %d times, want 2:\n%s", n, r.api.Policy(alice))
	}
	// Off: no store function, no binding.
	if controller.BindingsFrom(store, &config.Config{Substrate: config.SubstrateConfig{
		SelfServiceSecrets: config.SubstrateSelfServiceSecretsConfig{Mode: config.SelfServiceOff}}}, time.Now) != nil {
		t.Fatal("mode off still renders bindings")
	}
	if controller.BindingsFrom(nil, &config.Config{}, time.Now) != nil {
		t.Fatal("nil store renders bindings")
	}
}

// TestB1BindingsClosedUnlessBindingsMode: values_only and off give no
// self-service binding to any actor, whatever the store holds.
func TestB1BindingsClosedUnlessBindingsMode(t *testing.T) {
	store := secretbind.New(&cmBindings{})
	now := time.Date(2026, 11, 12, 20, 0, 0, 0, time.UTC)
	if err := store.Update(context.Background(), func(d *secretbind.Doc) error {
		d.Bindings = append(d.Bindings, secretbind.Binding{ID: "b-00000000a1", Name: "gl-work", Owner: render.PersonKey("sub-alice"),
			Template: "gitlab", Hosts: []string{"gitlab.com"}, State: secretbind.Active, Created: now})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for mode, want := range map[string]int{config.SelfServiceBindings: 1, config.SelfServiceValuesOnly: 0, config.SelfServiceOff: 0} {
		cfg := &config.Config{}
		cfg.Substrate.SelfServiceSecrets.Mode = mode
		got := 0
		if f := controller.BindingsFrom(store, cfg, func() time.Time { return now }); f != nil {
			got = len(f("sub-alice"))
		}
		if got != want {
			t.Errorf("mode %s: %d bindings, want %d", mode, got, want)
		}
	}
}
