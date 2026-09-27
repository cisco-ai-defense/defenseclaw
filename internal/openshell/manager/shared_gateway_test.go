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

package manager

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/policy"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestTwoDaemonsShareAGateway runs two managers, two data dirs with their
// own ingress and egress ports (a dev daemon next to the usual one), on one
// OpenShell gateway where a sandbox of an earlier release still uses the
// legacy gateway-wide ingress profile. Their concurrent creates, which
// import the same shared LLM and credential profiles, all succeed; each
// sandbox's ingress provider binds its token to its own daemon's listener;
// and nothing one daemon does touches the other's objects.
func TestTwoDaemonsShareAGateway(t *testing.T) {
	fake := openshelltest.New()
	a := newDaemonEnv(t, daemonOptions{fake: fake, owner: "aaaaaaaaaaaaaaaa", ingressPort: 18971, egressPort: 18972, apiPort: 18970}, nil)
	b := newDaemonEnv(t, daemonOptions{fake: fake, owner: "bbbbbbbbbbbbbbbb", ingressPort: 28971, egressPort: 28972, apiPort: 28970}, nil)
	// b's image is another harness build: the shared LLM profile must end
	// up with both images' binaries.
	const otherClaude = "/opt/defenseclaw-harness/claudecode-2/bin/claude"
	b.images.rec.NetworkBinaries = []image.Binary{{Name: "claude", Realpath: otherClaude}}
	ctx := context.Background()

	legacy, err := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: 38971})
	if err != nil {
		t.Fatal(err)
	}
	legacy.Spec.ID = profiles.LegacyIngressID
	if _, err := a.client.ImportProfiles(ctx, []openshell.ProfileImportItem{{Profile: legacy.Spec, Source: "earlier release"}}); err != nil {
		t.Fatal(err)
	}
	oldOwner := map[string]string{LabelManaged: "true", LabelOwner: "cccccccccccccccc", LabelSandbox: "old-box"}
	if _, err := a.client.CreateProvider(ctx, &openshell.Provider{Name: "old-box-ingress", Type: profiles.LegacyIngressID, Labels: oldOwner,
		Spec: openshell.ProviderSpec{Credentials: map[string]string{openshell.EnvSandboxToken: "old-token"}}}); err != nil {
		t.Fatal(err)
	}

	a.run()
	b.run()
	daemons := map[string]*harnessEnv{"a": a, "b": b}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []string
	)
	for id, e := range daemons {
		for i := 1; i <= 2; i++ {
			wg.Add(1)
			go func(e *harnessEnv, name string) {
				defer wg.Done()
				_, err := e.m.Create(ctx, sandboxapi.CreateRequest{
					Name: name, Harness: "claudecode", Project: e.project,
					LLM:         &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "sk-" + name}},
					Credentials: []sandboxapi.CredentialBinding{{Name: "STRIPE_API_KEY", Value: "stripe-" + name, Host: "api.stripe.com"}},
				})
				if err != nil {
					mu.Lock()
					errs = append(errs, name+": "+err.Error())
					mu.Unlock()
				}
			}(e, fmt.Sprintf("pn-%s-%d", id, i))
		}
	}
	wg.Wait()
	if len(errs) > 0 {
		sort.Strings(errs)
		t.Fatalf("concurrent creates failed:\n%v", errs)
	}

	check := func(e, other *harnessEnv, name string) {
		t.Helper()
		binding, err := e.store.Lookup(name)
		if err != nil {
			t.Fatalf("%s: no binding in its own daemon: %v", name, err)
		}
		if _, err := other.store.Lookup(name); err == nil {
			t.Fatalf("%s: the other daemon holds a binding for it", name)
		}
		ingress, err := e.client.GetProvider(ctx, name+"-ingress")
		if err != nil {
			t.Fatal(err)
		}
		if ingress.Type != profiles.IngressProfileID(e.ingressPort) || ingress.Labels[LabelOwner] != e.owner {
			t.Fatalf("%s: ingress provider type %s, owner %s; want %s of %s", name, ingress.Type, ingress.Labels[LabelOwner],
				profiles.IngressProfileID(e.ingressPort), e.owner)
		}
		token := ingress.Spec.Credentials[openshell.EnvSandboxToken]
		if matched, err := e.store.Match(token); err != nil || matched.ID != binding.ID {
			t.Fatalf("%s: the ingress token does not authenticate at its own daemon: %v", name, err)
		}
		if _, err := other.store.Match(token); err == nil {
			t.Fatalf("%s: the ingress token authenticates at the other daemon", name)
		}
		prof, err := e.client.GetProfile(ctx, ingress.Type)
		if err != nil || len(prof.Endpoints) != 1 || prof.Endpoints[0].Port != uint32(e.ingressPort) {
			t.Fatalf("%s: ingress profile %s = %+v, %v; want port %d", name, ingress.Type, prof, err, e.ingressPort)
		}
		pol, _ := fake.SandboxPolicy(openshell.DefaultWorkspace, name)
		if pol == nil || pol.NetworkPolicies[policy.EgressRuleName].Endpoints[0].Port != uint32(e.egressPort) {
			t.Fatalf("%s: egress rule does not reach its own daemon's proxy: %+v", name, pol)
		}
		llm, _ := e.client.GetProvider(ctx, name+"-llm")
		if llm == nil || llm.Type != profiles.AnthropicID || llm.Labels[LabelOwner] != e.owner {
			t.Fatalf("%s: llm provider = %+v", name, llm)
		}
	}
	for _, i := range []int{1, 2} {
		check(a, b, fmt.Sprintf("pn-a-%d", i))
		check(b, a, fmt.Sprintf("pn-b-%d", i))
	}

	// No ingress profile was ever updated, the legacy one included, and
	// the shared LLM profile holds both images' binaries.
	for _, e := range daemons {
		for _, id := range e.importer.updated {
			if id != profiles.AnthropicID {
				t.Fatalf("updated profile %s (updates %v)", id, e.importer.updated)
			}
		}
	}
	old, err := a.client.GetProfile(ctx, profiles.LegacyIngressID)
	if err != nil || old.ResourceVersion != 1 || old.Endpoints[0].Port != 38971 {
		t.Fatalf("the legacy ingress profile changed: %+v, %v", old, err)
	}
	shared, _ := a.client.GetProfile(ctx, profiles.AnthropicID)
	if bins := profileBinaries(*shared); !slices.Equal(bins, []string{otherClaude, testClaudeBin}) {
		t.Fatalf("shared LLM profile binaries = %v", bins)
	}

	// Reconciling either daemon leaves the other's sandboxes and providers
	// (and the earlier release's) alone.
	for _, e := range daemons {
		if err := e.m.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	all := []string{"old-box-ingress"}
	for _, n := range []string{"pn-a-1", "pn-a-2", "pn-b-1", "pn-b-2"} {
		all = append(all, n+"-cred-0", n+"-ingress", n+"-llm")
	}
	sort.Strings(all)
	if names := a.providers(); !slices.Equal(names, all) {
		t.Fatalf("providers after reconcile = %v, want %v", names, all)
	}

	// A provider name another daemon holds (its create of that name is
	// running) is refused, not replaced.
	const third = "dddddddddddddddd"
	busy := &openshell.Provider{Name: "pn-busy-ingress", Type: profiles.IngressProfileID(38972),
		Labels: map[string]string{LabelManaged: "true", LabelOwner: third, LabelSandbox: "pn-busy"},
		Spec:   openshell.ProviderSpec{Credentials: map[string]string{openshell.EnvSandboxToken: "third-token"}}}
	if _, err := a.client.CreateProvider(ctx, busy); err != nil {
		t.Fatal(err)
	}
	_, err = b.m.Create(ctx, sandboxapi.CreateRequest{Name: "pn-busy", Harness: "claudecode", Project: b.project})
	wantCode(t, err, sandboxapi.CodeConflict)
	kept, err := a.client.GetProvider(ctx, "pn-busy-ingress")
	if err != nil || kept.Labels[LabelOwner] != third || kept.Type != busy.Type || kept.Spec.Credentials[openshell.EnvSandboxToken] != "third-token" {
		t.Fatalf("the other daemon's provider was touched: %+v, %v", kept, err)
	}
	if _, err := a.client.DeleteProvider(ctx, "pn-busy-ingress"); err != nil {
		t.Fatal(err)
	}

	// Deleting a's sandboxes removes only a's providers; b's sandboxes keep
	// working against their own listener.
	for _, n := range []string{"pn-a-1", "pn-a-2"} {
		if _, err := a.m.Delete(ctx, n, sandboxapi.DeleteRequest{}); err != nil {
			t.Fatal(err)
		}
	}
	var left []string
	for _, n := range []string{"pn-b-1", "pn-b-2"} {
		left = append(left, n+"-cred-0", n+"-ingress", n+"-llm")
	}
	left = append(left, "old-box-ingress")
	sort.Strings(left)
	if names := a.providers(); !slices.Equal(names, left) {
		t.Fatalf("providers after a's deletes = %v, want %v", names, left)
	}
	for _, i := range []int{1, 2} {
		check(b, a, fmt.Sprintf("pn-b-%d", i))
	}
}

// TestCreateReplacesItsOwnLeftoverProvider pins that a provider an
// interrupted create of this data dir left behind is replaced, while one
// without DefenseClaw's labels (a user's) is refused like another daemon's.
func TestCreateReplacesItsOwnLeftoverProvider(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	left := &openshell.Provider{Name: "pn-left-ingress", Type: profiles.IngressProfileID(testIngressPort),
		Labels: map[string]string{LabelManaged: "true", LabelOwner: testOwner, LabelSandbox: "pn-left"},
		Spec:   openshell.ProviderSpec{Credentials: map[string]string{openshell.EnvSandboxToken: "stale"}}}
	if _, err := e.client.CreateProvider(ctx, left); err != nil {
		t.Fatal(err)
	}
	e.create(sandboxapi.CreateRequest{Name: "pn-left"})
	got, _ := e.client.GetProvider(ctx, "pn-left-ingress")
	if _, err := e.store.Match(got.Spec.Credentials[openshell.EnvSandboxToken]); err != nil {
		t.Fatalf("the leftover provider was not replaced: %+v", got)
	}

	user := &openshell.Provider{Name: "pn-user-ingress", Type: "generic",
		Spec: openshell.ProviderSpec{Credentials: map[string]string{"X": "y"}}}
	if _, err := e.client.CreateProvider(ctx, user); err != nil {
		t.Fatal(err)
	}
	_, err := e.m.Create(ctx, sandboxapi.CreateRequest{Name: "pn-user", Harness: "claudecode", Project: e.project})
	wantCode(t, err, sandboxapi.CodeConflict)
	if got, _ := e.client.GetProvider(ctx, "pn-user-ingress"); got == nil || got.Type != "generic" || got.Spec.Credentials["X"] != "y" {
		t.Fatalf("the user's provider was touched: %+v", got)
	}
}
