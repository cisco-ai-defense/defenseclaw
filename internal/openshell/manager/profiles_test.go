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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/policy"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestPlanLLM(t *testing.T) {
	spec, _ := harness.Get("claudecode")
	anthropic := func(creds map[string]string) *sandboxapi.LLMCredential {
		return &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: creds}
	}
	for _, tc := range []struct {
		name string
		req  *sandboxapi.LLMCredential
		ok   bool
	}{
		{"none", nil, true},
		{"anthropic", anthropic(map[string]string{"ANTHROPIC_API_KEY": "k"}), true},
		{"oauth", &sandboxapi.LLMCredential{Profile: profiles.ClaudeOAuthID, Credentials: map[string]string{"CLAUDE_CODE_OAUTH_TOKEN": "t"}}, true},
		{"wrong harness profile", &sandboxapi.LLMCredential{Profile: profiles.OpenAIID, Credentials: map[string]string{"OPENAI_API_KEY": "k"}}, false},
		{"foreign variable", anthropic(map[string]string{"ANTHROPIC_API_KEY": "k", "AWS_SECRET": "x"}), false},
		{"missing variable", anthropic(nil), false},
		{"multi-line value", anthropic(map[string]string{"ANTHROPIC_API_KEY": "a\nb"}), false},
	} {
		plan, err := planLLM(spec, tc.req, []string{testClaudeBin})
		if (err == nil) != tc.ok || (tc.ok && tc.req != nil && (plan == nil || plan.profile.ID != tc.req.Profile)) {
			t.Errorf("%s: planLLM = %+v, %v", tc.name, plan, err)
		}
	}
	if _, err := planLLM(spec, anthropic(map[string]string{"ANTHROPIC_API_KEY": "k"}), nil); err == nil {
		t.Fatal("planned an LLM credential with no binaries to pin")
	}
}

func TestPlanCredentials(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.APIPort = 18970
	eff, _, err := packs.Resolve(cfg, packs.Flags{})
	must(t, err)
	reserved := map[string]bool{"ANTHROPIC_API_KEY": true}
	good, err := planCredentials(eff, []sandboxapi.CredentialBinding{
		{Name: "STRIPE_API_KEY", Value: "s", Host: "API.Stripe.com"},
		{Name: "MOCK_KEY", Value: "m", Host: "host.openshell.internal", Port: 18921},
	}, reserved)
	if err != nil || len(good) != 2 || good[0].binding.Port != 443 || good[0].binding.Host != "api.stripe.com" ||
		good[0].profile.ID == good[1].profile.ID || good[1].profile.Spec.Endpoints[0].Port != 18921 {
		t.Fatalf("plan = %+v, %v", good, err)
	}
	one := func(name, value, host string, port int) []sandboxapi.CredentialBinding {
		return []sandboxapi.CredentialBinding{{Name: name, Value: value, Host: host, Port: port}}
	}
	for name, list := range map[string][]sandboxapi.CredentialBinding{
		"duplicate":        {{Name: "A", Value: "1", Host: "a.example"}, {Name: "A", Value: "2", Host: "b.example"}},
		"reserved":         one("ANTHROPIC_API_KEY", "1", "a.example", 0),
		"defenseclaw":      one(openshell.EnvSandboxToken, "1", "a.example", 0),
		"bad host":         one("A", "1", "https://a.example", 0),
		"wildcard":         one("A", "1", "*.example.com", 0),
		"blocklisted":      one("A", "1", "webhook.site", 0),
		"metadata":         one("A", "1", "169.254.169.254", 80),
		"api port":         one("A", "1", "host.openshell.internal", 18970),
		"gateway port":     one("A", "1", "host.openshell.internal", 17670),
		"empty value":      one("A", "", "a.example", 0),
		"loopback literal": one("A", "1", "127.0.0.1", 5432),
	} {
		if _, err := planCredentials(eff, list, reserved); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateExtraEnv(t *testing.T) {
	pinned := map[string]string{"DISABLE_AUTOUPDATER": "1"}
	must(t, validateExtraEnv(map[string]string{"ANTHROPIC_BASE_URL": "http://host.openshell.internal:18921", "FOO": "bar"}, pinned))
	for _, bad := range []map[string]string{
		{"DISABLE_AUTOUPDATER": "0"}, {"no_proxy": "*"}, {"PATH": "/tmp"}, {"BAD-NAME": "x"}, {"X": "a\nb"},
		{"DYLD_INSERT_LIBRARIES": "x"}, {"OPENSHELL_GATEWAY": "x"},
	} {
		if err := validateExtraEnv(bad, pinned); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

// A profile is imported once; another ingress port is another listener's
// profile, imported next to this one; LLM profiles merge network binaries
// from other images at the resource version they read.
func TestEnsureProfileImportsOnceAndUpdatesOnChange(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	p, err := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: testIngressPort})
	must(t, err)
	must(t, e.m.ensureProfile(ctx, e.gw, p, nil))
	must(t, e.m.ensureProfile(ctx, e.gw, p, nil))
	moved, _ := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: 28971})
	must(t, e.m.ensureProfile(ctx, e.gw, moved, nil))
	if len(e.importer.imported) != 2 || len(e.importer.updated) != 0 {
		t.Fatalf("imported %v updated %v, want each port's profile imported once", e.importer.imported, e.importer.updated)
	}
	for port, id := range map[int]string{testIngressPort: p.ID, 28971: moved.ID} {
		if got, err := e.client.GetProfile(ctx, id); err != nil || got.Endpoints[0].Port != uint32(port) {
			t.Fatalf("profile %s = %+v, %v", id, got, err)
		}
	}
	render := func(bins []string) (profiles.Profile, error) {
		return profiles.Render(profiles.AnthropicID, profiles.Input{Binaries: bins})
	}
	first, _ := render([]string{"/opt/a/claude"})
	second, _ := render([]string{"/opt/b/claude"})
	must(t, e.m.ensureProfile(ctx, e.gw, first, render))
	must(t, e.m.ensureProfile(ctx, e.gw, second, render))
	if got, _ := e.client.GetProfile(ctx, profiles.AnthropicID); len(got.Binaries) != 2 || got.ResourceVersion != 2 {
		t.Fatalf("binaries = %+v at version %d", got.Binaries, got.ResourceVersion)
	}
	// The image's own binaries again change nothing.
	if err := e.m.ensureProfile(ctx, e.gw, first, render); err != nil || len(e.importer.updated) != 1 {
		t.Fatalf("unchanged profile re-imported: %v, updated %v", err, e.importer.updated)
	}
	e.m.opts.Profiles = nil
	other, _ := profiles.Render(profiles.OpenAIID, profiles.Input{Binaries: []string{"/opt/codex"}})
	if err := e.m.ensureProfile(ctx, e.gw, other, nil); !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) {
		t.Fatalf("missing profile without importer: %v", err)
	}
}

// A shared profile another DefenseClaw daemon imports or updates under this
// one is merged with, not overwritten or failed on; a failure that is not a
// race is reported at once.
func TestEnsureProfileSurvivesAnotherDaemon(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	render := func(bins []string) (profiles.Profile, error) {
		return profiles.Render(profiles.OpenAIID, profiles.Input{Binaries: bins})
	}
	ours, _ := render([]string{"/opt/ours/codex"})
	theirs, _ := render([]string{"/opt/theirs/codex"})
	later, _ := render([]string{"/opt/later/codex"})
	binaries := func() []string { got, _ := e.client.GetProfile(ctx, profiles.OpenAIID); return profileBinaries(*got) }
	// The other daemon imports the same profile first: our import fails, and the next pass merges into theirs.
	raced := false
	e.importer.before = func(_ profiles.Profile, rv uint64) {
		if !raced && rv == 0 {
			raced = true
			_, err := e.client.ImportProfiles(ctx, []openshell.ProfileImportItem{{Profile: theirs.Spec, Source: "other daemon"}})
			must(t, err)
		}
	}
	must(t, e.m.ensureProfile(ctx, e.gw, ours, render))
	if bins := binaries(); !slices.Equal(bins, []string{"/opt/ours/codex", "/opt/theirs/codex"}) {
		t.Fatalf("binaries after a concurrent import = %v", bins)
	}
	// The other daemon updates it between our read and our update: the retry keeps their binary too.
	raced = false
	e.importer.before = func(_ profiles.Profile, rv uint64) {
		if !raced && rv != 0 {
			raced = true
			cur, _ := e.client.GetProfile(ctx, profiles.OpenAIID)
			mine, _ := render(append(profileBinaries(*cur), "/opt/theirs2/codex"))
			_, err := e.client.UpdateProfile(ctx, profiles.OpenAIID, cur.ResourceVersion, openshell.ProfileImportItem{Profile: mine.Spec, Source: "other daemon"})
			must(t, err)
		}
	}
	must(t, e.m.ensureProfile(ctx, e.gw, later, render))
	if bins := binaries(); !slices.Equal(bins, []string{"/opt/later/codex", "/opt/ours/codex", "/opt/theirs/codex", "/opt/theirs2/codex"}) {
		t.Fatalf("binaries after a concurrent update = %v", bins)
	}
	e.importer.before = nil
	e.importer.err = errors.New("openshell: boom")
	fresh, _ := profiles.Render(profiles.ClaudeOAuthID, profiles.Input{Binaries: []string{testClaudeBin}})
	for what, try := range map[string]func() error{
		"import": func() error { return e.m.ensureProfile(ctx, e.gw, fresh, nil) },
		// An update refused while nobody else changed the profile.
		"update": func() error {
			return e.m.ensureProfile(ctx, e.gw, theirs, func(bins []string) (profiles.Profile, error) { return render(append(bins, "/opt/newer/codex")) })
		},
	} {
		calls := e.importer.calls
		if err := try(); !sandboxapi.IsCode(err, sandboxapi.CodeUpstream) || e.importer.calls-calls != 1 {
			t.Fatalf("failed %s = %v after %d tries, want one", what, err, e.importer.calls-calls)
		}
	}
}

// The upstream CLI calls: an import, and an update whose file names the
// resource version it replaces (OpenShell 0.1.1 refuses one without it).
func TestCLIProfileImporter(t *testing.T) {
	p, err := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: 29001})
	must(t, err)
	run := &captureRunner{}
	imp := CLIProfileImporter{Binary: "/usr/local/bin/openshell", Runner: run, TempDir: t.TempDir()}
	must(t, imp.Import(t.Context(), "openshell", p, 0))
	must(t, imp.Import(t.Context(), "openshell", p, 7))
	if len(run.calls) != 2 {
		t.Fatalf("calls = %v", run.calls)
	}
	imported, updated := run.calls[0], run.calls[1]
	if imported.Name != "/usr/local/bin/openshell" || !slices.Equal(imported.Args[:2], []string{"profile", "import"}) ||
		!slices.Contains(imported.Args, "--global") || imported.Args[len(imported.Args)-1] != "openshell" {
		t.Fatalf("import = %v", imported)
	}
	if !slices.Equal(updated.Args[:2], []string{"profile", "update"}) || updated.Args[len(updated.Args)-1] != "defenseclaw-ingress-29001" {
		t.Fatalf("update = %v", updated)
	}
	if !bytes.Equal(run.files[0], p.YAML) || !bytes.Equal(run.files[1], append([]byte("resource_version: 7\n"), p.YAML...)) {
		t.Fatalf("files:\n%s\n%s", run.files[0], run.files[1])
	}
	if err := imp.Import(t.Context(), "", p, 0); err == nil {
		t.Fatal("imported without a gateway name")
	}
	run.err, run.out = errors.New("exit status 1"), []byte("line\n  × provider profile update failed\n")
	if err := imp.Import(t.Context(), "openshell", p, 7); err == nil || !strings.Contains(err.Error(), "provider profile update failed") {
		t.Fatalf("failed update = %v", err)
	}
}

// captureRunner records commands and the profile file each one names.
type captureRunner struct {
	calls []openshell.Command
	files [][]byte
	out   []byte
	err   error
}

func (r *captureRunner) Output(_ context.Context, cmd openshell.Command) ([]byte, error) {
	r.calls = append(r.calls, cmd)
	for i, a := range cmd.Args {
		if a == "-f" && i+1 < len(cmd.Args) {
			data, err := os.ReadFile(cmd.Args[i+1])
			if err != nil {
				return nil, err
			}
			r.files = append(r.files, data)
		}
	}
	return r.out, r.err
}

func (r *captureRunner) Run(context.Context, openshell.Command) error { return nil }

// Two daemons (data dirs with their own ports) share a gateway that still
// holds an earlier release's legacy ingress profile: their concurrent creates
// all succeed, each token binds to its own daemon's listener, and neither
// touches the other's objects.
func TestTwoDaemonsShareAGateway(t *testing.T) {
	fake := openshelltest.New()
	a := newDaemonEnv(t, daemonOptions{fake: fake, owner: "aaaaaaaaaaaaaaaa", ingressPort: 18971, egressPort: 18972, apiPort: 18970}, nil)
	b := newDaemonEnv(t, daemonOptions{fake: fake, owner: "bbbbbbbbbbbbbbbb", ingressPort: 28971, egressPort: 28972, apiPort: 28970}, nil)
	// b's image is another harness build: the shared LLM profile must end up with both images' binaries.
	const otherClaude = "/opt/defenseclaw-harness/claudecode-2/bin/claude"
	b.images.rec.NetworkBinaries = []image.Binary{{Name: "claude", Realpath: otherClaude}}
	ctx := t.Context()
	legacy, err := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: 38971})
	must(t, err)
	legacy.Spec.ID = profiles.LegacyIngressID
	_, err = a.client.ImportProfiles(ctx, []openshell.ProfileImportItem{{Profile: legacy.Spec, Source: "earlier release"}})
	must(t, err)
	_, err = a.client.CreateProvider(ctx, &openshell.Provider{Name: "old-box-ingress", Type: profiles.LegacyIngressID,
		Labels: map[string]string{LabelManaged: "true", LabelOwner: "cccccccccccccccc", LabelSandbox: "old-box"},
		Spec:   openshell.ProviderSpec{Credentials: map[string]string{openshell.EnvSandboxToken: "old-token"}}})
	must(t, err)

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
			name := fmt.Sprintf("pn-%s-%d", id, i)
			project := e.otherProject(name) // one folder is mounted live by one sandbox at a time
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := e.m.Create(ctx, sandboxapi.CreateRequest{Name: name, Harness: "claudecode", Project: project,
					LLM:         &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "sk-" + name}},
					Credentials: []sandboxapi.CredentialBinding{{Name: "STRIPE_API_KEY", Value: "stripe-" + name, Host: "api.stripe.com"}}})
				if err != nil {
					mu.Lock()
					errs = append(errs, name+": "+err.Error())
					mu.Unlock()
				}
			}()
		}
	}
	wg.Wait()
	if len(errs) > 0 {
		sort.Strings(errs)
		t.Fatalf("concurrent creates failed:\n%v", errs)
	}
	check := func(e, other *harnessEnv, name string) {
		t.Helper()
		binding := e.binding(name)
		if _, err := other.store.Lookup(name); err == nil {
			t.Fatalf("%s: the other daemon holds a binding for it", name)
		}
		ingress, err := e.client.GetProvider(ctx, name+"-ingress")
		must(t, err)
		if ingress.Type != profiles.IngressProfileID(e.ingressPort) || ingress.Labels[LabelOwner] != e.owner {
			t.Fatalf("%s: ingress provider type %s, owner %s; want %s of %s", name, ingress.Type, ingress.Labels[LabelOwner], profiles.IngressProfileID(e.ingressPort), e.owner)
		}
		token := ingress.Spec.Credentials[openshell.EnvSandboxToken]
		if matched, err := e.store.Match(token); err != nil || matched.ID != binding.ID {
			t.Fatalf("%s: the ingress token does not authenticate at its own daemon: %v", name, err)
		}
		if _, err := other.store.Match(token); err == nil {
			t.Fatalf("%s: the ingress token authenticates at the other daemon", name)
		}
		if prof, err := e.client.GetProfile(ctx, ingress.Type); err != nil || len(prof.Endpoints) != 1 || prof.Endpoints[0].Port != uint32(e.ingressPort) {
			t.Fatalf("%s: ingress profile %s = %+v, %v; want port %d", name, ingress.Type, prof, err, e.ingressPort)
		}
		if pol, _ := fake.SandboxPolicy(openshell.DefaultWorkspace, name); pol == nil || pol.NetworkPolicies[policy.EgressRuleName].Endpoints[0].Port != uint32(e.egressPort) {
			t.Fatalf("%s: egress rule does not reach its own daemon's proxy: %+v", name, pol)
		}
		if llm, _ := e.client.GetProvider(ctx, name+"-llm"); llm == nil || llm.Type != profiles.AnthropicID || llm.Labels[LabelOwner] != e.owner {
			t.Fatalf("%s: llm provider = %+v", name, llm)
		}
	}
	for _, i := range []int{1, 2} {
		check(a, b, fmt.Sprintf("pn-a-%d", i))
		check(b, a, fmt.Sprintf("pn-b-%d", i))
	}
	// No ingress profile was ever updated, the legacy one included; the shared LLM profile holds both images' binaries.
	for _, e := range daemons {
		for _, id := range e.importer.updated {
			if id != profiles.AnthropicID {
				t.Fatalf("updated profile %s (updates %v)", id, e.importer.updated)
			}
		}
	}
	if old, err := a.client.GetProfile(ctx, profiles.LegacyIngressID); err != nil || old.ResourceVersion != 1 || old.Endpoints[0].Port != 38971 {
		t.Fatalf("the legacy ingress profile changed: %+v, %v", old, err)
	}
	if shared, _ := a.client.GetProfile(ctx, profiles.AnthropicID); !slices.Equal(profileBinaries(*shared), []string{otherClaude, testClaudeBin}) {
		t.Fatalf("shared LLM profile binaries = %v", profileBinaries(*shared))
	}
	// Reconciling either daemon leaves the other's sandboxes and providers (and the earlier release's) alone.
	for _, e := range daemons {
		must(t, e.m.Reconcile(ctx))
	}
	providersOf := func(names ...string) []string {
		out := []string{"old-box-ingress"}
		for _, n := range names {
			out = append(out, n+"-cred-0", n+"-ingress", n+"-llm")
		}
		sort.Strings(out)
		return out
	}
	if names := a.providers(); !slices.Equal(names, providersOf("pn-a-1", "pn-a-2", "pn-b-1", "pn-b-2")) {
		t.Fatalf("providers after reconcile = %v", names)
	}
	// Deleting a's sandboxes removes only a's providers; b's sandboxes keep working against their own listener.
	a.deleteBox("pn-a-1", sandboxapi.DeleteRequest{})
	a.deleteBox("pn-a-2", sandboxapi.DeleteRequest{})
	if names := a.providers(); !slices.Equal(names, providersOf("pn-b-1", "pn-b-2")) {
		t.Fatalf("providers after a's deletes = %v", names)
	}
	for _, i := range []int{1, 2} {
		check(b, a, fmt.Sprintf("pn-b-%d", i))
	}
}

// A provider an interrupted create of this data dir left behind is replaced,
// while one another daemon holds (its create of that name is running) or one
// without DefenseClaw's labels (a user's) is refused, not touched.
func TestCreateReplacesItsOwnLeftoverProvider(t *testing.T) {
	e := newEnv(t, nil)
	ctx := t.Context()
	_, err := e.client.CreateProvider(ctx, &openshell.Provider{Name: "pn-left-ingress", Type: profiles.IngressProfileID(testIngressPort),
		Labels: map[string]string{LabelManaged: "true", LabelOwner: testOwner, LabelSandbox: "pn-left"},
		Spec:   openshell.ProviderSpec{Credentials: map[string]string{openshell.EnvSandboxToken: "stale"}}})
	must(t, err)
	e.create(sandboxapi.CreateRequest{Name: "pn-left"})
	if _, err := e.store.Match(e.ingressToken("pn-left")); err != nil {
		t.Fatal("the leftover provider was not replaced")
	}
	for name, labels := range map[string]map[string]string{
		"pn-busy": {LabelManaged: "true", LabelOwner: "dddddddddddddddd", LabelSandbox: "pn-busy"},
		"pn-user": nil,
	} {
		_, err = e.client.CreateProvider(ctx, &openshell.Provider{Name: name + "-ingress", Type: "generic", Labels: labels,
			Spec: openshell.ProviderSpec{Credentials: map[string]string{"X": "y"}}})
		must(t, err)
		_, err = e.tryCreate(sandboxapi.CreateRequest{Name: name, Project: e.otherProject(name)})
		wantCode(t, err, sandboxapi.CodeConflict)
		if got, _ := e.client.GetProvider(ctx, name+"-ingress"); got == nil || got.Type != "generic" || got.Spec.Credentials["X"] != "y" ||
			got.Labels[LabelOwner] != labels[LabelOwner] {
			t.Fatalf("%s: the other's provider was touched: %+v", name, got)
		}
	}
}
