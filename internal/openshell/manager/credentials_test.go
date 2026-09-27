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
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestPlanLLM(t *testing.T) {
	spec, _ := harness.Get("claudecode")
	bins := []string{testClaudeBin}
	for _, tc := range []struct {
		name string
		req  *sandboxapi.LLMCredential
		ok   bool
	}{
		{"none", nil, true},
		{"anthropic", &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "k"}}, true},
		{"oauth", &sandboxapi.LLMCredential{Profile: profiles.ClaudeOAuthID, Credentials: map[string]string{"CLAUDE_CODE_OAUTH_TOKEN": "t"}}, true},
		{"wrong harness profile", &sandboxapi.LLMCredential{Profile: profiles.OpenAIID, Credentials: map[string]string{"OPENAI_API_KEY": "k"}}, false},
		{"foreign variable", &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "k", "AWS_SECRET": "x"}}, false},
		{"missing variable", &sandboxapi.LLMCredential{Profile: profiles.AnthropicID}, false},
		{"multi-line value", &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "a\nb"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := planLLM(spec, tc.req, bins)
			if (err == nil) != tc.ok {
				t.Fatalf("planLLM = %+v, %v", plan, err)
			}
			if tc.ok && tc.req != nil && (plan == nil || plan.profile.ID != tc.req.Profile) {
				t.Fatalf("plan = %+v", plan)
			}
		})
	}
	if _, err := planLLM(spec, &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "k"}}, nil); err == nil {
		t.Fatal("planned an LLM credential with no binaries to pin")
	}
}

func TestPlanCredentials(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.APIPort = 18970
	eff, _, err := packs.Resolve(cfg, packs.Flags{})
	if err != nil {
		t.Fatal(err)
	}
	reserved := map[string]bool{"ANTHROPIC_API_KEY": true}
	good, err := planCredentials(eff, []sandboxapi.CredentialBinding{
		{Name: "STRIPE_API_KEY", Value: "s", Host: "API.Stripe.com"},
		{Name: "MOCK_KEY", Value: "m", Host: "host.openshell.internal", Port: 18921},
	}, reserved)
	if err != nil || len(good) != 2 || good[0].binding.Port != 443 || good[0].binding.Host != "api.stripe.com" {
		t.Fatalf("plan = %+v, %v", good, err)
	}
	if good[0].profile.ID == good[1].profile.ID || good[1].profile.Spec.Endpoints[0].Port != 18921 {
		t.Fatalf("profiles = %+v %+v", good[0].profile.Spec, good[1].profile.Spec)
	}
	for name, list := range map[string][]sandboxapi.CredentialBinding{
		"duplicate":        {{Name: "A", Value: "1", Host: "a.example"}, {Name: "A", Value: "2", Host: "b.example"}},
		"reserved":         {{Name: "ANTHROPIC_API_KEY", Value: "1", Host: "a.example"}},
		"defenseclaw":      {{Name: openshell.EnvSandboxToken, Value: "1", Host: "a.example"}},
		"bad host":         {{Name: "A", Value: "1", Host: "https://a.example"}},
		"wildcard":         {{Name: "A", Value: "1", Host: "*.example.com"}},
		"blocklisted":      {{Name: "A", Value: "1", Host: "webhook.site"}},
		"metadata":         {{Name: "A", Value: "1", Host: "169.254.169.254", Port: 80}},
		"api port":         {{Name: "A", Value: "1", Host: "host.openshell.internal", Port: 18970}},
		"gateway port":     {{Name: "A", Value: "1", Host: "host.openshell.internal", Port: 17670}},
		"empty value":      {{Name: "A", Value: "", Host: "a.example"}},
		"loopback literal": {{Name: "A", Value: "1", Host: "127.0.0.1", Port: 5432}},
	} {
		if _, err := planCredentials(eff, list, reserved); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateExtraEnv(t *testing.T) {
	pinned := map[string]string{"DISABLE_AUTOUPDATER": "1"}
	if err := validateExtraEnv(map[string]string{"ANTHROPIC_BASE_URL": "http://host.openshell.internal:18921", "FOO": "bar"}, pinned); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]string{
		{"DISABLE_AUTOUPDATER": "0"}, {"no_proxy": "*"}, {"PATH": "/tmp"}, {"BAD-NAME": "x"}, {"X": "a\nb"},
		{"DYLD_INSERT_LIBRARIES": "x"}, {"OPENSHELL_GATEWAY": "x"},
	} {
		if err := validateExtraEnv(bad, pinned); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestEnsureProfileImportsOnceAndUpdatesOnChange(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	p, err := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: testIngressPort})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := e.m.ensureProfile(ctx, e.gw, p, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.importer.imported) != 1 || len(e.importer.updated) != 0 {
		t.Fatalf("imported %v updated %v", e.importer.imported, e.importer.updated)
	}
	// Another ingress port is another listener's profile: imported next to
	// this one, which keeps its endpoint.
	moved, _ := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: 28971})
	if err := e.m.ensureProfile(ctx, e.gw, moved, nil); err != nil {
		t.Fatal(err)
	}
	if len(e.importer.imported) != 2 || len(e.importer.updated) != 0 {
		t.Fatalf("a port change updated a profile: imported %v updated %v", e.importer.imported, e.importer.updated)
	}
	for port, id := range map[int]string{testIngressPort: p.ID, 28971: moved.ID} {
		if got, err := e.client.GetProfile(ctx, id); err != nil || got.Endpoints[0].Port != uint32(port) {
			t.Fatalf("profile %s = %+v, %v", id, got, err)
		}
	}

	// LLM profiles merge network binaries from other images, updating the
	// profile at the resource version they read.
	render := func(bins []string) (profiles.Profile, error) {
		return profiles.Render(profiles.AnthropicID, profiles.Input{Binaries: bins})
	}
	first, _ := render([]string{"/opt/a/claude"})
	second, _ := render([]string{"/opt/b/claude"})
	if err := e.m.ensureProfile(ctx, e.gw, first, render); err != nil {
		t.Fatal(err)
	}
	if err := e.m.ensureProfile(ctx, e.gw, second, render); err != nil {
		t.Fatal(err)
	}
	got, _ := e.client.GetProfile(ctx, profiles.AnthropicID)
	if len(got.Binaries) != 2 || got.ResourceVersion != 2 {
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

// TestEnsureProfileSurvivesAnotherDaemon pins that a shared profile another
// DefenseClaw daemon imports or updates under this one is merged with, not
// overwritten or failed on.
func TestEnsureProfileSurvivesAnotherDaemon(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	render := func(bins []string) (profiles.Profile, error) {
		return profiles.Render(profiles.OpenAIID, profiles.Input{Binaries: bins})
	}
	ours, _ := render([]string{"/opt/ours/codex"})
	theirs, _ := render([]string{"/opt/theirs/codex"})
	later, _ := render([]string{"/opt/later/codex"})

	// The other daemon imports the same profile first: our import fails,
	// and the next pass merges into theirs.
	raced := 0
	e.importer.before = func(p profiles.Profile, rv uint64) {
		if raced == 0 && rv == 0 {
			raced++
			if _, err := e.client.ImportProfiles(ctx, []openshell.ProfileImportItem{{Profile: theirs.Spec, Source: "other daemon"}}); err != nil {
				t.Errorf("other daemon's import: %v", err)
			}
		}
	}
	if err := e.m.ensureProfile(ctx, e.gw, ours, render); err != nil {
		t.Fatalf("ensureProfile after a concurrent import: %v", err)
	}
	got, _ := e.client.GetProfile(ctx, profiles.OpenAIID)
	if bins := profileBinaries(*got); !slices.Equal(bins, []string{"/opt/ours/codex", "/opt/theirs/codex"}) {
		t.Fatalf("binaries after a concurrent import = %v", bins)
	}

	// The other daemon updates it between our read and our update: the
	// stale update is refused, and the retry keeps their binary too.
	raced = 0
	e.importer.before = func(p profiles.Profile, rv uint64) {
		if raced == 0 && rv != 0 {
			raced++
			cur, _ := e.client.GetProfile(ctx, profiles.OpenAIID)
			mine, _ := render(append(profileBinaries(*cur), "/opt/theirs2/codex"))
			if _, err := e.client.UpdateProfile(ctx, profiles.OpenAIID, cur.ResourceVersion, openshell.ProfileImportItem{Profile: mine.Spec, Source: "other daemon"}); err != nil {
				t.Errorf("other daemon's update: %v", err)
			}
		}
	}
	if err := e.m.ensureProfile(ctx, e.gw, later, render); err != nil {
		t.Fatalf("ensureProfile after a concurrent update: %v", err)
	}
	got, _ = e.client.GetProfile(ctx, profiles.OpenAIID)
	want := []string{"/opt/later/codex", "/opt/ours/codex", "/opt/theirs/codex", "/opt/theirs2/codex"}
	if bins := profileBinaries(*got); !slices.Equal(bins, want) {
		t.Fatalf("binaries after a concurrent update = %v, want %v", bins, want)
	}

	// A failure that is not a race is reported at once.
	e.importer.before = nil
	e.importer.err = errors.New("openshell: boom")
	calls := e.importer.calls
	fresh, _ := profiles.Render(profiles.ClaudeOAuthID, profiles.Input{Binaries: []string{testClaudeBin}})
	if err := e.m.ensureProfile(ctx, e.gw, fresh, nil); !sandboxapi.IsCode(err, sandboxapi.CodeUpstream) {
		t.Fatalf("import failure = %v", err)
	}
	if n := e.importer.calls - calls; n != 1 {
		t.Fatalf("a failed import was tried %d times", n)
	}
	// So is an update refused while nobody else changed the profile.
	calls = e.importer.calls
	if err := e.m.ensureProfile(ctx, e.gw, theirs, func(bins []string) (profiles.Profile, error) {
		return render(append(bins, "/opt/newer/codex"))
	}); !sandboxapi.IsCode(err, sandboxapi.CodeUpstream) {
		t.Fatalf("update failure = %v", err)
	}
	if n := e.importer.calls - calls; n != 1 {
		t.Fatalf("a failed update was tried %d times", n)
	}
}

// TestCLIProfileImporter pins the upstream CLI calls: an import, and an
// update whose file names the resource version it replaces (OpenShell
// 0.1.1 refuses an update without one).
func TestCLIProfileImporter(t *testing.T) {
	p, err := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: 29001})
	if err != nil {
		t.Fatal(err)
	}
	run := &captureRunner{}
	imp := CLIProfileImporter{Binary: "/usr/local/bin/openshell", Runner: run, TempDir: t.TempDir()}
	ctx := context.Background()
	if err := imp.Import(ctx, "openshell", p, 0); err != nil {
		t.Fatal(err)
	}
	if err := imp.Import(ctx, "openshell", p, 7); err != nil {
		t.Fatal(err)
	}
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
	if !bytes.Equal(run.files[0], p.YAML) {
		t.Fatalf("import file:\n%s", run.files[0])
	}
	if want := append([]byte("resource_version: 7\n"), p.YAML...); !bytes.Equal(run.files[1], want) {
		t.Fatalf("update file:\n%s", run.files[1])
	}
	if err := imp.Import(ctx, "", p, 0); err == nil {
		t.Fatal("imported without a gateway name")
	}
	run.err = errors.New("exit status 1")
	run.out = []byte("line\n  × provider profile update failed\n")
	if err := imp.Import(ctx, "openshell", p, 7); err == nil || !strings.Contains(err.Error(), "provider profile update failed") {
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
