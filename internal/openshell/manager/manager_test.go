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
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/policy"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

func TestCreateMountMode(t *testing.T) {
	e := newEnv(t, nil)
	e.ws.masked = []workspace.MaskedPath{{Rel: ".env", Reason: "name"}}
	e.run()
	sb := e.create(sandboxapi.CreateRequest{
		Name: "dc-claude-myapp-1a2b",
		LLM:  &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "sk-test-secret"}},
		Credentials: []sandboxapi.CredentialBinding{
			{Name: "STRIPE_API_KEY", Value: "stripe-secret", Host: "api.stripe.com"},
		},
		Env: map[string]string{"MY_FLAG": "1"},
	})
	if sb.Name != "dc-claude-myapp-1a2b" || sb.Phase != "ready" || sb.WorkdirMode != "mount" || sb.Workdir != "/work/myapp" {
		t.Fatalf("sandbox = %+v", sb)
	}
	if sb.Profile != "open" || !sb.Yolo || sb.Pack != "open" || sb.Launch.CredentialProfile != profiles.AnthropicID {
		t.Fatalf("posture = %+v", sb)
	}
	if sb.Snapshot == nil || sb.Snapshot.Kind != "git" {
		t.Fatalf("snapshot = %+v", sb.Snapshot)
	}

	// The OpenShell sandbox.
	got, err := e.client.GetSandbox(context.Background(), sb.Name)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		LabelManaged: "true", LabelOwner: testOwner, LabelHarness: "claudecode", LabelProfile: "open",
		LabelPack: "open", LabelWorkdirMode: "mount",
	} {
		if got.Labels[k] != v {
			t.Fatalf("label %s = %q, want %q (labels %v)", k, got.Labels[k], v, got.Labels)
		}
	}
	if key, value := workspace.ProjectLabel(e.project); got.Labels[key] != value {
		t.Fatalf("project label missing: %v", got.Labels)
	}
	env := got.Spec.Environment
	binding, err := e.store.Lookup(sb.Name)
	if err != nil {
		t.Fatal(err)
	}
	if env[openshell.EnvSandboxName] != sb.Name || env[openshell.EnvSandboxID] != binding.ID {
		t.Fatalf("identity env = %v", env)
	}
	if _, leaked := env[openshell.EnvSandboxToken]; leaked {
		t.Fatal("the binding token is in the plain environment with provider delivery")
	}
	proxy, err := url.Parse(env["HTTPS_PROXY"])
	if err != nil || proxy.Host != "host.openshell.internal:18972" || proxy.User == nil {
		t.Fatalf("HTTPS_PROXY = %q", env["HTTPS_PROXY"])
	}
	pass, _ := proxy.User.Password()
	if p, ok := e.m.creds.Authenticate(proxy.User.Username(), pass); !ok || p.BindingID != binding.ID || p.SandboxName != sb.Name {
		t.Fatalf("proxy credential not registered: %+v %v", p, ok)
	}
	if !strings.Contains(env["NO_PROXY"], "api.anthropic.com") || !strings.Contains(env["NO_PROXY"], "api.stripe.com") ||
		!strings.Contains(env["NO_PROXY"], "host.openshell.internal") {
		t.Fatalf("NO_PROXY = %q", env["NO_PROXY"])
	}
	if env["MY_FLAG"] != "1" || env["NODE_USE_ENV_PROXY"] != "1" {
		t.Fatalf("env = %v", env)
	}
	// OpenShell drops *_PROXY variables; the launchers export these.
	if env[openshell.EnvEgressURL] != env["HTTPS_PROXY"] || env[openshell.EnvEgressBypass] != env["NO_PROXY"] {
		t.Fatalf("egress aliases = %q %q", env[openshell.EnvEgressURL], env[openshell.EnvEgressBypass])
	}
	if _, secret := env["ANTHROPIC_API_KEY"]; secret {
		t.Fatal("the LLM key is in the plain environment")
	}
	tmpl := got.Spec.Template
	if tmpl == nil || tmpl.Image != "defenseclaw/sandbox-claudecode:test" {
		t.Fatalf("template = %+v", tmpl)
	}
	mounts := tmpl.DriverConfig["docker"].(map[string]any)["mounts"].([]any)
	if len(mounts) != 2 || mounts[0].(map[string]any)["target"] != "/work/myapp" {
		t.Fatalf("mounts = %v", mounts)
	}
	pol, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, sb.Name)
	if pol == nil || pol.NetworkPolicies[policy.EgressRuleName].Name == "" {
		t.Fatalf("policy has no egress rule: %+v", pol)
	}
	if pol.Process == nil || pol.Process.RunAsUser != "1000" {
		t.Fatalf("policy process = %+v", pol.Process)
	}

	// Providers, one per credential, with the binding token behind the
	// ingress profile.
	wantProviders := []string{sb.Name + "-cred-0", sb.Name + "-ingress", sb.Name + "-llm"}
	if names := e.providers(); !slices.Equal(names, wantProviders) {
		t.Fatalf("providers = %v, want %v", names, wantProviders)
	}
	if !slices.Equal(got.Spec.Providers, []string{sb.Name + "-ingress", sb.Name + "-llm", sb.Name + "-cred-0"}) {
		t.Fatalf("attached providers = %v", got.Spec.Providers)
	}
	ingress, err := e.client.GetProvider(context.Background(), sb.Name+"-ingress")
	if err != nil {
		t.Fatal(err)
	}
	if ingress.Type != profiles.IngressID || ingress.Labels[LabelSandbox] != sb.Name {
		t.Fatalf("ingress provider = %+v", ingress)
	}
	matched, err := e.store.Match(ingress.Spec.Credentials[openshell.EnvSandboxToken])
	if err != nil || matched.ID != binding.ID {
		t.Fatalf("ingress token does not authenticate the binding: %v", err)
	}
	llm, _ := e.client.GetProvider(context.Background(), sb.Name+"-llm")
	if llm.Type != profiles.AnthropicID || llm.Spec.Credentials["ANTHROPIC_API_KEY"] != "sk-test-secret" {
		t.Fatalf("llm provider = %+v", llm)
	}
	if !slices.Contains(e.importer.imported, profiles.IngressID) || !slices.Contains(e.importer.imported, profiles.AnthropicID) {
		t.Fatalf("imported profiles = %v", e.importer.imported)
	}

	// The binding describes the mount for FSView and carries the sandbox id.
	if binding.Workdir.Mode != sandboxauth.WorkdirMount || len(binding.Workdir.Mounts) != 1 ||
		binding.Workdir.Mounts[0].SandboxPath != "/work/myapp" || binding.Workdir.Mounts[0].HostPath != e.project {
		t.Fatalf("binding workdir = %+v", binding.Workdir)
	}
	if !slices.Equal(binding.Workdir.Masks, []string{"/work/myapp/.env"}) {
		t.Fatalf("binding masks = %v", binding.Workdir.Masks)
	}
	if binding.Connector != "claudecode" || binding.HookContractID != claudeContract(t) || binding.HostUser.UID != "1000" {
		t.Fatalf("binding = %+v", binding)
	}

	// Telemetry: creating then ready, the mask and the snapshot.
	if phases := e.tel.phases(sb.Name); !slices.Equal(phases, []audit.SandboxPhase{audit.SandboxPhaseCreating, audit.SandboxPhaseReady}) {
		t.Fatalf("lifecycle = %v", phases)
	}
	var ops []audit.SandboxWorkspaceOperation
	for _, w := range e.tel.workspace {
		ops = append(ops, w.Operation)
	}
	if !slices.Equal(ops, []audit.SandboxWorkspaceOperation{audit.SandboxWorkspaceMask, audit.SandboxWorkspaceSnapshot}) {
		t.Fatalf("workspace telemetry = %v", ops)
	}

	// Durable state, and the watcher runs.
	if _, err := os.Stat(filepath.Join(e.dataDir, "sandboxes", "manager", sb.Name+".json")); err != nil {
		t.Fatalf("record not saved: %v", err)
	}
	e.watch.waitStarted(t, sb.Name)
	list, err := e.m.List(context.Background())
	if err != nil || len(list) != 1 || list[0].Name != sb.Name {
		t.Fatalf("list = %v, %v", list, err)
	}
}

func TestCreateGeneratesName(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{})
	if !strings.HasPrefix(sb.Name, "dc-claude-myapp-") || !openshell.ValidSandboxName(sb.Name) {
		t.Fatalf("generated name %q", sb.Name)
	}
}

func TestCreateCopyModeAndStrict(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "copybox", Copy: true, Profile: "strict"})
	if sb.WorkdirMode != "copy" || sb.Workdir != "/sandbox/work/myapp" || sb.Profile != "strict" {
		t.Fatalf("sandbox = %+v", sb)
	}
	got, _ := e.client.GetSandbox(context.Background(), "copybox")
	if got.Spec.Template.DriverConfig != nil {
		t.Fatal("copy mode mounted something")
	}
	if _, ok := got.Spec.Environment["HTTPS_PROXY"]; ok {
		t.Fatal("strict profile got a proxy")
	}
	pol, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, "copybox")
	if _, ok := pol.NetworkPolicies[policy.EgressRuleName]; ok {
		t.Fatal("strict profile has the egress rule")
	}
	if len(e.ws.planned) != 0 {
		t.Fatal("copy mode planned a mount")
	}
	binding, _ := e.store.Lookup("copybox")
	if binding.Workdir.Mode != sandboxauth.WorkdirCopy || len(binding.Workdir.Mounts) != 0 {
		t.Fatalf("binding workdir = %+v", binding.Workdir)
	}
}

func TestCreateTokenDeliveryEnv(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.TokenDelivery = config.OpenShellTokenDeliveryEnv })
	sb := e.create(sandboxapi.CreateRequest{Name: "envbox"})
	got, _ := e.client.GetSandbox(context.Background(), sb.Name)
	token := got.Spec.Environment[openshell.EnvSandboxToken]
	if b, err := e.store.Match(token); err != nil || b.SandboxName != "envbox" {
		t.Fatalf("env token does not authenticate: %v", err)
	}
	if names := e.providers(); len(names) != 0 {
		t.Fatalf("providers = %v", names)
	}
}

func TestCreateRejections(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config.Config)
		req  sandboxapi.CreateRequest
		code string
	}{
		{"disabled", func(c *config.Config) { c.OpenShell.Enabled = false }, sandboxapi.CreateRequest{}, sandboxapi.CodeDisabled},
		{"unknown harness", nil, sandboxapi.CreateRequest{Harness: "nope"}, sandboxapi.CodeInvalid},
		{"relative project", nil, sandboxapi.CreateRequest{Project: "rel/path"}, sandboxapi.CodeInvalid},
		{"bad name", nil, sandboxapi.CreateRequest{Name: "Bad_Name"}, sandboxapi.CodeInvalid},
		{"harness not allowed by admin", func(c *config.Config) { c.OpenShell.Admin.AllowedHarnesses = []string{"codex"} },
			sandboxapi.CreateRequest{}, sandboxapi.CodeAdminViolation},
		{"unknown llm profile", nil, sandboxapi.CreateRequest{LLM: &sandboxapi.LLMCredential{Profile: "defenseclaw-openai"}}, sandboxapi.CodeInvalid},
		{"llm credential missing", nil, sandboxapi.CreateRequest{LLM: &sandboxapi.LLMCredential{Profile: profiles.AnthropicID}}, sandboxapi.CodeInvalid},
		{"credential to a blocklisted host", nil, sandboxapi.CreateRequest{Credentials: []sandboxapi.CredentialBinding{
			{Name: "TOKEN", Value: "x", Host: "webhook.site"}}}, sandboxapi.CodePolicyViolation},
		{"credential to the ingress port", nil, sandboxapi.CreateRequest{Credentials: []sandboxapi.CredentialBinding{
			{Name: "TOKEN", Value: "x", Host: "host.openshell.internal", Port: testIngressPort}}}, sandboxapi.CodePolicyViolation},
		{"credential to localhost", nil, sandboxapi.CreateRequest{Credentials: []sandboxapi.CredentialBinding{
			{Name: "TOKEN", Value: "x", Host: "localhost", Port: 5432}}}, sandboxapi.CodeInvalid},
		{"reserved credential name", nil, sandboxapi.CreateRequest{Credentials: []sandboxapi.CredentialBinding{
			{Name: "DEFENSECLAW_SANDBOX_TOKEN", Value: "x", Host: "api.example.com"}}}, sandboxapi.CodeInvalid},
		{"reserved env", nil, sandboxapi.CreateRequest{Env: map[string]string{"HTTPS_PROXY": "http://evil"}}, sandboxapi.CodeInvalid},
		{"loader env", nil, sandboxapi.CreateRequest{Env: map[string]string{"LD_PRELOAD": "/x.so"}}, sandboxapi.CodeInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.edit)
			req := tc.req
			if req.Harness == "" {
				req.Harness = "claudecode"
			}
			if req.Project == "" {
				req.Project = e.project
			}
			_, err := e.m.Create(context.Background(), req)
			wantCode(t, err, tc.code)
			assertNothingLeft(t, e)
		})
	}
}

func TestCreateAdminViolationMessage(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Admin.AllowedHarnesses = []string{"codex"} })
	_, err := e.m.Create(context.Background(), sandboxapi.CreateRequest{Harness: "claudecode", Project: e.project})
	apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation)
	if !strings.Contains(apiErr.Message, "blocked by your organization's DefenseClaw policy") || apiErr.Violation == nil || !apiErr.Violation.Admin {
		t.Fatalf("admin refusal = %+v", apiErr)
	}
	if apiErr.HTTPStatus() != 403 {
		t.Fatalf("status = %d", apiErr.HTTPStatus())
	}
}

// assertNothingLeft checks that a failed create left no trace.
func assertNothingLeft(t *testing.T, e *harnessEnv) {
	t.Helper()
	sbs, err := e.client.ListSandboxes(context.Background(), nil)
	if err != nil || len(sbs) != 0 {
		t.Fatalf("sandboxes left: %v %v", sbs, err)
	}
	if names := e.providers(); len(names) != 0 {
		t.Fatalf("providers left: %v", names)
	}
	if list := e.store.List(); len(list) != 0 {
		t.Fatalf("bindings left: %v", list)
	}
	e.m.mu.Lock()
	boxes := len(e.m.boxes)
	e.m.mu.Unlock()
	if boxes != 0 {
		t.Fatalf("%d boxes left", boxes)
	}
	entries, _ := os.ReadDir(filepath.Join(e.dataDir, "sandboxes", "manager"))
	if len(entries) != 0 {
		t.Fatalf("records left: %v", entries)
	}
}

func TestCreateRollsBackEachStep(t *testing.T) {
	for _, tc := range []struct {
		name       string
		setup      func(e *harnessEnv)
		code       string
		planned    bool
		snapshot   bool
		rolledBack bool
	}{
		{"image missing", func(e *harnessEnv) { e.images.err = ErrImageMissing }, sandboxapi.CodeImageUnavailable, false, false, false},
		{"image build fails", func(e *harnessEnv) { e.images.err = errors.New("docker build failed") }, sandboxapi.CodeImageUnavailable, false, false, false},
		{"mount refused", func(e *harnessEnv) { e.ws.planErr = &workspace.SourceError{Path: "/", Reason: "root"} }, sandboxapi.CodePolicyViolation, false, false, false},
		{"needs copy", func(e *harnessEnv) { e.ws.planErr = workspace.ErrNeedsCopy }, sandboxapi.CodeConflict, false, false, false},
		{"snapshot fails", func(e *harnessEnv) { e.ws.snapErr = errors.New("disk full") }, sandboxapi.CodeInternal, true, false, true},
		{"profile import fails", func(e *harnessEnv) { e.importer.err = errors.New("lint failed") }, sandboxapi.CodeUpstream, true, true, true},
		{"provider create fails", func(e *harnessEnv) {
			e.fake.FailNext(openshelltest.MethodCreateProvider, &types.StatusError{Code: types.ErrorInternal, Message: "boom"})
		}, sandboxapi.CodeUpstream, true, true, true},
		{"second provider create fails", func(e *harnessEnv) {
			n := 0
			e.fake.Intercept(func(method string) error {
				if method == openshelltest.MethodCreateProvider {
					n++
					if n == 2 {
						return &types.StatusError{Code: types.ErrorInternal, Message: "boom"}
					}
				}
				return nil
			})
		}, sandboxapi.CodeUpstream, true, true, true},
		{"sandbox create fails", func(e *harnessEnv) {
			e.fake.FailNext(openshelltest.MethodCreateSandbox, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "bad spec"})
		}, sandboxapi.CodeInvalid, true, true, true},
		{"wait ready fails", func(e *harnessEnv) {
			e.fake.FailNext(openshelltest.MethodWaitReady, &types.StatusError{Code: types.ErrorInternal, Message: "crashed"})
		}, sandboxapi.CodeUpstream, true, true, true},
		{"configuration rejected", func(e *harnessEnv) {
			e.fake.Intercept(func(method string) error {
				if method == openshelltest.MethodWaitReady {
					e.fake.SetAdmission(openshell.DefaultWorkspace, "rb-box", types.ConfigurationAdmissionRejected, "policy invalid")
				}
				return nil
			})
		}, sandboxapi.CodePolicyRejected, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			tc.setup(e)
			_, err := e.m.Create(context.Background(), sandboxapi.CreateRequest{
				Name: "rb-box", Harness: "claudecode", Project: e.project,
				LLM: &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "k"}},
			})
			wantCode(t, err, tc.code)
			assertNothingLeft(t, e)
			if got := slices.Contains(e.ws.released, "rb-box"); got != tc.planned {
				t.Fatalf("mount released = %v, want %v (planned %v)", got, tc.planned, e.ws.planned)
			}
			if got := slices.Contains(e.ws.deleted, "rb-box"); got != tc.snapshot {
				t.Fatalf("snapshot deleted = %v, want %v", got, tc.snapshot)
			}
			for _, u := range []string{"rb-box"} {
				if _, ok := e.m.creds.Lookup(u); ok {
					t.Fatal("proxy credential left registered")
				}
			}
			if tc.rolledBack {
				var failed bool
				for _, h := range e.tel.health {
					failed = failed || h.State == audit.SandboxHealthFailed
				}
				if !failed {
					t.Fatal("no failed health record")
				}
			}
		})
	}
}

func TestStartRotatesBinding(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "rotbox"})
	ingress, _ := e.client.GetProvider(context.Background(), "rotbox-ingress")
	oldToken := ingress.Spec.Credentials[openshell.EnvSandboxToken]
	binding, _ := e.store.Lookup("rotbox")

	stopped, err := e.m.Stop(context.Background(), sb.Name)
	if err != nil || stopped.Phase != "stopped" {
		t.Fatalf("stop = %+v, %v", stopped, err)
	}
	if len(e.ws.released) != 0 {
		t.Fatal("stop released the mount")
	}
	snapsBefore := len(e.ws.snapshots)
	started, err := e.m.Start(context.Background(), sb.Name, sandboxapi.StartRequest{})
	if err != nil || started.Phase != "ready" {
		t.Fatalf("start = %+v, %v", started, err)
	}
	ingress, _ = e.client.GetProvider(context.Background(), "rotbox-ingress")
	newToken := ingress.Spec.Credentials[openshell.EnvSandboxToken]
	if newToken == oldToken || newToken == "" {
		t.Fatal("start did not rotate the token")
	}
	if _, err := e.store.Match(oldToken); err == nil {
		t.Fatal("the old token still authenticates")
	}
	if b, err := e.store.Match(newToken); err != nil || b.ID != binding.ID {
		t.Fatalf("new token: %v", err)
	}
	if !slices.Contains(e.forgot, binding.ID) {
		t.Fatal("ingress state of the rotated binding not forgotten")
	}
	if len(e.ws.snapshots) != snapsBefore || !e.ws.lastSnapshot.Replace {
		t.Fatal("start did not take a fresh snapshot")
	}
	phases := e.tel.phases("rotbox")
	want := []audit.SandboxPhase{audit.SandboxPhaseCreating, audit.SandboxPhaseReady, audit.SandboxPhaseStopping,
		audit.SandboxPhaseStopped, audit.SandboxPhaseStarting, audit.SandboxPhaseReady}
	if !slices.Equal(phases, want) {
		t.Fatalf("lifecycle = %v, want %v", phases, want)
	}
}

func TestStartRefusedByAdmin(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "adminbox"})
	if _, err := e.m.Stop(context.Background(), "adminbox"); err != nil {
		t.Fatal(err)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowedHarnesses = []string{"codex"} })
	_, err := e.m.Start(context.Background(), "adminbox", sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodeAdminViolation)
}

func TestDeleteReleasesEverything(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "delbox",
		LLM: &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "k"}}})
	ingress, _ := e.client.GetProvider(context.Background(), "delbox-ingress")
	token := ingress.Spec.Credentials[openshell.EnvSandboxToken]
	binding, _ := e.store.Lookup("delbox")
	if _, err := e.m.Unblock(context.Background(), sandboxapi.UnblockRequest{Host: "webhook.site", Sandbox: "delbox"}); err != nil {
		t.Fatal(err)
	}

	resp, err := e.m.Delete(context.Background(), sb.Name, sandboxapi.DeleteRequest{})
	if err != nil || !resp.Deleted || len(resp.Providers) != 2 {
		t.Fatalf("delete = %+v, %v", resp, err)
	}
	if _, err := e.client.GetSandbox(context.Background(), "delbox"); !openshell.IsNotFound(err) {
		t.Fatalf("sandbox still there: %v", err)
	}
	if _, err := e.store.Match(token); !errors.Is(err, sandboxauth.ErrUnauthenticated) {
		t.Fatalf("token after delete: %v", err)
	}
	if names := e.providers(); len(names) != 0 {
		t.Fatalf("providers left: %v", names)
	}
	if _, ok := e.m.creds.Lookup(binding.ID); ok {
		t.Fatal("proxy credential left")
	}
	if len(e.m.unblocks.List()) != 0 {
		t.Fatal("unblocks left")
	}
	if !slices.Contains(e.ws.released, "delbox") || !slices.Contains(e.ws.deleted, "delbox") {
		t.Fatalf("workspace not released: released %v deleted %v", e.ws.released, e.ws.deleted)
	}
	phases := e.tel.phases("delbox")
	if phases[len(phases)-1] != audit.SandboxPhaseDeleted {
		t.Fatalf("lifecycle = %v", phases)
	}
	if _, err := e.m.Get(context.Background(), "delbox"); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("get after delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.dataDir, "sandboxes", "manager", "delbox.json")); !os.IsNotExist(err) {
		t.Fatalf("record left: %v", err)
	}
}

func TestDeleteKeepSnapshot(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "keepbox"})
	if _, err := e.m.Delete(context.Background(), "keepbox", sandboxapi.DeleteRequest{KeepSnapshot: true}); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(e.ws.deleted, "keepbox") {
		t.Fatal("snapshot deleted despite keep_snapshot")
	}
}

func TestUndoAndReview(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "undobox"})
	if _, err := e.m.Undo(context.Background(), "undobox", sandboxapi.UndoRequest{}); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
		t.Fatalf("undo while running: %v", err)
	}
	resp, err := e.m.Undo(context.Background(), "undobox", sandboxapi.UndoRequest{Stop: true, Restart: true})
	if err != nil || !resp.Stopped || !resp.Restarted || resp.Result == nil {
		t.Fatalf("undo = %+v, %v", resp, err)
	}
	if !slices.Contains(e.ws.undone, "undobox") {
		t.Fatal("undo not run")
	}
	review, err := e.m.Review(context.Background(), "undobox", sandboxapi.ReviewRequest{Diff: true})
	if err != nil || review.Summary != "2 files changed (+5 −1)" || !strings.Contains(review.RiskLine, "package.json") || review.Diff == "" {
		t.Fatalf("review = %+v, %v", review, err)
	}
	var undo, rev bool
	for _, w := range e.tel.workspace {
		undo = undo || (w.Operation == audit.SandboxWorkspaceUndo && w.Result == audit.SandboxWorkspaceApplied)
		rev = rev || (w.Operation == audit.SandboxWorkspaceReview && w.FlaggedCount != nil && *w.FlaggedCount == 1)
	}
	if !undo || !rev {
		t.Fatalf("workspace telemetry = %+v", e.tel.workspace)
	}

	copyBox := e.create(sandboxapi.CreateRequest{Name: "copyundo", Copy: true})
	if _, err := e.m.Undo(context.Background(), copyBox.Name, sandboxapi.UndoRequest{Stop: true}); !sandboxapi.IsCode(err, sandboxapi.CodeInvalid) {
		t.Fatalf("copy undo: %v", err)
	}
}

func TestReportWorkspace(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "copyrep", Copy: true})
	files := int64(3)
	if err := e.m.ReportWorkspace(context.Background(), "copyrep", sandboxapi.WorkspaceReport{
		Operation: sandboxapi.WorkspacePull, PullMode: audit.SandboxPullBranch, FileCount: &files, Paths: []string{"a.go"},
	}); err != nil {
		t.Fatal(err)
	}
	last := e.tel.workspace[len(e.tel.workspace)-1]
	if last.Operation != audit.SandboxWorkspacePull || last.PullMode != "branch" || *last.FileCount != 3 || last.Sandbox.Name != "copyrep" {
		t.Fatalf("workspace record = %+v", last)
	}
	negative := int64(-1)
	for _, bad := range []sandboxapi.WorkspaceReport{
		{Operation: "undo"},
		{Operation: sandboxapi.WorkspacePull},
		{Operation: sandboxapi.WorkspaceUpload, PullMode: "apply"},
		{Operation: sandboxapi.WorkspaceUpload, Result: "exploded"},
		{Operation: sandboxapi.WorkspaceUpload, ByteCount: &negative},
	} {
		if err := e.m.ReportWorkspace(context.Background(), "copyrep", bad); !sandboxapi.IsCode(err, sandboxapi.CodeInvalid) {
			t.Fatalf("report %+v: %v", bad, err)
		}
	}
	if err := e.m.ReportWorkspace(context.Background(), "nope", sandboxapi.WorkspaceReport{Operation: "upload"}); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("unknown sandbox: %v", err)
	}
}

func TestGatewayUnavailable(t *testing.T) {
	e := newEnv(t, nil)
	e.connErr = errors.New("connection refused")
	_, err := e.m.Create(context.Background(), sandboxapi.CreateRequest{Harness: "claudecode", Project: e.project})
	wantCode(t, err, sandboxapi.CodeUnavailable)
	st, err := e.m.Status(context.Background())
	if err != nil || st.Available || !strings.Contains(st.Reason, "connection refused") || !st.Enabled {
		t.Fatalf("status = %+v, %v", st, err)
	}
	e.connErr = nil
	// Within the reconnect backoff the failure is reported without redialing.
	if st, _ = e.m.Status(context.Background()); st.Available {
		t.Fatal("redialed inside the backoff")
	}
	e.m.now = func() time.Time { return time.Now().Add(time.Minute) }
	st, _ = e.m.Status(context.Background())
	if !st.Available || st.Gateway == nil || st.Gateway.Version != "0.1.1" || st.Pack != "open" {
		t.Fatalf("status = %+v", st)
	}
	var degraded, restored bool
	for _, h := range e.tel.health {
		degraded = degraded || h.State == audit.SandboxHealthDegraded
		restored = restored || h.State == audit.SandboxHealthRestored
	}
	if !degraded || !restored {
		t.Fatalf("health = %+v", e.tel.health)
	}
}

func TestComposeName(t *testing.T) {
	for _, tc := range []struct{ harness, project, want string }{
		{"claudecode", "/home/u/code/myapp", "dc-claude-myapp-7f3a"},
		{"codex", "/x/My App_2", "dc-codex-my-app-2-7f3a"},
		{"claudecode", "/x/" + strings.Repeat("a", 80), "dc-claude-" + strings.Repeat("a", 48) + "-7f3a"},
		{"claudecode", "", "dc-claude-project-7f3a"},
		{"claudecode", "/x/---", "dc-claude-project-7f3a"},
	} {
		got := composeName(tc.harness, tc.project, "7f3a")
		if got != tc.want || !openshell.ValidSandboxName(got) {
			t.Errorf("composeName(%q, %q) = %q, want %q", tc.harness, tc.project, got, tc.want)
		}
	}
	if n, err := GenerateName("claudecode", "/x/app"); err != nil || !openshell.ValidSandboxName(n) {
		t.Fatalf("GenerateName = %q, %v", n, err)
	}
}

func TestImageVersion(t *testing.T) {
	if v := ImageVersion(); v == "" || strings.ContainsAny(v, " /") {
		t.Fatalf("ImageVersion = %q", v)
	}
}

// TestStartRechecksAdminPolicy pins that an administrator change applies to
// a stopped sandbox: a live mount or learn mode the organization disallowed
// since refuses the start with the organization-policy message.
func TestStartRechecksAdminPolicy(t *testing.T) {
	for name, edit := range map[string]func(c *config.Config, project string){
		"allow_mount":      func(c *config.Config, _ string) { c.OpenShell.Admin.AllowMount = boolPtr(false) },
		"require_copy_for": func(c *config.Config, project string) { c.OpenShell.Admin.RequireCopyFor = []string{project} },
		"allow_learn_mode": func(c *config.Config, _ string) { c.OpenShell.Admin.AllowLearnMode = boolPtr(false) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.create(sandboxapi.CreateRequest{Name: "orgbox", Learn: true})
			if _, err := e.m.Stop(context.Background(), "orgbox"); err != nil {
				t.Fatal(err)
			}
			e.setConfig(func(c *config.Config) { edit(c, e.project) })
			_, err := e.m.Start(context.Background(), "orgbox", sandboxapi.StartRequest{})
			apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation)
			if !strings.Contains(apiErr.Message, sandboxapi.AdminMessage) {
				t.Fatalf("message = %q", apiErr.Message)
			}
			if got, _ := e.client.GetSandbox(context.Background(), "orgbox"); got.Status.Phase != openshell.PhaseStopped {
				t.Fatalf("refused sandbox started: %s", got.Status.Phase)
			}
		})
	}
}

// TestLaunchYoloFollowsThePolicy pins that skip-permissions mode follows
// the re-resolved policy: once the administrator forbids it, connect
// launches the harness with its permission prompts.
func TestLaunchYoloFollowsThePolicy(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "yolobox", Yolo: true})
	if !sb.Launch.Yolo {
		t.Fatalf("launch = %+v, want skip-permissions", sb.Launch)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowYolo = boolPtr(false) })
	e.m.refreshEgress()
	got, err := e.m.Get(context.Background(), "yolobox")
	if err != nil || got.Launch.Yolo || got.Yolo {
		t.Fatalf("after allow_yolo=false: launch %+v yolo %v, %v", got.Launch, got.Yolo, err)
	}
}

// TestAdminBlockRemovesApprovedRules pins that approved OpenShell rules,
// which bypass the egress proxy, are removed once the administrator blocks
// their destination.
func TestAdminBlockRemovesApprovedRules(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "rulebox"})
	e.watch.waitStarted(t, sb.Name)
	keep := addChunk(e, sb.Name, chunk("allow_keep_example_org_443", "keep.example.org", 443))
	gone := addChunk(e, sb.Name, chunk("allow_gone_example_org_443", "gone.example.org", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "approvals applied", func() bool {
		return chunkStatus(e, sb.Name, keep) == "approved" && chunkStatus(e, sb.Name, gone) == "approved"
	})
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"gone.example.org"} })
	e.m.enforceAll(context.Background())
	policy, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, sb.Name)
	if _, ok := policy.NetworkPolicies["allow_gone_example_org_443"]; ok {
		t.Fatal("the admin-blocked rule is still in the policy")
	}
	for _, rule := range []string{"allow_keep_example_org_443", "defenseclaw_egress"} {
		if _, ok := policy.NetworkPolicies[rule]; !ok {
			t.Fatalf("rule %s removed: %v", rule, policy.NetworkPolicies)
		}
	}
	var removed bool
	e.tel.mu.Lock()
	for _, p := range e.tel.policy {
		removed = removed || (p.Operation == audit.SandboxPolicyRuleRemove && p.Target == "allow_gone_example_org_443")
	}
	e.tel.mu.Unlock()
	if !removed {
		t.Fatal("no rule_remove record")
	}
}

// TestStartTokenDeliveryEnvKeepsTheToken pins that a sandbox created with
// token_delivery: env keeps authenticating after a restart: its token is
// a plain variable of the sandbox spec, which a rotation cannot reach.
func TestStartTokenDeliveryEnvKeepsTheToken(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.TokenDelivery = config.OpenShellTokenDeliveryEnv })
	sb := e.create(sandboxapi.CreateRequest{Name: "envstart"})
	got, _ := e.client.GetSandbox(context.Background(), sb.Name)
	token := got.Spec.Environment[openshell.EnvSandboxToken]
	if _, err := e.m.Stop(context.Background(), sb.Name); err != nil {
		t.Fatal(err)
	}
	// The delivery a sandbox was created with wins over a later setting.
	e.setConfig(func(c *config.Config) { c.OpenShell.TokenDelivery = config.OpenShellTokenDeliveryProvider })
	if _, err := e.m.Start(context.Background(), sb.Name, sandboxapi.StartRequest{}); err != nil {
		t.Fatal(err)
	}
	if b, err := e.store.Match(token); err != nil || b.SandboxName != sb.Name {
		t.Fatalf("the sandbox's token no longer authenticates after a restart: %v", err)
	}
}
