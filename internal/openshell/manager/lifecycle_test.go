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

//go:build !windows

package manager

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/policy"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

var anthropicLLM = &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "sk-test-secret"}}

var stripeCred = []sandboxapi.CredentialBinding{{Name: "STRIPE_API_KEY", Value: "stripe-secret", Host: "api.stripe.com"}}

func TestCreateMountMode(t *testing.T) {
	e := newEnv(t, nil)
	e.ws.masked = []workspace.MaskedPath{{Rel: ".env", Reason: "name"}}
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "claude-myapp-1a2b", LLM: anthropicLLM, Credentials: stripeCred,
		HostPorts: []int{5432}, Env: map[string]string{"MY_FLAG": "1"}})
	if sb.Phase != "ready" || sb.WorkdirMode != "mount" || sb.Workdir != "/work/myapp" || sb.Profile != "open" || !sb.Yolo ||
		sb.Pack != "open" || sb.Launch.CredentialProfile != profiles.AnthropicID || sb.Snapshot == nil || sb.Snapshot.Kind != "git" {
		t.Fatalf("sandbox = %+v", sb)
	}
	// The grants a resume keeps are shown with the sandbox, the credential's value never.
	grants := []sandboxapi.CredentialGrant{{Name: "STRIPE_API_KEY", Host: "api.stripe.com", Port: 443}}
	if !slices.Equal(sb.Credentials, grants) || !slices.Equal(sb.HostPorts, []int{5432}) || !slices.Equal(e.get(sb.Name).Credentials, grants) {
		t.Fatalf("grants = %+v, host ports %v", sb.Credentials, sb.HostPorts)
	}

	got, err := e.client.GetSandbox(t.Context(), sb.Name)
	must(t, err)
	key, value := workspace.ProjectLabel(e.project)
	for k, v := range map[string]string{LabelManaged: "true", LabelOwner: testOwner, LabelHarness: "claudecode", LabelProfile: "open",
		LabelPack: "open", LabelWorkdirMode: "mount", key: value} {
		if got.Labels[k] != v {
			t.Fatalf("label %s = %q, want %q", k, got.Labels[k], v)
		}
	}
	env, binding := got.Spec.Environment, e.binding(sb.Name)
	if env[openshell.EnvSandboxName] != sb.Name || env[openshell.EnvSandboxID] != binding.ID || env["MY_FLAG"] != "1" || env["NODE_USE_ENV_PROXY"] != "1" {
		t.Fatalf("env = %v", env)
	}
	for _, secret := range []string{openshell.EnvSandboxToken, "ANTHROPIC_API_KEY"} {
		if _, leaked := env[secret]; leaked {
			t.Fatalf("%s is in the plain environment", secret)
		}
	}
	proxy, err := url.Parse(env["HTTPS_PROXY"])
	if err != nil || proxy.Host != "host.openshell.internal:18972" || proxy.User == nil {
		t.Fatalf("HTTPS_PROXY = %q", env["HTTPS_PROXY"])
	}
	pass, _ := proxy.User.Password()
	if p, ok := e.m.creds.Authenticate(proxy.User.Username(), pass); !ok || p.BindingID != binding.ID || p.SandboxName != sb.Name {
		t.Fatalf("proxy credential not registered: %+v %v", p, ok)
	}
	for _, host := range []string{"api.anthropic.com", "api.stripe.com", "host.openshell.internal"} {
		if !strings.Contains(env["NO_PROXY"], host) {
			t.Fatalf("NO_PROXY = %q", env["NO_PROXY"])
		}
	}
	// OpenShell drops *_PROXY variables; the launchers export these.
	if env[openshell.EnvEgressURL] != env["HTTPS_PROXY"] || env[openshell.EnvEgressBypass] != env["NO_PROXY"] {
		t.Fatalf("egress aliases = %q %q", env[openshell.EnvEgressURL], env[openshell.EnvEgressBypass])
	}
	// The project and its protected paths, then the per-run managed configuration, read-only.
	tmpl := got.Spec.Template
	if tmpl == nil || tmpl.Image != "defenseclaw/sandbox-claudecode:test" {
		t.Fatalf("template = %+v", tmpl)
	}
	mounts := tmpl.DriverConfig["docker"].(map[string]any)["mounts"].([]any)
	if len(mounts) != 4 || mounts[0].(map[string]any)["target"] != "/work/myapp" {
		t.Fatalf("mounts = %v", mounts)
	}
	for i, want := range []string{connector.ClaudeCodeSandboxRunDropInPath, connector.ClaudeCodeSandboxManagedMCPPath} {
		if mt := mounts[2+i].(map[string]any); mt["target"] != want || mt["read_only"] != true || mt["type"] != "bind" {
			t.Fatalf("run config mount %d = %v", i, mt)
		}
	}
	pol, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, sb.Name)
	if pol == nil || pol.NetworkPolicies[policy.EgressRuleName].Name == "" || pol.Process == nil || pol.Process.RunAsUser != "1000" {
		t.Fatalf("policy = %+v", pol)
	}
	// The ingress provider's rule opens the ingress; the policy needs no rule of its own.
	if _, ok := pol.NetworkPolicies[policy.IngressRuleName]; ok {
		t.Fatal("the policy has its own ingress rule")
	}

	// Providers, one per credential, with the binding token behind the ingress profile.
	if names := e.providers(); !slices.Equal(names, []string{sb.Name + "-cred-0", sb.Name + "-ingress", sb.Name + "-llm"}) {
		t.Fatalf("providers = %v", names)
	}
	if !slices.Equal(got.Spec.Providers, []string{sb.Name + "-ingress", sb.Name + "-llm", sb.Name + "-cred-0"}) {
		t.Fatalf("attached providers = %v", got.Spec.Providers)
	}
	ingress, err := e.client.GetProvider(t.Context(), sb.Name+"-ingress")
	must(t, err)
	if ingress.Type != profiles.IngressProfileID(testIngressPort) || ingress.Labels[LabelSandbox] != sb.Name {
		t.Fatalf("ingress provider = %+v", ingress)
	}
	if matched, err := e.store.Match(ingress.Spec.Credentials[openshell.EnvSandboxToken]); err != nil || matched.ID != binding.ID {
		t.Fatalf("ingress token does not authenticate the binding: %v", err)
	}
	if llm, _ := e.client.GetProvider(t.Context(), sb.Name+"-llm"); llm.Type != profiles.AnthropicID || llm.Spec.Credentials["ANTHROPIC_API_KEY"] != "sk-test-secret" {
		t.Fatalf("llm provider = %+v", llm)
	}
	if !slices.Contains(e.importer.imported, profiles.IngressProfileID(testIngressPort)) || !slices.Contains(e.importer.imported, profiles.AnthropicID) {
		t.Fatalf("imported profiles = %v", e.importer.imported)
	}

	// The binding describes the mount for FSView and carries the sandbox id.
	if w := binding.Workdir; w.Mode != sandboxauth.WorkdirMount || len(w.Mounts) != 1 || w.Mounts[0].SandboxPath != "/work/myapp" ||
		w.Mounts[0].HostPath != e.project || !slices.Equal(w.Masks, []string{"/work/myapp/.env"}) {
		t.Fatalf("binding workdir = %+v", w)
	}
	if binding.Connector != "claudecode" || binding.HookContractID != claudeContract(t) || binding.HostUser.UID != "1000" {
		t.Fatalf("binding = %+v", binding)
	}

	// Telemetry: creating then ready, the mask and the snapshot.
	if phases := e.tel.phases(sb.Name); !slices.Equal(phases, []audit.SandboxPhase{audit.SandboxPhaseCreating, audit.SandboxPhaseReady}) {
		t.Fatalf("lifecycle = %v", phases)
	}
	var ops []audit.SandboxWorkspaceOperation
	for _, w := range where(&e.tel.mu, &e.tel.workspace, nil) {
		ops = append(ops, w.Operation)
	}
	if !slices.Equal(ops, []audit.SandboxWorkspaceOperation{audit.SandboxWorkspaceMask, audit.SandboxWorkspaceSnapshot}) {
		t.Fatalf("workspace telemetry = %v", ops)
	}
	if !fileExists(filepath.Join(e.dataDir, "sandboxes", "manager", sb.Name+".json")) {
		t.Fatal("record not saved")
	}
	e.watch.waitStarted(t, sb.Name)
	if list, err := e.m.List(t.Context()); err != nil || len(list) != 1 || list[0].Name != sb.Name {
		t.Fatalf("list = %v, %v", list, err)
	}
}

// A registration without a port and an unset API port still render a
// policy: policy.Render refuses zero ports, so the manager passes the same
// defaults packs.Resolve reserves.
func TestCreateResolvesUnsetPorts(t *testing.T) {
	e := newEnv(t, nil)
	e.gw.Port, e.apiPort = 0, 0
	e.m = e.newManager()
	if e.m.opts.APIPort != config.DefaultGatewayAPIPort || policyGatewayPort(0) != packs.OpenShellGatewayPort {
		t.Fatalf("APIPort = %d, gateway port %d", e.m.opts.APIPort, policyGatewayPort(0))
	}
	if pol, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, e.create(sandboxapi.CreateRequest{Name: "noports"}).Name); pol == nil {
		t.Fatal("no policy applied")
	}
}

func TestCreateCopyModeAndStrict(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "copybox", Copy: true, Profile: "strict"})
	if sb.WorkdirMode != "copy" || sb.Workdir != "/sandbox/work/myapp" || sb.Profile != "strict" || len(e.ws.planned) != 0 {
		t.Fatalf("sandbox = %+v, planned %v", sb, e.ws.planned)
	}
	// Copy mode mounts only the per-run managed configuration.
	got, _ := e.client.GetSandbox(t.Context(), "copybox")
	mounts := got.Spec.Template.DriverConfig["docker"].(map[string]any)["mounts"].([]any)
	for _, raw := range mounts {
		if mt := raw.(map[string]any); !strings.HasPrefix(mt["target"].(string), "/etc/claude-code/") || mt["read_only"] != true {
			t.Fatalf("copy mode mounted %v", mt)
		}
	}
	pol, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, "copybox")
	if pol.Process.RunAsUser != "1000" || pol.Process.RunAsGroup != "1000" {
		t.Fatalf("copy mode runs as %+v, not the image's uid/gid", pol.Process)
	}
	_, egressRule := pol.NetworkPolicies[policy.EgressRuleName]
	_, proxy := got.Spec.Environment["HTTPS_PROXY"]
	if len(mounts) != 2 || proxy || egressRule {
		t.Fatalf("strict copy: %d mounts, proxy %v, egress rule %v", len(mounts), proxy, egressRule)
	}
	if w := e.binding("copybox").Workdir; w.Mode != sandboxauth.WorkdirCopy || len(w.Mounts) != 0 {
		t.Fatalf("binding workdir = %+v", w)
	}
}

// The run's time zone reaches the sandbox as DefenseClaw's own variable,
// which the in-image shells turn into TZ; a value that is not a zone name
// is refused (cert copilot:F10: the harness showed UTC times).
func TestCreateGivesTheHostTimeZone(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "tzbox", Copy: true, TimeZone: "America/New_York"})
	got, _ := e.client.GetSandbox(t.Context(), sb.Name)
	if tz := got.Spec.Environment[openshell.EnvHostTimeZone]; tz != "America/New_York" {
		t.Fatalf("%s = %q", openshell.EnvHostTimeZone, tz)
	}
	if _, bad := got.Spec.Environment["TZ"]; bad {
		t.Fatal("TZ was set at create, where the image's zone file is not checked")
	}
	if _, err := e.tryCreate(sandboxapi.CreateRequest{Name: "tzbad", Copy: true, TimeZone: "../../etc/passwd"}); !sandboxapi.IsCode(err, sandboxapi.CodeInvalid) {
		t.Fatalf("a path as the time zone: %v", err)
	}
}

// With token_delivery: env the token is a plain variable, and the policy
// opens the ingress itself (no ingress provider carries its rule); it keeps
// authenticating after a restart, whatever the setting says by then.
func TestCreateTokenDeliveryEnv(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.TokenDelivery = config.OpenShellTokenDeliveryEnv })
	sb := e.create(sandboxapi.CreateRequest{})
	if !strings.HasPrefix(sb.Name, "myapp-") || !openshell.ValidNewSandboxName(sb.Name) {
		t.Fatalf("generated name %q", sb.Name)
	}
	got, _ := e.client.GetSandbox(t.Context(), sb.Name)
	token := got.Spec.Environment[openshell.EnvSandboxToken]
	if b, err := e.store.Match(token); err != nil || b.SandboxName != sb.Name {
		t.Fatalf("env token does not authenticate: %v", err)
	}
	if names := e.providers(); len(names) != 0 || len(e.importer.imported) != 0 {
		t.Fatalf("providers = %v, imported profiles = %v", names, e.importer.imported)
	}
	pol, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, sb.Name)
	rule, ok := pol.NetworkPolicies[policy.IngressRuleName]
	if !ok || len(rule.Endpoints) != 1 || rule.Endpoints[0].Host != policy.EgressHost || rule.Endpoints[0].Port != testIngressPort {
		t.Fatalf("ingress rule = %#v (present %t)", rule, ok)
	}
	e.stopBox(sb.Name)
	e.setConfig(func(c *config.Config) { c.OpenShell.TokenDelivery = config.OpenShellTokenDeliveryProvider })
	e.startBox(sb.Name, sandboxapi.StartRequest{})
	if b, err := e.store.Match(token); err != nil || b.SandboxName != sb.Name {
		t.Fatalf("the sandbox's token no longer authenticates after a restart: %v", err)
	}
}

// assertNothingLeft checks that a failed create left no trace.
func assertNothingLeft(t *testing.T, e *harnessEnv) {
	t.Helper()
	if sbs, err := e.client.ListSandboxes(t.Context(), nil); err != nil || len(sbs) != 0 {
		t.Fatalf("sandboxes left: %v %v", sbs, err)
	}
	if names := e.providers(); len(names) != 0 {
		t.Fatalf("providers left: %v", names)
	}
	list, err := e.client.ListProfiles(t.Context())
	must(t, err)
	for _, p := range list {
		if strings.HasPrefix(p.ID, credentialProfilePrefix) {
			t.Fatalf("credential profile %s left", p.ID)
		}
	}
	if list := e.store.List(); len(list) != 0 || e.m.creds.Len() != 0 {
		t.Fatalf("bindings left: %v, %d proxy credentials", list, e.m.creds.Len())
	}
	e.m.mu.Lock()
	boxes := len(e.m.boxes)
	e.m.mu.Unlock()
	if entries, _ := os.ReadDir(filepath.Join(e.dataDir, "sandboxes", "manager")); boxes != 0 || len(entries) != 0 {
		t.Fatalf("%d boxes, records left: %v", boxes, entries)
	}
}

func TestCreateRejections(t *testing.T) {
	cred := func(host string, port int) []sandboxapi.CredentialBinding {
		return []sandboxapi.CredentialBinding{{Name: "TOKEN", Value: "x", Host: host, Port: port}}
	}
	for _, tc := range []struct {
		name string
		edit func(*config.Config)
		req  sandboxapi.CreateRequest
		code string
		msg  string
	}{
		{"disabled", func(c *config.Config) { c.OpenShell.Enabled = false }, sandboxapi.CreateRequest{}, sandboxapi.CodeDisabled, ""},
		{"unknown harness", nil, sandboxapi.CreateRequest{Harness: "nope"}, sandboxapi.CodeInvalid, ""},
		{"relative project", nil, sandboxapi.CreateRequest{Project: "rel/path"}, sandboxapi.CodeInvalid, ""},
		{"bad name", nil, sandboxapi.CreateRequest{Name: "Bad_Name"}, sandboxapi.CodeInvalid, ""},
		// Generated names fit OpenShell 0.1.1's limit; a longer one is refused before anything is created.
		{"name over OpenShell's limit", nil, sandboxapi.CreateRequest{Name: "dc-claude-m1-calc-7500"}, sandboxapi.CodeInvalid, "at most 19 characters"},
		{"harness not allowed by admin", func(c *config.Config) { c.OpenShell.Admin.AllowedHarnesses = []string{"codex"} },
			sandboxapi.CreateRequest{}, sandboxapi.CodeAdminViolation, "blocked by your organization's DefenseClaw policy"},
		{"unknown llm profile", nil, sandboxapi.CreateRequest{LLM: &sandboxapi.LLMCredential{Profile: "defenseclaw-openai"}}, sandboxapi.CodeInvalid, ""},
		{"llm credential missing", nil, sandboxapi.CreateRequest{LLM: &sandboxapi.LLMCredential{Profile: profiles.AnthropicID}}, sandboxapi.CodeInvalid, ""},
		{"credential to a blocklisted host", nil, sandboxapi.CreateRequest{Credentials: cred("webhook.site", 0)}, sandboxapi.CodePolicyViolation, ""},
		{"credential to the ingress port", nil, sandboxapi.CreateRequest{Credentials: cred("host.openshell.internal", testIngressPort)}, sandboxapi.CodePolicyViolation, ""},
		{"credential to localhost", nil, sandboxapi.CreateRequest{Credentials: cred("localhost", 5432)}, sandboxapi.CodeInvalid, ""},
		{"reserved credential name", nil, sandboxapi.CreateRequest{Credentials: []sandboxapi.CredentialBinding{
			{Name: "DEFENSECLAW_SANDBOX_TOKEN", Value: "x", Host: "api.example.com"}}}, sandboxapi.CodeInvalid, ""},
		{"reserved env", nil, sandboxapi.CreateRequest{Env: map[string]string{"HTTPS_PROXY": "http://evil"}}, sandboxapi.CodeInvalid, ""},
		{"loader env", nil, sandboxapi.CreateRequest{Env: map[string]string{"LD_PRELOAD": "/x.so"}}, sandboxapi.CodeInvalid, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.edit)
			_, err := e.tryCreate(tc.req)
			apiErr := wantCode(t, err, tc.code)
			if !strings.Contains(apiErr.Message, tc.msg) {
				t.Fatalf("message = %q, want %q", apiErr.Message, tc.msg)
			}
			if tc.code == sandboxapi.CodeAdminViolation && (apiErr.Violation == nil || !apiErr.Violation.Admin || apiErr.HTTPStatus() != 403) {
				t.Fatalf("admin refusal = %+v", apiErr)
			}
			if n := e.fake.Calls(openshelltest.MethodCreateSandbox); n != 0 {
				t.Fatalf("create calls = %d", n)
			}
			assertNothingLeft(t, e)
		})
	}
}

func TestCreateRollsBackEachStep(t *testing.T) {
	fail := func(method string, code types.ErrorCode) func(*harnessEnv) {
		return func(e *harnessEnv) { e.fake.FailNext(method, &types.StatusError{Code: code, Message: "boom"}) }
	}
	for _, tc := range []struct {
		name                     string
		setup                    func(e *harnessEnv)
		code                     string
		planned, snapshot, alarm bool
	}{
		{"image missing", func(e *harnessEnv) { e.images.err = ErrImageMissing }, sandboxapi.CodeImageUnavailable, false, false, false},
		{"image build fails", func(e *harnessEnv) { e.images.err = errors.New("docker build failed") }, sandboxapi.CodeImageUnavailable, false, false, false},
		{"mount refused", func(e *harnessEnv) { e.ws.planErr = &workspace.SourceError{Path: "/", Reason: "root"} }, sandboxapi.CodePolicyViolation, false, false, false},
		{"needs copy", func(e *harnessEnv) { e.ws.planErr = workspace.ErrNeedsCopy }, sandboxapi.CodeNeedsCopy, false, false, false},
		{"snapshot fails", func(e *harnessEnv) { e.ws.snapErr = errors.New("disk full") }, sandboxapi.CodeInternal, true, false, true},
		{"profile import fails", func(e *harnessEnv) { e.importer.err = errors.New("lint failed") }, sandboxapi.CodeUpstream, true, true, true},
		{"provider create fails", fail(openshelltest.MethodCreateProvider, types.ErrorInternal), sandboxapi.CodeUpstream, true, true, true},
		{"second provider create fails", func(e *harnessEnv) {
			n := 0
			e.fake.Intercept(func(method string) error {
				if method == openshelltest.MethodCreateProvider {
					if n++; n == 2 {
						return &types.StatusError{Code: types.ErrorInternal, Message: "boom"}
					}
				}
				return nil
			})
		}, sandboxapi.CodeUpstream, true, true, true},
		// The failed create collects the --credential profile it imported, too.
		{"sandbox create fails", fail(openshelltest.MethodCreateSandbox, types.ErrorInvalidArgument), sandboxapi.CodeInvalid, true, true, true},
		// Bind mounts off in gateway.toml: the error names the fix, not OpenShell's conflict.
		{"bind mounts off", func(e *harnessEnv) {
			e.fake.FailNext(openshelltest.MethodCreateSandbox, &types.StatusError{Code: types.ErrorConflict, Message: "caller driver config is disabled"})
		}, sandboxapi.CodeUnavailable, true, true, true},
		{"wait ready fails", fail(openshelltest.MethodWaitReady, types.ErrorInternal), sandboxapi.CodeUpstream, true, true, true},
		{"configuration rejected", func(e *harnessEnv) {
			e.fake.Intercept(func(method string) error {
				if method == openshelltest.MethodWaitReady {
					e.fake.SetAdmission(openshell.DefaultWorkspace, "rb-box", types.ConfigurationAdmissionRejected, "policy invalid")
				}
				return nil
			})
		}, sandboxapi.CodePolicyRejected, true, true, true},
		// CreateSandbox failed after OpenShell created the sandbox (the gateway restarted).
		{"reply lost", func(e *harnessEnv) { createdButLost(e, e.m.managedSelector()) }, sandboxapi.CodeUnavailable, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			tc.setup(e)
			_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "rb-box", LLM: anthropicLLM, Credentials: stripeCred})
			wantCode(t, err, tc.code)
			assertNothingLeft(t, e)
			if got := slices.Contains(e.ws.released, "rb-box"); got != tc.planned {
				t.Fatalf("mount released = %v, want %v", got, tc.planned)
			}
			if got := slices.Contains(e.ws.deleted, "rb-box"); got != tc.snapshot {
				t.Fatalf("snapshot deleted = %v, want %v", got, tc.snapshot)
			}
			failed := where(&e.tel.mu, &e.tel.health, func(h audit.SandboxHealthEvent) bool { return h.State == audit.SandboxHealthFailed })
			if tc.alarm && len(failed) == 0 {
				t.Fatal("no failed health record")
			}
		})
	}
	// The rollback deletes only a sandbox of the name that carries this data dir's labels.
	e := newEnv(t, nil)
	createdButLost(e, map[string]string{LabelManaged: "true", LabelOwner: "fedcba9876543210"})
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "rb-box"})
	wantCode(t, err, sandboxapi.CodeUnavailable)
	if _, err := e.client.GetSandbox(t.Context(), "rb-box"); err != nil {
		t.Fatalf("the rollback deleted another daemon's sandbox: %v", err)
	}
}

// createdButLost makes the next CreateSandbox create the sandbox (with the
// labels) and then fail as unavailable.
func createdButLost(e *harnessEnv, labels map[string]string) {
	done := false
	e.fake.Intercept(func(method string) error {
		if method != openshelltest.MethodCreateSandbox || done {
			return nil
		}
		done = true
		if _, err := e.fake.SDK().Sandboxes().Create(context.Background(), openshell.DefaultWorkspace, "rb-box", &types.SandboxSpec{}, labels); err != nil {
			e.t.Errorf("create the sandbox under the call: %v", err)
		}
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "the gateway restarted"}
	})
}

// Another daemon collects the credential profile between this create's
// import and its provider; OpenShell refuses the provider, and the create
// imports the profile again.
func TestCreateImportsACredentialProfileThatVanished(t *testing.T) {
	e := newEnv(t, nil)
	var fired atomic.Bool
	e.fake.Intercept(func(method string) error {
		if method != openshelltest.MethodCreateProvider || fired.Load() {
			return nil
		}
		list, _ := e.client.ListProfiles(context.Background())
		for _, pf := range list {
			if strings.HasPrefix(pf.ID, "dc-cred-") {
				fired.Store(true)
				_, _ = e.client.DeleteProfile(context.Background(), pf.ID)
				return fmt.Errorf("provider type %q is not registered", pf.ID)
			}
		}
		return nil
	})
	sb := e.create(sandboxapi.CreateRequest{Name: "cred-race", Credentials: stripeCred})
	p, err := e.client.GetProvider(t.Context(), sb.Name+"-cred-0")
	must(t, err)
	if _, err := e.client.GetProfile(t.Context(), p.Type); err != nil {
		t.Fatalf("the profile was not imported again: %v", err)
	}
}

// An image built for another identity than the one the policy runs the
// workload as is refused before anything is created.
func TestCreateRunsAsTheImageIdentity(t *testing.T) {
	e := newEnv(t, nil)
	e.images.rec.UID, e.images.rec.GID, e.images.fixedUID = 4242, 4242, true
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "uid-foreign"})
	if apiErr := wantCode(t, err, sandboxapi.CodeImageUnavailable); !strings.Contains(apiErr.Error(), "4242") {
		t.Fatalf("create with a foreign-uid image = %v", err)
	}
	if _, err := e.client.GetSandbox(t.Context(), "uid-foreign"); !openshell.IsNotFound(err) {
		t.Fatalf("sandbox created with a foreign-uid image: %v", err)
	}
}

func TestStartRotatesBinding(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "rotbox"})
	oldToken, binding := e.ingressToken("rotbox"), e.binding("rotbox")
	if stopped, err := e.m.Stop(t.Context(), sb.Name); err != nil || stopped.Phase != "stopped" || len(e.ws.released) != 0 {
		t.Fatalf("stop = %+v, %v, released %v", stopped, err, e.ws.released)
	}
	snaps := len(e.ws.snapshots)
	if started, err := e.m.Start(t.Context(), sb.Name, sandboxapi.StartRequest{}); err != nil || started.Phase != "ready" {
		t.Fatalf("start = %+v, %v", started, err)
	}
	newToken := e.ingressToken("rotbox")
	if _, err := e.store.Match(oldToken); newToken == oldToken || newToken == "" || err == nil {
		t.Fatal("start did not rotate the token")
	}
	if b, err := e.store.Match(newToken); err != nil || b.ID != binding.ID || !slices.Contains(e.forgot, binding.ID) {
		t.Fatalf("new token: %v (forgotten ingress state %v)", err, e.forgot)
	}
	if len(e.ws.snapshots) != snaps || !e.ws.lastSnapshot.Replace {
		t.Fatal("start did not take a fresh snapshot")
	}
	want := []audit.SandboxPhase{audit.SandboxPhaseCreating, audit.SandboxPhaseReady, audit.SandboxPhaseStopping,
		audit.SandboxPhaseStopped, audit.SandboxPhaseStarting, audit.SandboxPhaseReady}
	if phases := e.tel.phases("rotbox"); !slices.Equal(phases, want) {
		t.Fatalf("lifecycle = %v, want %v", phases, want)
	}
}

// openshell.workdir.undo_ignored reaches the snapshots of a mounted project,
// the one at create and the one each start takes, from the configuration
// the daemon holds then: off, they keep no copy of ignored directories; on,
// they keep the configured names (or node_modules, .venv and venv) up to
// max_mb (500 MiB unless set) (#944).
func TestSnapshotsKeepTheConfiguredIgnoredDirs(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "keepbox"})
	if o := e.ws.lastSnapshot; o.KeepIgnored != nil || o.KeepIgnoredBytes != 0 {
		t.Fatalf("off: snapshot keeps %v up to %d bytes", o.KeepIgnored, o.KeepIgnoredBytes)
	}
	e.setConfig(func(c *config.Config) {
		c.OpenShell.Workdir.UndoIgnored = config.OpenShellUndoIgnoredConfig{Enabled: true}
	})
	if _, err := e.m.Stop(t.Context(), sb.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Start(t.Context(), sb.Name, sandboxapi.StartRequest{NewSnapshot: true}); err != nil {
		t.Fatal(err)
	}
	if o := e.ws.lastSnapshot; !slices.Equal(o.KeepIgnored, []string{"node_modules", ".venv", "venv"}) || o.KeepIgnoredBytes != 500<<20 {
		t.Fatalf("defaults: snapshot keeps %v up to %d bytes", o.KeepIgnored, o.KeepIgnoredBytes)
	}
	e.setConfig(func(c *config.Config) {
		c.OpenShell.Workdir.UndoIgnored = config.OpenShellUndoIgnoredConfig{Enabled: true, MaxMB: 64, Dirs: []string{"vendor"}}
	})
	if _, err := e.m.Delete(t.Context(), sb.Name, sandboxapi.DeleteRequest{}); err != nil {
		t.Fatal(err)
	}
	e.create(sandboxapi.CreateRequest{Name: "keepbox2"})
	if o := e.ws.lastSnapshot; !slices.Equal(o.KeepIgnored, []string{"vendor"}) || o.KeepIgnoredBytes != 64<<20 {
		t.Fatalf("configured: snapshot keeps %v up to %d bytes", o.KeepIgnored, o.KeepIgnoredBytes)
	}
}

// An administrator change applies to a stopped sandbox: a harness, live mount
// or learn mode the organization disallowed since refuses the start.
func TestStartRechecksAdminPolicy(t *testing.T) {
	for name, edit := range map[string]func(c *config.Config, project string){
		"allowed_harnesses": func(c *config.Config, _ string) { c.OpenShell.Admin.AllowedHarnesses = []string{"codex"} },
		"allow_mount":       func(c *config.Config, _ string) { c.OpenShell.Admin.AllowMount = boolPtr(false) },
		"require_copy_for":  func(c *config.Config, project string) { c.OpenShell.Admin.RequireCopyFor = []string{project} },
		"allow_learn_mode":  func(c *config.Config, _ string) { c.OpenShell.Admin.AllowLearnMode = boolPtr(false) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.create(sandboxapi.CreateRequest{Name: "orgbox", Learn: true})
			e.stopBox("orgbox")
			e.setConfig(func(c *config.Config) { edit(c, e.project) })
			_, err := e.m.Start(t.Context(), "orgbox", sandboxapi.StartRequest{})
			if apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation); !strings.Contains(apiErr.Message, sandboxapi.AdminMessage) {
				t.Fatalf("message = %q", apiErr.Message)
			}
			if got, _ := e.client.GetSandbox(t.Context(), "orgbox"); got.Status.Phase != openshell.PhaseStopped {
				t.Fatalf("refused sandbox started: %s", got.Status.Phase)
			}
		})
	}
}

// Start leaves a running session alone: its ingress token, pre-session
// snapshot, tool-call ledger and guard record stay as they are.
func TestStartRefusesARunningSandbox(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "livebox"})
	token, snap, binding := e.ingressToken("livebox"), e.ws.snapshots["livebox"], e.binding("livebox")
	e.m.toolCalls.ObservePre(binding.ID, idRef("toolu_1"), false)
	guard := e.boxOf("livebox").rec.Guard
	_, err := e.m.Start(t.Context(), "livebox", sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodeConflict)
	n, _ := e.m.toolCalls.tracked(binding.ID)
	if e.ingressToken("livebox") != token || e.ws.snapshots["livebox"] != snap || n != 1 || e.boxOf("livebox").rec.Guard != guard {
		t.Fatal("start changed a running session's token, snapshot, ledger or guard record")
	}
}

// A lifecycle call on a sandbox being created is refused at once instead of
// waiting out the create, which may build an image for a long time.
func TestLifecycleCallsDuringCreateFailFast(t *testing.T) {
	e := newEnv(t, nil)
	b, err := e.m.reserve("slowbox", e.project, "mount")
	must(t, err)
	b.op.Lock()
	defer b.op.Unlock()
	ctx := t.Context()
	for name, call := range map[string]func() error{
		"stop":   func() error { _, err := e.m.Stop(ctx, "slowbox"); return err },
		"start":  func() error { _, err := e.m.Start(ctx, "slowbox", sandboxapi.StartRequest{}); return err },
		"delete": func() error { _, err := e.m.Delete(ctx, "slowbox", sandboxapi.DeleteRequest{}); return err },
		"undo":   func() error { _, err := e.m.Undo(ctx, "slowbox", sandboxapi.UndoRequest{}); return err },
	} {
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			wantCode(t, err, sandboxapi.CodeConflict)
		case <-time.After(5 * time.Second):
			t.Fatalf("%s waited for the create", name)
		}
	}
}

// A stop or start OpenShell refused leaves the sandbox in the phase OpenShell
// reports (so triage, enforcement and the hook checks keep following it), and
// a failed stop lets a later hook tamper schedule another stop.
func TestFailedStopOrStartRestoresThePhase(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "stuckbox"})
	b := e.boxOf("stuckbox")
	e.m.mu.Lock()
	b.tamperStop = true
	e.m.mu.Unlock()
	e.fake.FailNext(openshelltest.MethodStopSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "driver busy"})
	if _, err := e.m.Stop(t.Context(), "stuckbox"); err == nil {
		t.Fatal("stop succeeded")
	}
	e.m.mu.Lock()
	phase, tamperStop := b.phase, b.tamperStop
	e.m.mu.Unlock()
	if phase != audit.SandboxPhaseReady || tamperStop {
		t.Fatalf("after the failed stop: phase %s, tamper stop pending %v", phase, tamperStop)
	}

	e.stopBox("stuckbox")
	e.fake.FailNext(openshelltest.MethodStartSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "driver busy"})
	if _, err := e.m.Start(t.Context(), "stuckbox", sandboxapi.StartRequest{}); err == nil {
		t.Fatal("start succeeded")
	}
	e.m.mu.Lock()
	phase, recorded := b.phase, b.rec.Phase
	e.m.mu.Unlock()
	if phase != audit.SandboxPhaseStopped || recorded != string(audit.SandboxPhaseStopped) {
		t.Fatalf("phase after the failed start = %s (recorded %s), want stopped", phase, recorded)
	}
}

// A new session keeps the pre-session snapshot while the folder still holds
// an earlier session's changes, and takes a fresh one once they were undone,
// when the folder is unchanged, or on request.
func TestStartKeepsTheSnapshotOfPendingChanges(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "keepsnap"})
	restarted := func(req sandboxapi.StartRequest) bool {
		t.Helper()
		before := e.ws.snapshots["keepsnap"]
		e.stopBox("keepsnap")
		e.startBox("keepsnap", req)
		return e.ws.snapshots["keepsnap"] != before
	}
	if restarted(sandboxapi.StartRequest{}) {
		t.Fatal("start replaced the snapshot of changes nobody undid or accepted")
	}
	if !slices.ContainsFunc(e.events("keepsnap", sandboxapi.ActivityWorkspace, "snapshot_kept"), func(ev sandboxapi.ActivityEvent) bool {
		return strings.Contains(ev.Message, "kept its undo point") && strings.Contains(ev.Message, "defenseclaw sandbox start keepsnap --new-snapshot")
	}) {
		t.Fatal("no notice that the snapshot was kept, with the command to take a new one")
	}
	if !restarted(sandboxapi.StartRequest{NewSnapshot: true}) {
		t.Fatal("--new-snapshot kept the old snapshot")
	}
	if _, err := e.m.Undo(t.Context(), "keepsnap", sandboxapi.UndoRequest{Stop: true}); err != nil {
		t.Fatal(err)
	}
	e.startBox("keepsnap", sandboxapi.StartRequest{})
	if e.ws.snapshots["keepsnap"].UndoneAt != nil {
		t.Fatal("the start after an undo kept the undone snapshot")
	}
	e.ws.mu.Lock()
	e.ws.clean = true
	e.ws.mu.Unlock()
	if !restarted(sandboxapi.StartRequest{}) {
		t.Fatal("the start of an unchanged folder kept the old snapshot")
	}
}

// Creates and starts are refused while the process does not hold its
// sandbox listeners.
func TestNoSandboxWithoutTheListeners(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "lstbox"})
	e.stopBox("lstbox")
	down := errors.New("the sandbox egress listener is not running in this process")
	e.m.opts.Listeners = func() error { return down }
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "lstbox2", Project: e.otherProject("l2")})
	wantCode(t, err, sandboxapi.CodeUnavailable)
	_, err = e.m.Start(t.Context(), "lstbox", sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodeUnavailable)
	down = nil
	e.startBox("lstbox", sandboxapi.StartRequest{})
}

// A folder (or one inside or around it) is mounted live by one sandbox at a
// time, copy mode is still offered, and undo waits for the others to stop.
func TestOneLiveMountPerFolder(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "firstbox"})
	sub := filepath.Join(e.project, "sub")
	must(t, os.MkdirAll(sub, 0o755))
	for _, project := range []string{e.project, sub} {
		_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "secondbox", Project: project})
		if apiErr := wantCode(t, err, sandboxapi.CodeConflict); !strings.Contains(apiErr.Message, "--copy") ||
			!strings.Contains(apiErr.Message, "`defenseclaw sandbox delete firstbox`") {
			t.Fatalf("refusal = %q, want the flag and the exact delete command", apiErr.Message)
		}
	}
	if _, err := e.m.Get(t.Context(), "secondbox"); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("the refused create left a box: %v", err)
	}
	e.create(sandboxapi.CreateRequest{Name: "copybox", Copy: true})
	e.deleteBox("firstbox", sandboxapi.DeleteRequest{KeepSnapshot: true})
	e.create(sandboxapi.CreateRequest{Name: "secondbox"})

	_, err := e.m.Undo(t.Context(), "firstbox", sandboxapi.UndoRequest{})
	wantCode(t, err, sandboxapi.CodeConflict)
	if slices.Contains(e.ws.undone, "firstbox") {
		t.Fatal("undo restored the folder under a running sandbox")
	}
	if _, err := e.m.Undo(t.Context(), "firstbox", sandboxapi.UndoRequest{Preview: true}); err != nil {
		t.Fatalf("a preview changes nothing and is allowed: %v", err)
	}
	e.stopBox("secondbox")
	if _, err := e.m.Undo(t.Context(), "firstbox", sandboxapi.UndoRequest{}); err != nil {
		t.Fatalf("undo once the other sandbox stopped: %v", err)
	}
}

// A mounted sandbox does not start while its project holds a secret its
// create-time masks leave visible, nor when the rescan cannot finish.
func TestStartRescansForSecrets(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Workdir.Masks = []string{"config/prod.yaml"} })
	e.ws.masked = []workspace.MaskedPath{{Rel: ".env", Reason: "name"}, {Rel: ".aws", Dir: true, Reason: "name"}}
	e.create(sandboxapi.CreateRequest{Name: "maskbox"})
	e.stopBox("maskbox")
	e.ws.scanned = []workspace.MaskedPath{{Rel: ".env"}, {Rel: ".aws/credentials"}, {Rel: "deploy/id_rsa", Reason: "name"}}
	_, err := e.m.Start(t.Context(), "maskbox", sandboxapi.StartRequest{})
	if apiErr := wantCode(t, err, sandboxapi.CodeConflict); !strings.Contains(apiErr.Message, "deploy/id_rsa") || strings.Contains(apiErr.Message, ".aws") {
		t.Fatalf("refusal = %q, want the one visible file named", apiErr.Message)
	}
	if n := e.fake.Calls(openshelltest.MethodStartSandbox); n != 0 {
		t.Fatal("the sandbox started with the secret visible")
	}
	if got := e.ws.lastScan; got.Project != e.project || !slices.Contains(got.Masks, "config/prod.yaml") {
		t.Fatalf("scan options = %+v, want the policy's masks", got)
	}
	e.ws.scanErr = errors.Join(workspace.ErrScanIncomplete, errors.New("too many entries"))
	_, err = e.m.Start(t.Context(), "maskbox", sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodeConflict)
	e.ws.scanned, e.ws.scanErr = []workspace.MaskedPath{{Rel: ".env"}}, nil
	e.startBox("maskbox", sandboxapi.StartRequest{})
}

// The end-of-session review names the secret files the next start refuses
// on (GAP-2094), and none while the masks cover what the scan finds.
func TestReviewNamesUnmaskedSecrets(t *testing.T) {
	e := newEnv(t, nil)
	e.ws.masked = []workspace.MaskedPath{{Rel: ".env", Reason: "name"}}
	e.create(sandboxapi.CreateRequest{Name: "revbox"})
	review, err := e.m.Review(t.Context(), "revbox", sandboxapi.ReviewRequest{})
	if err != nil || len(review.UnmaskedSecrets) != 0 {
		t.Fatalf("review = %+v, %v; want no unmasked secrets", review, err)
	}
	e.ws.scanned = []workspace.MaskedPath{{Rel: ".env"}, {Rel: "blk2.txt", Reason: "content"}}
	review, err = e.m.Review(t.Context(), "revbox", sandboxapi.ReviewRequest{})
	if err != nil || !slices.Equal(review.UnmaskedSecrets, []string{"blk2.txt"}) {
		t.Fatalf("review = %+v, %v; want blk2.txt named", review, err)
	}
	e.ws.scanErr = workspace.ErrScanIncomplete
	if review, err = e.m.Review(t.Context(), "revbox", sandboxapi.ReviewRequest{}); err != nil || len(review.UnmaskedSecrets) != 0 {
		t.Fatalf("review with a failed scan = %+v, %v; want it reviewed without names", review, err)
	}
}

// A sandbox whose template limits exceed the organization's lowered or newly
// set max_resources is reported and refused a start; one within the cap starts.
func TestStartRefusesLimitsAboveALowerMaximum(t *testing.T) {
	for _, tc := range []struct {
		name, memory string
		max          config.OpenShellResourcesConfig
		refuse       bool
	}{
		{"lowered below the limit", "4Gi", config.OpenShellResourcesConfig{Memory: "2Gi"}, true},
		{"set over an unlimited sandbox", "", config.OpenShellResourcesConfig{CPU: "2"}, true},
		{"within the cap", "1Gi", config.OpenShellResourcesConfig{Memory: "2Gi"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.create(sandboxapi.CreateRequest{Name: "resbox", Memory: tc.memory})
			e.stopBox("resbox")
			e.setConfig(func(c *config.Config) { c.OpenShell.Admin.MaxResources = tc.max })
			warned := findWarning(e.get("resbox").Warnings, "your organization now caps sandbox") != ""
			_, err := e.m.Start(t.Context(), "resbox", sandboxapi.StartRequest{})
			if !tc.refuse {
				if err != nil || warned {
					t.Fatalf("start = %v, warned %v; want it started", err, warned)
				}
				return
			}
			if apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation); !warned || apiErr.Violation == nil || !strings.HasPrefix(apiErr.Violation.Key, "resources.") {
				t.Fatalf("warned %v, violation = %+v", warned, apiErr.Violation)
			}
		})
	}
	if v := resourceViolation(nil, config.OpenShellResourcesConfig{CPU: "1"}); v != nil {
		t.Fatalf("a record without limits was judged: %+v", v)
	}
	if v := resourceViolation(&packs.Resources{CPU: "500m"}, config.OpenShellResourcesConfig{CPU: "1"}); v != nil {
		t.Fatalf("a limit within the cap = %+v", v)
	}
	if v := resourceViolation(&packs.Resources{CPU: "2"}, config.OpenShellResourcesConfig{CPU: "1"}); v == nil || v.Key != "resources.cpu" || !v.Admin() {
		t.Fatalf("a limit over the cap = %+v", v)
	}
}

// A stop asks the harness to exit before OpenShell stops the sandbox (so it
// runs its SessionEnd hook); a sandbox that does not answer is stopped
// anyway, and a stopped one has no harness to end.
func TestStopEndsTheHarnessFirst(t *testing.T) {
	e := liveEnv(t, "stopbox", nil)
	var mu sync.Mutex
	var order []string
	note := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }
	e.handleExec(func(context.Context, openshelltest.ExecCall) openshelltest.ExecResponse {
		note("exec")
		return openshelltest.ExecResponse{Stdout: []byte("exited\n")}
	})
	e.fake.Intercept(func(method string) error {
		if method == openshelltest.MethodStopSandbox {
			note("stop")
		}
		return nil
	})
	e.stopBox("stopbox")
	mu.Lock()
	got := slices.Clone(order)
	mu.Unlock()
	if len(got) < 2 || got[0] != "exec" || !slices.Contains(got, "stop") {
		t.Fatalf("calls = %v, want the harness asked to exit before the stop", got)
	}
	if calls := e.execCalls(); len(calls) != 1 || !slices.Contains(calls[0].Command, harness.ClaudeCode.InstallRoot()) ||
		!slices.Contains(calls[0].Command, harness.RunDir) || calls[0].Timeout <= harnessExitWait {
		t.Fatalf("exec calls = %+v", calls)
	}
	e.startBox("stopbox", sandboxapi.StartRequest{})
	e.handleExec(func(context.Context, openshelltest.ExecCall) openshelltest.ExecResponse {
		return openshelltest.ExecResponse{Err: errors.New("exec relay closed")}
	})
	e.stopBox("stopbox")
	if got := e.get("stopbox"); got.Phase != strings.ToLower(string(openshell.PhaseStopped)) {
		t.Fatalf("phase = %s", got.Phase)
	}
	before := len(e.fake.ExecCalls())
	e.stopBox("stopbox")
	if len(e.fake.ExecCalls()) != before {
		t.Fatal("a stopped sandbox's harness was asked to exit")
	}
}

// The script finds the harness by the install root its executable, or its
// command line, lies under, sends it SIGTERM and waits for it to exit; other
// processes are left alone.
func TestEndHarnessScript(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the script reads /proc")
	}
	root := filepath.Join(t.TempDir(), "harness")
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep(1)")
	}
	data, err := os.ReadFile(sleepBin)
	must(t, err)
	bin := writeFile(t, filepath.Join(root, "bin", "fakeharness"), string(data))
	must(t, os.Chmod(bin, 0o755))
	script := func(wait string) string {
		out, err := exec.Command("/bin/sh", "-c", endHarnessScript, "defenseclaw-end-harness", root, wait).Output()
		must(t, err)
		return strings.TrimSpace(string(out))
	}
	exits := func(c *exec.Cmd) {
		t.Helper()
		must(t, c.Start())
		t.Cleanup(func() { _ = c.Process.Kill() })
		exited := make(chan struct{})
		go func() { _ = c.Wait(); close(exited) }()
		if out := script("50"); out != "exited" {
			t.Fatalf("script said %q", out)
		}
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Fatal("the harness did not exit")
		}
	}
	other := exec.Command(sleepBin, "60")
	must(t, other.Start())
	t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
	exits(exec.Command(bin, "60"))
	if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(other.Process.Pid))); err != nil {
		t.Fatal("another process was signalled")
	}
	if out := script("5"); out != "none" {
		t.Fatalf("script with no harness = %q", out)
	}
	// Run through a link outside the install root by an interpreter elsewhere
	// (live: /usr/local/bin/claude): its command line names it.
	link := filepath.Join(t.TempDir(), "harness")
	must(t, os.Symlink(writeFile(t, filepath.Join(root, "bin", "harness.sh"), "while :; do sleep 1; done\n"), link))
	exits(exec.Command("/bin/sh", link))
}

// A detached run the stop ends read "exited with status 143" after the
// sandbox started again (the live CLI test): the SIGTERM let its runner
// record the harness's status. The script marks a run that has not ended
// interrupted first, and leaves a finished run, and a sandbox without a
// run, alone.
func TestEndHarnessScriptMarksTheDetachedRun(t *testing.T) {
	root := filepath.Join(t.TempDir(), "no-harness")
	end := func(args ...string) {
		t.Helper()
		out, err := exec.Command("/bin/sh", append([]string{"-c", endHarnessScript, "defenseclaw-end-harness", root, "1"}, args...)...).Output()
		if err != nil || parseHarnessEnd(out).Harness != "none" {
			t.Fatalf("script = %q, %v", out, err)
		}
	}
	exitOf := func(dir string) string {
		data, err := os.ReadFile(filepath.Join(dir, "latest.exit"))
		if os.IsNotExist(err) {
			return "(none)"
		}
		must(t, err)
		return string(data)
	}
	going, finished, none := t.TempDir(), t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(going, "latest.pid"), "4242\n")
	writeFile(t, filepath.Join(finished, "latest.pid"), "4242\n")
	writeFile(t, filepath.Join(finished, "latest.exit"), "0\n")
	end(going)
	end(finished)
	end(none)
	end()
	for dir, want := range map[string]string{going: "interrupted\n", finished: "0\n", none: "(none)"} {
		if got := exitOf(dir); got != want {
			t.Fatalf("%s latest.exit = %q, want %q", filepath.Base(dir), got, want)
		}
	}
}

// A delete releases everything the sandbox held, and the --credential
// profile once no other sandbox uses it; the ingress profile stays.
func TestDeleteReleasesEverything(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "delbox", LLM: anthropicLLM, Credentials: stripeCred})
	e.create(sandboxapi.CreateRequest{Name: "cred-b", Credentials: stripeCred, Project: e.otherProject("cred-b")})
	token, binding, dir := e.ingressToken("delbox"), e.binding("delbox"), filepath.Join(e.dataDir, "sandboxes", "delbox")
	p, err := e.client.GetProvider(t.Context(), "delbox-cred-0")
	if err != nil || !strings.HasPrefix(p.Type, "dc-cred-") || !fileExists(dir) {
		t.Fatalf("credential provider = %+v, %v; data directory %v", p, err, fileExists(dir))
	}
	_, err = e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "webhook.site", Sandbox: "delbox"})
	must(t, err)
	if resp, err := e.m.Delete(t.Context(), "delbox", sandboxapi.DeleteRequest{}); err != nil || !resp.Deleted || len(resp.Providers) != 3 {
		t.Fatalf("delete = %+v, %v", resp, err)
	}
	if _, err := e.client.GetSandbox(t.Context(), "delbox"); !openshell.IsNotFound(err) {
		t.Fatalf("sandbox still there: %v", err)
	}
	if _, err := e.store.Match(token); !errors.Is(err, sandboxauth.ErrUnauthenticated) {
		t.Fatalf("token after delete: %v", err)
	}
	if _, ok := e.m.creds.Lookup(binding.ID); ok || !slices.Equal(e.providers(), []string{"cred-b-cred-0", "cred-b-ingress"}) || len(e.m.unblocks.List()) != 0 {
		t.Fatalf("left: proxy credential %v, providers %v, unblocks %v", ok, e.providers(), e.m.unblocks.List())
	}
	if !slices.Contains(e.ws.released, "delbox") || !slices.Contains(e.ws.deleted, "delbox") {
		t.Fatalf("workspace not released: released %v deleted %v", e.ws.released, e.ws.deleted)
	}
	if phases := e.tel.phases("delbox"); phases[len(phases)-1] != audit.SandboxPhaseDeleted {
		t.Fatalf("lifecycle = %v", phases)
	}
	if _, err := e.m.Get(t.Context(), "delbox"); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("get after delete: %v", err)
	}
	if fileExists(filepath.Join(e.dataDir, "sandboxes", "manager", "delbox.json")) || fileExists(dir) {
		t.Fatal("record or data directory left")
	}
	// cred-b still uses the shared profile; the last user takes it along.
	if _, err := e.client.GetProfile(t.Context(), p.Type); err != nil {
		t.Fatalf("a profile another sandbox uses was deleted: %v", err)
	}
	e.deleteBox("cred-b", sandboxapi.DeleteRequest{})
	if _, err := e.client.GetProfile(t.Context(), p.Type); !openshell.IsNotFound(err) {
		t.Fatalf("the unused credential profile is left: %v", err)
	}
	if _, err := e.client.GetProfile(t.Context(), profiles.IngressProfileID(testIngressPort)); err != nil {
		t.Fatalf("the ingress profile went too: %v", err)
	}
}

// Teardown lists and removes what interrupted creates left under the data
// dir, and nothing else: no foreign file, no recorded or retained sandbox,
// not the record store.
func TestOrphanedSandboxData(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "live"})
	e.create(sandboxapi.CreateRequest{Name: "keepbox", Project: e.otherProject("keep")})
	e.deleteBox("keepbox", sandboxapi.DeleteRequest{KeepSnapshot: true})
	root := filepath.Join(e.dataDir, "sandboxes")
	for _, rel := range []string{"orphan-a/copy/stage/myapp/README.md", "orphan-a/run-config/settings.json", "orphan-a/workspace/masks/empty",
		"orphan-b/notes.txt", "live/run-config/extra.json", "keepbox/run-config/extra.json"} {
		writeFile(t, filepath.Join(root, filepath.FromSlash(rel)), "x")
	}
	if got := OrphanedSandboxData(e.dataDir); !slices.Equal(got, []string{"orphan-a", "orphan-b"}) {
		t.Fatalf("orphans = %v", got)
	}
	must(t, RemoveOrphanedSandboxData(e.dataDir, "orphan-a"))
	if fileExists(filepath.Join(root, "orphan-a")) {
		t.Fatal("orphan-a is left")
	}
	if err := RemoveOrphanedSandboxData(e.dataDir, "orphan-b"); err == nil || !strings.Contains(err.Error(), "left in place") ||
		!fileExists(filepath.Join(root, "orphan-b", "notes.txt")) {
		t.Fatalf("orphan-b = %v, want the foreign file left", err)
	}
	for _, name := range []string{"live", "keepbox", "manager", "../escape"} {
		if err := RemoveOrphanedSandboxData(e.dataDir, name); err == nil {
			t.Fatalf("RemoveOrphanedSandboxData(%s) succeeded", name)
		}
	}
	if !fileExists(filepath.Join(root, "live", "run-config", "extra.json")) || !fileExists(filepath.Join(root, "keepbox", "run-config", "extra.json")) {
		t.Fatal("a recorded sandbox's data was removed")
	}

	// A pre-session snapshot left without a record or directory is data too.
	dataDir, project := t.TempDir(), e.otherProject("snap")
	writeFile(t, filepath.Join(project, "README.md"), "hello\n")
	_, err := workspace.Snapshot(t.Context(), workspace.SnapshotOptions{Project: project, Name: "lostsnap", DataDir: dataDir})
	must(t, err)
	if got := OrphanedSandboxData(dataDir); !slices.Equal(got, []string{"lostsnap"}) {
		t.Fatalf("orphans = %v, want the snapshot's sandbox", got)
	}
	must(t, RemoveOrphanedSandboxData(dataDir, "lostsnap"))
	if _, err := workspace.LoadSnapshot(dataDir, "lostsnap"); !errors.Is(err, workspace.ErrSnapshotNotFound) || len(OrphanedSandboxData(dataDir)) != 0 {
		t.Fatalf("the orphaned snapshot is left: %v", err)
	}
}

// A kept snapshot is reachable under the sandbox's name, across a restart
// too, until the box is deleted, which drops the record and its directory.
func TestDeleteKeepSnapshot(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "keepbox"})
	e.deleteBox("keepbox", sandboxapi.DeleteRequest{KeepSnapshot: true})
	dir := filepath.Join(e.dataDir, "sandboxes", "keepbox")
	must(t, os.MkdirAll(dir, 0o700))
	if slices.Contains(e.ws.deleted, "keepbox") || slices.Contains(OrphanedSandboxData(e.dataDir), "keepbox") {
		t.Fatal("the kept snapshot was deleted or listed as leftover data")
	}
	e.m = e.newManager()
	if got := e.get("keepbox"); got.Phase != "deleted" || got.Snapshot == nil {
		t.Fatalf("kept box = %+v", got)
	}
	if st, _ := e.m.Status(t.Context()); st.Sandboxes != 0 {
		t.Fatalf("status counts the kept snapshot as a sandbox: %d", st.Sandboxes)
	}
	if _, err := e.m.Start(t.Context(), "keepbox", sandboxapi.StartRequest{}); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
		t.Fatalf("start of a deleted sandbox: %v", err)
	}
	if _, err := e.tryCreate(sandboxapi.CreateRequest{Name: "keepbox"}); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
		t.Fatalf("create over the kept snapshot: %v", err)
	}
	if _, err := e.m.Review(t.Context(), "keepbox", sandboxapi.ReviewRequest{}); err != nil {
		t.Fatalf("review: %v", err)
	}
	if _, err := e.m.Undo(t.Context(), "keepbox", sandboxapi.UndoRequest{Stop: true, Restart: true}); err != nil || !slices.Contains(e.ws.undone, "keepbox") {
		t.Fatalf("undo: %v", err)
	}
	e.deleteBox("keepbox", sandboxapi.DeleteRequest{})
	if _, err := e.m.Get(t.Context(), "keepbox"); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) || !slices.Contains(e.ws.deleted, "keepbox") {
		t.Fatalf("box survived: %v (snapshots deleted %v)", err, e.ws.deleted)
	}
	if p, _ := e.m.records.path("keepbox"); fileExists(p) || fileExists(dir) {
		t.Fatal("the record or the sandbox directory survived the delete")
	}
}

// A started undo or delete runs to its end when the API request that started
// it goes away: the restore is a sequence of git steps on the user's folder.
func TestUndoAndDeleteRunToTheirEndWhenTheCallerLeaves(t *testing.T) {
	for _, op := range []string{"undo", "delete"} {
		t.Run(op, func(t *testing.T) {
			e := newEnv(t, nil)
			e.create(sandboxapi.CreateRequest{Name: "leavebox"})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			mid := errors.New("not reached")
			leave := func(c context.Context) { cancel(); mid = c.Err() }
			var err error
			if op == "undo" {
				e.stopBox("leavebox")
				e.ws.onUndo = leave
				_, err = e.m.Undo(ctx, "leavebox", sandboxapi.UndoRequest{})
			} else {
				e.ws.onDeleteSnapshot = leave
				_, err = e.m.Delete(ctx, "leavebox", sandboxapi.DeleteRequest{})
			}
			if err != nil || mid != nil {
				t.Fatalf("%s = %v; the step ran on a context the caller's leaving cancelled: %v", op, err, mid)
			}
			if op == "delete" && fileExists(filepath.Join(e.dataDir, "sandboxes", "manager", "leavebox.json")) {
				t.Fatal("record left")
			}
		})
	}
}

func TestUndoReviewAndWorkspaceReports(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "undobox"})
	if _, err := e.m.Undo(t.Context(), "undobox", sandboxapi.UndoRequest{}); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
		t.Fatalf("undo while running: %v", err)
	}
	resp, err := e.m.Undo(t.Context(), "undobox", sandboxapi.UndoRequest{Stop: true, Restart: true})
	if err != nil || !resp.Stopped || !resp.Restarted || resp.Result == nil || !slices.Contains(e.ws.undone, "undobox") {
		t.Fatalf("undo = %+v, %v", resp, err)
	}
	review, err := e.m.Review(t.Context(), "undobox", sandboxapi.ReviewRequest{Diff: true})
	if err != nil || review.Summary != "2 files changed (+5 −1)" || !strings.Contains(review.RiskLine, "package.json") || review.Diff == "" {
		t.Fatalf("review = %+v, %v", review, err)
	}
	var undo, rev bool
	for _, w := range where(&e.tel.mu, &e.tel.workspace, nil) {
		undo = undo || (w.Operation == audit.SandboxWorkspaceUndo && w.Result == audit.SandboxWorkspaceApplied)
		rev = rev || (w.Operation == audit.SandboxWorkspaceReview && w.FlaggedCount != nil && *w.FlaggedCount == 1)
	}
	if !undo || !rev {
		t.Fatalf("workspace telemetry = %+v", e.tel.workspace)
	}
	e.create(sandboxapi.CreateRequest{Name: "copyrep", Copy: true})
	if _, err := e.m.Undo(t.Context(), "copyrep", sandboxapi.UndoRequest{Stop: true}); !sandboxapi.IsCode(err, sandboxapi.CodeInvalid) ||
		!strings.Contains(err.Error(), "pull --apply") || strings.Contains(err.Error(), "never changed") {
		t.Fatalf("copy undo: %v", err)
	}

	// The CLI reports copy-mode workspace operations, a revert of an apply as an undo.
	files := int64(3)
	must(t, e.m.ReportWorkspace(t.Context(), "copyrep", sandboxapi.WorkspaceReport{
		Operation: sandboxapi.WorkspacePull, PullMode: audit.SandboxPullBranch, FileCount: &files, Paths: []string{"a.go"}}))
	if last := e.tel.workspace[len(e.tel.workspace)-1]; last.Operation != audit.SandboxWorkspacePull || last.PullMode != "branch" ||
		*last.FileCount != 3 || last.Sandbox.Name != "copyrep" {
		t.Fatalf("workspace record = %+v", last)
	}
	must(t, e.m.ReportWorkspace(t.Context(), "copyrep", sandboxapi.WorkspaceReport{Operation: sandboxapi.WorkspaceUndo, FileCount: &files}))
	if last := e.tel.workspace[len(e.tel.workspace)-1]; last.Operation != audit.SandboxWorkspaceUndo || last.PullMode != "" {
		t.Fatalf("undo record = %+v", last)
	}
	negative := int64(-1)
	for _, bad := range []sandboxapi.WorkspaceReport{
		{Operation: "restore"}, {Operation: sandboxapi.WorkspaceUndo, PullMode: "apply"}, {Operation: sandboxapi.WorkspacePull},
		{Operation: sandboxapi.WorkspaceUpload, PullMode: "apply"}, {Operation: sandboxapi.WorkspaceUpload, Result: "exploded"},
		{Operation: sandboxapi.WorkspaceUpload, ByteCount: &negative},
	} {
		if err := e.m.ReportWorkspace(t.Context(), "copyrep", bad); !sandboxapi.IsCode(err, sandboxapi.CodeInvalid) {
			t.Fatalf("report %+v: %v", bad, err)
		}
	}
	if err := e.m.ReportWorkspace(t.Context(), "nope", sandboxapi.WorkspaceReport{Operation: "upload"}); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("unknown sandbox: %v", err)
	}
}

func TestGatewayUnavailable(t *testing.T) {
	e := newEnv(t, nil)
	e.connErr = errors.New("connection refused")
	_, err := e.tryCreate(sandboxapi.CreateRequest{})
	wantCode(t, err, sandboxapi.CodeUnavailable)
	if st, err := e.m.Status(t.Context()); err != nil || st.Available || !strings.Contains(st.Reason, "connection refused") || !st.Enabled {
		t.Fatalf("status = %+v, %v", st, err)
	}
	e.connErr = nil
	// Within the reconnect backoff the failure is reported without redialing.
	if st, _ := e.m.Status(t.Context()); st.Available {
		t.Fatal("redialed inside the backoff")
	}
	e.m.now = func() time.Time { return time.Now().Add(time.Minute) }
	if st, _ := e.m.Status(t.Context()); !st.Available || st.Gateway == nil || st.Gateway.Version != "0.1.1" || st.Pack != "open" {
		t.Fatalf("status = %+v", st)
	}
	var degraded, restored bool
	for _, h := range where(&e.tel.mu, &e.tel.health, nil) {
		degraded = degraded || h.State == audit.SandboxHealthDegraded
		restored = restored || h.State == audit.SandboxHealthRestored
	}
	if !degraded || !restored {
		t.Fatalf("health = %+v", e.tel.health)
	}
}

// Generated names fit OpenShell 0.1.1's 19-character limit whatever the
// folder is called (m1-calc once produced dc-claude-m1-calc-7500), and so
// do the providers named after a sandbox (39 characters were accepted live).
func TestComposeName(t *testing.T) {
	for _, tc := range []struct{ project, want string }{
		{"/home/u/code/myapp", "myapp-7f3a"},
		{"/home/u/m1-calc", "m1-calc-7f3a"},
		{"/x/My App_2", "my-app-2-7f3a"},
		{"/x/defenseclaw-openshell", "defenseclaw-op-7f3a"},
		{"/x/" + strings.Repeat("a", 80), strings.Repeat("a", 14) + "-7f3a"},
		{"/x/abcdefghijklm-nopq", "abcdefghijklm-7f3a"}, // a cut that ends in '-' drops it
		{"", "project-7f3a"},
		{"/x/---", "project-7f3a"},
		{"/x/.hidden", "hidden-7f3a"},
	} {
		if got := composeName(tc.project, "7f3a"); got != tc.want || !openshell.ValidNewSandboxName(got) {
			t.Errorf("composeName(%q) = %q, want %q", tc.project, got, tc.want)
		}
	}
	for _, project := range []string{"/x/app", "/x/" + strings.Repeat("z", 40), "/"} {
		if n, err := GenerateName(project); err != nil || !openshell.ValidNewSandboxName(n) || workspace.ValidateName(n) != nil {
			t.Fatalf("GenerateName(%q) = %q, %v", project, n, err)
		}
	}
	longest := strings.Repeat("a", openshell.MaxSandboxNameLen)
	for _, p := range []string{providerName(longest, roleIngress, 0), providerName(longest, roleCredential, 15)} {
		if len(p) > 39 {
			t.Errorf("provider name %q is %d characters", p, len(p))
		}
	}
}

// A byte limit never splits a UTF-8 sequence: reject reasons, OpenShell
// errors and project paths can hold any text.
func TestTruncateKeepsRunesWhole(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"short", 16, "short"}, {"exact", 5, "exact"}, {"abcdef", 3, "abc"},
		{"aé", 2, "a"}, {"aéb", 3, "aé"}, {"ab→", 4, "ab"}, {"a\U0001F600", 4, "a"}, {"a\U0001F600b", 5, "a\U0001F600"},
		{"\xff\xfe\xfd\xfc", 2, "\xff\xfe"}, // not UTF-8: a plain byte cut
		{"a\x80\x80\x80\x80\x80", 5, "a\x80\x80\x80\x80"},
	} {
		if got := truncate(tc.in, tc.n); got != tc.want || len(got) > tc.n || (utf8.ValidString(tc.in) && !utf8.ValidString(got)) {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

// A sandbox deleted outside DefenseClaw and followed by another of the same
// name is never stopped, started or deleted in its place: Get reports it
// missing, Stop and Start refuse, Delete releases DefenseClaw's state only.
func TestOperationsLeaveASandboxThatTookTheName(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "namebox"})
	other := replaceOutside(t, e, "namebox", map[string]string{LabelManaged: "true", LabelOwner: "fedcba9876543210"}, openshell.PhaseReady)
	if got := e.get("namebox"); got.Phase != "missing" {
		t.Fatalf("get = %+v; want it missing", got)
	}
	if _, err := e.m.Stop(t.Context(), "namebox"); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) || e.fake.Calls(openshelltest.MethodStopSandbox) != 0 {
		t.Fatalf("stop = %v, want a conflict and the other sandbox left running", err)
	}
	if resp, err := e.m.Delete(t.Context(), "namebox", sandboxapi.DeleteRequest{}); err != nil || !resp.Deleted {
		t.Fatalf("delete = %+v, %v", resp, err)
	}
	if now, err := e.client.GetSandbox(t.Context(), "namebox"); err != nil || now.ID != other.ID || len(e.providers()) != 0 {
		t.Fatalf("Delete deleted the other sandbox (%+v, %v) or left its own providers %v", now, err, e.providers())
	}

	// A stopped sandbox of the name that is not DefenseClaw's never gets the session's token.
	e.create(sandboxapi.CreateRequest{Name: "startbox", Project: e.otherProject("start")})
	e.stopBox("startbox")
	replaceOutside(t, e, "startbox", e.m.managedSelector(), openshell.PhaseStopped)
	if _, err := e.m.Start(t.Context(), "startbox", sandboxapi.StartRequest{}); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) ||
		e.fake.Calls(openshelltest.MethodStartSandbox) != 0 {
		t.Fatalf("start = %v, want a conflict and no start call", err)
	}
}

// replaceOutside deletes a sandbox outside DefenseClaw and creates another
// under its name, with labels, in phase. The fake gateway gives sandboxes no
// IDs: the box records one and the new sandbox gets another.
func replaceOutside(t *testing.T, e *harnessEnv, name string, labels map[string]string, phase openshell.SandboxPhase) *openshell.Sandbox {
	t.Helper()
	e.m.mu.Lock()
	e.m.boxes[name].rec.ID = "id-" + name
	e.m.mu.Unlock()
	_, err := e.client.DeleteSandbox(t.Context(), name)
	must(t, err)
	_, err = e.fake.SDK().Sandboxes().Create(t.Context(), openshell.DefaultWorkspace, name, &types.SandboxSpec{}, labels)
	must(t, err)
	must(t, e.fake.SetPhase(openshell.DefaultWorkspace, name, phase))
	sb, err := e.client.GetSandbox(t.Context(), name)
	must(t, err)
	sb.ID = "id-other-" + name
	e.fake.SDK().AddSandbox(openshell.DefaultWorkspace, sb)
	return sb
}

// A restarted daemon reports a still-ready sandbox's uptime from when it
// became ready (record.ReadyAt; OpenShell 0.1.1 reports no transition
// times), not from its adoption; a stop ends it.
func TestUptimeSurvivesADaemonRestart(t *testing.T) {
	e := liveEnv(t, "uptimebox", nil)
	e.stop()
	recs, errs := newRecordStore(e.dataDir).loadAll()
	if len(errs) > 0 || len(recs) != 1 || recs[0].ReadyAt.IsZero() {
		t.Fatalf("records = %+v, %v; want the ready time kept", recs, errs)
	}
	time.Sleep(2100 * time.Millisecond) // the daemon is down; the sandbox keeps running
	e.restartDaemon()
	eventually(t, "the adopted sandbox is ready", func() bool {
		sb, err := e.m.Get(t.Context(), "uptimebox")
		return err == nil && sb.Phase == "ready" && !sb.StartedAt.IsZero()
	})
	if sb := e.get("uptimebox"); sb.UptimeSeconds < 2 || !sb.StartedAt.Equal(recs[0].ReadyAt) {
		t.Fatalf("uptime after the restart = %ds since %v, want it counted from %v", sb.UptimeSeconds, sb.StartedAt, recs[0].ReadyAt)
	}
	e.stopBox("uptimebox")
	e.m.mu.Lock()
	ready := e.m.boxes["uptimebox"].rec.ReadyAt
	e.m.mu.Unlock()
	if !ready.IsZero() {
		t.Fatalf("a stopped sandbox keeps its ready time %v", ready)
	}
}

// A delete OpenShell refuses leaves the sandbox watched, in the phase
// OpenShell reports.
func TestDeleteFailureKeepsWatching(t *testing.T) {
	e := liveEnv(t, "stubborn", nil)
	e.fake.FailNext(openshelltest.MethodDeleteSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "driver busy"})
	if _, err := e.m.Delete(t.Context(), "stubborn", sandboxapi.DeleteRequest{}); err == nil {
		t.Fatal("delete succeeded")
	}
	e.m.mu.Lock()
	b := e.m.boxes["stubborn"]
	watching, phase := b.watchCancel != nil, b.phase
	e.m.mu.Unlock()
	if !watching || phase != audit.SandboxPhaseReady {
		t.Fatalf("watching %v, phase %s; want the ready sandbox still watched", watching, phase)
	}
	e.watch.push(t, "stubborn", stream.Event{Kind: stream.KindStatus, Status: &stream.Status{Phase: openshell.PhaseStopped}})
	eventually(t, "status after the failed delete", func() bool {
		phases := e.tel.phases("stubborn")
		return phases[len(phases)-1] == audit.SandboxPhaseStopped
	})
}

func findWarning(warnings []string, prefix string) string {
	for _, w := range warnings {
		if strings.HasPrefix(w, prefix) {
			return w
		}
	}
	return ""
}
