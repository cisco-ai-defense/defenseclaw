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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// useSandboxAvailability replaces the gateway's availability probe with a
// Linux one whose devices answer access.
func useSandboxAvailability(t *testing.T, access func(path string, uid int) sandboxDeviceAccess) {
	t.Helper()
	probe := newSandboxAvailabilityProbe()
	probe.goos, probe.goarch = "linux", "amd64"
	probe.access = access
	probe.prerequisite = nil
	probe.cpuInfoPath = filepath.Join(t.TempDir(), "absent") // no CPU flags check: the test host's CPU is not the test's
	old := defaultSandboxAvailability
	defaultSandboxAvailability = probe
	t.Cleanup(func() { defaultSandboxAvailability = old })
}

func sandboxDevicesUsable(string, int) sandboxDeviceAccess {
	return sandboxDeviceAccess{State: sandboxDeviceUsable}
}

func sandboxDevicesMissing(string, int) sandboxDeviceAccess {
	return sandboxDeviceAccess{State: sandboxDeviceMissing}
}

// requireSandboxTestAPI is a standalone managed gateway whose
// openshell.admin requires connectors in a sandbox. The host guardrail
// mode is observe: the gate refuses whatever the mode.
func requireSandboxTestAPI(t *testing.T, whenUnavailable string, required ...string) (*APIServer, *audit.Store) {
	t.Helper()
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.Mode = "observe"
	cfg.OpenShell.Enabled = true
	cfg.OpenShell.Admin.RequiredFor = required
	cfg.OpenShell.Admin.WhenUnavailable = whenUnavailable
	cfg.OpenShell.Admin.RequestAccess = "it-security@example.com"
	return &APIServer{scannerCfg: cfg, store: store, logger: logger}, store
}

// requireSandboxHook is one host hook of a connector, as its agent sends it.
type requireSandboxHook struct {
	connector, path, body string
	headers               map[string]string
}

var requireSandboxHooks = []requireSandboxHook{
	{connector: "claudecode", path: "/api/v1/claude-code/hook",
		body: `{"hook_event_name":"UserPromptSubmit","session_id":"s1","prompt":"hello","cwd":"__CWD__"}`},
	{connector: "codex", path: "/api/v1/codex/hook",
		body:    `{"hook_event_name":"PreToolUse","session_id":"s1","turn_id":"t1","tool_name":"Bash","tool_use_id":"u1","tool_input":{"command":"ls"},"cwd":"__CWD__"}`,
		headers: map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract}},
	{connector: "cursor", path: "/api/v1/cursor/hook",
		body: `{"hook_event_name":"beforeShellExecution","conversation_id":"c1","generation_id":"g1","command":"ls","cwd":"__CWD__","workspace_roots":["__CWD__"]}`},
	{connector: "copilot", path: "/api/v1/copilot/hook",
		body:    `{"timestamp":1790976011985,"cwd":"__CWD__","toolName":"bash","toolArgs":"{\"command\":\"ls\"}"}`,
		headers: map[string]string{"X-DefenseClaw-Copilot-Event": "preToolUse"}},
}

// requireSandboxProject is the project directory the hooks run in: a real
// directory, so the evaluator's own checks of it pass too.
func requireSandboxProject(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// postRequireSandboxHook sends hook, run in project, as the kernel-verified
// uid 1001.
func postRequireSandboxHook(t *testing.T, api *APIServer, hook requireSandboxHook, project string, ctx context.Context, extra map[string]string) map[string]any {
	t.Helper()
	// JSON-escape the path: Windows temp dirs have backslashes.
	quoted, err := json.Marshal(project)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.ReplaceAll(hook.body, "__CWD__", string(quoted[1:len(quoted)-1]))
	req := httptest.NewRequest(http.MethodPost, hook.path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hook.headers {
		req.Header.Set(k, v)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	if ctx == nil {
		ctx = req.Context()
	}
	req = req.WithContext(withManagedHookPeer(ctx, managedHookPeer{UID: 1001, Name: "alice"}))
	w := httptest.NewRecorder()
	api.handleAgentHook(hook.connector).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status %d body %s", hook.connector, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: decode %s: %v", hook.connector, w.Body.String(), err)
	}
	return out
}

// requireSandboxAuditOutcome is the require_sandbox field of the last
// connector-hook audit row ("" when it has none).
func requireSandboxAuditOutcome(t *testing.T, store *audit.Store) string {
	t.Helper()
	events, err := store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if ev.Action != string(audit.ActionConnectorHook) {
			continue
		}
		for _, field := range strings.Fields(ev.Details) {
			if v, ok := strings.CutPrefix(field, "require_sandbox="); ok {
				return v
			}
		}
		return ""
	}
	t.Fatal("no connector-hook audit row")
	return ""
}

// TestRequireSandboxRefusesHostRunPerConnector: a host run of each
// machine-hooked connector the floor requires is refused at its first
// blockable event with the paste-ready command, in observe mode too, and
// the refusal is on the audit row.
func TestRequireSandboxRefusesHostRunPerConnector(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	for _, hook := range requireSandboxHooks {
		t.Run(hook.connector, func(t *testing.T) {
			api, store := requireSandboxTestAPI(t, "", hook.connector)
			project := requireSandboxProject(t)
			out := postRequireSandboxHook(t, api, hook, project, nil, nil)
			want := sandboxapi.HostRunRefused(hook.connector, "", project, "it-security@example.com")
			if out["action"] != "block" || out["reason"] != want {
				t.Fatalf("host run not refused:\n got action=%v reason=%v\nwant %q", out["action"], out["reason"], want)
			}
			var body strings.Builder
			enc := json.NewEncoder(&body)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(out); err != nil || !strings.Contains(body.String(), `cd '`+project+`' && defenseclaw sandbox run `) {
				t.Fatalf("the agent output lacks the sandbox command: %s", body.String())
			}
			if got := requireSandboxAuditOutcome(t, store); got != requireSandboxRefused {
				t.Fatalf("audit require_sandbox = %q, want %q", got, requireSandboxRefused)
			}
		})
	}
}

// GAP-0185, GAP-0187: a managed gateway can't see into home folders, so
// the cd command names the folder the hook reported even where the gateway
// can't check it, shell-quoted for a folder with a quote, a space and an
// accent.
func TestRequireSandboxRefusalNamesAReportedProject(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	project := "/home/ent-alice/src/dccert-missing/o'brien app é"
	for _, hook := range requireSandboxHooks[:2] {
		api, _ := requireSandboxTestAPI(t, "", hook.connector)
		out := postRequireSandboxHook(t, api, hook, project, nil, nil)
		reason, _ := out["reason"].(string)
		want := `cd '/home/ent-alice/src/dccert-missing/o'\''brien app é' && defenseclaw sandbox run `
		if out["action"] != "block" || !strings.Contains(reason, want) {
			t.Fatalf("%s: reason %q lacks %q", hook.connector, reason, want)
		}
	}
}

// TestRequireSandboxIgnoresBypassAndForgedSandboxClaims: what a wrapper
// bypass or a forged nested run can put in front of the gateway (the
// bypass and sandbox variables, a sandbox bearer, registration and
// identity headers) never makes a host run a sandbox run.
func TestRequireSandboxIgnoresBypassAndForgedSandboxClaims(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	t.Setenv("DEFENSECLAW_NO_SANDBOX", "1")
	t.Setenv("DEFENSECLAW_SANDBOX_ID", "dcb-forged")
	t.Setenv("DEFENSECLAW_SANDBOX_NAME", "forged")
	t.Setenv("DEFENSECLAW_SANDBOX_TOKEN", "dc-forged-token")
	forged := map[string]string{
		"Authorization":                      "Bearer dc-forged-token",
		"X-DefenseClaw-Sandbox-Registration": "reg-aaaaaaaaaaaaaaaaaaaaaaaaaa",
		"X-DefenseClaw-Sandbox-Id":           "dcb-forged",
		"X-DefenseClaw-Client":               "sandbox-relay",
		"X-DefenseClaw-Agent-Surface":        "sandbox",
	}
	for _, hook := range requireSandboxHooks {
		api, store := requireSandboxTestAPI(t, "", hook.connector)
		if out := postRequireSandboxHook(t, api, hook, requireSandboxProject(t), nil, forged); out["action"] != "block" {
			t.Fatalf("%s: forged sandbox claims let the host run through: %v", hook.connector, out)
		}
		if got := requireSandboxAuditOutcome(t, store); got != requireSandboxRefused {
			t.Fatalf("%s: audit require_sandbox = %q", hook.connector, got)
		}
	}
	// Host hooks never read the sandbox variables: the native hook runner
	// has no code that could forward them.
	sources, err := filepath.Glob(filepath.Join("connector", "hookexec", "*.go"))
	if err != nil || len(sources) == 0 {
		t.Fatalf("hookexec sources: %v %v", sources, err)
	}
	for _, path := range sources {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"DEFENSECLAW_SANDBOX_", "DEFENSECLAW_NO_SANDBOX"} {
			if strings.Contains(string(data), name) {
				t.Errorf("%s reads %s: host hooks must never consult the sandbox variables", path, name)
			}
		}
	}
}

// TestRequireSandboxWhenUnavailable covers both when_unavailable values on
// an account that can't run a sandbox (no docker).
func TestRequireSandboxWhenUnavailable(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesMissing)
	hook := requireSandboxHooks[0]

	api, store := requireSandboxTestAPI(t, "", hook.connector)
	out := postRequireSandboxHook(t, api, hook, requireSandboxProject(t), nil, nil)
	want := sandboxapi.HostRunUnavailable(hook.connector, sandboxUnavailableNoDocker, "no_docker", "it-security@example.com")
	if out["action"] != "block" || out["reason"] != want {
		t.Fatalf("refuse: action=%v reason=%v, want %q", out["action"], out["reason"], want)
	}
	if got := requireSandboxAuditOutcome(t, store); got != requireSandboxUnavailable {
		t.Fatalf("refuse: audit require_sandbox = %q", got)
	}

	api, store = requireSandboxTestAPI(t, config.OpenShellWhenUnavailableAlert, hook.connector)
	if out := postRequireSandboxHook(t, api, hook, requireSandboxProject(t), nil, nil); out["action"] == "block" {
		t.Fatalf("alert: the host run was refused: %v", out)
	}
	if got := requireSandboxAuditOutcome(t, store); got != requireSandboxAlert {
		t.Fatalf("alert: audit require_sandbox = %q", got)
	}
}

// TestRequireSandboxExemptAndUnrequired: an exempt user's host run and a
// connector the floor doesn't require are evaluated as usual.
func TestRequireSandboxExemptAndUnrequired(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	hook := requireSandboxHooks[0]

	api, store := requireSandboxTestAPI(t, "", hook.connector)
	ctx := withEnterpriseExemptUser(context.Background())
	if out := postRequireSandboxHook(t, api, hook, requireSandboxProject(t), ctx, nil); out["action"] == "block" {
		t.Fatalf("exempt user refused: %v", out)
	}
	if got := requireSandboxAuditOutcome(t, store); got != requireSandboxExempt {
		t.Fatalf("exempt: audit require_sandbox = %q", got)
	}

	api, store = requireSandboxTestAPI(t, "", "codex")
	if out := postRequireSandboxHook(t, api, hook, requireSandboxProject(t), nil, nil); out["action"] == "block" {
		t.Fatalf("unrequired connector refused: %v", out)
	}
	if got := requireSandboxAuditOutcome(t, store); got != "" {
		t.Fatalf("unrequired: audit require_sandbox = %q", got)
	}
}

// TestRequireSandboxDecisionScope pins where the gate applies: standalone
// managed only, never on a relayed sandbox request, only at the events it
// judges, and only where the agent honours a block.
func TestRequireSandboxDecisionScope(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "alice"})

	api, _ := requireSandboxTestAPI(t, "", "claudecode", "codex")
	if got := api.requireSandboxDecision(peer, "claudecode", "UserPromptSubmit", "/p", ""); got.Outcome != requireSandboxRefused {
		t.Fatalf("managed prompt: %+v", got)
	}
	for _, event := range []string{"PostToolUse", "Stop", "SessionEnd"} {
		if got := api.requireSandboxDecision(peer, "claudecode", event, "/p", ""); got.Outcome != "" {
			t.Errorf("%s judged: %+v", event, got)
		}
	}

	oss := &APIServer{scannerCfg: &config.Config{}}
	oss.scannerCfg.OpenShell.Admin.RequiredFor = []string{"claudecode"}
	if got := oss.requireSandboxDecision(peer, "claudecode", "UserPromptSubmit", "/p", ""); got.Outcome != "" {
		t.Fatalf("per-user gateway gated: %+v", got)
	}

	relayed := relayedSandboxRequest
	relayedSandboxRequest = func(context.Context) bool { return true }
	got := api.requireSandboxDecision(peer, "claudecode", "UserPromptSubmit", "/p", "")
	relayedSandboxRequest = relayed
	if got.Outcome != "" {
		t.Fatalf("relayed sandbox request gated: %+v", got)
	}

	// Claude Code can't block SessionStart, so the prompt refuses; Codex
	// honours a block there and refuses at once.
	for connectorName, wantGated := range map[string]bool{"claudecode": false, "codex": true} {
		req := agentHookRequest{ConnectorName: connectorName, HookEventName: "SessionStart", CWD: "/p"}
		_, _, gated := api.requireSandboxHostRun(peer, api.hookProfileForConnector(connectorName), connectorName, req,
			[]byte(`{"hook_event_name":"SessionStart"}`), map[string]any{"hook_event_name": "SessionStart"}, "cli")
		if gated != wantGated {
			t.Errorf("%s SessionStart gated=%t, want %t", connectorName, gated, wantGated)
		}
	}
}

// TestRequireSandboxFloorCombines pins the combine rules the gate reads
// through config.SandboxFloor: required_for union, refuse wins,
// request_access replaced by the profile's.
func TestRequireSandboxFloorCombines(t *testing.T) {
	cfg := &config.Config{}
	cfg.OpenShell.Admin = config.OpenShellAdminConfig{RequiredFor: []string{"codex"},
		WhenUnavailable: config.OpenShellWhenUnavailableAlert, RequestAccess: "org@example.com"}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"contractors": {Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"claudecode"},
			WhenUnavailable: config.OpenShellWhenUnavailableRefuse, RequestAccess: "contractors@example.com"}},
		"engineering": {Sandbox: &config.OpenShellAdminConfig{WhenUnavailable: config.OpenShellWhenUnavailableAlert}},
		"plain":       {},
	}
	f, _, err := requireSandboxFloor(cfg, "contractors")
	if err != nil || !connectorListed(f.RequiredFor, "codex") || !connectorListed(f.RequiredFor, "claudecode") ||
		f.WhenUnavailable != config.OpenShellWhenUnavailableRefuse || f.RequestAccess != "contractors@example.com" {
		t.Fatalf("contractors floor = %+v, %v", f, err)
	}
	if len(cfg.OpenShell.Admin.RequiredFor) != 1 {
		t.Fatalf("the base floor was modified: %v", cfg.OpenShell.Admin.RequiredFor)
	}
	if f, _, _ := requireSandboxFloor(cfg, "engineering"); f.WhenUnavailable != config.OpenShellWhenUnavailableAlert ||
		f.RequestAccess != "org@example.com" {
		t.Fatalf("engineering floor = %+v", f)
	}
	if f, _, _ := requireSandboxFloor(cfg, "plain"); len(f.RequiredFor) != 1 {
		t.Fatalf("plain floor = %+v", f)
	}
	if _, _, err := requireSandboxFloor(cfg, "missing"); err == nil {
		t.Fatal("an unknown profile has a floor")
	}
	if !requiredAnywhere(cfg, "claudecode") || requiredAnywhere(cfg, "cursor") {
		t.Fatal("requiredAnywhere")
	}
}

// TestSandboxAvailabilityProbe covers the platform, switch, account and
// driver checks, and the per-account cache.
func TestSandboxAvailabilityProbe(t *testing.T) {
	cfg := &config.Config{}
	cfg.OpenShell.Enabled = true
	probe := func(goos, goarch string, access func(string, int) sandboxDeviceAccess) *sandboxAvailabilityProbe {
		p := newSandboxAvailabilityProbe()
		p.goos, p.goarch, p.access, p.prerequisite, p.cpuInfoPath = goos, goarch, access, nil, filepath.Join(t.TempDir(), "absent")
		return p
	}
	only := func(want string, state sandboxDeviceState, group string) func(string, int) sandboxDeviceAccess {
		return func(path string, _ int) sandboxDeviceAccess {
			if path != want {
				t.Errorf("probed %s, want %s", path, want)
			}
			return sandboxDeviceAccess{State: state, Group: group}
		}
	}
	vm := &config.Config{}
	vm.OpenShell.Enabled = true
	vm.Enterprise.OpenShell.Driver = config.EnterpriseOpenShellDriverVM
	vm.Enterprise.OpenShell.DriverFallback = config.EnterpriseOpenShellFallbackNone
	off := &config.Config{}
	docker := sandboxAvailability{Available: true, Driver: "docker", DriverReason: "configured"}
	for name, tc := range map[string]struct {
		p     *sandboxAvailabilityProbe
		cfg   *config.Config
		uid   int
		known bool
		want  sandboxAvailability
	}{
		"windows":       {probe("windows", "amd64", sandboxDevicesUsable), cfg, 1001, true, sandboxUnavailable(sandboxUnavailableWindows)},
		"intel mac":     {probe("darwin", "amd64", sandboxDevicesUsable), cfg, 1001, true, sandboxUnavailable(sandboxUnavailableAppleSilicon)},
		"apple silicon": {probe("darwin", "arm64", sandboxDevicesMissing), cfg, 501, true, sandboxAvailability{Available: true, Driver: "vm", DriverReason: "configured"}},
		"turned off":    {probe("linux", "amd64", sandboxDevicesUsable), off, 1001, true, sandboxUnavailable(sandboxUnavailableOff)},
		"no uid":        {probe("linux", "amd64", sandboxDevicesUsable), cfg, 0, false, sandboxUnavailable(sandboxUnavailableAccount)},
		"root":          {probe("linux", "amd64", sandboxDevicesUsable), cfg, 0, true, sandboxUnavailable(sandboxUnavailableRoot)},
		"docker ok":     {probe("linux", "amd64", only(sandboxDockerSocketPath, sandboxDeviceUsable, "")), cfg, 1001, true, docker},
		"no docker":     {probe("linux", "amd64", only(sandboxDockerSocketPath, sandboxDeviceMissing, "")), cfg, 1001, true, sandboxUnavailable(sandboxUnavailableNoDocker)},
		"docker denied": {probe("linux", "amd64", only(sandboxDockerSocketPath, sandboxDeviceDenied, "")), cfg, 1001, true, sandboxUnavailable(sandboxUnavailableDockerAccess)},
		"kvm ok":        {probe("linux", "amd64", sandboxDevicesUsable), vm, 1001, true, sandboxAvailability{Available: true, Driver: "vm", DriverReason: "configured"}},
		// GAP-0511: the MicroVM driver boots an image built in Docker for the
		// account, so KVM without Docker is no sandbox.
		"kvm without docker": {probe("linux", "amd64", func(path string, _ int) sandboxDeviceAccess {
			if path == sandboxDockerSocketPath {
				return sandboxDeviceAccess{State: sandboxDeviceNotMember, Group: "docker"}
			}
			return sandboxDeviceAccess{State: sandboxDeviceUsable}
		}), vm, 1001, true, sandboxAvailability{Why: "MicroVM sandboxes start from an agent image built in Docker for your account, and your account isn't in the docker group that can use Docker",
			Code: "no_docker_group"}},
		"no kvm":     {probe("linux", "amd64", only(sandboxKVMDevicePath, sandboxDeviceMissing, "")), vm, 1001, true, sandboxVMRequired("kvm_missing")},
		"kvm denied": {probe("linux", "amd64", only(sandboxKVMDevicePath, sandboxDeviceDenied, "")), vm, 1001, true, sandboxVMRequired("kvm_access")},
		// GAP-0257: the cause is named, with the group to ask for.
		"no docker group": {probe("linux", "amd64", only(sandboxDockerSocketPath, sandboxDeviceNotMember, "docker")), cfg, 1001, true,
			sandboxAvailability{Why: "your account isn't in the docker group that can use Docker", Code: "no_docker_group"}},
		"no kvm group": {probe("linux", "amd64", only(sandboxKVMDevicePath, sandboxDeviceNotMember, "kvm")), vm, 1001, true,
			sandboxAvailability{Why: "your organization requires MicroVM sandboxes, and your account isn't in the kvm group that can use /dev/kvm", Code: "no_kvm_group"}},
		"unnamed kvm group": {probe("linux", "amd64", only(sandboxKVMDevicePath, sandboxDeviceNotMember, "")), vm, 1001, true,
			sandboxAvailability{Why: "your organization requires MicroVM sandboxes, and your account isn't in the group that can use /dev/kvm", Code: "no_kvm_group"}},
		// GAP-0384: an unreachable directory is not "can't use Docker".
		// GAP-0507: nor a refusal; a run starts provisionally, and the
		// daemon's own probe as the account decides at sandbox start.
		"groups unknown": {probe("linux", "amd64", only(sandboxDockerSocketPath, sandboxDeviceGroupsUnknown, "")), cfg, 1001, true,
			sandboxAvailability{Available: true, Driver: "docker", DriverReason: "configured", Provisional: true}},
		// The MicroVM driver also needs the account's Docker (GAP-0511).
		"kvm groups unknown": {probe("linux", "amd64", func(path string, _ int) sandboxDeviceAccess {
			if path == sandboxKVMDevicePath {
				return sandboxDeviceAccess{State: sandboxDeviceGroupsUnknown}
			}
			return sandboxDeviceAccess{State: sandboxDeviceUsable}
		}), vm, 1001, true,
			sandboxAvailability{Available: true, Driver: "vm", DriverReason: "configured", Provisional: true}},
	} {
		if got := tc.p.check(tc.cfg, tc.uid, tc.known, config.OpenShellAdminConfig{}); got != tc.want {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}

	calls := 0
	p := probe("linux", "amd64", func(string, int) sandboxDeviceAccess { calls++; return sandboxDeviceAccess{State: sandboxDeviceUsable} })
	p.prerequisite = func(*config.Config, int, string) string { return "OpenShell is not installed" }
	for range 3 {
		if got := p.check(cfg, 1001, true, config.OpenShellAdminConfig{}); got.Why != "OpenShell is not installed" {
			t.Fatalf("prerequisite: %+v", got)
		}
	}
	if calls != 1 {
		t.Fatalf("the account was probed %d times within the cache TTL", calls)
	}
	// A provisional answer (a failed group lookup) is not held for the TTL:
	// the next hook retries.
	calls = 0
	p = probe("linux", "amd64", func(string, int) sandboxDeviceAccess {
		calls++
		return sandboxDeviceAccess{State: sandboxDeviceGroupsUnknown}
	})
	p.check(cfg, 1001, true, config.OpenShellAdminConfig{})
	p.check(cfg, 1001, true, config.OpenShellAdminConfig{})
	if calls != 2 {
		t.Fatalf("a failed lookup was cached (%d probes)", calls)
	}
}

// TestRequireSandboxNamesOnlyTheCallersProfile: a profile's required_for
// refuses its own subjects' host runs, and the refusal names the caller's
// profile and contact only.
func TestRequireSandboxNamesOnlyTheCallersProfile(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	api, store := requireSandboxTestAPI(t, "")
	cfg := api.scannerCfg
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"contractors": {Description: "Contractors", Sandbox: &config.OpenShellAdminConfig{
			RequiredFor: []string{"claudecode"}, RequestAccess: "contractors-help@example.com"}},
		"secret-team": {Description: "Another group", Sandbox: &config.OpenShellAdminConfig{
			RequiredFor: []string{"claudecode", "codex"}, RequestAccess: "secret@example.com"}},
	}
	cfg.Guardrail.DefaultProfile = "contractors"
	api.initGuardrailProfiles(cfg)
	if api.guardrailProfileSet() == nil {
		t.Fatal("profiles did not load")
	}
	project := requireSandboxProject(t)
	out := postRequireSandboxHook(t, api, requireSandboxHooks[0], project, nil, nil)
	want := sandboxapi.HostRunRefused("claudecode", "contractors", project, "contractors-help@example.com")
	if out["reason"] != want {
		t.Fatalf("reason = %v, want %q", out["reason"], want)
	}
	if body, _ := json.Marshal(out); strings.Contains(string(body), "secret") {
		t.Fatalf("the refusal names another profile: %s", body)
	}
	if got := requireSandboxAuditOutcome(t, store); got != requireSandboxRefused {
		t.Fatalf("audit require_sandbox = %q", got)
	}
	// codex is required only by the other profile: not refused here.
	if out := postRequireSandboxHook(t, api, requireSandboxHooks[1], project, nil, nil); out["action"] == "block" {
		t.Fatalf("another profile's required_for refused this caller: %v", out)
	}
}

// GAP-0293, GAP-0384: a refusal from the default profile that applies only
// because the directory lookup failed says so and to retry, whether a
// sandbox can run or not; a verified default match reads as before.
func TestRequireSandboxProvisionalRefusal(t *testing.T) {
	api, _ := requireSandboxTestAPI(t, "")
	cfg := api.scannerCfg
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"offline-floor": {Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"claudecode"}}},
	}
	cfg.Guardrail.DefaultProfile = "offline-floor"
	api.initGuardrailProfiles(cfg)
	set := api.guardrailProfileSet()
	if set == nil {
		t.Fatal("profiles did not load")
	}
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "bob"})
	as := func(match string) context.Context {
		return context.WithValue(peer, resolvedGuardrailProfileKey{}, &resolvedGuardrailProfile{
			decision: profileDecision{Name: "offline-floor", Match: match}, set: set})
	}
	for _, devices := range []func(string, int) sandboxDeviceAccess{sandboxDevicesUsable, sandboxDevicesMissing} {
		useSandboxAvailability(t, devices)
		got := api.requireSandboxDecision(as(profileMatchDefaultLookupFailed), "claudecode", "UserPromptSubmit", "/p", "")
		lines := strings.Split(got.Message, "\n")
		if !got.refuses() || len(lines) < 3 || !strings.Contains(lines[1], "directory couldn't be reached") || !strings.Contains(lines[1], "Try again") {
			t.Fatalf("provisional %s: %q", got.Outcome, got.Message)
		}
		if plain := api.requireSandboxDecision(as(profileMatchDefault), "claudecode", "UserPromptSubmit", "/p", ""); strings.Contains(plain.Message, "directory") {
			t.Fatalf("a verified default match reads as provisional: %q", plain.Message)
		}
	}
}
