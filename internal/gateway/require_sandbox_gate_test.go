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
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// requireSandboxAuditField is the value of key on the last connector-hook
// audit row ("" when it has none).
func requireSandboxAuditField(t *testing.T, store *audit.Store, key string) string {
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
			if v, ok := strings.CutPrefix(field, key+"="); ok {
				return v
			}
		}
		return ""
	}
	t.Fatal("no connector-hook audit row")
	return ""
}

// captureRequireSandboxRecords collects the gate's telemetry records.
func captureRequireSandboxRecords(t *testing.T) *[]requireSandboxRecord {
	t.Helper()
	var got []requireSandboxRecord
	old := recordRequireSandbox
	recordRequireSandbox = func(_ context.Context, _ *APIServer, rec requireSandboxRecord) { got = append(got, rec) }
	t.Cleanup(func() { recordRequireSandbox = old })
	return &got
}

// GAP-0266: an installed 0.1.3 prerequisite is unavailable, but it must
// never be described to the caller as absent. The lifecycle has already
// published the version and the administrator's remedy in the trusted record.
func TestSandboxPrerequisiteNamesInstalledUnsupportedOpenShell(t *testing.T) {
	cfg := &config.Config{}
	cfg.Enterprise.OpenShell.Install = config.EnterpriseOpenShellInstallPrerequisite
	record := sandboxPrerequisitesRecord{Version: 1, Install: cfg.Enterprise.OpenShell.Install, Driver: "docker"}
	if err := json.Unmarshal([]byte(`{"missing":[{"item":"openshell cli","detail":"openshell is not installed"}]}`), &record); err != nil {
		t.Fatal(err)
	}
	// Read the real record shape, including its detail and fix, to catch a
	// parser that discards the part that distinguishes old from absent.
	var fromRecord sandboxPrerequisitesRecord
	if err := json.Unmarshal([]byte(`{"version":1,"install":"prerequisite","driver":"docker","ready":false,"missing":[{"item":"openshell cli","detail":"openshell: OpenShell 0.1.3 runs no DefenseClaw sandbox: upgrade OpenShell to 0.1.5 in place","fix":"upgrade OpenShell to 0.1.5"}]}`), &fromRecord); err != nil {
		t.Fatal(err)
	}
	why := sandboxPrerequisiteWhy(cfg, "linux", "docker", fromRecord, true)
	if !strings.Contains(why, "OpenShell 0.1.3") || !strings.Contains(why, "upgrade OpenShell to 0.1.5") || strings.Contains(why, "not installed") {
		t.Fatalf("installed unsupported OpenShell: %q", why)
	}
	if code := sandboxUnavailable(why).Code; code != "prerequisite_missing" {
		t.Fatalf("installed unsupported OpenShell reason code = %q", code)
	}
	if got := sandboxPrerequisiteWhy(cfg, "linux", "docker", record, true); got != sandboxUnavailableNoOpenShell {
		t.Fatalf("absent OpenShell = %q", got)
	}
}

// TestRequireSandboxExemptWindowsAccountForms (GAP-0092): a per-user
// credential's account is exempt by every form Windows enrollment accepts
// (the SID, the profile folder, the account, DOMAIN\account, any case), so
// an exempt AD user's host run is allowed where enrollment exempts her.
func TestRequireSandboxExemptWindowsAccountForms(t *testing.T) {
	const sid = "S-1-5-21-1000-2000-3000-1105"
	restoreHome, restoreLookup := userScopedIdentityHome, requireSandboxAccountForID
	t.Cleanup(func() { userScopedIdentityHome, requireSandboxAccountForID = restoreHome, restoreLookup })
	userScopedIdentityHome = func(id string) string {
		if id == sid {
			return `C:\Users\alice.DCLAB\`
		}
		return ""
	}
	lookupOK := true
	requireSandboxAccountForID = func(id string) (string, string, bool) {
		if id == sid && lookupOK {
			return "alice", "DCLAB", true
		}
		return "", "", false
	}
	subject := VerifiedSubject{UserID: sid, UserName: "alice", Source: subjectSourceUserCredential}
	for _, tc := range []struct {
		list   []string
		lookup bool
		want   bool
	}{
		{[]string{`DCLAB\alice`}, true, true},
		{[]string{`dclab\ALICE`}, true, true},
		{[]string{"Alice"}, true, true},
		{[]string{"alice.dclab"}, true, true},
		{[]string{strings.ToLower(sid)}, true, true},
		{[]string{" ", `DCLAB\bob`, `DCLAB\alice`}, true, true},
		{[]string{`DCLAB\bob`}, true, false},
		{[]string{`OTHER\alice`}, true, false},
		{[]string{"S-1-5-21-1000-2000-3000-1106"}, true, false},
		// LookupAccountSid failing: the verified subject's account domain
		// stands in.
		{[]string{`DCLAB\alice`}, false, true},
	} {
		lookupOK = tc.lookup
		s := subject
		if !tc.lookup {
			s.Directory.AccountDomain = "DCLAB"
		}
		if got := requireSandboxAccountListed(tc.list, s); got != tc.want {
			t.Errorf("exempt_users %q (lookup %t) = %t, want %t", tc.list, tc.lookup, got, tc.want)
		}
	}
	lookupOK = true

	// Through the hook: a user-scoped credential's subject, exempt as
	// DOMAIN\name and as a mixed-case name, is not refused; another
	// account's entry refuses it.
	useSandboxAvailability(t, sandboxDevicesUsable)
	hook := requireSandboxHooks[0]
	ctx := withVerifiedSubject(context.Background(), subject)
	for list, want := range map[string]string{`DCLAB\alice`: requireSandboxExempt, "Alice": requireSandboxExempt, `DCLAB\bob`: requireSandboxRefused} {
		api, store := requireSandboxTestAPI(t, "", hook.connector)
		api.scannerCfg.Enterprise.Enrollment.ExemptUsers = []string{list}
		out := postRequireSandboxHook(t, api, hook, requireSandboxProject(t), ctx, nil)
		if blocked := out["action"] == "block"; blocked != (want == requireSandboxRefused) {
			t.Errorf("exempt_users [%s]: action %v", list, out["action"])
		}
		if got := requireSandboxAuditOutcome(t, store); got != want {
			t.Errorf("exempt_users [%s]: audit require_sandbox = %q, want %q", list, got, want)
		}
	}
}

// TestSandboxPrerequisiteRecord (GAP-0093): the probe reads the record the
// lifecycle publishes; a missing, stale, foreign or untrusted record, or a
// missing prerequisite, makes sandboxes unavailable.
func TestSandboxPrerequisiteRecord(t *testing.T) {
	restore := sandboxRecordTrusted
	trusted := true
	sandboxRecordTrusted = func(fs.FileInfo) bool { return trusted }
	t.Cleanup(func() { sandboxRecordTrusted = restore })
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ready := write("ready.json", `{"version":1,"install":"prerequisite","driver":"docker","ready":true}`)
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(ready, link); err != nil {
		t.Fatal(err)
	}
	docker := &config.Config{}
	docker.OpenShell.Enabled = true
	setup := &config.Config{}
	setup.OpenShell.Enabled = true
	setup.Enterprise.OpenShell.Install = config.EnterpriseOpenShellInstallSetup
	vm := &config.Config{}
	vm.OpenShell.Enabled = true
	vm.Enterprise.OpenShell.Driver = config.EnterpriseOpenShellDriverVM
	for name, tc := range map[string]struct {
		path string
		cfg  *config.Config
		want string
	}{
		"ready":         {ready, docker, ""},
		"no record":     {filepath.Join(dir, "absent.json"), docker, sandboxUnavailableNotSetUp},
		"no path":       {"", docker, sandboxUnavailableNotSetUp},
		"symlink":       {link, docker, sandboxUnavailableNotSetUp},
		"other driver":  {ready, vm, sandboxUnavailableSetupChanging},
		"other install": {ready, setup, sandboxUnavailableSetupChanging},
		"version 2":     {write("v2.json", `{"version":2,"install":"prerequisite","driver":"docker","ready":true}`), docker, sandboxUnavailableNotSetUp},
		"garbage":       {write("bad.json", `{"version":1,`), docker, sandboxUnavailableNotSetUp},
		"too large":     {write("big.json", `{"version":1,"install":"prerequisite","driver":"docker","ready":true,"pad":"`+strings.Repeat("x", sandboxPrerequisitesMaxBytes)+`"}`), docker, sandboxUnavailableNotSetUp},
		"no openshell": {write("cli.json", `{"version":1,"install":"prerequisite","driver":"docker","ready":false,"missing":[{"item":"docker"},{"item":"openshell cli","detail":"/opt/x","fix":"y"}]}`),
			docker, sandboxUnavailableNoOpenShell},
		"no docker": {write("docker.json", `{"version":1,"install":"prerequisite","driver":"docker","ready":false,"missing":[{"item":"docker"}]}`),
			docker, sandboxUnavailableDockerMissing},
		// GAP-0266: an installed release the host refuses is named, never
		// "not installed".
		"unsupported release": {write("old.json", `{"version":1,"install":"prerequisite","driver":"docker","ready":false,"missing":[{"item":"openshell cli","detail":"d","fix":"f","version":"0.1.3"},{"item":"openshell gateway","version":"0.1.3"}]}`),
			docker, "OpenShell 0.1.3 is installed, but that release is unsupported: sandboxes need OpenShell 0.1.5 or later, below 0.2.0"},
		"unsupported prerelease": {write("pre.json", `{"version":1,"install":"prerequisite","driver":"vm","ready":false,"missing":[{"item":"microvm driver","version":"0.1.5-pre.3"}]}`),
			vm, "OpenShell 0.1.5-pre.3 is installed, but that release is unsupported: sandboxes need OpenShell 0.1.5 or later, below 0.2.0"},
		"release above the window": {write("new.json", `{"version":1,"install":"prerequisite","driver":"docker","ready":false,"missing":[{"item":"openshell gateway","version":"0.2.0"}]}`),
			docker, "OpenShell 0.2.0 is installed, but that release is unsupported: sandboxes need OpenShell 0.1.5 or later, below 0.2.0"},
		"not the pinned release": {write("pin.json", `{"version":1,"install":"prerequisite","driver":"docker","ready":false,"missing":[{"item":"openshell cli","version":"0.1.6"}]}`),
			docker, "OpenShell 0.1.6 is installed, but it is not the release your organization requires"},
		"unreadable release": {write("junk.json", `{"version":1,"install":"prerequisite","driver":"docker","ready":false,"missing":[{"item":"openshell cli","version":"x.y"}]}`),
			docker, sandboxUnavailableNoOpenShell},
		"other item": {write("e2fs.json", `{"version":1,"install":"setup","driver":"docker","ready":false,"missing":[{"item":"e2fsprogs"}]}`),
			setup, sandboxUnavailablePrerequisiteOther},
	} {
		record, ok := readSandboxPrerequisites(tc.path)
		if got := sandboxPrerequisiteWhy(tc.cfg, "linux", sandboxDriverFor(tc.cfg, "linux"), record, ok); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
	// A MicroVM configuration with the docker fallback: the MicroVM part
	// and the fallback part are read apart, and a record without a
	// fallback part has no docker set up.
	auto := &config.Config{}
	auto.OpenShell.Enabled = true
	auto.Enterprise.OpenShell.Driver = config.EnterpriseOpenShellDriverAuto
	both := write("auto.json", `{"version":1,"install":"prerequisite","driver":"auto","ready":false,"missing":[{"item":"kvm"}],`+
		`"fallback":{"driver":"docker","ready":true}}`)
	vmOnly := write("auto-nofb.json", `{"version":1,"install":"prerequisite","driver":"auto","ready":true}`)
	for name, tc := range map[string]struct {
		path, driver, want string
	}{
		"vm part":          {both, "vm", sandboxUnavailablePrerequisiteOther},
		"fallback part":    {both, "docker", ""},
		"no fallback part": {vmOnly, "docker", sandboxUnavailableNotSetUp},
		"vm ready":         {vmOnly, "vm", ""},
	} {
		record, ok := readSandboxPrerequisites(tc.path)
		if got := sandboxPrerequisiteWhy(auto, "linux", tc.driver, record, ok); got != tc.want {
			t.Errorf("auto %s: %q, want %q", name, got, tc.want)
		}
	}
	trusted = false
	if record, ok := readSandboxPrerequisites(ready); ok || sandboxPrerequisiteWhy(docker, "linux", "docker", record, ok) != sandboxUnavailableNotSetUp {
		t.Fatal("an untrusted record was believed")
	}
	if got := sandboxUnavailable(sandboxUnavailableNotSetUp); got.Code != "prerequisite_missing" || got.Available {
		t.Fatalf("not set up = %+v", got)
	}
}

// TestRequireSandboxPrerequisiteMissing (GAP-0093): without the lifecycle's
// OpenShell record, sandboxes are unavailable: refused with the "not
// available" text under refuse, allowed and recorded under alert.
func TestRequireSandboxPrerequisiteMissing(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	defaultSandboxAvailability.prerequisite = sandboxOpenShellPrerequisite
	restorePath := sandboxPrerequisitesPath
	absent := filepath.Join(t.TempDir(), "absent.json")
	sandboxPrerequisitesPath = func(string) string { return absent }
	t.Cleanup(func() { sandboxPrerequisitesPath = restorePath })
	records := captureRequireSandboxRecords(t)
	hook := requireSandboxHooks[0]

	api, store := requireSandboxTestAPI(t, "", hook.connector)
	out := postRequireSandboxHook(t, api, hook, requireSandboxProject(t), nil, nil)
	want := sandboxapi.HostRunUnavailable(hook.connector, sandboxUnavailableNotSetUp, "prerequisite_missing", "it-security@example.com")
	if out["action"] != "block" || out["reason"] != want {
		t.Fatalf("refuse: action=%v reason=%v, want %q", out["action"], out["reason"], want)
	}
	if got := requireSandboxAuditOutcome(t, store); got != requireSandboxUnavailable {
		t.Fatalf("refuse: audit require_sandbox = %q", got)
	}

	defaultSandboxAvailability.cache = nil
	api, store = requireSandboxTestAPI(t, config.OpenShellWhenUnavailableAlert, hook.connector)
	if out := postRequireSandboxHook(t, api, hook, requireSandboxProject(t), nil, nil); out["action"] == "block" {
		t.Fatalf("alert: the host run was refused: %v", out)
	}
	if got := requireSandboxAuditOutcome(t, store); got != requireSandboxAlert {
		t.Fatalf("alert: audit require_sandbox = %q", got)
	}
	wantRecords := []requireSandboxRecord{
		{Unavailable: true, Connector: "claudecode", Reason: "prerequisite_missing", Rule: "claudecode", UserID: "1001", UserName: "alice"},
		{Unavailable: true, Allowed: true, Connector: "claudecode", Reason: "prerequisite_missing", Rule: "claudecode", UserID: "1001", UserName: "alice"},
	}
	if len(*records) != len(wantRecords) || (*records)[0] != wantRecords[0] || (*records)[1] != wantRecords[1] {
		t.Fatalf("records = %+v, want %+v", *records, wantRecords)
	}
}

// TestRequireSandboxRecords (GAP-0095): a refused host run and an
// unavailable one (refused or alerted) each make one record for the
// managed sandbox telemetry with a registered reason code; an exempt or
// unrequired run makes none.
func TestRequireSandboxRecords(t *testing.T) {
	hook := requireSandboxHooks[1]
	records := captureRequireSandboxRecords(t)

	useSandboxAvailability(t, sandboxDevicesUsable)
	api, _ := requireSandboxTestAPI(t, "", hook.connector)
	postRequireSandboxHook(t, api, hook, requireSandboxProject(t), nil, nil)
	postRequireSandboxHook(t, api, hook, requireSandboxProject(t), withEnterpriseExemptUser(context.Background()), nil)
	api, _ = requireSandboxTestAPI(t, "", "claudecode")
	postRequireSandboxHook(t, api, hook, requireSandboxProject(t), nil, nil)

	useSandboxAvailability(t, sandboxDevicesMissing)
	api, _ = requireSandboxTestAPI(t, "", hook.connector)
	postRequireSandboxHook(t, api, hook, requireSandboxProject(t), nil, nil)
	api, _ = requireSandboxTestAPI(t, config.OpenShellWhenUnavailableAlert, hook.connector)
	postRequireSandboxHook(t, api, hook, requireSandboxProject(t), nil, nil)

	want := []requireSandboxRecord{
		{Connector: "codex", Reason: requireSandboxReasonRequired, Rule: "codex", UserID: "1001", UserName: "alice"},
		{Unavailable: true, Connector: "codex", Reason: "no_docker", Rule: "codex", UserID: "1001", UserName: "alice"},
		{Unavailable: true, Allowed: true, Connector: "codex", Reason: "no_docker", Rule: "codex", UserID: "1001", UserName: "alice"},
	}
	if len(*records) != len(want) {
		t.Fatalf("records = %+v, want %+v", *records, want)
	}
	for i := range want {
		if (*records)[i] != want[i] {
			t.Errorf("record %d = %+v, want %+v", i, (*records)[i], want[i])
		}
	}
	// Every code is one the telemetry registry accepts.
	code := regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	codes := []string{requireSandboxReasonRequired, sandboxUnavailable("anything else").Code}
	for _, c := range sandboxUnavailableCodes {
		codes = append(codes, c)
	}
	for _, c := range codes {
		if !code.MatchString(c) {
			t.Errorf("reason code %q is not a registered code shape", c)
		}
	}
}

// GAP-0184, GAP-0229, GAP-0243, GAP-0410: the gate's records carry the
// caller's own profile match and subject key, as a registration's do, and
// the strict managed recorder accepts the stamp; a Windows caller (a SID,
// no uid) is keyed too.
func TestRequireSandboxRecordsCarryTheProfile(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	records := captureRequireSandboxRecords(t)
	api, _ := requireSandboxTestAPI(t, "")
	cfg := api.scannerCfg
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"contractors": {Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"claudecode"}}},
	}
	cfg.Guardrail.DefaultProfile = "contractors"
	api.initGuardrailProfiles(cfg)
	t.Cleanup(func() { managedSandboxRecorders.Delete(api) })
	postRequireSandboxHook(t, api, requireSandboxHooks[0], requireSandboxProject(t), nil, nil)
	if len(*records) != 1 {
		t.Fatalf("records = %+v", *records)
	}
	rec := (*records)[0]
	if rec.Profile != "contractors" || rec.ProfileMatch != profileMatchDefault || rec.ProfileDigest == "" || rec.Provisional {
		t.Fatalf("record profile = %+v", rec)
	}
	identity := api.requireSandboxIdentity(context.Background(), rec)
	m := identity.Managed
	if m.GuardrailProfile != "contractors" || m.ProfileMatch != audit.SandboxProfileMatchDefault || m.ProfileDigest != rec.ProfileDigest ||
		m.Provisional == nil || *m.Provisional || !regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`).MatchString(m.SubjectKey) {
		t.Fatalf("stamp = %+v", m)
	}
	if err := api.managedSandboxRecorder().RecordSandboxHostRunRefused(context.Background(), audit.SandboxHostRunRefusedEvent{
		Sandbox: identity, Subject: audit.SandboxManagedSubject{UserID: rec.UserID, UserName: rec.UserName},
		Reason: rec.Reason, Rule: rec.Rule,
	}); err != nil {
		t.Fatalf("the recorder refused the stamp: %v", err)
	}
	windows := rec
	windows.UserID = "S-1-5-21-1000-2000-3000-1105"
	if key := api.requireSandboxSubjectKey(windows); key == "" || key == m.SubjectKey {
		t.Fatalf("windows subject key = %q", key)
	}
	if key := (*APIServer)(nil).requireSandboxSubjectKey(rec); key != "" {
		t.Fatalf("a gateway without a key stamped %q", key)
	}
}

// TestRequireSandboxFailsClosed (GAP-0096): a floor that can't be computed
// and a panic in the gate both refuse the host run of a connector some
// floor requires (policy_unloadable) on every connector, and leave the
// hooks of other connectors to the evaluator.
func TestRequireSandboxFailsClosed(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	restore := requireSandboxFloor
	t.Cleanup(func() { requireSandboxFloor = restore })
	for name, floor := range map[string]func(*config.Config, string) (config.OpenShellAdminConfig, string, error){
		"unloadable": func(*config.Config, string) (config.OpenShellAdminConfig, string, error) {
			return config.OpenShellAdminConfig{}, "", errors.New("contradictory sandbox policy")
		},
		"panic": func(*config.Config, string) (config.OpenShellAdminConfig, string, error) {
			panic("forced require-sandbox gate failure")
		},
	} {
		requireSandboxFloor = floor
		for _, hook := range requireSandboxHooks {
			api, store := requireSandboxTestAPI(t, "", hook.connector)
			out := postRequireSandboxHook(t, api, hook, requireSandboxProject(t), nil, nil)
			if out["action"] != "block" || out["reason"] != sandboxapi.PolicyUnloadable() {
				t.Errorf("%s/%s: action=%v reason=%v", name, hook.connector, out["action"], out["reason"])
			}
			if got := requireSandboxAuditOutcome(t, store); got != requireSandboxUnloadable {
				t.Errorf("%s/%s: audit require_sandbox = %q", name, hook.connector, got)
			}
			wantErr := map[string]string{"unloadable": "", "panic": "internal"}[name]
			if got := requireSandboxAuditField(t, store, "require_sandbox_error"); got != wantErr {
				t.Errorf("%s/%s: audit require_sandbox_error = %q, want %q", name, hook.connector, got, wantErr)
			}
		}
		other := requireSandboxHooks[0]
		api, store := requireSandboxTestAPI(t, "", "codex")
		if out := postRequireSandboxHook(t, api, other, requireSandboxProject(t), nil, nil); out["action"] == "block" {
			t.Errorf("%s: a connector no floor requires was refused: %v", name, out)
		}
		if got := requireSandboxAuditOutcome(t, store); got != "" {
			t.Errorf("%s: unrequired audit require_sandbox = %q", name, got)
		}
	}

	// A failed gate never refuses an event it does not judge.
	requireSandboxFloor = func(*config.Config, string) (config.OpenShellAdminConfig, string, error) { panic("forced") }
	api, _ := requireSandboxTestAPI(t, "", "claudecode")
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "alice"})
	req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PostToolUse", CWD: "/p"}
	if _, _, gated := api.requireSandboxHostRun(peer, api.hookProfileForConnector("claudecode"), "claudecode", req,
		[]byte(`{"hook_event_name":"PostToolUse"}`), map[string]any{"hook_event_name": "PostToolUse"}, "cli"); gated {
		t.Fatal("a failed gate refused PostToolUse")
	}
}

// TestRequireSandboxRefusalNamesTheSurface (GAP-0098): a hook from an app
// or IDE extension is refused with the text that says its agent can't run
// in a sandbox and points to the CLI harness; a CLI hook keeps the
// paste-ready run and enable commands.
func TestRequireSandboxRefusalNamesTheSurface(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	project := requireSandboxProject(t)
	for _, hook := range requireSandboxHooks {
		api, _ := requireSandboxTestAPI(t, "", hook.connector)
		out := postRequireSandboxHook(t, api, hook, project, nil, map[string]string{hookexec.AgentSurfaceHeader: connector.HostSurfaceExtension})
		want := sandboxapi.HostRunRefusedOn(hook.connector, connector.HostSurfaceExtension, "", project, "it-security@example.com")
		if out["action"] != "block" || out["reason"] != want {
			t.Errorf("%s extension: action=%v reason=%v, want %q", hook.connector, out["action"], out["reason"], want)
		}
		if reason, _ := out["reason"].(string); strings.Contains(reason, "sandbox enable") || !strings.Contains(reason, "IDE extension") {
			t.Errorf("%s extension: %q", hook.connector, reason)
		}
	}
	for _, surface := range []string{connector.HostSurfaceDesktop, connector.HostSurfaceExtension} {
		if sandboxapi.HostRunRefusedOn("cursor", surface, "", "/p", "") == sandboxapi.HostRunRefused("cursor", "", "/p", "") {
			t.Errorf("surface %s reads as the CLI", surface)
		}
	}
	if sandboxapi.HostRunRefusedOn("cursor", connector.HostSurfaceCLI, "p", "/p", "c") != sandboxapi.HostRunRefused("cursor", "p", "/p", "c") {
		t.Error("the CLI surface does not read as HostRunRefused")
	}

	header := func(v string) http.Header {
		h := http.Header{}
		if v != "" {
			h.Set(hookexec.AgentSurfaceHeader, v)
		}
		return h
	}
	ctx := context.Background()
	for _, tc := range []struct {
		ctx    context.Context
		header string
		want   string
	}{
		{ctx, "", connector.HostSurfaceCLI},
		{ctx, "Desktop", connector.HostSurfaceDesktop},
		{ctx, "extension", connector.HostSurfaceExtension},
		{ctx, "sandbox", connector.HostSurfaceCLI},
		{withCopilotVSCodeLocal(ctx), "", connector.HostSurfaceExtension},
	} {
		if got := requireSandboxSurface(tc.ctx, header(tc.header)); got != tc.want {
			t.Errorf("surface header %q: %q, want %q", tc.header, got, tc.want)
		}
	}
}

// TestSandboxRecordTrustedNeedsRoot: a record a user could have written is
// never believed.
func TestSandboxRecordTrustedNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	p := filepath.Join(t.TempDir(), "prerequisites.json")
	if err := os.WriteFile(p, []byte(`{"version":1,"ready":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if sandboxRecordTrusted(info) {
		t.Fatal("a record the test user owns is trusted")
	}
}
