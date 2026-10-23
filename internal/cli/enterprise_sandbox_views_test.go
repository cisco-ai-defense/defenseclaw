// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

type fakeRegStore struct {
	all   []sandboxreg.Registration
	opens int
}

func (f *fakeRegStore) Create(int, sandboxreg.Registration) error { return errors.New("read-only") }
func (f *fakeRegStore) Get(uid int, id string) (sandboxreg.Registration, bool, error) {
	for _, r := range f.all {
		if r.UID == uid && r.ID == id {
			return r, true, nil
		}
	}
	return sandboxreg.Registration{}, false, nil
}
func (f *fakeRegStore) Bind(int, string, sandboxrelay.BindRequest) (sandboxreg.Registration, error) {
	return sandboxreg.Registration{}, errors.New("read-only")
}
func (f *fakeRegStore) Revoke(int, string, string) error { return errors.New("read-only") }
func (f *fakeRegStore) Deleted(int, string) error        { return errors.New("read-only") }
func (f *fakeRegStore) List(uid int) ([]sandboxreg.Registration, error) {
	var out []sandboxreg.Registration
	for _, r := range f.all {
		if r.UID == uid {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *fakeRegStore) ListAll() ([]sandboxreg.Registration, error) { return f.all, nil }
func (f *fakeRegStore) Update(int, sandboxreg.Registration) error   { return errors.New("read-only") }
func (f *fakeRegStore) Purge() error                                { return errors.New("read-only") }

func sandboxViewsFixture(t *testing.T, uid int) (*fakeRegStore, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("this fixture models Unix root permissions")
	}
	platform := runtime.GOOS
	if platform == "darwin" {
		platform = "macos"
	}
	store := &fakeRegStore{all: []sandboxreg.Registration{
		{ID: "reg-bbbb", UID: 1002, UserName: "bob", Profile: "", ProfileMatch: sandboxreg.MatchDefault, Harness: "codex", State: sandboxreg.StateRevoked,
			RevokedReason: "subject changed", CreatedAt: time.Date(2026, 9, 27, 11, 0, 0, 0, time.UTC), Driver: "docker", SandboxName: "b-box"},
		{ID: "reg-aaaa", UID: 1001, UserName: "alice", Profile: "contractors", ProfileMatch: sandboxreg.MatchGroup, MatchedGroup: `CORP\Contractors`,
			Harness: "claudecode", HarnessVersion: "2.1.0", State: sandboxreg.StateLive, Driver: "docker", OpenShell: "0.1.3", InstallMode: "setup", WorkdirMode: "copy",
			SandboxName: "a-box", EffectiveDigest: "sha256:1234", CreatedAt: time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC), TamperTier: "managed",
			SeenAt:  time.Now(),
			MCPKept: []string{"ok-srv", "user-srv"}, MCPSkipped: []sandboxrelay.MCPSkip{{Name: "blocked-srv", Reason: sandboxrelay.MCPSkipOrganizationBlock}, {Name: "asset-srv", Reason: sandboxrelay.MCPSkipAssetPolicy}}},
	}}
	prevStore, prevUID, prevCfg, prevFloor := sandboxRegistrationStore, managedHostCallerUID, cfg, sandboxFloorFor
	prevPin, prevLoad := enterpriseDiscoveryPinManagedEnv, enterpriseDiscoveryLoadConfig
	t.Cleanup(func() {
		sandboxRegistrationStore, managedHostCallerUID, cfg, sandboxFloorFor = prevStore, prevUID, prevCfg, prevFloor
		enterpriseDiscoveryPinManagedEnv, enterpriseDiscoveryLoadConfig = prevPin, prevLoad
	})
	// The views load the deployment's config; the fixture's cfg stands in.
	enterpriseDiscoveryPinManagedEnv = func() error { return nil }
	enterpriseDiscoveryLoadConfig = func(*cobra.Command) error { return nil }
	sandboxRegistrationStore = func(string) (sandboxreg.Store, error) { store.opens++; return store, nil }
	managedHostCallerUID = func() int { return uid }
	cfg = &config.Config{DeploymentMode: "managed_enterprise", DataDir: t.TempDir()}
	cfg.Enterprise.Profile = "standalone"
	cfg.OpenShell.Admin.EgressAllowOnly = []string{"api.example.net"}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"contractors": {Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"claudecode"}, RequestAccess: "it-security@example.com"}},
	}
	return store, platform
}

func runSandboxView(t *testing.T, platform string, args ...string) (string, error) {
	t.Helper()
	cmd := newEnterpriseSandboxCommand(platform)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestEnterpriseSandboxListShowsEveryAccountToRoot(t *testing.T) {
	_, platform := sandboxViewsFixture(t, 0)
	out, err := runSandboxView(t, platform, "list")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"reg-aaaa", "alice", "contractors", "group", "a-box", "reg-bbbb", "bob", "(floor)", "revoked"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "reg-bbbb") < strings.Index(out, "reg-aaaa") {
		// oldest first: alice (10:00) before bob (11:00)
		t.Errorf("not oldest first:\n%s", out)
	}
	out, err = runSandboxView(t, platform, "list", "--user", "1001", "--state", "live", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Total         int                       `json:"total"`
		Registrations []sandboxreg.Registration `json:"registrations"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Total != 1 || doc.Registrations[0].ID != "reg-aaaa" {
		t.Fatalf("filtered json = %+v, %v\n%s", doc, err, out)
	}
	if _, err := runSandboxView(t, platform, "list", "--state", "weird"); err == nil {
		t.Error("an unknown --state was accepted")
	}
}

// The list shows each registration in its state now: a pending one past its
// PendingTTL is expired and a live one whose daemon stopped reporting its
// sandbox running is stopped, so neither passes for a run under way
// (GAP-0479, GAP-0488).
func TestFilterRegistrationsShowsTheStateNow(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	all := []sandboxreg.Registration{
		{ID: "reg-pend", State: sandboxreg.StatePending, CreatedAt: now.Add(-time.Minute)},
		{ID: "reg-abnd", State: sandboxreg.StatePending, CreatedAt: now.Add(-time.Hour)},
		{ID: "reg-live", State: sandboxreg.StateLive, BoundAt: now.Add(-time.Hour), SeenAt: now.Add(-time.Minute)},
		{ID: "reg-gone", State: sandboxreg.StateLive, BoundAt: now.Add(-time.Hour), SeenAt: now.Add(-sandboxreg.LiveLease)},
		{ID: "reg-stop", State: sandboxreg.StateStopped, BoundAt: now.Add(-time.Hour), SeenAt: now.Add(-time.Minute)},
	}
	want := map[string]string{"reg-pend": "pending", "reg-abnd": "expired", "reg-live": "live", "reg-gone": "stopped", "reg-stop": "stopped"}
	for _, r := range filterRegistrations(all, "", "", now) {
		if r.State != want[r.ID] {
			t.Errorf("%s: state %q, want %q", r.ID, r.State, want[r.ID])
		}
	}
	if got := filterRegistrations(all, "", sandboxreg.StatePending, now); len(got) != 1 || got[0].ID != "reg-pend" {
		t.Errorf("--state pending = %+v, want only the run under way", got)
	}
}

// Root's list reads the deployment's config itself: nothing loaded it before
// the view, so a verified standalone deployment was refused as "needs a
// standalone managed deployment" (GAP-0182, GAP-0242).
func TestEnterpriseSandboxListLoadsTheManagedConfig(t *testing.T) {
	_, platform := sandboxViewsFixture(t, 0)
	loaded := cfg
	cfg = nil
	pinned := false
	enterpriseDiscoveryPinManagedEnv = func() error { pinned = true; return nil }
	enterpriseDiscoveryLoadConfig = func(*cobra.Command) error { cfg = loaded; return nil }
	out, err := runSandboxView(t, platform, "list")
	if err != nil || !pinned || !strings.Contains(out, "reg-aaaa") {
		t.Fatalf("list = %v (pinned %v)\n%s", err, pinned, out)
	}
	enterpriseDiscoveryLoadConfig = func(*cobra.Command) error { return errors.New("failed to load config: marker") }
	cfg = nil
	if _, err := runSandboxView(t, platform, "list"); err == nil || !strings.Contains(err.Error(), "marker") {
		t.Fatalf("a config that does not load = %v, want its error", err)
	}
}

// The admin views are root's: a standard account is told so, and the store
// is never opened for it.
func TestEnterpriseSandboxViewsRefuseNonRoot(t *testing.T) {
	store, platform := sandboxViewsFixture(t, 1000)
	for _, args := range [][]string{{"list"}, {"explain", "--registration", "reg-aaaa"}} {
		out, err := runSandboxView(t, platform, args...)
		if err == nil || !strings.Contains(err.Error(), "an administrator runs it") || !strings.Contains(err.Error(), "defenseclaw sandbox policy explain") {
			t.Errorf("%v: err = %v\n%s", args, err, out)
		}
		for _, leak := range []string{"alice", "bob", "reg-aaaa\t"} {
			if strings.Contains(out, leak) {
				t.Errorf("%v printed %q to a standard user", args, leak)
			}
		}
	}
	// --json refuses with the errors[] document, as the other views do.
	out, err := runSandboxView(t, platform, "list", "--json")
	var doc struct {
		Errors []struct{ Code, Message string } `json:"errors"`
	}
	if err == nil || json.Unmarshal([]byte(out), &doc) != nil || len(doc.Errors) != 1 || doc.Errors[0].Code != "elevation_required" {
		t.Errorf("list --json as a standard user = %v\n%s", err, out)
	}
	if store.opens != 0 {
		t.Errorf("the store was opened %d times for a standard user", store.opens)
	}
}

func TestEnterpriseSandboxExplainRegistration(t *testing.T) {
	_, platform := sandboxViewsFixture(t, 0)
	// Floor not wired: the organization's and the profile's keys apart.
	out, err := runSandboxView(t, platform, "explain", "--registration", "reg-aaaa")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// GAP-0554: the servers the registration kept and skipped, with reasons.
	for _, want := range []string{"kept ok-srv, user-srv", "skipped blocked-srv (organization_block)", "skipped asset-srv (asset_policy)"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain lacks the MCP rows %q:\n%s", want, out)
		}
	}
	for _, want := range []string{"Registration reg-aaaa", "alice (uid 1001)", `matched by group CORP\Contractors`, "claudecode 2.1.0", "egress_allow_only", "organization", "required_for", "profile"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain lacks %q:\n%s", want, out)
		}
	}
	// Floor wired: the user's own rows follow.
	sandboxFloorFor = func(c *config.Config, profile string) (config.OpenShellAdminConfig, string, error) {
		f := c.OpenShell.Admin
		f.RequiredFor = []string{"claudecode"}
		f.RequestAccess = "it-security@example.com"
		return f, "sha256:feed", nil
	}
	out, err = runSandboxView(t, platform, "explain", "--registration", "reg-aaaa")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"What the user sees", "claude run only in a sandbox on this computer", "only 1 host is reachable (api.example.net)", "access: it-security@example.com",
		"2 of your servers included; 1 blocked by your organization; 1 left out by your organization's asset policy"} {
		if !strings.Contains(out, want) {
			t.Errorf("floor explain lacks %q:\n%s", want, out)
		}
	}
	out, _ = runSandboxView(t, platform, "explain", "--registration", "reg-aaaa", "--json")
	var doc registrationExplain
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Policy.Digest != "sha256:feed" || doc.Managed == nil || doc.Registration.UserName != "alice" {
		t.Fatalf("json = %+v, %v", doc, err)
	}
	if _, err := runSandboxView(t, platform, "explain", "--registration", "reg-nope"); err == nil {
		t.Error("an unknown registration was explained")
	}
	if _, err := runSandboxView(t, platform, "explain"); err == nil {
		t.Error("explain without --registration was accepted")
	}
}

// A profile that sets a looser value than the organization's does not decide
// the result: the source of that key is the organization, and of a key the
// profile really changes, the profile.
func TestSandboxPolicySourcesFollowTheResolvedFloor(t *testing.T) {
	sandboxViewsFixture(t, 0)
	cfg.OpenShell.Admin.AllowedHarnesses = []string{"claudecode"}
	cfg.Guardrail.Profiles["contractors"] = config.GuardrailProfile{Sandbox: &config.OpenShellAdminConfig{
		AllowedHarnesses: []string{"claudecode", "codex"}, // looser: the floor keeps the organization's list
		RequiredFor:      []string{"claudecode"},
	}}
	sandboxFloorFor = func(c *config.Config, profile string) (config.OpenShellAdminConfig, string, error) {
		f := c.OpenShell.Admin
		f.RequiredFor = []string{"claudecode"}
		return f, "sha256:feed", nil
	}
	view := sandboxPolicyOf(cfg, "contractors")
	if got := view.Sources["allowed_harnesses"]; got != sandboxapi.ExplainSourceOrganization {
		t.Errorf("a looser overlay's source = %q, want organization", got)
	}
	if got := view.Sources["required_for"]; got != sandboxapi.ExplainSourceProfile {
		t.Errorf("a key the profile sets = %q, want profile", got)
	}
	if got := view.Sources["egress_allow_only"]; got != sandboxapi.ExplainSourceOrganization {
		t.Errorf("an organization key = %q, want organization", got)
	}
}

// GAP-0102: a profile's when_unavailable: alert cannot loosen an unset base,
// which is refuse; profile-explain showed no value and named the profile.
// It shows refuse, the organization's.
func TestSandboxPolicyShowsTheWinningWhenUnavailable(t *testing.T) {
	sandboxViewsFixture(t, 0)
	cfg.OpenShell.Admin = config.OpenShellAdminConfig{}
	cfg.Guardrail.Profiles["contractors"] = config.GuardrailProfile{Sandbox: &config.OpenShellAdminConfig{
		RequiredFor: []string{"claudecode"}, WhenUnavailable: config.OpenShellWhenUnavailableAlert,
	}}
	sandboxFloorFor = (*config.Config).SandboxFloor
	view := sandboxPolicyOf(cfg, "contractors")
	if view.FloorError != "" {
		t.Fatal(view.FloorError)
	}
	if got := view.Floor["when_unavailable"]; got != config.OpenShellWhenUnavailableRefuse {
		t.Errorf("floor when_unavailable = %v, want refuse", got)
	}
	if got := view.Sources["when_unavailable"]; got != sandboxapi.ExplainSourceOrganization {
		t.Errorf("when_unavailable source = %q, want organization", got)
	}
	if got := view.Sources["required_for"]; got != sandboxapi.ExplainSourceProfile {
		t.Errorf("required_for source = %q, want profile", got)
	}
}

func TestEnterpriseSandboxListUserFilterIgnoresCase(t *testing.T) {
	_, platform := sandboxViewsFixture(t, 0)
	out, err := runSandboxView(t, platform, "list", "--user", "ALICE", "--json")
	if err != nil || !strings.Contains(out, "reg-aaaa") || strings.Contains(out, "reg-bbbb") {
		t.Fatalf("--user ALICE = %v\n%s", err, out)
	}
}

// GAP-0615: qualified spellings select the resolved account's UID, even
// when registrations store bare names, and never discard an unknown domain.
func TestEnterpriseSandboxListUserFilterTakesDirectorySpellings(t *testing.T) {
	store, platform := sandboxViewsFixture(t, 0)
	store.all = append(store.all,
		sandboxreg.Registration{ID: "reg-qualified", UID: 1001, UserName: "alice@corp.example.test"},
		sandboxreg.Registration{ID: "reg-partner", UID: 1003, UserName: "alice"})
	previous := enterprisePolicyResolveTarget
	t.Cleanup(func() { enterprisePolicyResolveTarget = previous })
	resolved := ""
	enterprisePolicyResolveTarget = func(name string) (enterprisehooks.TargetCredentials, error) {
		resolved = name
		uids := map[string]int{
			"alice@corp.example.test": 1001, `CORP\alice`: 1001, "Alice@CORP": 1001,
			"alice.alias@corp.example.test": 1001, "alice@partner.example.test": 1003,
			"bobby@corp.example.test": 1004, "ali@corp": 1005, `CORP\ali`: 1005,
		}
		if uid, ok := uids[name]; ok {
			return enterprisehooks.TargetCredentials{UID: uid}, nil
		}
		return enterprisehooks.TargetCredentials{}, errors.New("no account named by this qualified spelling")
	}
	for _, tc := range []struct {
		user    string
		ids     []string
		wantErr bool
	}{
		{"alice", []string{"reg-qualified", "reg-partner", "reg-aaaa"}, false},
		{"1001", []string{"reg-qualified", "reg-aaaa"}, false},
		{"alice@corp.example.test", []string{"reg-qualified", "reg-aaaa"}, false},
		{`CORP\alice`, []string{"reg-qualified", "reg-aaaa"}, false},
		{"Alice@CORP", []string{"reg-qualified", "reg-aaaa"}, false},
		{" alice.alias@corp.example.test ", []string{"reg-qualified", "reg-aaaa"}, false},
		{"alice@partner.example.test", []string{"reg-partner"}, false},
		{"bobby@corp.example.test", nil, false},
		{"ali@corp", nil, false},
		{`CORP\ali`, nil, false},
		{"alice@other.invalid", nil, true},
		{`OTHER\alice`, nil, true},
		{"alice@corp.other.test", nil, true},
	} {
		t.Run(tc.user, func(t *testing.T) {
			resolved = ""
			out, err := runSandboxView(t, platform, "list", "--user", tc.user, "--json")
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "resolve --user") || strings.Contains(out, "reg-") {
					t.Fatalf("unknown domain: err=%v output=%s", err, out)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Total         int                       `json:"total"`
				Registrations []sandboxreg.Registration `json:"registrations"`
			}
			if err := json.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, r := range doc.Registrations {
				ids = append(ids, r.ID)
			}
			if doc.Total != len(tc.ids) || !reflect.DeepEqual(ids, tc.ids) {
				t.Fatalf("registrations=%v total=%d, want %v", ids, doc.Total, tc.ids)
			}
			if strings.ContainsAny(tc.user, `@\`) && resolved != strings.TrimSpace(tc.user) {
				t.Fatalf("resolved %q, want the full spelling %q", resolved, tc.user)
			}
		})
	}
}

func TestProfileExplainGainsEffectiveSandbox(t *testing.T) {
	_, platform := sandboxViewsFixture(t, 0)
	previous := enterpriseIdentityViewGet
	t.Cleanup(func() { enterpriseIdentityViewGet = previous })
	enterpriseIdentityViewGet = func(path string, out any) (string, error) {
		return "127.0.0.1:18970", json.Unmarshal([]byte(`{"profile":"contractors","match":"group","effective":{"mode":"action"}}`), out)
	}
	cmd := newEnterpriseIdentityViewCommand(platform, enterpriseIdentityViews[0])
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--user", "alice"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Effective struct {
			Mode    string `json:"mode"`
			Sandbox struct {
				Profile string            `json:"profile"`
				Sources map[string]string `json:"sources"`
			} `json:"sandbox"`
		} `json:"effective"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if doc.Effective.Mode != "action" || doc.Effective.Sandbox.Profile != "contractors" ||
		doc.Effective.Sandbox.Sources["egress_allow_only"] != "organization" || doc.Effective.Sandbox.Sources["required_for"] != "profile" {
		t.Fatalf("effective = %+v\n%s", doc.Effective, out.String())
	}

	// No sandbox policy configured: the answer is untouched.
	cfg = &config.Config{}
	answer := json.RawMessage(`{"profile":"p","effective":{"mode":"action"}}`)
	if got := addSandboxToProfileExplain(answer, cfg); string(got) != string(answer) {
		t.Errorf("answer changed without a sandbox policy: %s", got)
	}
}

func TestSandboxCommandKeepsSecureClientAnnotationOnEveryPlatform(t *testing.T) {
	for _, platform := range []string{"linux", "macos", "windows"} {
		var found *bool
		for _, c := range newEnterpriseIdentityViewCommands(platform) {
			if c.Name() == "sandbox" {
				ok := c.Annotations[enterpriseIdentityViewAnnotation] != ""
				found = &ok
			}
		}
		if found == nil || !*found {
			t.Errorf("%s: sandbox group missing or not marked as an identity view (Secure Client would keep it)", platform)
		}
	}
}

func TestPolicyVerifySandboxRows(t *testing.T) {
	prevProfile, prevGroups := enterprisePolicySandboxProfile, enterpriseAccountGroups
	t.Cleanup(func() { enterprisePolicySandboxProfile, enterpriseAccountGroups = prevProfile, prevGroups })
	enterprisePolicySandboxProfile = func(string) (string, string, string, bool, error) {
		return "contractors", "group", `CORP\Contractors`, false, nil
	}
	c := &config.Config{}
	c.OpenShell.Enabled = true
	c.Guardrail.Profiles = map[string]config.GuardrailProfile{"contractors": {Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"claudecode", "codex"}}}}
	states := []enterprisepolicy.State{
		{Connector: "claudecode", Route: enterprisepolicy.RouteMachinePolicy, Covered: true},
		{Connector: "codex", Route: enterprisepolicy.RoutePerUser},
	}
	enterpriseAccountGroups = func(int) ([]string, error) { return []string{"users"}, nil }
	got := buildEnterprisePolicySandbox(c, "linux", "alice", 1001, states)
	if got == nil || got.Profile != "contractors" || got.Group != `CORP\Contractors` {
		t.Fatalf("sandbox rows = %+v", got)
	}
	byCheck := map[string]enterprisePolicySandboxRow{}
	for _, r := range got.Rows {
		byCheck[r.Check+" "+r.Connector] = r
	}
	if r := byCheck["required claudecode"]; r.State != sandboxRowOK {
		t.Errorf("claudecode row = %+v", r)
	}
	if r := byCheck["required codex"]; r.State != sandboxRowWarn || !strings.Contains(r.Detail, "no machine-owned hook") {
		t.Errorf("codex row = %+v", r)
	}
	if r := byCheck["docker group "]; r.State != sandboxRowFail || !strings.Contains(r.Detail, "usermod -aG docker alice") {
		t.Errorf("docker row = %+v", r)
	}
	if !got.failed() {
		t.Error("a required agent whose account cannot start a sandbox must fail the report")
	}
	enterpriseAccountGroups = func(int) ([]string, error) { return []string{"docker"}, nil }
	if got := buildEnterprisePolicySandbox(c, "linux", "alice", 1001, states); got.failed() {
		t.Errorf("in the docker group it still fails: %+v", got.Rows)
	}
	// An unresolved profile is a note, never a failure on its own.
	enterprisePolicySandboxProfile = func(string) (string, string, string, bool, error) {
		return "", "", "", false, errors.New("gateway down")
	}
	if got := buildEnterprisePolicySandbox(c, "linux", "alice", 1001, states); got.Note == "" || got.failed() {
		t.Errorf("unresolved profile = %+v", got)
	}
	if r := byCheck["floor "]; r.State != sandboxRowOK || !strings.Contains(r.Detail, "profile contractors resolves to sha256:") ||
		!strings.Contains(r.Detail, "from the profile: required_for") || got.FloorDigest == "" {
		t.Errorf("floor row = %+v (digest %q)", r, got.FloorDigest)
	}
	// Nothing configured, and Windows: no rows.
	if buildEnterprisePolicySandbox(&config.Config{}, "linux", "alice", 1, nil) != nil || buildEnterprisePolicySandbox(c, "windows", "alice", -1, nil) != nil {
		t.Error("rows without a sandbox policy or on Windows")
	}
}

// policy verify --user checks the required pack the profile's floor names:
// present, and its content matches required_pack_digest; nothing pinned is a
// warning naming the digest to pin (GAP-0327, GAP-0366). The rows are the
// same on a rerun.
func TestPolicyVerifyRequiredPackRows(t *testing.T) {
	prevProfile, prevGroups := enterprisePolicySandboxProfile, enterpriseAccountGroups
	t.Cleanup(func() { enterprisePolicySandboxProfile, enterpriseAccountGroups = prevProfile, prevGroups })
	enterprisePolicySandboxProfile = func(string) (string, string, string, bool, error) {
		return "contractors", "group", "contractors", false, nil
	}
	enterpriseAccountGroups = func(int) ([]string, error) { return []string{"docker"}, nil }
	strict, err := packs.Builtin("strict")
	if err != nil {
		t.Fatal(err)
	}
	states := []enterprisepolicy.State{{Connector: "claudecode", Route: enterprisepolicy.RouteMachinePolicy, Covered: true}}
	rows := func(pack, pin string) *enterprisePolicySandbox {
		c := &config.Config{}
		c.OpenShell.Enabled = true
		c.Guardrail.Profiles = map[string]config.GuardrailProfile{"contractors": {Sandbox: &config.OpenShellAdminConfig{
			RequiredFor: []string{"claudecode"}, RequiredPack: pack, RequiredPackDigest: pin}}}
		return buildEnterprisePolicySandbox(c, "linux", "alice", 1001, states)
	}
	packRow := func(sb *enterprisePolicySandbox) enterprisePolicySandboxRow {
		for _, r := range sb.Rows {
			if r.Check == "required pack" {
				return r
			}
		}
		t.Fatalf("no required pack row: %+v", sb.Rows)
		return enterprisePolicySandboxRow{}
	}
	ok := rows("strict", strict.Digest)
	if r := packRow(ok); r.State != sandboxRowOK || !strings.Contains(r.Detail, "matches the pinned digest "+strict.Digest) ||
		!strings.Contains(r.Detail, "set by the profile") || ok.PackDigest != strict.Digest || ok.failed() {
		t.Errorf("pinned pack = %+v (%+v)", r, ok)
	}
	if again := rows("strict", strict.Digest); !reflect.DeepEqual(again.Rows, ok.Rows) {
		t.Errorf("a rerun changed the rows:\n%+v\n%+v", ok.Rows, again.Rows)
	}
	if r := packRow(rows("strict", "")); r.State != sandboxRowWarn || !strings.Contains(r.Detail, `required_pack_digest: "`+strict.Digest+`"`) {
		t.Errorf("unpinned pack = %+v", r)
	}
	wrong := rows("strict", "sha256:"+strings.Repeat("0", 64))
	if r := packRow(wrong); r.State != sandboxRowFail || !strings.Contains(r.Detail, "not the pinned required_pack_digest") || !wrong.failed() {
		t.Errorf("a pin that does not match = %+v", r)
	}
	missing := rows(filepath.Join(t.TempDir(), "absent", "pack.yaml"), "")
	if r := packRow(missing); r.State != sandboxRowFail || !strings.Contains(r.Detail, "does not load") || !missing.failed() {
		t.Errorf("a missing pack = %+v", r)
	}
}

// An administrator reads the digest required_pack_digest pins without a
// sandbox daemon, gateway or installed deployment: root has no daemon on a
// managed computer, so `sandbox pack show` cannot answer it (GAP-0224).
func TestEnterpriseSandboxPackDigest(t *testing.T) {
	_, platform := sandboxViewsFixture(t, 1000)
	dir := filepath.Join(t.TempDir(), "contractors")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "version: 1\nname: contractors\nnetwork: {mode: open}\napprovals: {mode: triage}\nworkspace: {mode: mount}\n" +
		"harness: {yolo: true}\nmcp: {import: true, host_ports: false}\nhooks: {fail_mode: closed}\n"
	file := filepath.Join(dir, "pack.yaml")
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	want, err := packs.Validate(file, "")
	if err != nil {
		t.Fatal(err)
	}
	out, err := runSandboxView(t, platform, "pack-digest", file)
	if err != nil || !strings.Contains(out, "digest      "+want.Digest) || !strings.Contains(out, `required_pack_digest: "`+want.Digest+`"`) {
		t.Fatalf("pack-digest = %v\n%s", err, out)
	}
	out, err = runSandboxView(t, platform, "pack-digest", "strict", "--json")
	strict, _ := packs.Builtin("strict")
	var doc sandboxPackDigest
	if err != nil || json.Unmarshal([]byte(out), &doc) != nil || doc.Digest != strict.Digest || !doc.Trusted || doc.Source != "built-in" {
		t.Fatalf("pack-digest strict --json = %v %+v\n%s", err, doc, out)
	}
	if _, err := runSandboxView(t, platform, "pack-digest", filepath.Join(dir, "absent.yaml")); err == nil {
		t.Fatal("a missing pack printed a digest")
	}
}
