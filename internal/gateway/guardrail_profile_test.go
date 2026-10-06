// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	osuser "os/user"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

type testVerifiedSubjectKey struct{}

// stubProfileSources replaces the verified-identity sources for one test:
// only a subject placed under testVerifiedSubjectKey is verified, and the
// gateway's process owner is not.
func stubProfileSources(t *testing.T) {
	t.Helper()
	prevSubject, prevAgent, prevOwner := profileSubjectSource, profileAgentSource, processOwnerProfileSubject
	profileSubjectSource = func(ctx context.Context) (profileSubject, bool) {
		subject, ok := ctx.Value(testVerifiedSubjectKey{}).(profileSubject)
		return subject, ok
	}
	profileAgentSource = func(context.Context) (string, bool) { return "", false }
	processOwnerProfileSubject = func() (profileSubject, bool) { return profileSubject{}, false }
	t.Cleanup(func() {
		profileSubjectSource, profileAgentSource, processOwnerProfileSubject = prevSubject, prevAgent, prevOwner
		liveGuardrailProfiles.Store(nil)
	})
}

func profileSecurityConfig() *config.Config {
	cfg := &config.Config{}
	// The base mode differs from the default profile's, so a request that
	// escaped profile resolution would show up as action.
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "opencode"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict":  {Mode: "action", BlockAt: "LOW"},
		"tooling": {Mode: "action"},
		"watch":   {Mode: "observe"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Users: []string{"alice@CORP.EXAMPLE"}}},
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{`CORP\Contractors`}}},
		{Profile: "tooling", Match: config.ProfileMatch{Groups: []string{"dcidr-grp"}}},
		{Profile: "tooling", Match: config.ProfileMatch{Connectors: []string{"codex"}}},
	}
	cfg.Guardrail.DefaultProfile = "watch"
	return cfg
}

// TestGuardrailProfileSelectionIgnoresClaimedIdentity is the profile
// security matrix: only a verified subject selects a profile. Forged
// identity headers, a payload user and claimed session facts never move a
// request into (or out of) a profile.
func TestGuardrailProfileSelectionIgnoresClaimedIdentity(t *testing.T) {
	stubProfileSources(t)
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, profileSecurityConfig())
	if api.guardrailProfileSet() == nil {
		t.Fatal("profiles were not derived at load")
	}
	claimedAlice := func(ctx context.Context) context.Context {
		// What the hook headers and session-facts header produce: a claimed
		// identity naming the strict user.
		return ContextWithAgentIdentity(ctx, AgentIdentity{UserID: "alice@CORP.EXAMPLE", UserName: "alice"})
	}
	verified := func(subject profileSubject) func(context.Context) context.Context {
		return func(ctx context.Context) context.Context {
			return context.WithValue(ctx, testVerifiedSubjectKey{}, subject)
		}
	}
	cases := []struct {
		name      string
		ctx       []func(context.Context) context.Context
		connector string
		profile   string
		match     string
		group     string
	}{
		{name: "verified UPN in any case", ctx: []func(context.Context) context.Context{verified(profileSubject{UserID: "1001", UPN: "Alice@corp.example"})}, connector: "cursor", profile: "strict", match: profileMatchUser},
		{name: "verified group", ctx: []func(context.Context) context.Context{verified(profileSubject{UserID: "1002", Groups: []string{"S-1-5-21-1", `corp\contractors`}})}, connector: "cursor", profile: "strict", match: profileMatchGroup, group: `CORP\Contractors`},
		{name: "verified Windows group by bare name", ctx: []func(context.Context) context.Context{verified(profileSubject{UserID: "S-1-5-21-7-1001", Groups: []string{"S-1-5-21-7-1037", `HOST\DCIDR-grp`}})}, connector: "cursor", profile: "tooling", match: profileMatchGroup, group: "dcidr-grp"},
		{name: "verified other user keeps default", ctx: []func(context.Context) context.Context{verified(profileSubject{UserID: "1003", UserName: "bob"})}, connector: "cursor", profile: "watch", match: profileMatchDefault},
		{name: "claimed headers alone", ctx: []func(context.Context) context.Context{claimedAlice}, connector: "cursor", profile: "watch", match: profileMatchDefaultUnverified},
		{name: "claimed headers over a verified other user", ctx: []func(context.Context) context.Context{verified(profileSubject{UserID: "1003", UserName: "bob"}), claimedAlice}, connector: "cursor", profile: "watch", match: profileMatchDefault},
		{name: "unverified connector-only assignment", ctx: []func(context.Context) context.Context{claimedAlice}, connector: "codex", profile: "tooling", match: profileMatchConnector},
		{name: "failed directory lookup", ctx: []func(context.Context) context.Context{verified(profileSubject{UserID: "1001", UPN: "alice@corp.example", LookupFailed: true})}, connector: "cursor", profile: "watch", match: profileMatchDefaultLookupFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			for _, apply := range tc.ctx {
				ctx = apply(ctx)
			}
			ctx = api.withGuardrailProfileDecision(ctx, tc.connector)
			got := api.resolveProfile(ctx)
			if got.Name != tc.profile || got.Match != tc.match || got.MatchedGroup != tc.group {
				t.Fatalf("resolveProfile = %+v, want profile=%q match=%q group=%q", got, tc.profile, tc.match, tc.group)
			}
			if got.Digest == "" {
				t.Fatalf("resolved profile %q has no digest", got.Name)
			}
			wantMode := map[string]string{"strict": "action", "tooling": "action", "watch": "observe"}[tc.profile]
			if mode := api.agentHookMode(ctx, tc.connector); mode != wantMode {
				t.Fatalf("agentHookMode = %q, want %q", mode, wantMode)
			}
		})
	}

	// End to end: a hook request carrying the strict user in every claimed
	// place still runs under the default (observe) profile.
	body := `{"hook_event_name":"tool.execute.before","tool_name":"read","user":"alice@CORP.EXAMPLE","user_id":"alice@CORP.EXAMPLE"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/opencode/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(llmEventUserIDHeader, "alice@CORP.EXAMPLE")
	req.Header.Set(llmEventUserNameHeader, "alice")
	req.Header.Set("X-DefenseClaw-Session-Facts", `{"kerberos_principal":"alice@CORP.EXAMPLE","assurance":"claimed"}`)
	req = req.WithContext(claimedAlice(req.Context()))
	recorder := httptest.NewRecorder()
	api.handleAgentHook("opencode").ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("hook status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode hook response: %v", err)
	}
	if resp.Mode != "observe" {
		t.Fatalf("forged identity hook ran in mode %q, want the default profile's observe", resp.Mode)
	}
}

// TestGuardrailProfileSelectsVerifiedDirectoryGroup runs the real S1
// source: a verified subject's directory group selects the group's profile,
// a request that only claims that user in its headers gets the default, and
// a waited-on lookup that never resolved reports default_lookup_failed.
func TestGuardrailProfileSelectsVerifiedDirectoryGroup(t *testing.T) {
	prevOwner := processOwnerProfileSubject
	processOwnerProfileSubject = func() (profileSubject, bool) { return profileSubject{}, false }
	t.Cleanup(func() {
		processOwnerProfileSubject = prevOwner
		setIdentityFactsEnabled(false)
		setIdentityLookupBlocking(false)
		liveGuardrailProfiles.Store(nil)
	})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"ml": {Mode: "action"}, "watch": {Mode: "observe"}}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "ml", Match: config.ProfileMatch{Groups: []string{"DC-ML-Team@dclab.test"}}},
	}
	cfg.Guardrail.DefaultProfile = "watch"
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	applyIdentityPosture(cfg)
	alice := VerifiedSubject{
		UserID: "1201", UserName: "dcad-alice@dclab.test", Source: subjectSourcePeerCredentials,
		Directory: useridentity.DirectoryFacts{
			UPN: "dcad-alice@dclab.test", Groups: []string{"dc-ml-team@dclab.test"}, ResolvedAt: time.Now(),
		},
	}
	unresolved := alice
	unresolved.Directory = useridentity.DirectoryFacts{}
	check := func(t *testing.T, ctx context.Context, profile, match, group string) {
		t.Helper()
		got := api.resolveProfile(api.withGuardrailProfileDecision(ctx, "claude-code"))
		if got.Name != profile || got.Match != match || got.MatchedGroup != group {
			t.Fatalf("resolveProfile = %+v, want profile=%q match=%q group=%q", got, profile, match, group)
		}
	}
	t.Run("verified group", func(t *testing.T) {
		check(t, withVerifiedSubject(context.Background(), alice), "ml", profileMatchGroup, "DC-ML-Team@dclab.test")
	})
	t.Run("agent assignment on the hook path", func(t *testing.T) {
		// The profile is resolved at authentication, before the hook path
		// derives the agent identity; enrichAgentHookContext must re-resolve.
		req := agentHookRequest{ConnectorName: "codex", SessionID: "s-agentpin"}
		agent, verified := agentIdentityFromContext(enrichAgentHookContext(context.Background(), req))
		if agent == "" || !verified {
			t.Skip("no verified agent identity on this host (machine id unreadable)")
		}
		pinned := &config.Config{}
		pinned.Guardrail.Profiles = map[string]config.GuardrailProfile{"agentpin": {Mode: "action"}, "ml": {Mode: "action"}}
		pinned.Guardrail.ProfileAssignments = []config.ProfileAssignment{
			{Profile: "agentpin", Match: config.ProfileMatch{Agents: []string{agent}}},
			{Profile: "ml", Match: config.ProfileMatch{Groups: []string{"dc-ml-team@dclab.test"}}},
		}
		pinnedAPI := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, pinned)
		ctx := pinnedAPI.withGuardrailProfileDecision(withVerifiedSubject(context.Background(), alice), "codex")
		if got := pinnedAPI.resolveProfile(enrichAgentHookContext(ctx, req)); got.Name != "agentpin" || got.Match != profileMatchAgent {
			t.Fatalf("resolveProfile = %+v, want agentpin by agent", got)
		}
	})
	t.Run("unresolved lookup", func(t *testing.T) {
		check(t, withVerifiedSubject(context.Background(), unresolved), "watch", profileMatchDefaultLookupFailed, "")
	})
	t.Run("claimed headers", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", nil)
		request.RemoteAddr = "127.0.0.1:40000"
		request.Header.Set(llmEventUserIDHeader, "1201")
		request.Header.Set(llmEventUserNameHeader, "dcad-alice@dclab.test")
		request.Header.Set(useridentity.SessionFactsHeader, "v1;k=ssh;krb=dcad-alice@DCLAB.TEST;upn=dcad-alice@dclab.test")
		CorrelationMiddleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			check(t, r.Context(), "watch", profileMatchDefaultUnverified, "")
		})).ServeHTTP(httptest.NewRecorder(), request)
	})
}

// TestGuardrailProfileReloadRederivesProfiles pins the reload path: a profile
// edit re-derives the set, changes that profile's digest only, and preloads
// the rule pack a profile newly selects.
func TestGuardrailProfileReloadRederivesProfiles(t *testing.T) {
	stubProfileSources(t)
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	priorManaged := ManagedEnterpriseActive()
	setManagedEnterpriseRedactionPosture(false)
	t.Cleanup(func() { setManagedEnterpriseRedactionPosture(priorManaged) })

	packDir := t.TempDir()
	writeRulePackFixtureFile(t, packDir, "rules/marker.yaml", `version: 1
category: secret
rules:
  - id: PROFILE-MARKER
    pattern: "profile_marker_token"
    title: profile reload fixture
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")
	raw := func(strict string) []byte {
		return []byte(fmt.Sprintf(
			"config_version: 8\ndata_dir: %q\ngateway:\n  config_reload:\n    mode: hot\nguardrail:\n  enabled: true\n  rule_pack_dir: \"\"\n  profiles:\n    strict: %s\n    watch: {mode: observe}\n  default_profile: watch\nobservability: {}\n",
			fixture.dataDir, strict,
		))
	}
	oldRaw := raw(`{mode: action}`)
	newRaw := raw(fmt.Sprintf(`{mode: action, block_at: low, rule_pack_dir: %q}`, packDir))
	oldCfg, err := config.LoadRuntimeV8CandidateFromBytes(fixture.configPath, oldRaw)
	if err != nil {
		t.Fatalf("load old config: %v", err)
	}
	newCfg, err := config.LoadRuntimeV8CandidateFromBytes(fixture.configPath, newRaw)
	if err != nil {
		t.Fatalf("load new config: %v", err)
	}
	fixture.sidecar.publishConfig(oldCfg)
	fixture.sidecar.router = routerWithDefaultRulePack(t)
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cloneConfig(oldCfg))
	fixture.sidecar.apiServer = api
	before := guardrailProfileDigests(api.guardrailProfileSet())
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, oldRaw)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	compiled, err := config.ParseCompileObservabilityV8(fixture.configPath, newRaw, config.ObservabilityV8CompileOptions{DefaultDataDir: fixture.dataDir})
	if err != nil {
		t.Fatalf("compile new observability plan: %v", err)
	}
	if diff := diffConfigs(oldCfg, newCfg); !containsString(diff.Changed, "guardrail.profiles") || len(diff.RestartRequired) != 0 {
		t.Fatalf("profile edit diff = %+v, want a hot guardrail.profiles change", diff)
	}
	if err := fixture.sidecar.applyConfigReloadSnapshot(context.Background(), oldCfg, newCfg,
		ConfigDiff{Changed: []string{"guardrail", "guardrail.profiles"}},
		configReloadSource{sourceName: fixture.configPath, raw: newRaw, compiledV8: compiled},
	); err != nil {
		t.Fatalf("apply profile reload: %v", err)
	}

	set := api.guardrailProfileSet()
	after := guardrailProfileDigests(set)
	if after["strict"] == before["strict"] || after["watch"] != before["watch"] {
		t.Fatalf("digests before=%v after=%v, want only strict to change", before, after)
	}
	changes := diffGuardrailProfileDigests(&guardrailProfileSet{profiles: map[string]config.DerivedGuardrailProfile{
		"strict": {Digest: before["strict"]}, "watch": {Digest: before["watch"]},
	}}, set)
	if len(changes) != 1 || changes[0].Name != "strict" {
		t.Fatalf("digest changes = %+v, want strict only", changes)
	}
	ctx := context.WithValue(context.Background(), testVerifiedSubjectKey{}, profileSubject{UserID: "1001"})
	set.assignments = []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Users: []string{"1001"}}}}
	ctx = api.withGuardrailProfileDecision(ctx, "codex")
	if ids := findingIDs(scanAllRulesForConnectorFor(ctx, "codex", "profile_marker_token", "exec")); !containsRuleID(ids, "PROFILE-MARKER") {
		t.Fatalf("strict profile did not scan with its rule pack: %v", ids)
	}
	if ids := findingIDs(ScanAllRulesForConnector("codex", "profile_marker_token", "exec")); containsRuleID(ids, "PROFILE-MARKER") {
		t.Fatalf("profile rule pack leaked into the base rule set: %v", ids)
	}
}

// GAP-0094: a local account's groups count once each. macOS listed every
// gid and then its name, so explain and identity.observed doubled the count.
func TestLocalAccountGroupsCountEachGroupOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows lists each group as its SID and name")
	}
	account, err := osuser.Current()
	if err != nil {
		t.Skip(err)
	}
	gids, err := account.GroupIds()
	if err != nil || len(gids) == 0 {
		t.Skip("no groups for the current account")
	}
	groups := localAccountGroups(account)
	if len(groups) != len(gids) || identityGroupCount(groups) != int64(len(gids)) {
		t.Fatalf("localAccountGroups = %v (count %d), want one entry per gid %v", groups, identityGroupCount(groups), gids)
	}
}
