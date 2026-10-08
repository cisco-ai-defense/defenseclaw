// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// An inspect scan must use the authenticated connector profile override.
func TestInspectScanUsesAuthenticatedConnectorProfilePack(t *testing.T) {
	stubProfileSources(t)
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	packDir := filepath.Join(t.TempDir(), "codex-pack")
	writeRulePackFixtureFile(t, packDir, "rules/marker.yaml", `version: 1
category: secret
rules:
  - id: INSPECT-CONNECTOR-MARKER
    pattern: "inspect_connector_marker_token"
    title: inspect connector fixture
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict": {Connectors: map[string]config.PerConnectorGuardrailConfig{
			"codex": {RulePackDir: packDir},
		}},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Connectors: []string{"codex"}}},
	}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	ctx := withAuthenticatedInspectConnector(t.Context(), "codex")
	ctx = api.withGuardrailProfileDecision(ctx, "")
	findings, err := scanWithTimeout(ctx, "inspect_connector_marker_token", "shell-response", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ids := findingIDs(findings); !containsRuleID(ids, "INSPECT-CONNECTOR-MARKER") {
		t.Fatalf("authenticated connector pack not used: %v", ids)
	}
}

// Removing the last profile must leave unmatched hooks on the live base mode.
func TestGuardrailProfileRemovalUsesReloadedBaseForUnmatchedHook(t *testing.T) {
	stubProfileSources(t)
	startup := &config.Config{}
	startup.Guardrail.Mode = "observe"
	startup.Guardrail.Profiles = map[string]config.GuardrailProfile{"strict": {Mode: "action"}}
	startup.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Users: []string{"1001"}}},
	}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, startup)
	live := startup
	api.SetGenerationSource(func() *Generation { return &Generation{Config: live} })
	ctx := api.withGuardrailProfileDecision(t.Context(), "opencode")
	if got := hookModeForConfig(api.decisionConfig(ctx), "opencode"); got != "observe" {
		t.Fatalf("startup unmatched hook mode = %q", got)
	}
	reloaded := *startup
	reloaded.Guardrail = startup.Guardrail
	reloaded.Guardrail.Mode = "action"
	reloaded.Guardrail.Profiles = nil
	reloaded.Guardrail.ProfileAssignments = nil
	live = &reloaded
	api.setGuardrailProfiles(nil)
	if got := hookModeForConfig(api.decisionConfig(ctx), "opencode"); got != "action" {
		t.Fatalf("reloaded unmatched hook mode = %q, want action", got)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?connector=opencode", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	rec := httptest.NewRecorder()
	api.handleGuardrailProfileResolve(rec, req)
	var explained struct {
		Effective map[string]any `json:"effective"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &explained); err != nil {
		t.Fatalf("decode profile explain: %v", err)
	}
	if got := explained.Effective["mode"]; got != "action" {
		t.Fatalf("explain mode = %v, live hook mode = action", got)
	}
}

// A reload during a request must attribute records to the profile enforced
// by decisions after the reload.
func TestGuardrailProfileTelemetryFollowsReloadedSet(t *testing.T) {
	stubProfileSources(t)
	cfg := &config.Config{}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict": {Mode: "action"}, "watch": {Mode: "observe"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Users: []string{"1001"}}},
	}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, profileSubject{UserID: "1001"})
	ctx = api.withGuardrailProfileDecision(ctx, "")
	if got := api.decisionConfig(ctx).Guardrail.Mode; got != "action" {
		t.Fatalf("initial decision mode = %q", got)
	}
	next := *cfg
	next.Guardrail = cfg.Guardrail
	next.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "watch", Match: config.ProfileMatch{Users: []string{"1001"}}},
	}
	set, err := newGuardrailProfileSet(&next, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	api.setGuardrailProfiles(set)
	if got := api.decisionConfig(ctx).Guardrail.Mode; got != "observe" {
		t.Fatalf("reloaded decision mode = %q", got)
	}
	if name, _ := guardrailProfileTelemetryFor(ctx).Name.Get(); name != "watch" {
		t.Fatalf("telemetry profile = %q, want enforced watch", name)
	}
}

// TestSubjectGroupsMatchLikeEqualFold: the group index answers as the scan
// with strings.EqualFold it replaced (GAP-0118), for names, SIDs, DOMAIN\name
// groups, a bare name against a DOMAIN\name group, padding, and runes whose
// case folding is not their lower case.
func TestSubjectGroupsMatchLikeEqualFold(t *testing.T) {
	reference := func(groups []string, want string) bool {
		if anyEqualFold(groups, want) {
			return true
		}
		want = strings.TrimSpace(want)
		if want == "" || strings.Contains(want, `\`) {
			return false
		}
		for _, group := range groups {
			if i := strings.LastIndexByte(group, '\\'); i >= 0 && strings.EqualFold(strings.TrimSpace(group[i+1:]), want) {
				return true
			}
		}
		return false
	}
	groups := []string{"DC-ML-Team@dclab.test", "S-1-5-21-1-2-3-1104", `CORP\Contractors`, " padded ", "ΣΑΣ", "Key", "5002", `CORP\ `}
	for _, want := range []string{"dc-ml-team@DCLAB.TEST", "s-1-5-21-1-2-3-1104", `corp\contractors`, "contractors", `OTHER\Contractors`, "PADDED",
		"σας", "ΣΑς", "key", "KEY", "5002", "", "  ", "missing", `CORP\`, "Contractor", "dc-ml-team"} {
		if got, want2 := (&subjectGroups{list: groups}).has(want), reference(groups, want); got != want2 {
			t.Errorf("has(%q) = %t, the EqualFold scan says %t", want, got, want2)
		}
	}
	if (&subjectGroups{}).has("anything") {
		t.Error("a subject with no groups is in a group")
	}
}

// A matched group longer than the attribute allows is left out of the
// decision records instead of failing them (GAP-0319).
func TestGuardrailProfileTelemetryBoundsTheMatchedGroup(t *testing.T) {
	telemetry := func(group string) guardrailProfileTelemetry {
		return guardrailProfileTelemetryFor(context.WithValue(t.Context(), resolvedGuardrailProfileKey{}, &resolvedGuardrailProfile{
			decision: profileDecision{Name: "strict", Digest: "sha256:0", Match: profileMatchGroup, MatchedGroup: group},
		}))
	}
	if got, ok := telemetry(`CORP\Contractors`).MatchedGroup.Get(); !ok || got != `CORP\Contractors` {
		t.Fatalf("matched group = %q (present %t), want CORP\\Contractors", got, ok)
	}
	long := telemetry(`CORP\` + strings.Repeat("組", 90))
	if got, ok := long.MatchedGroup.Get(); ok {
		t.Fatalf("a %d-byte matched group was kept", len(got))
	}
	if name, _ := long.Name.Get(); name != "strict" {
		t.Fatalf("profile name = %q, want strict", name)
	}
}

func TestGuardrailWaitsForAPIProfilePublication(t *testing.T) {
	previous := liveGuardrailProfiles.Load()
	t.Cleanup(func() { liveGuardrailProfiles.Store(previous) })
	liveGuardrailProfiles.Store(nil)
	s := &Sidecar{apiProfilesReady: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- s.waitForAPIProfilePublication(t.Context()) }()
	select {
	case err := <-done:
		t.Fatalf("guardrail started before API profile publication: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"strict": {Mode: "action"}}
	cfg.Guardrail.DefaultProfile = "strict"
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	s.setAPIServer(api)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if set := liveGuardrailProfiles.Load(); set == nil || set.defaultProfile != "strict" {
		t.Fatal("guardrail started without the action profile")
	}
}

// The guardrail proxy scans the requests a profile selects with the
// profile's rule pack and applies its HILT, as explain says it does
// (GAP-0313). Its thresholds come from requestThresholds.
func TestGuardrailProxyAppliesTheProfileRulePackAndHILT(t *testing.T) {
	stubProfileSources(t)
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	previous := liveGuardrailProfiles.Load()
	t.Cleanup(func() { liveGuardrailProfiles.Store(previous) })
	packDir := filepath.Join(t.TempDir(), "strict")
	writeRulePackFixtureFile(t, packDir, "rules/marker.yaml", `version: 1
category: secret
rules:
  - id: PROXY-PROFILE-MARKER
    pattern: "proxy_profile_marker_token"
    title: proxy profile fixture
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"contractors": {Connectors: map[string]config.PerConnectorGuardrailConfig{
			"openclaw": {RulePackDir: packDir},
		}, HILT: &config.HILTConfig{Enabled: true, MinSeverity: "medium"}},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "contractors", Match: config.ProfileMatch{Connectors: []string{"openclaw"}}},
	}
	NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	inspector := NewGuardrailInspector("local", nil, nil)
	inspector.SetHILTConfig(false, "HIGH")
	proxy := &GuardrailProxy{cfg: &config.GuardrailConfig{Connector: "openclaw"}, gatewayToken: "owner-token"}
	subject := context.WithValue(t.Context(), testVerifiedSubjectKey{}, profileSubject{UserID: "1001"})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil).WithContext(subject)
	req.Header.Set("X-DC-Auth", "Bearer owner-token")
	ctx := proxy.withProxyAgent(req).Context()
	if name, _ := guardrailProfileTelemetryFor(ctx).Name.Get(); name != "contractors" {
		t.Fatalf("proxy profile = %q, want contractors", name)
	}
	// A completion: the prompt surface reports and never blocks. The
	// profile's HILT (MEDIUM) turns the HIGH finding into a confirm.
	verdict := inspector.Inspect(ctx, "completion", "please keep proxy_profile_marker_token safe", nil, "test-model", "action")
	if verdict == nil || verdict.Action != "confirm" || !strings.Contains(strings.Join(verdict.Findings, ","), "PROXY-PROFILE-MARKER") {
		t.Fatalf("proxy verdict = %+v, want a confirm by the profile's rule pack and HILT", verdict)
	}
	if hilt := inspector.hiltInputFor(ctx); hilt == nil || !hilt.Enabled || hilt.MinSeverity != "MEDIUM" {
		t.Fatalf("proxy HILT input = %+v, want the profile's (enabled, MEDIUM)", hilt)
	}
}

// Proxy records must describe the configuration the proxy actually applies.
func TestProxyTelemetryOmitsUnappliedProfile(t *testing.T) {
	stubProfileSources(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"contractors": {Mode: "action"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "contractors", Match: config.ProfileMatch{Connectors: []string{"openclaw"}}},
	}
	NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	proxy := &GuardrailProxy{cfg: &config.GuardrailConfig{Connector: "openclaw"}}
	request := proxy.withProxyAgent(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if profile := proxyProfileFor(request.Context()); profile != nil {
		t.Fatalf("unverified proxy applied profile %+v", profile.decision)
	}
	meta := proxyLLMEventMeta(proxy, request, &ChatRequest{Model: "test-model"}, "test-provider")
	if name, present := meta.Profile.Name.Get(); present {
		t.Fatalf("unapplied profile %q appeared in proxy telemetry", name)
	}
	// A provider bearer can authenticate a connector without proving the
	// caller is the gateway owner. The process owner remains ineligible.
	processOwnerProfileSubject = func() (profileSubject, bool) {
		return profileSubject{UserID: "owner"}, true
	}
	providerRequest := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	providerRequest.Header.Set("Authorization", "Bearer provider-key")
	providerRequest = proxy.withProxyAgent(providerRequest)
	if profile := proxyProfileFor(providerRequest.Context()); profile != nil {
		t.Fatalf("provider-key request inherited owner profile %+v", profile.decision)
	}
	if id, _ := agentIdentityFromContext(providerRequest.Context()); id != "" {
		t.Fatalf("provider-key request inherited owner agent identity %q", id)
	}
}

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
		{Profile: "strict", Match: config.ProfileMatch{Users: []string{"alice@CORP.EXAMPLE", `CORP\carol`}}},
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
		{name: "verified DOMAIN\\user of the Windows domain", ctx: []func(context.Context) context.Context{verified(profileSubject{UserID: "S-1-5-21-7-1105", UserName: "carol", Domain: "corp.example", AccountDomain: "CORP", Principal: "carol@corp.example"})}, connector: "cursor", profile: "strict", match: profileMatchUser},
		{name: "DOMAIN\\user of another domain keeps default", ctx: []func(context.Context) context.Context{verified(profileSubject{UserID: "1005", UserName: "carol", Domain: "other.example"})}, connector: "cursor", profile: "watch", match: profileMatchDefault},
		{name: "verified other user keeps default", ctx: []func(context.Context) context.Context{verified(profileSubject{UserID: "1003", UserName: "bob"})}, connector: "cursor", profile: "watch", match: profileMatchDefault},
		{name: "claimed headers alone", ctx: []func(context.Context) context.Context{claimedAlice}, connector: "cursor", profile: "watch", match: profileMatchDefaultUnverified},
		{name: "claimed headers over a verified other user", ctx: []func(context.Context) context.Context{verified(profileSubject{UserID: "1003", UserName: "bob"}), claimedAlice}, connector: "cursor", profile: "watch", match: profileMatchDefault},
		{name: "unverified connector-only assignment", ctx: []func(context.Context) context.Context{claimedAlice}, connector: "codex", profile: "tooling", match: profileMatchConnector},
		{name: "failed directory lookup", ctx: []func(context.Context) context.Context{verified(profileSubject{UserID: "1001", UPN: "alice@corp.example", LookupFailed: true})}, connector: "cursor", profile: "watch", match: profileMatchDefaultLookupFailed},
		{name: "failed directory lookup on a connector-only assignment", ctx: []func(context.Context) context.Context{verified(profileSubject{UserID: "1002", LookupFailed: true})}, connector: "codex", profile: "watch", match: profileMatchDefaultLookupFailed},
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
	t.Run("agent and connector assignments on every path", func(t *testing.T) {
		// The hook path resolves the profile at authentication, before it
		// derives the agent identity; the inspect API and the LLM proxy
		// carry none, and the proxy's connector is server-side config
		// (GAP-0148, GAP-0170).
		req := agentHookRequest{ConnectorName: "zeptoclaw", SessionID: "s-agentpin"}
		agent, verified := agentIdentityFromContext(enrichAgentHookContext(context.Background(), req))
		if agent == "" || !verified {
			t.Skip("no verified agent identity on this host (machine id unreadable)")
		}
		subject := withVerifiedSubject(context.Background(), alice)
		for match, want := range map[string]config.ProfileMatch{
			profileMatchAgent:     {Agents: []string{agent}},
			profileMatchConnector: {Connectors: []string{"zeptoclaw"}},
		} {
			pinned := &config.Config{}
			pinned.Guardrail.Mode = "action"
			pinned.Guardrail.Profiles = map[string]config.GuardrailProfile{"pin": {Mode: "observe"}, "ml": {Mode: "action"}}
			pinned.Guardrail.ProfileAssignments = []config.ProfileAssignment{
				{Profile: "pin", Match: want},
				{Profile: "ml", Match: config.ProfileMatch{Groups: []string{"dc-ml-team@dclab.test"}}},
			}
			pinnedAPI := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, pinned)
			hook := enrichAgentHookContext(pinnedAPI.withGuardrailProfileDecision(subject, "zeptoclaw"), req)
			inspect := pinnedAPI.withGuardrailProfileDecision(withAuthenticatedInspectConnector(subject, "zeptoclaw"), "")
			for path, ctx := range map[string]context.Context{"hook": hook, "inspect": inspect} {
				if got := pinnedAPI.resolveProfile(ctx); got.Name != "pin" || got.Match != match {
					t.Fatalf("%s: resolveProfile = %+v, want pin by %s", path, got, match)
				}
			}
			proxy := &GuardrailProxy{cfg: &config.GuardrailConfig{Connector: "zeptoclaw"}}
			r := proxy.withProxyAgent(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil).WithContext(subject))
			if mode, _ := proxy.profileModeFor(r.Context(), "action", ""); mode != "observe" {
				t.Fatalf("proxy mode with %s pin = %q, want observe", match, mode)
			}
			if id, _ := agentIdentityFromContext(r.Context()); id != agent {
				t.Fatalf("proxy agent identity = %q, want %q", id, agent)
			}
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
	disabledDir := filepath.Join(t.TempDir(), "disabled-app-protection-pack")
	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")
	raw := func(strict string) []byte {
		return []byte(fmt.Sprintf(
			"config_version: 8\ndata_dir: %q\ngateway:\n  config_reload:\n    mode: hot\nguardrail:\n  enabled: true\n  rule_pack_dir: \"\"\n  profiles:\n    strict: %s\n    watch: {mode: observe}\n  profile_assignments:\n    - {profile: strict, match: {users: [\"1001\"]}}\n  default_profile: watch\napplication_protection:\n  enabled: false\n  guardrail: {rule_pack_dir: %q}\n  connectors:\n    cursor: {guardrail: {rule_pack_dir: %q}}\nobservability: {}\n",
			fixture.dataDir, strict, disabledDir, disabledDir,
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
	ctx = api.withGuardrailProfileDecision(ctx, "codex")
	if ids := findingIDs(scanAllRulesForConnectorFor(ctx, "codex", "profile_marker_token", "exec")); !containsRuleID(ids, "PROFILE-MARKER") {
		t.Fatalf("strict profile did not scan with its rule pack: %v", ids)
	}
	if ids := findingIDs(ScanAllRulesForConnector("codex", "profile_marker_token", "exec")); containsRuleID(ids, "PROFILE-MARKER") {
		t.Fatalf("profile rule pack leaked into the base rule set: %v", ids)
	}
}

// TestProfileRulePackLoadedAfterStart pins GAP-0333: a profile whose rule
// pack directory did not exist when the gateway started scans with the base
// rule set only until a retry loads the pack, and explain says so meanwhile.
func TestProfileRulePackLoadedAfterStart(t *testing.T) {
	stubProfileSources(t)
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	priorManaged := ManagedEnterpriseActive()
	setManagedEnterpriseRedactionPosture(false)
	t.Cleanup(func() { setManagedEnterpriseRedactionPosture(priorManaged) })
	packDir := filepath.Join(t.TempDir(), "late-pack")
	cfg := &config.Config{}
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"strict": {Mode: "action", RulePackDir: packDir}}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Users: []string{"1001"}}}}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	set := api.guardrailProfileSet()
	scan := func() []string {
		ctx := context.WithValue(context.Background(), testVerifiedSubjectKey{}, profileSubject{UserID: "1001"})
		return findingIDs(scanAllRulesForConnectorFor(api.withGuardrailProfileDecision(ctx, "codex"), "codex", "profile_marker_token", "exec"))
	}
	if set == nil || containsRuleID(scan(), "PROFILE-MARKER") {
		t.Fatal("a profile whose pack is missing must scan with the base rule set")
	}
	if note := set.pendingRulePackNote("strict", set.profiles["strict"].Config, "codex"); !strings.Contains(note, "did not load") {
		t.Fatalf("explain note = %q, want the missing pack", note)
	}
	writeRulePackFixtureFile(t, packDir, "rules/marker.yaml", `version: 1
category: secret
rules:
  - id: PROFILE-MARKER
    pattern: "profile_marker_token"
    title: late pack fixture
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
	writeRulePackFixtureFile(t, packDir, "suppressions.yaml", `version: 1
pre_judge_strips: []
finding_suppressions:
  - id: PROFILE-SUPPRESSION
    finding_pattern: "PROFILE-MARKER"
    entity_pattern: "profile_marker_token"
    reason: allowed in this profile
tool_suppressions: []
`)
	for _, retry := range set.missing {
		retry.mu.Lock()
		retry.nextTry = time.Time{}
		retry.mu.Unlock()
	}
	if ids := scan(); !containsRuleID(ids, "PROFILE-MARKER") {
		t.Fatalf("the pack created after start was not used: %v", ids)
	}
	if note := set.pendingRulePackNote("strict", set.profiles["strict"].Config, "codex"); note != "" {
		t.Fatalf("explain note = %q after the pack loaded", note)
	}
	ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, profileSubject{UserID: "1001"})
	ctx = api.withGuardrailProfileDecision(ctx, "codex")
	pack := api.connectorRulePack(ctx, "codex")
	if pack == nil || pack.Suppressions == nil || len(pack.Suppressions.FindingSupps) != 1 ||
		pack.Suppressions.FindingSupps[0].ID != "PROFILE-SUPPRESSION" {
		t.Fatalf("retry did not supply the profile judge suppression: %+v", pack)
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
	groups, err := accountGroups(account)
	if err != nil || len(groups) != len(gids) || identityGroupCount(groups) != int64(len(gids)) {
		t.Fatalf("accountGroups = %v (count %d), err %v; want one entry per gid %v", groups, identityGroupCount(groups), err, gids)
	}
}

// TestExplainReportsAFailedDirectoryLookup pins GAP-0124: when the directory
// lookup of an account fails, explain says so, as a request gets
// default_lookup_failed; it must not answer from the OS account database
// with a profile no request receives.
func TestExplainReportsAFailedDirectoryLookup(t *testing.T) {
	previousBlocking := identityLookupBlocking.Load()
	setIdentityLookupBlocking(true)
	t.Cleanup(func() { setIdentityLookupBlocking(previousBlocking) })
	prevAccount, prevFacts := profileExplainAccount, profileExplainDirectoryFacts
	t.Cleanup(func() { profileExplainAccount, profileExplainDirectoryFacts = prevAccount, prevFacts })
	profileExplainAccount = func(string) (string, string, error) { return "94401116", "dcad-manygroups@dclab.test", nil }
	profileExplainDirectoryFacts = func(string) (useridentity.DirectoryFacts, error) {
		return useridentity.DirectoryFacts{}, errors.New("in 3000 groups, more than the 2048 DefenseClaw names")
	}
	subject, err := lookupDirectoryProfileSubject("dcad-manygroups")
	if err != nil || !subject.LookupFailed || !strings.Contains(subject.LookupError, "3000 groups") || len(subject.Groups) != 0 {
		t.Fatalf("subject = %+v, %v; want a failed lookup that names its reason and has no groups", subject, err)
	}
}

// TestExplainShowsWhatRequestsGetWhileTheGatewayLookupFails pins GAP-0212:
// explain resolves the account afresh, but the gateway's requests for it get
// default_lookup_failed while its own lookups fail, and explain says so; groups
// kept as numbers are named as a sign of an unreachable directory.
func TestExplainShowsWhatRequestsGetWhileTheGatewayLookupFails(t *testing.T) {
	previousBlocking := identityLookupBlocking.Load()
	setIdentityLookupBlocking(true)
	t.Cleanup(func() { setIdentityLookupBlocking(previousBlocking) })
	prevFacts, prevFailure := cachedDirectoryFacts, cachedDirectoryFailure
	t.Cleanup(func() { cachedDirectoryFacts, cachedDirectoryFailure = prevFacts, prevFailure })
	cachedDirectoryFacts = func(string) (useridentity.DirectoryFacts, time.Time, bool) {
		return useridentity.DirectoryFacts{}, time.Time{}, false
	}
	since := time.Now().Add(-time.Minute)
	cachedDirectoryFailure = func(string) (time.Time, string, bool) { return since, "groups of dcad-manygroups: timeout", true }
	explained := profileSubject{UserID: "94401116", UserName: "dcad-manygroups", Groups: []string{"94400513"}}
	set := &guardrailProfileSet{}
	decision := set.match(&explained, profileSubjectLookup, "", "")
	view, warning := explainCacheView(set, &explained, decision, "", "", time.Now())
	if view == nil || view["match"] != profileMatchDefaultLookupFailed || !strings.Contains(warning, "default_lookup_failed") ||
		!strings.Contains(warning, "timeout") {
		t.Fatalf("view %v, warning %q; want the lookup failure named", view, warning)
	}
	if note := unnamedGroupsNote(&explained); !strings.Contains(note, "1 of this account's 1 group(s) are shown by number") {
		t.Fatalf("unnamed groups note = %q", note)
	}
}

// TestExplainNamesWindowsGroupsWithoutAnIdentityRecord pins GAP-0121 and
// GAP-0136: an account without a guardian identity record has unknown groups,
// not none, and groups the guardian could not name stay bare SIDs; both are
// said, and facts awaiting the record are refreshed early.
func TestExplainNamesWindowsGroupsWithoutAnIdentityRecord(t *testing.T) {
	previous := currentIdentitySpoolDir()
	t.Cleanup(func() { setIdentitySpoolDir(previous) })
	setIdentitySpoolDir(t.TempDir())
	if note := spoolRecordNote("S-1-5-21-1-2-3-1104", time.Now()); !strings.Contains(note, "no identity record for this account yet") {
		t.Fatalf("spool note = %q", note)
	}
	if !awaitingSpool(useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory}) ||
		awaitingSpool(useridentity.DirectoryFacts{Groups: []string{"S-1-1-0", "Everyone"}}) {
		t.Fatal("facts without groups must await the record, facts with groups must not")
	}
	// GAP-0334: an SSSD account without the guardian's UPN is refreshed
	// early on a gateway that reads the spool; with the UPN it is not.
	if !awaitingSpoolUPN(useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Principal: "bob@CORP.EXAMPLE"}) ||
		awaitingSpoolUPN(useridentity.DirectoryFacts{Source: useridentity.SourceSSSDInfoPipe, UPN: "bob@corp.example"}) {
		t.Fatal("SSSD facts without a UPN must await the guardian record, facts with it must not")
	}
	setIdentitySpoolDir("")
	if spoolRecordNote("S-1-5-21-1-2-3-1104", time.Now()) != "" {
		t.Fatal("a gateway without a spool has no record to wait for")
	}
	named := &profileSubject{Groups: []string{"S-1-1-0", "Everyone", "S-1-5-21-1-2-3-9001", "S-1-5-21-1-2-3-9002"}}
	if note := unnamedGroupsNote(named); !strings.Contains(note, "2 of this account's 3 group(s) have no name, only a SID") {
		t.Fatalf("unnamed SID note = %q", note)
	}
}

// TestExplainNamesEntraIDAccountsThroughTheLSA pins GAP-0222: explain names
// an Entra ID account by its SID, bare name or UPN through the LSA, as the
// hook path names it, where os/user failed for every Entra ID account; a
// name the LSA cannot resolve is reported with the LSA's reason.
func TestExplainNamesEntraIDAccountsThroughTheLSA(t *testing.T) {
	const sid = "S-1-12-1-2531559698-1231582900-1003231414-1134328369"
	alice := windowsAccount{SID: sid, Name: "EntraAlice", User: true}
	noMapping := errors.New("No mapping between account names and security IDs was done.")
	bySID := func(s string) (windowsAccount, error) {
		if strings.EqualFold(s, sid) {
			return alice, nil
		}
		return windowsAccount{}, noMapping
	}
	// LookupAccountName takes an Entra ID account only in the AzureAD domain.
	byName := func(name string) (windowsAccount, error) {
		switch strings.ToLower(name) {
		case `azuread\entraalice`, `azuread\entra-alice@contoso.example`:
			return alice, nil
		}
		return windowsAccount{}, noMapping
	}
	for _, name := range []string{strings.ToLower(sid), "EntraAlice", "entra-alice@contoso.example", `AzureAD\EntraAlice`} {
		if id, user, err := resolveWindowsExplainAccount(name, bySID, byName); err != nil || id != sid || user != "EntraAlice" {
			t.Errorf("resolve(%q) = %q, %q, %v; want %s, EntraAlice", name, id, user, err, sid)
		}
	}
	if _, _, err := resolveWindowsExplainAccount("entra-bob@contoso.example", bySID, byName); err == nil || !strings.Contains(err.Error(), noMapping.Error()) {
		t.Errorf("unknown account: err = %v; want an error with the LSA's reason", err)
	}
	// An AD UPN with an alternate suffix resolves through its
	// DOMAIN\sAMAccountName, as the live decision names it (GAP-0609).
	previous := windowsSAMNameForUPN
	windowsSAMNameForUPN = func(upn string) string {
		if strings.EqualFold(upn, "ew3.contract@alt.dclab.test") {
			return `DCLAB\dcad-ew3`
		}
		return ""
	}
	t.Cleanup(func() { windowsSAMNameForUPN = previous })
	ew3 := windowsAccount{SID: "S-1-5-21-1-2-3-1203", Name: "dcad-ew3", User: true}
	adByName := func(name string) (windowsAccount, error) {
		if strings.EqualFold(name, `DCLAB\dcad-ew3`) {
			return ew3, nil
		}
		return byName(name)
	}
	if id, user, err := resolveWindowsExplainAccount("ew3.contract@alt.dclab.test", bySID, adByName); err != nil || id != ew3.SID || user != "dcad-ew3" {
		t.Errorf("alternate-suffix UPN = %q, %q, %v; want %s, dcad-ew3", id, user, err, ew3.SID)
	}
}

// TestExplainReportsGroupsThatCannotBeListed pins GAP-0201: an account whose
// groups the OS database cannot list is a failed lookup in explain too, with
// the reason, not an account with no groups that gets the plain default.
func TestExplainReportsGroupsThatCannotBeListed(t *testing.T) {
	prev := accountGroupIDs
	t.Cleanup(func() { accountGroupIDs = prev })
	accountGroupIDs = func(*osuser.User) ([]string, error) {
		return nil, errors.New("user: list groups for dcad-manygroups failed")
	}
	subject := localProfileSubject(&osuser.User{Uid: "94401116", Username: "dcad-manygroups"})
	decision := (&guardrailProfileSet{}).match(&subject, profileSubjectLookup, "", "")
	if !subject.LookupFailed || !strings.Contains(subject.LookupError, "list groups") || decision.Match != profileMatchDefaultLookupFailed {
		t.Fatalf("subject = %+v, match %q; want a failed lookup that names its reason", subject, decision.Match)
	}
}

// TestAssignmentsIgnoreUnicodeNormalisationForm pins GAP-0154: an assignment
// typed with a combining accent (decomposed, NFD) matches the precomposed
// (NFC) group, user and principal the directory holds, and the reverse.
func TestAssignmentsIgnoreUnicodeNormalisationForm(t *testing.T) {
	const (
		groupNFC, groupNFD = "dc-\u00e9quipe@dclab.test", "dc-e\u0301quipe@dclab.test"
		userNFC, userNFD   = "dcad-zo\u00eb@dclab.test", "dcad-zoe\u0308@dclab.test"
	)
	for _, tc := range []struct{ held, spelled string }{{groupNFC, groupNFD}, {groupNFD, groupNFC}} {
		subject := &profileSubject{UserID: "94401117", Groups: []string{tc.held}}
		if _, group, ok := assignmentMatches(config.ProfileMatch{Groups: []string{strings.ToUpper(tc.spelled)}}, subject,
			&subjectGroups{list: subject.Groups}, true, "", ""); !ok || group == "" {
			t.Errorf("group %+q does not match the held %+q", tc.spelled, tc.held)
		}
	}
	for _, tc := range []struct{ held, spelled string }{{userNFC, userNFD}, {userNFD, userNFC}} {
		for _, subject := range []*profileSubject{{UserID: "94401117", UserName: tc.held}, {UserID: "94401117", Principal: tc.held}, {UserID: "94401117", UPN: tc.held}} {
			if _, _, ok := assignmentMatches(config.ProfileMatch{Users: []string{tc.spelled}}, subject,
				&subjectGroups{}, true, "", ""); !ok {
				t.Errorf("user %+q does not match the held %+q (%+v)", tc.spelled, tc.held, subject)
			}
		}
	}
}

// TestUnknownAssignmentGroupsAreReported pins GAP-0135: a group an assignment
// names that the host definitely does not know (renamed or deleted in the
// directory) is a warning; one that exists, one whose lookup failed, and
// SIDs (off Windows) are not.
func TestUnknownAssignmentGroupsAreReported(t *testing.T) {
	// The directory cache is shared by the tests of the package; other tests
	// leave failing lookups in it, and the group check says nothing then
	// (GAP-0229).
	previousHealth := directoryCacheHealth
	t.Cleanup(func() { directoryCacheHealth = previousHealth })
	directoryCacheHealth = func() identityCacheHealth { return identityCacheHealth{} }
	assignments := []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"dc-rename-me@dclab.test", "dc-ml-team@dclab.test"}}},
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"S-1-5-21-1-2-3-1104", "dc-flaky@dclab.test", "DC-RENAME-ME@dclab.test"}}},
	}
	exists := func(_ context.Context, name string) (bool, error) {
		switch name {
		case "dc-ml-team@dclab.test":
			return true, nil
		case "dc-flaky@dclab.test":
			return false, errors.New("getent timed out")
		case "S-1-5-21-1-2-3-1104":
			t.Error("a SID was looked up as a name")
		}
		return false, nil
	}
	got := unknownAssignmentGroupsForOS(context.Background(), assignments, exists, nil, "linux")
	if len(got) != 2 || !strings.HasPrefix(got[0], `assignment 1: group "dc-rename-me@dclab.test" is not known`) ||
		!strings.HasPrefix(got[1], `assignment 2: group "DC-RENAME-ME@dclab.test" is not known`) {
		t.Fatalf("warnings = %q, want the renamed group in assignments 1 and 2 only", got)
	}

	// GAP-0332: SSSD names realm groups name@domain, so a short name is
	// absent while the qualified one exists; the warning names it.
	qualify := func(_ context.Context, name string) string {
		if name == "dc-ml-short" {
			return "dc-ml-short@dclab.test"
		}
		return ""
	}
	short := []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"dc-ml-short"}}}}
	if got := unknownAssignmentGroupsForOS(context.Background(), short, exists, qualify, "linux"); len(got) != 1 ||
		!strings.Contains(got[0], `the host knows it as "dc-ml-short@dclab.test"`) {
		t.Fatalf("short-name warnings = %q, want the qualified name", got)
	}
	// GAP-0916: after a switch to short names the qualified group still
	// resolves, but as dc-ml-team, the name group lists carry: it is warned.
	switched := func(_ context.Context, name string) string {
		if name == "dc-ml-team@dclab.test" {
			return "dc-ml-team"
		}
		return ""
	}
	qualified := []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"dc-ml-team@dclab.test"}}}}
	if got := unknownAssignmentGroupsForOS(context.Background(), qualified, exists, switched, "linux"); len(got) != 1 ||
		!strings.Contains(got[0], `assignment 1: group "dc-ml-team@dclab.test" is listed by this host as "dc-ml-team"`) ||
		!strings.Contains(got[0], "use_fully_qualified_names = False") {
		t.Fatalf("qualified-to-short warnings = %q, want the short spelling named", got)
	}
	// GAP-0332: the domain of a seen account group (an SSSD domain realmd
	// does not list) is offered for the short-name hint.
	noteGroupDomains([]string{"dc-okta-users@okta", "wheel"})
	if !slices.Contains(observedGroupDomains.list(), "okta") {
		t.Fatalf("observed group domains = %q, want okta", observedGroupDomains.list())
	}

	// The background pass below runs with this host's rules; Windows looks
	// SIDs up and has no SSSD domain note
	// (TestWindowsUnknownAssignmentChecksQualifiedNamesAndOldSIDs).
	if runtime.GOOS == "windows" {
		return
	}

	// A command does not wait for a slow directory: the pass runs in the
	// background, and it is waited for only briefly the first time.
	prev := profileGroupExists
	t.Cleanup(func() { profileGroupExists = prev })
	release := make(chan struct{})
	profileGroupExists = func(ctx context.Context, name string) (bool, error) {
		<-release
		return exists(ctx, name)
	}
	set := &guardrailProfileSet{assignments: assignments}
	if early := set.unknownGroupWarnings(10 * time.Millisecond); len(early) != 0 {
		t.Fatalf("warnings = %q before the first pass finished", early)
	}
	close(release)
	if late := set.unknownGroupWarnings(2 * time.Second); len(late) != 2 {
		t.Fatalf("warnings = %q after the pass finished, want 2", late)
	}
	// status and verify read /health right after a gateway restart: it
	// waits for the first pass as profile-explain does (GAP-0830).
	slow := make(chan struct{})
	profileGroupExists = func(ctx context.Context, name string) (bool, error) {
		<-slow
		return exists(ctx, name)
	}
	set = &guardrailProfileSet{assignments: assignments}
	time.AfterFunc(50*time.Millisecond, func() { close(slow) })
	if got := set.healthProfileWarnings(); len(got) != 2 {
		t.Fatalf("health warnings = %q right after start, want the 2 profile-explain lists", got)
	}

	// GAP-0229: an SSSD that is offline with a cold cache answers "no such
	// group" for groups that exist. While lookups fail, or the explained
	// account failed to resolve, nothing is warned and no pass is kept; the
	// next pass runs once they work.
	profileGroupExists = func(context.Context, string) (bool, error) { return false, nil }
	set = &guardrailProfileSet{assignments: assignments}
	directoryCacheHealth = func() identityCacheHealth { return identityCacheHealth{Failing: 1} }
	if got := set.unknownGroupWarnings(2 * time.Second); len(got) != 0 {
		t.Fatalf("warnings = %q while directory lookups fail, want none", got)
	}
	directoryCacheHealth = func() identityCacheHealth { return identityCacheHealth{} }
	if got := profileExplainWarnings(set, profileDecision{}, &profileSubject{LookupFailed: true}); len(got) != 0 {
		t.Fatalf("warnings = %q for an account whose lookup failed, want none", got)
	}
	// GAP-0255: the gateway's own lookups work (a local account, or at start
	// before the first failure) but no group of dclab.test is known, Domain
	// Users included: one note, no group reported as renamed or deleted.
	// The note names each assignment and group it cannot confirm (GAP-0928).
	if got := set.unknownGroupWarnings(2 * time.Second); len(got) != 1 || !strings.HasPrefix(got[0], "could not confirm group names written for dclab.test") ||
		strings.Contains(got[0], "SSSD") || !strings.Contains(got[0], `assignment 1: group "dc-rename-me@dclab.test"`) {
		t.Fatalf("warnings = %q while the directory does not answer, want one note naming the groups", got)
	}
	profileGroupExists = func(_ context.Context, name string) (bool, error) { return name == "domain users@dclab.test", nil }
	set = &guardrailProfileSet{assignments: assignments}
	if got := set.unknownGroupWarnings(2 * time.Second); len(got) != 4 {
		t.Fatalf("warnings = %q once the directory answers, want the 4 absent groups", got)
	}
}

func TestWindowsUnknownAssignmentChecksQualifiedNamesAndOldSIDs(t *testing.T) {
	assignments := []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{
		`CORP\renamed-team`, "S-1-5-21-1-2-3-1104", `CORP\active-team`,
	}}}}
	var looked []string
	exists := func(_ context.Context, name string) (bool, error) {
		looked = append(looked, name)
		return name == `CORP\active-team`, nil
	}
	warnings := unknownAssignmentGroupsForOS(context.Background(), assignments, exists, nil, "windows")
	if len(warnings) != 2 || !strings.Contains(warnings[0], "renamed-team") ||
		!strings.Contains(warnings[1], "S-1-5-21-1-2-3-1104") || len(looked) != 3 {
		t.Fatalf("warnings=%q lookups=%q", warnings, looked)
	}
}

func TestUnknownAssignmentGroupsReportsIncompleteCheck(t *testing.T) {
	groups := make([]string, profileGroupCheckMax+1)
	for i := range groups {
		groups[i] = fmt.Sprintf("group-%d", i)
	}
	assignments := []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: groups}}}
	checked := 0
	exists := func(context.Context, string) (bool, error) {
		checked++
		return true, nil
	}
	warnings := unknownAssignmentGroups(context.Background(), assignments, exists, nil)
	if checked != profileGroupCheckMax || len(warnings) != 1 || !strings.Contains(warnings[0], "not checked") {
		t.Fatalf("checked = %d, warnings = %q; want a warning that later groups were not checked", checked, warnings)
	}
}

func TestUnknownAssignmentGroupsNormalizeUnicode(t *testing.T) {
	assignments := []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"dc-cafe\u0301"}}},
	}
	exists := func(_ context.Context, name string) (bool, error) {
		return name == "dc-caf\u00e9", nil
	}
	if warnings := unknownAssignmentGroups(context.Background(), assignments, exists, nil); len(warnings) != 0 {
		t.Fatalf("a matching NFD group was reported unknown: %q", warnings)
	}
}

func TestPerUserWindowsGroupAssignmentsWarn(t *testing.T) {
	assignments := []config.ProfileAssignment{
		{Profile: "team", Match: config.ProfileMatch{Groups: []string{"DOMAIN\\team"}}},
	}
	warnings := perUserWindowsGroupWarnings(assignments)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "groups cannot match") {
		t.Fatalf("warnings = %q", warnings)
	}
}

// TestExplainShowsTheProfileRequestsStillGet pins GAP-0134: explain resolves
// the account's fresh groups, but requests keep the gateway's cached facts
// for up to 15 minutes, so explain reports their age and the profile they
// still get when it differs.
func TestExplainShowsTheProfileRequestsStillGet(t *testing.T) {
	set := &guardrailProfileSet{
		profiles:       map[string]config.DerivedGuardrailProfile{"ml": {Digest: "d1"}, "watch": {Digest: "d2"}},
		assignments:    []config.ProfileAssignment{{Profile: "ml", Match: config.ProfileMatch{Groups: []string{"dc-ml-team@dclab.test"}}}},
		defaultProfile: "watch",
	}
	explained := &profileSubject{UserID: "1201", Groups: []string{"dc-ml-team@dclab.test"}}
	decision := set.match(explained, profileSubjectLookup, "", "")
	now := time.Now()
	prev := cachedDirectoryFacts
	t.Cleanup(func() { cachedDirectoryFacts = prev })
	cached := useridentity.DirectoryFacts{Groups: []string{"dc-devs@dclab.test"}, ResolvedAt: now}
	cachedDirectoryFacts = func(string) (useridentity.DirectoryFacts, time.Time, bool) {
		return cached, now.Add(-7 * time.Minute), true
	}
	view, warning := explainCacheView(set, explained, decision, "", "", now)
	if view["age_seconds"] != 420 || view["refresh_after_seconds"] != 480 || view["profile"] != "watch" || view["differs"] != true ||
		!strings.Contains(warning, "7m0s ago") || !strings.Contains(warning, "within 8m0s") {
		t.Fatalf("view = %v, warning = %q; want 7 minute old facts that still give watch", view, warning)
	}
	cached.Groups = []string{"dc-ml-team@dclab.test"}
	if view, warning := explainCacheView(set, explained, decision, "", "", now); view["differs"] != false || warning != "" {
		t.Fatalf("view = %v, warning = %q; cached facts that agree must not warn", view, warning)
	}
	cachedDirectoryFacts = func(string) (useridentity.DirectoryFacts, time.Time, bool) { return cached, time.Time{}, false }
	if view, _ := explainCacheView(set, explained, decision, "", "", now); view != nil {
		t.Fatalf("view = %v for an account nothing is cached for", view)
	}
}

// After a hot reload, Secure Client decides with the start-time
// configuration, as before the configuration generation (GAP-0140, issue
// #1092); every other profile decides with the live generation.
func TestSecureClientDecidesWithTheStartTimeConfig(t *testing.T) {
	start := &config.Config{DeploymentMode: "managed_enterprise"}
	live := &config.Config{DeploymentMode: "managed_enterprise"}
	api := &APIServer{scannerCfg: start, generationSource: func() *Generation { return &Generation{Config: live} }}
	if got := api.decisionConfig(context.Background()); got != start {
		t.Fatal("Secure Client decided with the reloaded configuration")
	}
	start.DeploymentMode, live.DeploymentMode = "", ""
	if got := api.decisionConfig(context.Background()); got != live {
		t.Fatal("a per-user gateway decided with the start-time configuration")
	}
}

// TestProfileExplainShowsTheSubjectWithoutProfiles pins GAP-0280: the
// documented identity check (`profile explain --user U --json | jq .subject`)
// printed null on an install with no guardrail profiles, because the handler
// answered before any directory lookup.
func TestProfileExplainShowsTheSubjectWithoutProfiles(t *testing.T) {
	prev := profileExplainSubjectLookup
	profileExplainSubjectLookup = func(string) (profileSubject, error) {
		return profileSubject{UserID: "1201", UserName: "alice", Principal: "alice@CORP.EXAMPLE.COM", Groups: []string{"dc-devs@corp.example.com"}}, nil
	}
	t.Cleanup(func() { profileExplainSubjectLookup = prev; liveGuardrailProfiles.Store(nil) })
	liveGuardrailProfiles.Store(nil)
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, &config.Config{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?user=alice", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	rec := httptest.NewRecorder()
	api.handleGuardrailProfileResolve(rec, req)
	var out struct {
		Configured bool           `json:"profiles_configured"`
		Subject    map[string]any `json:"subject"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	if out.Configured || out.Subject["principal"] != "alice@CORP.EXAMPLE.COM" || out.Subject["group_count"] != float64(1) {
		t.Fatalf("explain = %s", rec.Body.String())
	}
}

// TestProfileExplainSaysWhyTheLookupFailed: explain --user for an account the
// OS names but cannot resolve (an Entra user the aad module has not cached)
// reported default_lookup_failed with no lookup_error and no user id.
func TestProfileExplainSaysWhyTheLookupFailed(t *testing.T) {
	previousBlocking := identityLookupBlocking.Load()
	setIdentityLookupBlocking(true)
	t.Cleanup(func() { setIdentityLookupBlocking(previousBlocking) })
	prev := profileExplainSubjectLookup
	profileExplainSubjectLookup = func(string) (profileSubject, error) {
		return profileSubject{UserID: "10259079", UserName: "bob", LookupFailed: true}, fmt.Errorf("uid 10259079: not found")
	}
	t.Cleanup(func() { profileExplainSubjectLookup = prev; liveGuardrailProfiles.Store(nil) })
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"watch": {Mode: "observe"}}
	cfg.Guardrail.DefaultProfile = "watch"
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?user=bob", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	rec := httptest.NewRecorder()
	api.handleGuardrailProfileResolve(rec, req)
	var out struct {
		Match       string         `json:"match"`
		LookupError string         `json:"lookup_error"`
		Subject     map[string]any `json:"subject"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	if out.Match != profileMatchDefaultLookupFailed || !strings.Contains(out.LookupError, "not found") || out.Subject["user_id"] != "10259079" {
		t.Fatalf("explain = %s", rec.Body.String())
	}
}

func TestProfileExplainWarnsUnknownConnectorNames(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict": {Connectors: map[string]config.PerConnectorGuardrailConfig{"claude": {}}},
	}
	set := &guardrailProfileSet{
		base:        cfg,
		assignments: []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Connectors: []string{"claude"}}}},
	}
	warnings := profileExplainWarnings(set, profileDecision{}, &profileSubject{LookupFailed: true})
	if len(warnings) != 2 || !strings.Contains(warnings[0], "profile_assignments[0].match.connectors") ||
		!strings.Contains(warnings[1], `profiles["strict"].connectors`) {
		t.Fatalf("unknown connector warnings = %q", warnings)
	}
}

func TestProfileExplainFlagsUnknownConnectorAndUnverifiedAgent(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"strict": {Mode: "action"}}
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
	api.setGuardrailProfiles(&guardrailProfileSet{base: cfg, profiles: map[string]config.DerivedGuardrailProfile{}, defaultProfile: "strict"})
	t.Cleanup(func() { api.setGuardrailProfiles(nil) })
	for _, check := range []struct {
		query string
		code  int
		want  string
	}{
		{"?connector=claudcode", http.StatusBadRequest, "valid connectors: amp, antigravity, claudecode, codex"},
		{"?user=not-a-real-account&connector=codex&agent=agt-0000000000000000", http.StatusOK, "not verified against a host identity record"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve"+check.query, nil)
		req.RemoteAddr = "127.0.0.1:40000"
		response := httptest.NewRecorder()
		api.handleGuardrailProfileResolve(response, req)
		if response.Code != check.code || !strings.Contains(response.Body.String(), check.want) {
			t.Fatalf("%s = %d %s", check.query, response.Code, response.Body.String())
		}
	}
}

func TestProfileExplainNamesHookIdentityCacheWindow(t *testing.T) {
	previous := profileExplainSubjectLookup
	profileExplainSubjectLookup = func(string) (profileSubject, error) {
		return profileSubject{UserID: "1201", UserName: "alice", Groups: []string{"team"}}, nil
	}
	t.Cleanup(func() { profileExplainSubjectLookup = previous })
	cfg := &config.Config{}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"strict": {Mode: "action"}}
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
	api.setGuardrailProfiles(&guardrailProfileSet{base: cfg, profiles: map[string]config.DerivedGuardrailProfile{},
		assignments: []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"team"}}}}})
	t.Cleanup(func() { api.setGuardrailProfiles(nil) })
	req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?user=alice", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	response := httptest.NewRecorder()
	api.handleGuardrailProfileResolve(response, req)
	if !strings.Contains(response.Body.String(), "previous profile for up to 15 minutes") {
		t.Fatalf("explain omitted hook cache window: %s", response.Body.String())
	}
}

func TestProfileExplainWarnsBareGroupMayMatchAnotherDomain(t *testing.T) {
	note := shortNameGroupNote(profileDecision{Match: profileMatchGroup, MatchedGroup: "dc-ew-twin", Assignment: 1})
	if !strings.Contains(note, "same-named group in another domain") || runtime.GOOS != "windows" && (strings.Contains(note, "SID") || strings.Contains(note, `DOMAIN\name`)) {
		t.Fatalf("bare group warning = %q", note)
	}
	if qualified := shortNameGroupNote(profileDecision{Match: profileMatchGroup, MatchedGroup: `DCLAB\dc-ew-twin`, Assignment: 1}); qualified != "" {
		t.Fatalf("qualified group warning = %q", qualified)
	}
}

// A DOMAIN\\user assignment uses the account domain the directory verified,
// not the first label of an unrelated DNS realm. winbind with use default
// domain = yes names the account bare and confirms its NetBIOS domain; an
// account named DCLAB\\dcad-bob that no directory confirms (nslcd, a plain
// LDAP domain of SSSD) is selected by its uid only (GAP-0456, GAP-0814).
func TestProfileQualifiedUserMatchesVerifiedAccountDomain(t *testing.T) {
	previous := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(previous) })
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "1201", UserName: `CONTOSO\alice`,
		Directory: useridentity.DirectoryFacts{
			Domain: "corp.contoso.com", AccountDomain: "CONTOSO", Principal: "alice@CORP.CONTOSO.COM",
			ResolvedAt: time.Now(),
		},
	}, true)
	if !userEntryMatches(&subject, `CONTOSO\alice`) {
		t.Fatal("the verified NetBIOS account domain did not match")
	}
	if userEntryMatches(&subject, `CORP\alice`) {
		t.Fatal("a DNS first label selected another account domain")
	}
	winbind := profileSubjectFromVerified(VerifiedSubject{UserID: "2003913", UserName: "dcad-eli7",
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceWinbind, Domain: "dclab.test", AccountDomain: "DCLAB",
			ResolvedAt: time.Now()}}, true)
	if !userEntryMatches(&winbind, `DCLAB\dcad-eli7`) || userEntryMatches(&winbind, `OTHER\dcad-eli7`) {
		t.Fatal("a bare winbind name must match DCLAB\\user of its confirmed NetBIOS domain only")
	}
	for _, source := range []string{useridentity.SourceNSSLDAP, useridentity.SourceSSSD} {
		namesake := profileSubjectFromVerified(VerifiedSubject{UserID: "72001", UserName: `DCLAB\dcad-bob`,
			Directory: useridentity.DirectoryFacts{Source: source, ResolvedAt: time.Now()}}, true)
		if runtime.GOOS != "windows" && (userEntryMatches(&namesake, `DCLAB\dcad-bob`) || userEntryMatches(&namesake, "dcad-bob") ||
			!userEntryMatches(&namesake, "72001")) {
			t.Fatalf("%s account named DCLAB\\dcad-bob without a confirmed domain must match by uid only: %+v", source, namesake)
		}
	}
	// macOS: the guardian record carries the NetBIOS domain the AD node
	// names, so DCLAB\user matches the mobile account (GAP-0635).
	mac := profileSubjectFromVerified(VerifiedSubject{
		UserID: "2092147702", UserName: "dcad-w2i-c",
		Directory: mergeSpoolFacts(useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, ResolvedAt: time.Now()},
			enterprisehooks.IdentitySpoolRecord{AccountDomain: "DCLAB", Facts: useridentity.DirectoryFacts{
				Directory: useridentity.DirectoryActiveDirectory, Domain: "dclab.test", Principal: "dcad-w2i-c@dclab.test",
			}}),
	}, true)
	if !userEntryMatches(&mac, "DCLAB\\dcad-w2i-c") || userEntryMatches(&mac, "OTHERDOM\\dcad-w2i-c") {
		t.Fatalf("macOS AD subject %+v: DCLAB\\user must match and OTHERDOM\\user must not", mac)
	}
	// Windows: a local account by COMPUTER\user or .\user, an Entra ID
	// account by AzureAD\name (GAP-0636, GAP-0676); .\ never names an Entra
	// or domain account.
	local := profileSubjectFromVerified(VerifiedSubject{UserID: "S-1-5-21-9-9-9-1001", UserName: "dcw-ew1",
		Directory: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, AccountDomain: "WS01", ResolvedAt: time.Now()}}, true)
	entra := profileSubjectFromVerified(VerifiedSubject{UserID: "S-1-12-1-1-2-3-4", UserName: "EntraAlice",
		Directory: useridentity.DirectoryFacts{Directory: useridentity.DirectoryEntraID, AccountDomain: "AzureAD",
			Domain: "contoso.example", UPN: "alice@contoso.example", ResolvedAt: time.Now()}}, true)
	if !userEntryMatches(&local, "WS01\\dcw-ew1") || !userEntryMatches(&local, ".\\dcw-ew1") ||
		!userEntryMatches(&entra, "AzureAD\\EntraAlice") || userEntryMatches(&entra, ".\\EntraAlice") {
		t.Fatal("COMPUTER\\user and .\\user must select the local account, AzureAD\\name the Entra ID account, and .\\ no Entra account")
	}
}

// Windows LSA facts do not establish group membership until the guardian's
// current identity record supplies its token groups.
func TestProfileWindowsAwaitingSpoolUsesLookupFailed(t *testing.T) {
	previous := currentIdentitySpoolDir()
	setIdentitySpoolDir(t.TempDir())
	t.Cleanup(func() { setIdentitySpoolDir(previous) })
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "S-1-5-21-1-2-3-1001", UserName: "alice",
		Directory: useridentity.DirectoryFacts{
			Source: useridentity.SourceWindowsLSA, Domain: "corp.example.com",
			Directory: useridentity.DirectoryActiveDirectory, ResolvedAt: time.Now(),
		},
	}, true)
	set := &guardrailProfileSet{
		defaultProfile: "watch",
		assignments: []config.ProfileAssignment{
			{Profile: "strict", Match: config.ProfileMatch{Groups: []string{`CORP\\Contractors`}}},
			{Profile: "tooling", Match: config.ProfileMatch{Connectors: []string{"codex"}}},
		},
	}
	if got := set.matchUncached(&subject, profileSubjectVerified, "codex", ""); got.Match != profileMatchDefaultLookupFailed {
		t.Fatalf("missing spool groups selected %+v", got)
	}
}

// Explain and its live-cache view keep agent matches when the configuration
// never requires a directory lookup.
func TestProfileExplainKeepsAgentWhenLookupFails(t *testing.T) {
	previousBlocking := identityLookupBlocking.Load()
	setIdentityLookupBlocking(false)
	t.Cleanup(func() { setIdentityLookupBlocking(previousBlocking) })
	prevAccount, prevFacts := profileExplainAccount, profileExplainDirectoryFacts
	prevCached, prevFailure := cachedDirectoryFacts, cachedDirectoryFailure
	t.Cleanup(func() {
		profileExplainAccount, profileExplainDirectoryFacts = prevAccount, prevFacts
		cachedDirectoryFacts, cachedDirectoryFailure = prevCached, prevFailure
	})
	profileExplainAccount = func(string) (string, string, error) { return "1201", "alice", nil }
	profileExplainDirectoryFacts = func(string) (useridentity.DirectoryFacts, error) {
		return useridentity.DirectoryFacts{}, errors.New("directory unavailable")
	}
	cachedDirectoryFacts = func(string) (useridentity.DirectoryFacts, time.Time, bool) {
		return useridentity.DirectoryFacts{}, time.Time{}, false
	}
	cachedDirectoryFailure = func(string) (time.Time, string, bool) {
		return time.Now().Add(-time.Minute), "directory unavailable", true
	}
	subject, err := lookupDirectoryProfileSubject("alice")
	if err != nil {
		t.Fatal(err)
	}
	set := &guardrailProfileSet{
		defaultProfile: "watch",
		assignments: []config.ProfileAssignment{
			{Profile: "tooling", Match: config.ProfileMatch{Agents: []string{"agt-0123456789abcdef"}}},
		},
	}
	decision := set.match(&subject, profileSubjectLookup, "", "agt-0123456789abcdef")
	if decision.Match != profileMatchAgent {
		t.Fatalf("explain selected %+v", decision)
	}
	view, _ := explainCacheView(set, &subject, decision, "", "agt-0123456789abcdef", time.Now())
	if view == nil || view["match"] != profileMatchAgent {
		t.Fatalf("cache view = %v", view)
	}
}

// TestUnconfirmedQualifiedNameMatchesNoUsersEntry pins GAP-0596: with short
// SSSD names a plain LDAP domain may name an account by an e-mail address in
// the joined domain (dcad-bob@dclab.test). Its facts confirm no domain, so no
// users entry selects it by name: its bare part is the AD dcad-bob's name and
// its whole name his principal. Its uid still selects it, and the AD account,
// whose domain its facts confirm, keeps matching by name and principal.
func TestUnconfirmedQualifiedNameMatchesNoUsersEntry(t *testing.T) {
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(false) })
	now := time.Now()
	ldap := profileSubjectFromVerified(VerifiedSubject{UserID: "62001", UserName: "dcad-bob@dclab.test",
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Directory: useridentity.DirectoryLDAP, ResolvedAt: now}}, true)
	ad := profileSubjectFromVerified(VerifiedSubject{UserID: "94401104", UserName: "dcad-bob",
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Domain: "dclab.test", Realm: "DCLAB.TEST",
			Principal: "dcad-bob@dclab.test", ResolvedAt: now}}, true)
	matches := func(subject profileSubject, entry string) bool {
		_, _, ok := assignmentMatches(config.ProfileMatch{Users: []string{entry}}, &subject, &subjectGroups{}, true, "", "")
		return ok
	}
	for entry, want := range map[string]bool{"dcad-bob": false, "dcad-bob@dclab.test": false, "DCLAB.TEST\\dcad-bob": false, "62001": true} {
		if matches(ldap, entry) != want {
			t.Errorf("users [%s] on the LDAP account %+v: match %v, want %v", entry, ldap, !want, want)
		}
	}
	for _, entry := range []string{"dcad-bob", "dcad-bob@DCLAB.TEST", "94401104"} {
		if !matches(ad, entry) {
			t.Errorf("users [%s] does not select the AD account %+v", entry, ad)
		}
	}
}

// A verified UID is sufficient for a users assignment during a directory outage.
func TestVerifiedUIDAssignmentSurvivesDirectoryFailure(t *testing.T) {
	set := &guardrailProfileSet{
		defaultProfile: "watch",
		profiles: map[string]config.DerivedGuardrailProfile{
			"strict": {}, "watch": {},
		},
		assignments: []config.ProfileAssignment{
			{Profile: "watch", Match: config.ProfileMatch{Users: []string{"1002"}, Groups: []string{"ops"}}},
			{Profile: "strict", Match: config.ProfileMatch{Users: []string{"1001"}}},
		},
	}
	subject := &profileSubject{UserID: "1001", LookupFailed: true}
	if got := set.matchUncached(subject, profileSubjectVerified, "codex", ""); got.Name != "strict" || got.Match != profileMatchUser {
		t.Fatalf("verified UID selected %+v; want strict user assignment", got)
	}
}
