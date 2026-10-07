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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

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
	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")
	raw := func(strict string) []byte {
		return []byte(fmt.Sprintf(
			"config_version: 8\ndata_dir: %q\ngateway:\n  config_reload:\n    mode: hot\nguardrail:\n  enabled: true\n  rule_pack_dir: \"\"\n  profiles:\n    strict: %s\n    watch: {mode: observe}\n  profile_assignments:\n    - {profile: strict, match: {users: [\"1001\"]}}\n  default_profile: watch\nobservability: {}\n",
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
	prevAccount, prevFacts := profileExplainAccount, profileExplainDirectoryFacts
	t.Cleanup(func() { profileExplainAccount, profileExplainDirectoryFacts = prevAccount, prevFacts })
	profileExplainAccount = func(string) (string, string, bool) { return "94401116", "dcad-manygroups@dclab.test", true }
	profileExplainDirectoryFacts = func(string) (useridentity.DirectoryFacts, error) {
		return useridentity.DirectoryFacts{}, errors.New("in 3000 groups, more than the 2048 DefenseClaw names")
	}
	subject, err := lookupDirectoryProfileSubject("dcad-manygroups")
	if err != nil || !subject.LookupFailed || !strings.Contains(subject.LookupError, "3000 groups") || len(subject.Groups) != 0 {
		t.Fatalf("subject = %+v, %v; want a failed lookup that names its reason and has no groups", subject, err)
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
// SIDs are not.
func TestUnknownAssignmentGroupsAreReported(t *testing.T) {
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
	got := unknownAssignmentGroups(context.Background(), assignments, exists)
	if len(got) != 2 || !strings.HasPrefix(got[0], `assignment 1: group "dc-rename-me@dclab.test" is not known`) ||
		!strings.HasPrefix(got[1], `assignment 2: group "DC-RENAME-ME@dclab.test" is not known`) {
		t.Fatalf("warnings = %q, want the renamed group in assignments 1 and 2 only", got)
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

	// GAP-0229: an SSSD that is offline with a cold cache answers "no such
	// group" for groups that exist. While lookups fail, or the explained
	// account failed to resolve, nothing is warned and no pass is kept; the
	// next pass runs once they work.
	previousHealth := directoryCacheHealth
	t.Cleanup(func() { directoryCacheHealth = previousHealth })
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
	if got := set.unknownGroupWarnings(2 * time.Second); len(got) != 4 {
		t.Fatalf("warnings = %q once the directory answers, want the 4 absent groups", got)
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

// TestProfileExplainSaysWhyTheLookupFailed: explain --user for an account the
// OS names but cannot resolve (an Entra user the aad module has not cached)
// reported default_lookup_failed with no lookup_error and no user id.
func TestProfileExplainSaysWhyTheLookupFailed(t *testing.T) {
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
