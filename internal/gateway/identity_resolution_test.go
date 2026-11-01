// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// identityTestPlatform is one platform's way of naming an account and its
// strict group: the ID kind, the directory providers that answer for it,
// and how a group entry is written there.
type identityTestPlatform struct {
	os        string
	id        string
	kind      string
	name      string
	group     string
	providers []identityTestProvider
}

type identityTestProvider struct {
	source    string
	directory useridentity.Directory
	domain    string
	sid       string
	// record is a macOS account's local node record
	// (DirectoryFacts.AccountRecord).
	record string
}

// keyed reports whether a proven account of the provider names its
// incarnation: by a SID, a macOS local node record, or its Windows SID. An
// account no token names keeps nothing proven (review loop 3).
func (provider identityTestProvider) keyed(p identityTestPlatform) bool {
	return provider.sid != "" || provider.record != "" || p.kind == useridentity.KindWindowsSID
}

var identityTestPlatforms = []identityTestPlatform{
	{os: "linux", id: "70001", kind: useridentity.KindPOSIXUID, name: "alice", group: "eng-strict", providers: []identityTestProvider{
		{source: useridentity.SourceNSSFiles, directory: useridentity.DirectoryLocal},
		{source: useridentity.SourceSSSD, directory: useridentity.DirectoryActiveDirectory, domain: "corp.example", sid: "S-1-5-21-1-2-3-1601"},
		{source: useridentity.SourceNSSLDAP, directory: useridentity.DirectoryLDAP, domain: "corp.example"},
		{source: useridentity.SourceWinbind, directory: useridentity.DirectoryActiveDirectory, domain: "corp.example", sid: "S-1-5-21-1-2-3-1602"},
	}},
	{os: "darwin", id: "501", kind: useridentity.KindPOSIXUID, name: "alice", group: "eng-strict", providers: []identityTestProvider{
		// A mobile account (a local node record), a local account, and a
		// network account with no local record.
		{source: useridentity.SourceMacOSOpenDirectory, directory: useridentity.DirectoryActiveDirectory, domain: "corp.example", record: "record:0a1b2c"},
		{source: useridentity.SourceMacOSOpenDirectory, directory: useridentity.DirectoryLocal, record: "record:3d4e5f"},
		{source: useridentity.SourceMacOSOpenDirectory, directory: useridentity.DirectoryActiveDirectory, domain: "corp.example"},
	}},
	{os: "windows", id: "S-1-5-21-9-9-9-1105", kind: useridentity.KindWindowsSID, name: `CORP\alice`, group: "S-1-5-21-9-9-9-2201",
		providers: []identityTestProvider{
			{source: useridentity.SourceWindowsLSA, directory: useridentity.DirectoryActiveDirectory, domain: "corp.example"},
			{source: useridentity.SourceWindowsIdentityStore, directory: useridentity.DirectoryEntraID, domain: "corp.example"},
		}},
}

// The proof states of one pass, as the verified subject carries them.
const (
	stateProven         = "proven"
	stateStale          = "stale"
	stateUnknown        = "unknown"
	stateFailed         = "failed"
	stateGroupsUnknown  = "groups-unknown"
	stateGroupsUnproven = "groups-unconfirmed"
)

func identityTestSubject(p identityTestPlatform, provider identityTestProvider, state string, inGroup bool) profileSubject {
	facts := useridentity.DirectoryFacts{
		Directory: provider.directory, Source: provider.source, Domain: provider.domain,
		Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(), AccountSID: provider.sid,
		AccountRecord: provider.record,
	}
	if inGroup {
		facts.Groups = []string{p.group, "everyone"}
	} else {
		facts.Groups = []string{"everyone"}
	}
	switch state {
	case stateUnknown, stateFailed:
		facts = useridentity.DirectoryFacts{}
	case stateGroupsUnknown:
		facts.Groups, facts.GroupsPartial = nil, true
	case stateGroupsUnproven:
		facts.Groups = []string{"7000", "everyone"}
		facts.UnconfirmedGroups = []string{"7000"}
	}
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: p.id, IDKind: p.kind, UserName: p.name, Directory: facts,
		Source: subjectSourcePeerCredentials}, true)
	switch state {
	case stateStale:
		subject.cachedFactsAge = 20 * time.Minute
	case stateFailed:
		subject.LookupError = "unixidentity: uid " + p.id + " is held by more than one account"
	}
	return subject
}

func identityTestSet(t *testing.T, p identityTestPlatform, defaultProfile string, assignments ...config.ProfileAssignment) *guardrailProfileSet {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict":  {Mode: "action", BlockAt: "LOW"},
		"tooling": {Mode: "action", BlockAt: "HIGH"},
		"watch":   {Mode: "observe"},
	}
	cfg.Guardrail.ProfileAssignments = assignments
	cfg.Guardrail.DefaultProfile = defaultProfile
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil || set == nil {
		t.Fatalf("profile set: %v", err)
	}
	return set
}

// GAP-0522: a decision that depends on a missing OS identity fact must
// refuse with that fact named, including a guardian UPN on macOS. A missing
// fact unrelated to any assignment does not make the decision uncertain.
func TestGAP0522UncertainIdentityNamesTheMissingFact(t *testing.T) {
	p := identityTestPlatforms[1]
	base := identityTestSubject(p, p.providers[1], stateProven, false)
	const legacy = "agt-00000000000000aa"
	for _, tc := range []struct {
		name       string
		subject    profileSubject
		assignment config.ProfileMatch
		unresolved func(string) bool
		fact       string
	}{
		{name: "macOS UPN", subject: func() profileSubject {
			s := base
			s.upnUnproven = true
			return s
		}(), assignment: config.ProfileMatch{Users: []string{"dcm-std1@example.test"}}, fact: "UPN"},
		{name: "account", subject: profileSubject{UserID: p.id, IDKind: p.kind, LookupFailed: true},
			assignment: config.ProfileMatch{Users: []string{"dcm-std1"}}, fact: "account"},
		{name: "groups", subject: func() profileSubject {
			s := base
			s.GroupsUnknown = true
			return s
		}(), assignment: config.ProfileMatch{Groups: []string{"engineering"}}, fact: "group"},
		{name: "agent", subject: base, assignment: config.ProfileMatch{Agents: []string{legacy}},
			unresolved: func(entry string) bool { return entry == legacy }, fact: "agent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := identityTestSet(t, p, "watch", config.ProfileAssignment{Profile: "strict", Match: tc.assignment})
			got := set.selectProfile(&tc.subject, resolveIdentity(&tc.subject, tc.unresolved), profileSubjectVerified, "hermes", nil, profilePathAny, "agt-00000000000000bb")
			if got.Refused == "" || !strings.Contains(got.Refused, tc.fact) ||
				strings.Contains(got.Refused, ": ,") || !strings.Contains(got.Refused, "explain --user 501 --connector hermes") {
				t.Fatalf("uncertain %s decision: %+v", tc.name, got)
			}
			if name, present := guardrailProfileTelemetryFromDecision(got).Name.Get(); present {
				t.Fatalf("uncertain %s decision recorded inferred profile %q", tc.name, name)
			}
			if tc.name == "macOS UPN" {
				api := &APIServer{}
				api.guardrailProfiles.set.Store(set)
				ctx := context.WithValue(t.Context(), resolvedGuardrailProfileKey{}, &resolvedGuardrailProfile{decision: got, set: set})
				w := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", nil).WithContext(ctx)
				if !api.refuseProfileInspect(w, r, "/api/v1/inspect/tool", "inspect-tool-block", "tool") ||
					w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"action":"block"`) ||
					!strings.Contains(w.Body.String(), "UPN is unconfirmed") {
					t.Fatalf("inspect refusal = %d %s", w.Code, w.Body.String())
				}
				if response, refused := api.refuseProfileHook(ctx, api.hookProfileForConnector("hermes"), "hermes",
					agentHookRequest{ConnectorName: "hermes", HookEventName: "pre_tool_call"}, nil, nil); !refused ||
					response.Action != "block" || response.Reason != got.Refused {
					t.Fatalf("hook refusal = %+v, %v", response, refused)
				}
				w = httptest.NewRecorder()
				if !refuseProfileProxy(w, r) || w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "UPN is unconfirmed") {
					t.Fatalf("proxy refusal = %d %s", w.Code, w.Body.String())
				}
				w = httptest.NewRecorder()
				sandboxRefuseView(w, got)
				if w.Code < http.StatusBadRequest || !strings.Contains(w.Body.String(), "UPN is unconfirmed") ||
					strings.Contains(w.Body.String(), "strict") || strings.Contains(w.Body.String(), "watch") {
					t.Fatalf("sandbox refusal = %d %s", w.Code, w.Body.String())
				}
			}
		})
	}
	base.upnUnproven = true
	set := identityTestSet(t, p, "watch", config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"engineering"}}})
	if got := set.match(&base, profileSubjectVerified, "hermes", ""); got.Refused != "" {
		t.Fatalf("unrelated UPN uncertainty refused a proven group decision: %+v", got)
	}

	// An unproven fact refuses only when it could change the profile: an
	// assignment that may apply but gives the profile the proven facts
	// already select decides the request.
	unknownGroups := identityTestSubject(p, p.providers[1], stateGroupsUnknown, false)
	byGroup := config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}}
	byUID := config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{p.id}}}
	for _, tc := range []struct {
		name        string
		def         string
		assignments []config.ProfileAssignment
		want        string
		refused     bool
	}{
		{name: "the default gives the same profile", def: "strict", assignments: []config.ProfileAssignment{byGroup}, want: "strict"},
		{name: "a proven match gives the same profile", def: "watch", assignments: []config.ProfileAssignment{byUID, byGroup}, want: "strict"},
		{name: "the default differs", def: "watch", assignments: []config.ProfileAssignment{byGroup}, refused: true},
		{name: "a proven match differs", def: "strict", assignments: []config.ProfileAssignment{
			{Profile: "tooling", Match: config.ProfileMatch{Users: []string{p.id}}}, byGroup}, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := identityTestSet(t, p, tc.def, tc.assignments...)
			got := set.selectProfile(&unknownGroups, resolveIdentity(&unknownGroups, nil), profileSubjectVerified, "hermes", nil, profilePathAny, "")
			if tc.refused {
				if got.Refused == "" || !strings.Contains(got.Refused, "group membership is unconfirmed") {
					t.Fatalf("%+v; want a refusal naming the group fact", got)
				}
				return
			}
			if got.Refused != "" || got.Name != tc.want {
				t.Fatalf("%+v; want %s, not refused", got, tc.want)
			}
		})
	}
}

// Process credentials prove groups even when the holder's account name is
// unproven. An uncertain weaker named-user assignment cannot change an
// already proven stricter group decision, regardless of assignment order.
func TestProvenStrictGroupCoversUncertainWeakerNamedUser(t *testing.T) {
	p := identityTestPlatforms[0]
	subject := identityTestSubject(p, p.providers[0], stateProven, true)
	subject.holderUnproven = true
	group := config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}}
	name := config.ProfileAssignment{Profile: "watch", Match: config.ProfileMatch{Users: []string{p.name}}}
	for _, assignments := range [][]config.ProfileAssignment{{group, name}, {name, group}} {
		set := identityTestSet(t, p, "watch", assignments...)
		got := set.match(&subject, profileSubjectVerified, "codex", "")
		if got.Name != "strict" || got.Match != profileMatchGroup || got.Refused != "" || len(got.Unproven) != 0 {
			t.Fatalf("assignments %+v: %+v; want proven strict group", assignments, got)
		}
	}
	// If the uncertain assignment enforces something the proven one does
	// not, only the account fact must be named in the refusal.
	set := identityTestSet(t, p, "watch",
		config.ProfileAssignment{Profile: "tooling", Match: group.Match},
		config.ProfileAssignment{Profile: "strict", Match: name.Match})
	got := set.match(&subject, profileSubjectVerified, "codex", "")
	if !slices.Equal(got.Unproven, []string{"account:unknown"}) || !strings.Contains(got.Refused, "account holder is unconfirmed") {
		t.Fatalf("uncertain stronger user assignment = %+v; want account-only refusal", got)
	}
}

// A proven meet has the sandbox floor of every member. An unproven account
// name cannot change that decision when its sandbox floor is already covered,
// even when both the meet and the uncertain profile carry sandbox settings.
func TestProvenMeetCoversUncertainSandboxProfile(t *testing.T) {
	p := identityTestPlatforms[0]
	subject := identityTestSubject(p, p.providers[0], stateProven, true)
	subject.holderUnproven = true
	group := config.ProfileAssignment{Profile: "sandboxed", Match: config.ProfileMatch{Groups: []string{p.group}}}
	uid := config.ProfileAssignment{Profile: "low", Match: config.ProfileMatch{Users: []string{p.id}}}
	unknown := config.ProfileAssignment{Profile: "weaker", Match: config.ProfileMatch{Users: []string{p.name}}}
	for _, assignments := range [][]config.ProfileAssignment{{group, uid, unknown}, {unknown, uid, group}} {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "observe"
		cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
			"sandboxed": {Mode: "action", BlockAt: "HIGH", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex", "claudecode"}}},
			"low":       {Mode: "action", BlockAt: "LOW"},
			"weaker":    {Mode: "observe", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}},
			"stronger":  {Mode: "observe", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex", "claudecode", "hermes"}}},
		}
		cfg.Guardrail.DefaultProfile = "weaker"
		cfg.Guardrail.ProfileAssignments = assignments
		set := newGuardrailProfileSetFor(t, cfg)
		got := set.match(&subject, profileSubjectVerified, "codex", "")
		want := config.ProfileMeetName([]string{"low", "sandboxed"})
		if got.Name != want || got.Refused != "" || len(got.Unproven) != 0 {
			t.Fatalf("assignments %+v: %+v; want proven meet %s without refusal", assignments, got, want)
		}
		derived, ok := set.derivedProfile(got.Name)
		if !ok || resolveThresholds(derived.Config, "codex").Block != "LOW" ||
			!slices.Contains(derived.Sandbox.RequiredFor, "claudecode") {
			t.Fatalf("meet %+v; want the proven block and sandbox floors", derived)
		}
		cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{group, uid,
			{Profile: "stronger", Match: unknown.Match}}
		set = newGuardrailProfileSetFor(t, cfg)
		got = set.match(&subject, profileSubjectVerified, "codex", "")
		if !slices.Equal(got.Unproven, []string{"account:unknown"}) ||
			!strings.Contains(got.Refused, "account holder is unconfirmed") {
			t.Fatalf("uncertain stronger sandbox assignment = %+v; want account-only refusal", got)
		}
	}
	// The same floor rule applies when one proven assignment selected the
	// stricter sandbox profile without needing a combined profile.
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"sandboxed": {Mode: "action", BlockAt: "LOW", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex", "claudecode"}}},
		"weaker":    {Mode: "observe", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}},
	}
	cfg.Guardrail.DefaultProfile = "weaker"
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{group, unknown}
	set := newGuardrailProfileSetFor(t, cfg)
	got := set.match(&subject, profileSubjectVerified, "codex", "")
	if got.Name != "sandboxed" || got.Refused != "" || len(got.Unproven) != 0 {
		t.Fatalf("proven sandbox profile = %+v; want sandboxed without refusal", got)
	}
}

// A proven meet already enforces each member's pack. An unconfirmed account
// name that repeats a proven member cannot change the decision, even when
// the other proven member selected a different pack.
func TestProvenMeetCoversUncertainDuplicateMemberWithDifferentPacks(t *testing.T) {
	p := identityTestPlatforms[0]
	subject := identityTestSubject(p, p.providers[0], stateProven, true)
	subject.holderUnproven = true
	root := t.TempDir()
	aDir, bDir, cDir := filepath.Join(root, "a"), filepath.Join(root, "b"), filepath.Join(root, "c")
	writeRulePackFixtureFile(t, aDir, "rules/a.yaml", `version: 1
category: secret
rules:
  - id: MEET-DUPLICATE-A
    pattern: "meet_duplicate_a"
    title: first member
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
	writeRulePackFixtureFile(t, bDir, "rules/b.yaml", `version: 1
category: secret
rules:
  - id: MEET-DUPLICATE-B
    pattern: "meet_duplicate_b"
    title: second member
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
	writeRulePackFixtureFile(t, cDir, "rules/c.yaml", `version: 1
category: secret
rules:
  - id: MEET-DUPLICATE-C
    pattern: "meet_duplicate_c"
    title: third profile
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
	group := config.ProfileAssignment{Profile: "a", Match: config.ProfileMatch{Groups: []string{p.group}}}
	uid := config.ProfileAssignment{Profile: "b", Match: config.ProfileMatch{Users: []string{p.id}}}
	for _, member := range []string{"a", "b"} {
		unknown := config.ProfileAssignment{Profile: member, Match: config.ProfileMatch{Users: []string{p.name}}}
		for _, assignments := range [][]config.ProfileAssignment{{group, uid, unknown}, {unknown, uid, group}} {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "observe"
			cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
				"a": {Mode: "action", BlockAt: "HIGH", RulePackDir: aDir},
				"b": {Mode: "action", BlockAt: "HIGH", RulePackDir: bDir},
				"c": {Mode: "action", BlockAt: "HIGH", RulePackDir: cDir},
			}
			cfg.Guardrail.ProfileAssignments = assignments
			set := newGuardrailProfileSetFor(t, cfg)
			got := set.match(&subject, profileSubjectVerified, "codex", "")
			want := config.ProfileMeetName([]string{"a", "b"})
			if got.Name != want || got.Refused != "" || len(got.Unproven) != 0 {
				t.Fatalf("uncertain duplicate %s, assignments %+v: %+v; want proven meet %s", member, assignments, got, want)
			}
		}
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"a": {Mode: "action", BlockAt: "HIGH", RulePackDir: aDir},
		"b": {Mode: "action", BlockAt: "HIGH", RulePackDir: bDir},
		"c": {Mode: "action", BlockAt: "HIGH", RulePackDir: cDir},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{group, uid,
		{Profile: "c", Match: config.ProfileMatch{Users: []string{p.name}}}}
	got := newGuardrailProfileSetFor(t, cfg).match(&subject, profileSubjectVerified, "codex", "")
	if got.Refused == "" || !slices.Contains(got.Unproven, "account:unknown") {
		t.Fatalf("uncertain different pack = %+v; want account-holder refusal", got)
	}
}

// Without a proven assignment, an uncertain profile needs its account fact
// only when it could change enforcement on the request's path. Two observe
// profiles with different names make the same hook decision.
func TestUncertainObserveProfileUsesDefaultWithoutProvenAssignment(t *testing.T) {
	stubProfileSources(t)
	p := identityTestPlatforms[0]
	subject := identityTestSubject(p, p.providers[0], stateProven, false)
	subject.holderUnproven = true
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "codex"
	cfg.Codex.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"watch": {Mode: "observe"}, "other-watch": {Mode: "observe"},
	}
	cfg.Guardrail.DefaultProfile = "watch"
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "other-watch", Match: config.ProfileMatch{Users: []string{p.name}}},
	}
	set := newGuardrailProfileSetFor(t, cfg)
	for _, path := range []profilePath{profilePathHook, profilePathInspect} {
		got := set.selectProfile(&subject, resolveIdentity(&subject, nil), profileSubjectVerified, "codex", nil, path, "")
		if got.Name != "watch" || got.Refused != "" {
			t.Errorf("observe on path %d = %+v; want unrefused default", path, got)
		}
	}
	pathless := set.selectProfile(&subject, resolveIdentity(&subject, nil), profileSubjectVerified, "codex", nil, profilePathAny, "")
	if pathless.Refused == "" {
		t.Fatalf("pathless selection = %+v; want proof before naming another profile", pathless)
	}

	// An inspect-only uncertain profile also cannot change the hook decision,
	// even though its unconfirmed account would matter to an inspect request.
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Profiles["other-watch"] = config.GuardrailProfile{}
	inspectOnly := newGuardrailProfileSetFor(t, cfg)
	if configBlocksOn(inspectOnly.profileConfig("other-watch"), "codex", profilePathHook) ||
		!configBlocksOn(inspectOnly.profileConfig("other-watch"), "codex", profilePathInspect) {
		t.Fatal("fixture: uncertain profile must observe hooks and act on inspection")
	}
	if got := inspectOnly.selectProfile(&subject, resolveIdentity(&subject, nil), profileSubjectVerified, "codex", nil, profilePathHook, ""); got.Name != "watch" || got.Refused != "" {
		t.Errorf("inspect-only uncertain profile on hook = %+v; want unrefused default", got)
	}
	if got := inspectOnly.selectProfile(&subject, resolveIdentity(&subject, nil), profileSubjectVerified, "codex", nil, profilePathInspect, ""); got.Refused == "" {
		t.Errorf("inspect-only uncertain profile on inspect = %+v; want account proof", got)
	}

	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, subject)
	for _, source := range []*guardrailProfileSet{set, inspectOnly} {
		api.guardrailProfiles.set.Store(source)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(`{"session_id":"observe-session","hook_event_name":"UserPromptSubmit","prompt":"echo hi"}`)).WithContext(ctx)
		setTestCodexHookBinding(req, "UserPromptSubmit", defaultTestCodexHookContract)
		rec := httptest.NewRecorder()
		api.handleAgentHook("codex").ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"action":"allow"`) || strings.Contains(rec.Body.String(), "refused this request") {
			t.Fatalf("observe hook = %d %s; want allow without identity refusal", rec.Code, rec.Body.String())
		}
	}

	// A different name remains relevant when its mode can block this hook.
	cfg.Guardrail.Mode = "observe"
	cfg.Codex.Mode = ""
	cfg.Guardrail.Profiles["other-watch"] = config.GuardrailProfile{Mode: "action"}
	acting := newGuardrailProfileSetFor(t, cfg)
	if !configBlocksOn(acting.profileConfig("other-watch"), "codex", profilePathHook) {
		t.Fatal("fixture: uncertain profile does not act on the hook")
	}
	got := acting.selectProfile(&subject, resolveIdentity(&subject, nil), profileSubjectVerified, "codex", nil, profilePathHook, "")
	if !slices.Equal(got.Unproven, []string{"account:unknown"}) || !strings.Contains(got.Refused, "account holder is unconfirmed") {
		t.Fatalf("uncertain enforcing assignment = %+v; want account-only refusal", got)
	}
	// The fallback itself may act. An uncertain observe profile could weaken
	// it, so their different enforcement still needs the account fact.
	cfg.Guardrail.Profiles["watch"] = config.GuardrailProfile{Mode: "action"}
	cfg.Guardrail.Profiles["other-watch"] = config.GuardrailProfile{Mode: "observe"}
	weaker := newGuardrailProfileSetFor(t, cfg)
	got = weaker.selectProfile(&subject, resolveIdentity(&subject, nil), profileSubjectVerified, "codex", nil, profilePathHook, "")
	if !slices.Equal(got.Unproven, []string{"account:unknown"}) || !strings.Contains(got.Refused, "account holder is unconfirmed") {
		t.Fatalf("uncertain weaker assignment = %+v; want account-only refusal", got)
	}
}

// TestResolveIdentityProofStatesAcrossProvidersAndPlatforms is the table
// of resolveIdentity: every proof state of a pass, for every directory
// provider, on Linux, macOS and Windows, and the profile the one selection
// rule gives it with a strict group assignment over a weaker default. A
// fact not proven never selects the weaker default.
func TestResolveIdentityProofStatesAcrossProvidersAndPlatforms(t *testing.T) {
	type want struct {
		account, groups proofStatus
		keyed           bool
		profile, match  string
	}
	for _, p := range identityTestPlatforms {
		for _, provider := range p.providers {
			for _, tc := range []struct {
				state   string
				inGroup bool
				want    want
			}{
				{stateProven, true, want{proofProven, proofProven, true, "strict", profileMatchGroup}},
				{stateProven, false, want{proofProven, proofProven, true, "watch", profileMatchDefault}},
				// explain serves the cached facts its hooks still apply
				// (cachedFactsAge): within their TTL they are proven, so
				// explain and hooks agree.
				{stateStale, true, want{proofProven, proofProven, true, "strict", profileMatchGroup}},
				{stateUnknown, true, want{proofUnknown, proofUnknown, false, "strict", profileMatchDefaultLookupFailed}},
				{stateFailed, true, want{proofFailed, proofUnknown, false, "strict", profileMatchDefaultLookupFailed}},
				{stateGroupsUnknown, true, want{proofProven, proofUnknown, true, "strict", profileMatchDefaultLookupFailed}},
				{stateGroupsUnproven, true, want{proofProven, proofUnknown, true, "strict", profileMatchDefaultLookupFailed}},
			} {
				name := p.os + "/" + provider.source + "/" + string(provider.directory) + "/" + tc.state
				t.Run(name, func(t *testing.T) {
					subject := identityTestSubject(p, provider, tc.state, tc.inGroup)
					res := resolveIdentity(&subject, nil)
					if tc.state == stateFailed && res.Groups == proofUnknown {
						tc.want.groups = proofUnknown
					}
					if res.Account != tc.want.account || res.Groups != tc.want.groups || res.Agent != proofProven {
						t.Fatalf("resolution %+v; want account %s, groups %s", res, tc.want.account, tc.want.groups)
					}
					if tc.want.keyed && !provider.keyed(p) {
						tc.want.keyed = false
					}
					if (res.Incarnation.key() != "") != tc.want.keyed {
						t.Fatalf("incarnation %+v keyed %v; want keyed %v", res.Incarnation, res.Incarnation.key() != "", tc.want.keyed)
					}
					if p.kind == useridentity.KindWindowsSID && tc.want.keyed && res.Incarnation.Token == "" {
						t.Fatalf("a Windows SID names its own incarnation: %+v", res.Incarnation)
					}
					set := identityTestSet(t, p, "watch",
						config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}})
					got := set.selectProfile(&subject, res, profileSubjectVerified, "codex", nil, profilePathAny, "")
					if got.Name != tc.want.profile || got.Match != tc.want.match {
						t.Fatalf("decision %+v; want %s (%s)", got, tc.want.profile, tc.want.match)
					}
					if tc.want.account != proofProven || tc.want.groups != proofProven {
						if len(got.Unproven) == 0 || !slices.Contains(got.Candidates, "strict") {
							t.Fatalf("unproven decision %+v names no unproven fact or candidate", got)
						}
					}
				})
			}
		}
	}
}

// When the profiles that may apply do not cover each other, their meet
// applies: never a refusal, and never the weaker of them.
func TestUnprovenFactsWithIncomparableProfilesApplyTheirMeet(t *testing.T) {
	p := identityTestPlatforms[0]
	cfg := &config.Config{}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict":  {Mode: "action", BlockAt: "LOW", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}},
		"default": {Mode: "action", BlockAt: "HIGH"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}}}
	cfg.Guardrail.DefaultProfile = "default"
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	subject := identityTestSubject(p, p.providers[1], stateUnknown, true)
	got := set.match(&subject, profileSubjectVerified, "codex", "")
	if got.Name != config.ProfileMeetName([]string{"default", "strict"}) || got.Match != profileMatchDefaultLookupFailed {
		t.Fatalf("decision %+v; want the meet of default and strict", got)
	}
	derived, ok := set.derivedProfile(got.Name)
	if !ok || derived.Config.HookModeForConnector("codex") != "action" || resolveThresholds(derived.Config, "codex").Block != "LOW" ||
		!slices.Contains(derived.Sandbox.RequiredFor, "codex") {
		t.Fatalf("meet %+v; want action, block_at LOW and codex required in a sandbox", derived)
	}
}

// GAP-0323: a cold lookup timeout or a directory outage with a strict group
// assignment before a weaker default selected default_lookup_failed and
// the weaker default. It now refuses and names the missing group fact;
// the strict profile is only a diagnostic candidate.
func TestGAP0323LookupFailureNeverSelectsAWeakerDefault(t *testing.T) {
	p := identityTestPlatforms[0]
	set := identityTestSet(t, p, "watch",
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}})
	failed := profileSubject{UserID: p.id, IDKind: p.kind, LookupFailed: true}
	if got := set.match(&failed, profileSubjectVerified, "codex", ""); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed ||
		!strings.Contains(got.Refused, "group membership is unconfirmed") {
		t.Fatalf("failed lookup selected %+v; want refusal naming group membership, with strict only as candidate", got)
	}
	// A uid assignment needs no directory and still applies; the failed
	// lookup cannot make the account weaker than it either.
	set = identityTestSet(t, p, "watch",
		config.ProfileAssignment{Profile: "tooling", Match: config.ProfileMatch{Users: []string{p.id}}},
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}})
	if got := set.match(&failed, profileSubjectVerified, "codex", ""); got.Name != "strict" ||
		!strings.Contains(got.Refused, "group membership is unconfirmed") {
		t.Fatalf("a uid assignment before an unknown group selected %+v; want refusal naming the group, with strict only as candidate", got)
	}
}

// GAP-0402: an earlier user-name or connector-only assignment must not hide
// a later group assignment whose membership is unknown; a proved other uid
// or another connector does.
func TestGAP0402UnknownMembershipIsNotHiddenByEarlierAssignments(t *testing.T) {
	p := identityTestPlatforms[0]
	failed := profileSubject{UserID: p.id, IDKind: p.kind, LookupFailed: true}
	unknownGroups := identityTestSubject(p, p.providers[1], stateGroupsUnknown, true)
	for _, first := range []config.ProfileMatch{{Users: []string{"alice"}}, {Connectors: []string{"codex"}}} {
		set := identityTestSet(t, p, "watch",
			config.ProfileAssignment{Profile: "watch", Match: first},
			config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"ldap-privileged"}}})
		for _, subject := range []profileSubject{failed, unknownGroups} {
			if got := set.match(&subject, profileSubjectVerified, "codex", ""); got.Name != "strict" {
				t.Fatalf("first %+v, subject %+v: %+v; want strict", first, subject, got)
			}
		}
	}
	set := identityTestSet(t, p, "watch",
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"ldap-privileged"}, Connectors: []string{"cursor"}}})
	if got := set.match(&unknownGroups, profileSubjectVerified, "codex", ""); got.Name != "watch" {
		t.Fatalf("a group assignment of another connector made %+v; want the default", got)
	}
	set = identityTestSet(t, p, "watch",
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"ldap-privileged"}, Users: []string{"2002"}}})
	if got := set.match(&unknownGroups, profileSubjectVerified, "codex", ""); got.Name != "watch" {
		t.Fatalf("a group assignment of a proved other uid made %+v; want the default", got)
	}
}

// When several assignments match, the strictest wins whatever their order
// (owner rule for 1.0.4).
func TestSeveralMatchingAssignmentsTheStrictestWins(t *testing.T) {
	p := identityTestPlatforms[0]
	subject := identityTestSubject(p, p.providers[1], stateProven, true)
	for _, order := range [][]config.ProfileAssignment{
		{{Profile: "watch", Match: config.ProfileMatch{Users: []string{"alice"}}}, {Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}}},
		{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}}, {Profile: "watch", Match: config.ProfileMatch{Users: []string{"alice"}}}},
		{{Profile: "tooling", Match: config.ProfileMatch{Connectors: []string{"codex"}}}, {Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}}},
	} {
		set := identityTestSet(t, p, "watch", order...)
		got := set.match(&subject, profileSubjectVerified, "codex", "")
		if got.Name != "strict" || got.Match != profileMatchGroup {
			t.Fatalf("assignments %+v: %+v; want strict as group", order, got)
		}
	}
}

// The last profile proven for an exact incarnation is a candidate while a
// fact is unproven; another incarnation of the same uid (a recreated
// account) never inherits it.
func TestLastProvenProfileIsKeyedByTheWholeIncarnation(t *testing.T) {
	p := identityTestPlatforms[0]
	set := identityTestSet(t, p, "watch",
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}},
		config.ProfileAssignment{Profile: "tooling", Match: config.ProfileMatch{Groups: []string{"tools"}}})
	proven := identityTestSubject(p, p.providers[1], stateProven, false)
	proven.UPN = "alice@corp.example"
	if got := set.match(&proven, profileSubjectVerified, "codex", ""); got.Name != "strict" {
		t.Fatalf("proven UPN: %+v; want strict", got)
	}
	// Groups unknown now, and the UPN is not given this pass: the UPN
	// entry may apply, and the incarnation was proven strict.
	later := identityTestSubject(p, p.providers[1], stateGroupsUnknown, false)
	later.upnUnproven = true
	if got := set.match(&later, profileSubjectVerified, "codex", ""); got.Name != "strict" || !slices.Contains(got.Candidates, "strict") {
		t.Fatalf("unproven UPN and groups: %+v; want strict", got)
	}
	res := resolveIdentity(&later, nil)
	if last, ok := set.provenProfiles.get(res.Incarnation, true); !ok || last != "strict" {
		t.Fatalf("last proven profile %q %v; want strict", last, ok)
	}
	recreated := later
	recreated.accountToken = "S-1-5-21-1-2-3-1777"
	if _, ok := set.provenProfiles.get(resolveIdentity(&recreated, nil).Incarnation, true); ok {
		t.Fatal("a recreated account under the same uid and name inherited the last proven profile")
	}
}

// An unresolved 1.0.3 agents entry anywhere in the list makes the agent
// fact unproven, in either order (GAP-0337, GAP-0424). When the entry gives
// the profile a proven assignment already gives, the decision needs no
// unproven fact; when it gives another one, the request is refused naming
// the agent fact.
func TestUnresolvedLegacyAgentEntryIsStrictestInEitherOrder(t *testing.T) {
	p := identityTestPlatforms[0]
	const legacy = "agt-00000000000000aa"
	subject := identityTestSubject(p, p.providers[0], stateProven, false)
	unresolved := func(entry string) bool { return entry == legacy }
	for _, legacyFirst := range []bool{true, false} {
		for _, entryProfile := range []string{"watch", "strict"} {
			legacyAssignment := config.ProfileAssignment{Profile: entryProfile, Match: config.ProfileMatch{Agents: []string{legacy}}}
			general := config.ProfileAssignment{Profile: "watch", Match: config.ProfileMatch{Connectors: []string{"codex"}}}
			assignments := []config.ProfileAssignment{general, legacyAssignment}
			if legacyFirst {
				assignments = []config.ProfileAssignment{legacyAssignment, general}
			}
			set := identityTestSet(t, p, "strict", assignments...)
			got := set.selectProfile(&subject, resolveIdentity(&subject, unresolved), profileSubjectVerified, "codex", nil, profilePathAny, "agt-00000000000000bb")
			if entryProfile == "watch" && (got.Name != "watch" || got.Match != profileMatchConnector || got.Refused != "") {
				t.Fatalf("legacyFirst=%v, entry watch: %+v; want watch by connector, not refused", legacyFirst, got)
			}
			if entryProfile == "strict" && (!strings.Contains(got.Refused, "pre-upgrade agent identity") ||
				!slices.Equal(got.Unproven, []string{"agent:unknown"})) {
				t.Fatalf("legacyFirst=%v, entry strict: %+v; want a refusal naming the agent fact", legacyFirst, got)
			}
		}
	}
}

// Privacy: the account a meet applies to sees it as the strictest
// combination, never the names of its members (one may be the profile of a
// group it is not proven to be in, or another account's).
func TestMeetNamesNoMemberToTheAccount(t *testing.T) {
	p := identityTestPlatforms[0]
	cfg := &config.Config{}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict":  {Mode: "action", BlockAt: "LOW", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}},
		"default": {Mode: "action", BlockAt: "HIGH"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}, Users: []string{"bob@corp.example"}}},
	}
	cfg.Guardrail.DefaultProfile = "default"
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	subject := identityTestSubject(p, p.providers[1], stateUnknown, true)
	got := set.match(&subject, profileSubjectVerified, "codex", "")
	label := profileUserLabel(got.Name)
	if !config.IsProfileMeet(got.Name) || label != profileMeetLabel || strings.Contains(label, "default") || strings.Contains(label, "bob") ||
		strings.Contains(label, p.group) || strings.Contains(label, got.Name) {
		t.Fatalf("decision %+v shown as %q; want the strictest combination, naming no member", got, label)
	}
	if profileUserLabel("strict") != "strict" {
		t.Fatal("a single profile keeps its own name")
	}
}

// GAP-0522, the rest of the class. A refusal names the facts the decision
// needs and no other. A managed Mac's local node account has no UPN, so it
// is not refused for a UPN entry, with or without the guardian's record
// (GAP-0532); an Open Directory answer without a directory still waits for
// the record's UPN. A .\name entry never waits for a UPN. A Windows account
// without current token groups is told why.
func TestUncertainIdentityRefusalNamesOnlyWhatTheDecisionNeeds(t *testing.T) {
	previous := currentIdentitySpoolDir()
	setIdentitySpoolDir(t.TempDir())
	t.Cleanup(func() { setIdentitySpoolDir(previous) })
	mac := identityTestPlatforms[1]
	local := func(record bool) profileSubject {
		return profileSubjectFromVerified(VerifiedSubject{UserID: "502", IDKind: useridentity.KindPOSIXUID, UserName: "bob",
			Directory: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Source: useridentity.SourceMacOSOpenDirectory,
				Groups: []string{"staff"}, ResolvedAt: time.Now(), Assurance: useridentity.AssuranceVerified, GuardianRecord: record},
			Source: subjectSourcePeerCredentials}, true)
	}
	byUPN := config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}}
	set := identityTestSet(t, mac, "watch", byUPN)
	unrecorded := local(false)
	if got := set.match(&unrecorded, profileSubjectVerified, "codex", ""); got.Refused != "" || got.Name != "watch" {
		t.Fatalf("local node account before the guardian's record: %+v; want watch, not refused", got)
	}
	awaiting := profileSubjectFromVerified(VerifiedSubject{UserID: "2027364327", IDKind: useridentity.KindPOSIXUID, UserName: "carol",
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceMacOSOpenDirectory,
			Groups: []string{"staff"}, ResolvedAt: time.Now(), Assurance: useridentity.AssuranceVerified},
		Source: subjectSourcePeerCredentials}, true)
	if got := set.match(&awaiting, profileSubjectVerified, "codex", ""); !strings.Contains(got.Refused, "UPN is unconfirmed") {
		t.Fatalf("directory account before the guardian's record: %+v; want a refusal naming the UPN", got)
	}
	recorded := local(true)
	if got := set.match(&recorded, profileSubjectVerified, "codex", ""); got.Refused != "" || got.Name != "watch" {
		t.Fatalf("with the guardian's record: %+v; want watch, not refused", got)
	}
	dotted := identityTestSet(t, mac, "watch", config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{`.\kiosk`}}})
	if got := dotted.match(&awaiting, profileSubjectVerified, "codex", ""); got.Refused != "" || got.Name != "watch" {
		t.Fatalf(".\\name entry: %+v; want watch, not refused", got)
	}

	// Groups and the UPN are both unproven; only a group assignment exists.
	both := identityTestSubject(mac, mac.providers[0], stateGroupsUnknown, false)
	both.upnUnproven = true
	groups := identityTestSet(t, mac, "watch", config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{mac.group}}})
	got := groups.match(&both, profileSubjectVerified, "codex", "")
	if !strings.Contains(got.Refused, "group membership is unconfirmed") || strings.Contains(got.Refused, "UPN") ||
		!slices.Equal(got.Unproven, []string{"groups:unknown"}) {
		t.Fatalf("%+v; want a refusal naming the groups only", got)
	}

	win := identityTestPlatforms[2]
	signedOut := profileSubjectFromVerified(VerifiedSubject{UserID: win.id, IDKind: win.kind, UserName: win.name,
		Directory: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Source: useridentity.SourceWindowsLSA,
			Domain: "corp.example", GroupsPartial: true, ResolvedAt: time.Now(), Assurance: useridentity.AssuranceVerified},
		Source: subjectSourcePeerCredentials}, true)
	winSet := identityTestSet(t, win, "watch", config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{win.group}}})
	if got := winSet.match(&signedOut, profileSubjectVerified, "codex", ""); !strings.Contains(got.Refused, "group membership is unconfirmed") ||
		!strings.Contains(got.Refused, "no desktop session") {
		t.Fatalf("Windows without a desktop session: %+v; want the groups and the reason named", got)
	}
}
