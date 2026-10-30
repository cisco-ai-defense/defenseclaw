//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// fakeTrustedResolver is an account database for the trusted connector
// tests: accounts by name and uid, groups by gid.
type fakeTrustedResolver struct {
	accounts map[string]unixidentity.Account
	groupIDs map[int][]int
	groups   map[int]string
	slow     *atomic.Bool
	lookups  *atomic.Int64
}

func (f fakeTrustedResolver) wait() {
	if f.lookups != nil {
		f.lookups.Add(1)
	}
	if f.slow != nil && f.slow.Load() {
		time.Sleep(trustedConnectorLookupBudget + 500*time.Millisecond)
	}
}

func (f fakeTrustedResolver) LookupUser(name string) (unixidentity.Account, error) {
	f.wait()
	if a, ok := f.accounts[name]; ok {
		return a, nil
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func (f fakeTrustedResolver) LookupUID(uid int) (unixidentity.Account, error) {
	f.wait()
	for _, a := range f.accounts {
		if a.UID == uid {
			return a, nil
		}
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func (f fakeTrustedResolver) LookupGroupID(gid int) (unixidentity.Group, error) {
	if name, ok := f.groups[gid]; ok {
		return unixidentity.Group{Name: name, GID: gid}, nil
	}
	return unixidentity.Group{}, unixidentity.ErrNotFound
}

func (f fakeTrustedResolver) LookupGroup(name string) (unixidentity.Group, error) {
	for gid, n := range f.groups {
		if n == name {
			return unixidentity.Group{Name: n, GID: gid}, nil
		}
	}
	return unixidentity.Group{}, unixidentity.ErrNotFound
}

func (f fakeTrustedResolver) GroupIDs(a unixidentity.Account) ([]int, error) {
	return f.groupIDs[a.UID], nil
}

func (f fakeTrustedResolver) ListUsers() ([]unixidentity.Account, bool, error) {
	return nil, false, nil
}

type trustedConnectorFixture struct {
	resolver fakeTrustedResolver
	facts    map[string]useridentity.DirectoryFacts
}

const (
	svcUID   = 2001
	svc2UID  = 2002
	eng1UID  = 3001
	eng2UID  = 3002
	adminUID = 3003
	outUID   = 3004
)

// useTrustedConnectorFixture installs two connectors: gas (svc-gas, acting
// for the agents group and eng2) and other (svc-other), honoured as from a
// signed bundle.
func useTrustedConnectorFixture(t *testing.T) *trustedConnectorFixture {
	t.Helper()
	f := &trustedConnectorFixture{
		resolver: fakeTrustedResolver{
			accounts: map[string]unixidentity.Account{
				"svc-gas":   {Name: "svc-gas", UID: svcUID, Home: "/var/lib/svc-gas"},
				"svc-other": {Name: "svc-other", UID: svc2UID, Home: "/var/lib/svc-other"},
				"eng1":      {Name: "eng1", UID: eng1UID, Home: "/home/eng1"},
				"eng2":      {Name: "eng2", UID: eng2UID, Home: "/home/eng2"},
				"admin1":    {Name: "admin1", UID: adminUID, Home: "/home/admin1"},
				"outsider":  {Name: "outsider", UID: outUID, Home: "/home/outsider"},
				"toor":      {Name: "toor", UID: 0, Home: "/root"},
				"svcadmin":  {Name: "svcadmin", UID: 2009, Home: "/var/lib/svcadmin"},
			},
			groupIDs: map[int][]int{
				svcUID: {svcUID}, svc2UID: {svc2UID}, eng1UID: {eng1UID, 5001}, eng2UID: {eng2UID},
				adminUID: {adminUID, 5001, 10}, outUID: {outUID}, 2009: {2009, 27},
			},
			groups: map[int]string{
				svcUID: "svc-gas", svc2UID: "svc-other", eng1UID: "eng1", eng2UID: "eng2", adminUID: "admin1",
				outUID: "outsider", 2009: "svcadmin", 5001: "agents", 10: "wheel", 27: "sudo",
			},
			slow:    &atomic.Bool{},
			lookups: &atomic.Int64{},
		},
		facts: map[string]useridentity.DirectoryFacts{},
	}
	for name, account := range f.resolver.accounts {
		var groups []string
		for _, gid := range f.resolver.groupIDs[account.UID] {
			groups = append(groups, f.resolver.groups[gid])
		}
		f.facts[strconv.Itoa(account.UID)] = useridentity.DirectoryFacts{
			Groups: groups, Directory: useridentity.DirectoryLocal, Source: "test", ResolvedAt: time.Now(),
			Principal: name,
		}
	}
	previousResolver, previousActivation := trustedConnectorResolver, trustedConnectorActivation
	previousLookup, previousTwins := actingForDirectoryLookup, trustedConnectorSameNameAccounts
	trustedConnectorResolver = func(context.Context) unixidentity.Resolver { return f.resolver }
	trustedConnectorActivation = func(*config.Config) (bool, string) { return true, "" }
	actingForDirectoryLookup = func(uid string) (useridentity.DirectoryFacts, bool) {
		facts, ok := f.facts[uid]
		return facts, ok
	}
	trustedConnectorSameNameAccounts = func(context.Context, unixidentity.Resolver, unixidentity.Account) ([]unixidentity.Account, error) {
		return nil, nil
	}
	t.Cleanup(func() {
		trustedConnectorResolver, trustedConnectorActivation = previousResolver, previousActivation
		actingForDirectoryLookup, trustedConnectorSameNameAccounts = previousLookup, previousTwins
		trustedConnectorsState.Store(nil)
		actingForPeople.Lock()
		actingForPeople.entries = map[string]actingForPersonAnswer{}
		actingForPeople.Unlock()
	})
	trustedConnectorsState.Store(buildTrustedConnectorState(trustedConnectorTestConfig()))
	return f
}

func trustedConnectorTestConfig() *config.Config {
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	cfg.Enterprise.Identity.TrustedConnectors = []config.TrustedConnectorConfig{
		{Name: "gas", Account: "svc-gas", MayActFor: config.TrustedConnectorScope{Groups: []string{"agents"}, Users: []string{"eng2"}}},
		{Name: "other", Account: "svc-other", MayActFor: config.TrustedConnectorScope{Users: []string{"eng1"}}},
		{Name: "bad", Account: "svcadmin", MayActFor: config.TrustedConnectorScope{Users: []string{"eng1"}}},
	}
	return cfg
}

// socketContext is a hook-socket request from uid, verified by its peer
// credentials, as managedHookPeerAuth leaves it.
func socketContext(uid int, name, home string) context.Context {
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: uid, Name: name, Home: home})
	return withVerifiedSubject(ctx, VerifiedSubject{
		UserID: strconv.Itoa(uid), IDKind: useridentity.KindPOSIXUID, UserName: name, Source: subjectSourcePeerCredentials,
	})
}

func gatewayEvent(t *testing.T, body string) connector.AgentGatewayEvent {
	t.Helper()
	ev, err := connector.DecodeAgentGatewayEvent([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestTrustedConnectorStateResolvesByID(t *testing.T) {
	useTrustedConnectorFixture(t)
	s := trustedConnectorStateNow()
	if !s.honoured || len(s.entries) != 3 {
		t.Fatalf("state = %+v", s)
	}
	gas, ok := trustedConnectorForAccount(strconv.Itoa(svcUID))
	if !ok || gas.Name != "gas" || !gas.Users[strconv.Itoa(eng2UID)] || !gas.Groups["5001"] || gas.Disabled != "" {
		t.Fatalf("gas = %+v", gas)
	}
	bad, ok := trustedConnectorForAccount("2009")
	if !ok || bad.Disabled != "account_is_administrator" {
		t.Fatalf("an admin service account is usable: %+v", bad)
	}
}

func TestTrustedConnectorsIgnoredWithoutSignedActivation(t *testing.T) {
	useTrustedConnectorFixture(t)
	trustedConnectorActivation = func(*config.Config) (bool, string) { return false, trustedConnectorsNoAnchors }
	trustedConnectorsState.Store(buildTrustedConnectorState(trustedConnectorTestConfig()))
	if _, ok := trustedConnectorForAccount(strconv.Itoa(svcUID)); ok {
		t.Fatal("a CONFIG= install honours trusted_connectors")
	}
	if s := trustedConnectorStateNow(); !s.configured || s.honoured || s.reason != trustedConnectorsNoAnchors {
		t.Fatalf("state = %+v", s)
	}
	api := &APIServer{}
	ctx, refusal, audit := api.agentGatewayIdentity(socketContext(svcUID, "svc-gas", "/var/lib/svc-gas"),
		gatewayEvent(t, `{"event":"session_start","session_id":"s","acting_for":{"user":"eng1"}}`), time.Now())
	if refusal.refused() || !audit.actingForIgnored {
		t.Fatalf("refusal=%+v audit=%+v, want ignored", refusal, audit)
	}
	if _, ok := actingForFromContext(ctx); ok {
		t.Fatal("acting_for honoured")
	}
}

func TestActingForDecisions(t *testing.T) {
	useTrustedConnectorFixture(t)
	api := &APIServer{}
	svc := func() context.Context { return socketContext(svcUID, "svc-gas", "/var/lib/svc-gas") }
	session := 0
	event := func(user string) connector.AgentGatewayEvent {
		session++
		body := `{"event":"session_start","session_id":"s` + strconv.Itoa(session) + `"}`
		if user != "" {
			body = `{"event":"session_start","session_id":"s` + strconv.Itoa(session) + `","acting_for":{"user":"` + user + `"}}`
		}
		return gatewayEvent(t, body)
	}
	for _, tc := range []struct {
		name, user, code, cause string
		ctx                     context.Context
	}{
		{"no acting_for from a listed account", "", actingForRefusedRequired, "absent", svc()},
		{"unknown user", "nobody", actingForRefusedNotAllowed, actingForCauseUnknownUser, svc()},
		{"out of set", "outsider", actingForRefusedNotAllowed, actingForCauseOutOfSet, svc()},
		{"admin by group", "admin1", actingForRefusedNotAllowed, actingForCauseAdminTarget, svc()},
		{"uid 0 alias", "toor", actingForRefusedNotAllowed, actingForCauseAdminTarget, svc()},
		{"uid 0", "0", actingForRefusedNotAllowed, actingForCauseAdminTarget, svc()},
		{"itself", "svc-gas", actingForRefusedNotAllowed, actingForCauseConnectorSelf, svc()},
		{"another connector", "svc-other", actingForRefusedNotAllowed, actingForCauseConnectorSelf, svc()},
		{"admin service account", "eng1", actingForRefusedConnectorDisabled, "account_is_administrator", socketContext(2009, "svcadmin", "/var/lib/svcadmin")},
	} {
		_, refusal, _ := api.agentGatewayIdentity(tc.ctx, event(tc.user), time.Now())
		if refusal.Code != tc.code || refusal.Cause != tc.cause {
			t.Errorf("%s: refusal = %+v, want %s/%s", tc.name, refusal, tc.code, tc.cause)
		}
	}
	// By group, by user and by uid.
	for _, user := range []string{"eng1", "eng2", strconv.Itoa(eng1UID)} {
		ctx, refusal, _ := api.agentGatewayIdentity(svc(), event(user), time.Now())
		af, ok := actingForFromContext(ctx)
		if refusal.refused() || !ok || af.Connector != "gas" || af.ConnectorAccountID != strconv.Itoa(svcUID) {
			t.Fatalf("%s: refusal=%+v acting=%+v", user, refusal, af)
		}
	}
}

// Must-change 1: never for a per-user credential, a process owner, a TCP
// token call or a sandbox call.
func TestActingForOnlyForHookSocketPeers(t *testing.T) {
	useTrustedConnectorFixture(t)
	api := &APIServer{}
	ev := gatewayEvent(t, `{"event":"session_start","session_id":"s","acting_for":{"user":"eng1"}}`)
	userScoped := withVerifiedSubject(context.WithValue(context.Background(), verifiedUserScopedIdentityContextKey{}, strconv.Itoa(svcUID)),
		VerifiedSubject{UserID: strconv.Itoa(svcUID), Source: subjectSourceUserCredential})
	owner := withVerifiedSubject(context.Background(), VerifiedSubject{UserID: strconv.Itoa(svcUID), Source: subjectSourceProcessOwner})
	sandboxed := sandboxauth.WithRequest(socketContext(svcUID, "svc-gas", "/var/lib/svc-gas"), sandboxauth.Binding{ID: "b", Connector: "claudecode"}, nil)
	mixed := withVerifiedSubject(withManagedHookPeer(context.Background(), managedHookPeer{UID: svcUID}),
		VerifiedSubject{UserID: strconv.Itoa(svcUID), Source: subjectSourceUserCredential})
	for name, ctx := range map[string]context.Context{
		"per-user credential": userScoped, "process owner": owner, "token call": context.Background(),
		"sandbox": sandboxed, "peer with a credential subject": mixed,
	} {
		out, refusal, audit := api.agentGatewayIdentity(ctx, ev, time.Now())
		if refusal.refused() || !audit.actingForIgnored {
			t.Errorf("%s: refusal=%+v audit=%+v, want ignored", name, refusal, audit)
		}
		if _, ok := actingForFromContext(out); ok {
			t.Errorf("%s: acting_for honoured", name)
		}
	}
}

// Must-change 3 and #1391 item 5: a session or root id used for one person
// is refused for another.
func TestActingForSessionPinning(t *testing.T) {
	useTrustedConnectorFixture(t)
	api := &APIServer{}
	svc := socketContext(svcUID, "svc-gas", "/var/lib/svc-gas")
	_, first, _ := api.agentGatewayIdentity(svc, gatewayEvent(t, `{"event":"session_start","session_id":"pin-1","root_session_id":"root-1","acting_for":{"user":"eng1"}}`), time.Now())
	if first.refused() {
		t.Fatal(first)
	}
	_, again, _ := api.agentGatewayIdentity(svc, gatewayEvent(t, `{"event":"session_end","session_id":"pin-1","acting_for":{"user":"eng1"}}`), time.Now())
	if again.refused() {
		t.Fatal(again)
	}
	_, switched, _ := api.agentGatewayIdentity(svc, gatewayEvent(t, `{"event":"session_start","session_id":"pin-1","acting_for":{"user":"eng2"}}`), time.Now())
	if switched.Code != actingForRefusedSessionMismatch {
		t.Fatalf("a session switched person: %+v", switched)
	}
	_, root, _ := api.agentGatewayIdentity(svc, gatewayEvent(t, `{"event":"session_start","session_id":"pin-2","root_session_id":"root-1","acting_for":{"user":"eng2"}}`), time.Now())
	if root.Code != actingForRefusedSessionMismatch || root.Cause != "root_session_id" {
		t.Fatalf("a root id switched person: %+v", root)
	}
}

// Must-change 7: a timeout or a partial answer refuses, and is not kept.
func TestActingForLookupFailuresRefuseAndAreNotCached(t *testing.T) {
	f := useTrustedConnectorFixture(t)
	entry, _ := trustedConnectorForAccount(strconv.Itoa(svcUID))
	f.resolver.slow.Store(true)
	if _, refusal := resolveActingFor(entry, "eng1", time.Now()); refusal.Code != actingForRefusedLookupUnavailable {
		t.Fatalf("timeout: %+v", refusal)
	}
	f.resolver.slow.Store(false)
	before := f.resolver.lookups.Load()
	if _, refusal := resolveActingFor(entry, "eng1", time.Now()); refusal.refused() {
		t.Fatalf("after the timeout: %+v", refusal)
	}
	if f.resolver.lookups.Load() == before {
		t.Fatal("the timed-out answer was cached")
	}
	partial := f.facts[strconv.Itoa(eng2UID)]
	delete(f.facts, strconv.Itoa(eng2UID))
	if _, refusal := resolveActingFor(entry, "eng2", time.Now()); refusal.Code != actingForRefusedLookupUnavailable {
		t.Fatalf("no facts: %+v", refusal)
	}
	f.facts[strconv.Itoa(eng2UID)] = partial
	if _, refusal := resolveActingFor(entry, "eng2", time.Now()); refusal.refused() {
		t.Fatalf("facts back: %+v", refusal)
	}
}

// What the person gets, and what stays the connector's (must-change 8, 10).
func TestActingForBindsThePersonOnly(t *testing.T) {
	useTrustedConnectorFixture(t)
	previous := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(previous) })
	api := &APIServer{}
	svcCtx := socketContext(svcUID, "svc-gas", "/var/lib/svc-gas")
	ctx, refusal, _ := api.agentGatewayIdentity(svcCtx, gatewayEvent(t, `{"event":"session_start","session_id":"bind","acting_for":{"user":"eng1"}}`), time.Now())
	if refusal.refused() {
		t.Fatal(refusal)
	}
	eng1 := strconv.Itoa(eng1UID)
	subject, source := profileRequestSubject(ctx)
	if source != profileSubjectVerifiedByConnector || subject == nil || subject.UserID != eng1 {
		t.Fatalf("profile subject %+v from %q", subject, source)
	}
	if id := AgentIdentityFromContext(ctx); id.UserID != eng1 {
		t.Fatalf("records name %q", id.UserID)
	}
	identity := requestIdentityFor(ctx, eng1)
	if identity == nil || identity.Directory.Assurance != useridentity.AssuranceVerifiedByConnector {
		t.Fatalf("identity = %+v", identity)
	}
	if got, present := identity.v8().Assurance.Get(); !present || got != "verified_by_connector" {
		t.Fatalf("v8 assurance = %+v", got)
	}
	// The checks that need the person's own process keep seeing the
	// connector's account.
	if verified, ok := verifiedSubjectFromContext(ctx); !ok || verified.UserID != strconv.Itoa(svcUID) {
		t.Fatalf("verified subject = %+v", verified)
	}
	if id, _ := requireSandboxCaller(ctx); id != strconv.Itoa(svcUID) {
		t.Fatalf("require-sandbox caller = %s", id)
	}
	if uid, _ := requestPeerUID(ctx); uid != svcUID {
		t.Fatalf("peer uid = %d", uid)
	}
	if requireSandboxExemptUser(ctx, &config.Config{}) {
		t.Fatal("the person is an exempt user")
	}
	if home := trustedActiveHome(ctx); home != "/var/lib/svc-gas" {
		t.Fatalf("~ resolves to %q, want the connector account's home", home)
	}
	if caller := verifiedSessionCaller(ctx); caller != "uid:2001/for:"+eng1 {
		t.Fatalf("session caller = %q", caller)
	}
	user := hookAgentIdentityUser(ctx)
	if user.ID != eng1 || user.Home != "/var/lib/svc-gas" || user.Connector != "gas:2001" {
		t.Fatalf("agent identity user = %+v", user)
	}
	if fp := agentIdentityInstallFP(connector.AgentGatewayConnectorName, user); fp != "trusted-connector:gas:2001" {
		t.Fatalf("install fingerprint = %q", fp)
	}
	other := user
	other.Connector = "other:2002"
	if agentIdentityInstallFP(connector.AgentGatewayConnectorName, other) == agentIdentityInstallFP(connector.AgentGatewayConnectorName, user) {
		t.Fatal("two connectors acting for one person share an agent identity")
	}
	extra := actingForAuditExtra(ctx)
	if extra["trusted_connector"] != "gas" || extra["acting_for_user_id"] != eng1 || extra["principal_assurance"] != "verified_by_connector" {
		t.Fatalf("audit extra = %v", extra)
	}
	// One connector instance per (connector account, person).
	af, _ := actingForFromContext(ctx)
	other2 := af
	other2.Person.UserID = strconv.Itoa(eng2UID)
	a, b := trustedConnectorInstanceID(af), trustedConnectorInstanceID(other2)
	if a == b {
		t.Fatal("two people share a connector instance")
	}
	if parsed, err := uuid.Parse(string(a)); err != nil || parsed.Version() != 7 {
		t.Fatalf("instance id %q is not a UUIDv7", a)
	}
	if strings.Contains(string(a), eng1) {
		t.Fatal("instance id carries the uid")
	}
}

// Must-change 1 of #1394: the agent-gateway route admits a trusted
// connector's account or an enrolled user; root and anyone else get
// enterprise_managed_connector_unknown.
func TestManagedHookAuthorizerAgentGateway(t *testing.T) {
	useTrustedConnectorFixture(t)
	uid := eng1UID
	ledger := managedHookLedger{Targets: []managedHookLedgerTarget{{User: "eng1", UID: &uid, Connector: "claudecode", OK: true}}}
	z := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, nil, func() (managedHookLedger, error) { return ledger, nil })
	for name, tc := range map[string]struct {
		peer  managedHookPeer
		allow bool
	}{
		"trusted connector": {managedHookPeer{UID: svcUID, Name: "svc-gas"}, true},
		"enrolled user":     {managedHookPeer{UID: eng1UID, Name: "eng1"}, true},
		"unknown account":   {managedHookPeer{UID: outUID, Name: "outsider"}, false},
		"root":              {managedHookPeer{UID: 0, Name: "root"}, false},
	} {
		decision := z.decide(tc.peer, connector.AgentGatewayConnectorName, "")
		if decision.Allow != tc.allow || (!tc.allow && decision.Reason != managedHookReasonConnectorUnknown) {
			t.Errorf("%s: decision = %+v", name, decision)
		}
	}
}

// Review F1: an entry whose lookup fails keeps the account id it had, so
// the account is refused rather than served under its own profile; an
// account that never resolved refuses every acting_for.
func TestTrustedConnectorLookupFailureKeepsTheAccountListed(t *testing.T) {
	f := useTrustedConnectorFixture(t)
	f.resolver.slow.Store(true)
	next := buildTrustedConnectorStateFrom(trustedConnectorTestConfig(), trustedConnectorStateNow())
	trustedConnectorsState.Store(next)
	entry, ok := trustedConnectorForAccount(strconv.Itoa(svcUID))
	if !ok || entry.Disabled != "lookup_failed" {
		t.Fatalf("entry after a failed refresh = %+v (listed %v)", entry, ok)
	}
	api := &APIServer{}
	_, refusal, _ := api.agentGatewayIdentity(socketContext(svcUID, "svc-gas", "/var/lib/svc-gas"),
		gatewayEvent(t, `{"event":"session_start","session_id":"lf","acting_for":{"user":"eng1"}}`), time.Now())
	if refusal.Code != actingForRefusedConnectorDisabled {
		t.Fatalf("refusal = %+v", refusal)
	}
	cold := buildTrustedConnectorStateFrom(trustedConnectorTestConfig(), nil)
	trustedConnectorsState.Store(cold)
	if !cold.unresolved {
		t.Fatal("a never-resolved entry is not marked")
	}
	_, refusal, _ = api.agentGatewayIdentity(socketContext(svcUID, "svc-gas", "/var/lib/svc-gas"),
		gatewayEvent(t, `{"event":"session_start","session_id":"lf2","acting_for":{"user":"eng1"}}`), time.Now())
	if refusal.Code != actingForRefusedConnectorDisabled || refusal.Cause != "account_unresolved" {
		t.Fatalf("cold refusal = %+v", refusal)
	}
}

// Review F2: two connector accounts sending one session id for two people
// never share in-memory session state.
func TestActingForSessionStateIsPerConnectorAndPerson(t *testing.T) {
	useTrustedConnectorFixture(t)
	api := &APIServer{}
	a, ra, _ := api.agentGatewayIdentity(socketContext(svcUID, "svc-gas", "/var/lib/svc-gas"),
		gatewayEvent(t, `{"event":"session_start","session_id":"1","acting_for":{"user":"eng1"}}`), time.Now())
	b, rb, _ := api.agentGatewayIdentity(socketContext(svc2UID, "svc-other", "/var/lib/svc-other"),
		gatewayEvent(t, `{"event":"session_start","session_id":"1","acting_for":{"user":"eng1"}}`), time.Now())
	if ra.refused() || rb.refused() {
		t.Fatal(ra, rb)
	}
	if sandboxSessionStateKey(a, "1") == sandboxSessionStateKey(b, "1") || sandboxSessionStateKey(a, "1") == "1" {
		t.Fatalf("keys %q %q", sandboxSessionStateKey(a, "1"), sandboxSessionStateKey(b, "1"))
	}
	if verifiedSessionCaller(a) == verifiedSessionCaller(b) {
		t.Fatal("one session caller for two connectors")
	}
}

// Review F5: the service account is checked on every call.
func TestTrustedConnectorAdminCallerRefusedPerCall(t *testing.T) {
	useTrustedConnectorFixture(t)
	api := &APIServer{}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: svcUID, GID: 0, Name: "svc-gas", Home: "/var/lib/svc-gas"})
	ctx = withVerifiedSubject(ctx, VerifiedSubject{UserID: strconv.Itoa(svcUID), Source: subjectSourcePeerCredentials})
	_, refusal, _ := api.agentGatewayIdentity(ctx, gatewayEvent(t, `{"event":"session_start","session_id":"adm","acting_for":{"user":"eng1"}}`), time.Now())
	if refusal.Code != actingForRefusedConnectorDisabled || refusal.Cause != "account_is_administrator" {
		t.Fatalf("gid 0: %+v", refusal)
	}
	ctx = withManagedHookPeer(context.Background(), managedHookPeer{UID: svcUID, GID: svcUID, Name: "svc-gas"})
	ctx = withVerifiedSubject(ctx, VerifiedSubject{UserID: strconv.Itoa(svcUID), Source: subjectSourcePeerCredentials,
		Directory: useridentity.DirectoryFacts{Groups: []string{"svc-gas", "Domain Admins@dclab.test"}}})
	_, refusal, _ = api.agentGatewayIdentity(ctx, gatewayEvent(t, `{"event":"session_start","session_id":"adm2","acting_for":{"user":"eng1"}}`), time.Now())
	if refusal.Code != actingForRefusedConnectorDisabled {
		t.Fatalf("admin group: %+v", refusal)
	}
}

// Review F7: a trusted connector's account gets no other hook route.
func TestTrustedConnectorAccountOnlyOnItsRoute(t *testing.T) {
	useTrustedConnectorFixture(t)
	uid := svcUID
	ledger := managedHookLedger{Targets: []managedHookLedgerTarget{{User: "svc-gas", UID: &uid, Connector: "claudecode", OK: true}}}
	z := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, []string{"codex"}, func() (managedHookLedger, error) { return ledger, nil })
	for _, name := range []string{"claudecode", "codex"} {
		if d := z.decide(managedHookPeer{UID: svcUID, Name: "svc-gas"}, name, ""); d.Allow || d.Reason != managedHookReasonTrustedConnectorRoute {
			t.Errorf("%s: %+v", name, d)
		}
	}
	if d := z.decide(managedHookPeer{UID: svcUID, Name: "svc-gas"}, connector.AgentGatewayConnectorName, ""); !d.Allow {
		t.Fatalf("agent-gateway: %+v", d)
	}
}

// Review F8: a refused spelling is kept, and one account has a bounded
// number of lookups in flight.
func TestActingForRefusalsCachedAndLookupsBounded(t *testing.T) {
	f := useTrustedConnectorFixture(t)
	entry, _ := trustedConnectorForAccount(strconv.Itoa(svcUID))
	if _, refusal := resolveActingFor(entry, "ghost", time.Now()); refusal.Cause != actingForCauseUnknownUser {
		t.Fatal(refusal)
	}
	before := f.resolver.lookups.Load()
	if _, refusal := resolveActingFor(entry, "ghost", time.Now()); refusal.Cause != actingForCauseUnknownUser {
		t.Fatal(refusal)
	}
	if f.resolver.lookups.Load() != before {
		t.Fatal("a refused spelling was looked up again")
	}
	for i := 0; i < actingForLookupsPerAccount; i++ {
		if !beginActingForLookup(entry.AccountID) {
			t.Fatalf("lookup %d refused", i)
		}
	}
	if _, refusal := resolveActingFor(entry, "eng2", time.Now()); refusal.Code != actingForRefusedLookupUnavailable || refusal.Cause != "busy" {
		t.Fatalf("over the bound: %+v", refusal)
	}
	for i := 0; i < actingForLookupsPerAccount; i++ {
		endActingForLookup(entry.AccountID)
	}
}

// Review F3: without anchors, or with a store that holds no verified
// current bundle, the list is not honoured.
func TestSignedBundleActivationFailsClosed(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DeploymentMode: "managed_enterprise", ConfigFilePath: filepath.Join(dir, "config.yaml")}
	cfg.Enterprise.Profile = "standalone"
	if err := os.WriteFile(cfg.ConfigFilePath, []byte("config_version: 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, reason := signedBundleActivation(cfg); ok || reason != trustedConnectorsNoAnchors {
		t.Fatalf("no anchors: %v %s", ok, reason)
	}
	if err := os.MkdirAll(filepath.Join(dir, "trust"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trust", "bundle-anchors.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := signedBundleActivation(cfg); ok {
		t.Fatal("invalid anchors honoured")
	}
	if ok, reason := signedBundleActivation(&config.Config{}); ok || reason != trustedConnectorsNotManaged {
		t.Fatalf("per-user: %v %s", ok, reason)
	}
}
