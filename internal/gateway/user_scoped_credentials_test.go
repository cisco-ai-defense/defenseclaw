// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/user"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

const userScopedTestKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type userScopedTestLedger struct {
	ledger     managedHookLedger
	generation uint64
}

func (l *userScopedTestLedger) set(targets ...managedHookLedgerTarget) {
	l.ledger = managedHookLedger{Targets: targets}
	l.generation++
}

func userScopedTestUID(uid int) *int { return &uid }

type userScopedObservation struct {
	called    bool
	userID    string
	userName  string
	idKind    string
	ctxUserID string
	ctxName   string
	connector string
	source    string
}

// newUserScopedTestServer returns a standalone API server whose per-user
// credentials derive from userScopedTestKey and the given ledger, and whose
// account names resolve through names. The handler chain is the TCP one:
// correlation, then tokenAuth.
func newUserScopedTestServer(t *testing.T, standalone bool, ledger *userScopedTestLedger, names map[string]string) (*APIServer, http.Handler, *userScopedObservation) {
	t.Helper()
	api, _ := tokenAuthTestServer(t, "gateway-master-token")
	api.scannerCfg.DataDir = t.TempDir()
	if standalone {
		api.scannerCfg.DeploymentMode = "managed_enterprise"
		api.scannerCfg.Enterprise.Profile = "standalone"
	}
	now := time.Unix(1_700_000_000, 0)
	api.userScopedCredentials = &userScopedCredentialStore{
		dataDir: api.configDataDir,
		loadKey: func(string) (string, error) { return userScopedTestKey, nil },
		newLedger: func(string) func() (managedHookLedger, uint64, error) {
			return func() (managedHookLedger, uint64, error) { return ledger.ledger, ledger.generation, nil }
		},
		// Every request refreshes: the clock advances past the interval.
		now: func() time.Time {
			now = now.Add(2 * userScopedCredentialRefreshInterval)
			return now
		},
	}
	restoreName, restoreForName := userScopedIdentityName, userScopedIdentityForName
	userScopedIdentityName = func(identity string) string { return names[identity] }
	userScopedIdentityForName = func(name string) (string, bool) {
		for identity, held := range names {
			if strings.EqualFold(held, name) {
				return identity, true
			}
		}
		return "", false
	}
	t.Cleanup(func() { userScopedIdentityName, userScopedIdentityForName = restoreName, restoreForName })

	observed := &userScopedObservation{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := AgentIdentityFromContext(r.Context())
		*observed = userScopedObservation{
			called:    true,
			userID:    r.Header.Get(llmEventUserIDHeader),
			userName:  r.Header.Get(llmEventUserNameHeader),
			idKind:    identity.UserIDKind,
			ctxUserID: identity.UserID,
			ctxName:   identity.UserName,
			connector: authenticatedHookConnector(r.Context()),
			source:    r.Header.Get(otelSourceHeader),
		}
		w.WriteHeader(http.StatusOK)
	})
	handler := CorrelationMiddleware(NewAgentRegistry("", ""))(api.tokenAuth(next))
	return api, handler, observed
}

func userScopedTestToken(t *testing.T, kind, scope, identity string) string {
	t.Helper()
	var (
		token string
		err   error
	)
	if kind == connector.UserScopedHookCredential {
		token, err = connector.UserScopedHookAPIToken(userScopedTestKey, scope, identity)
	} else {
		token, err = connector.UserScopedOTLPPathToken(userScopedTestKey, connector.OTLPPathTokenScope(scope), identity)
	}
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func serveUserScopedTest(handler http.Handler, observed *userScopedObservation, method, path, token string, headers map[string]string, peerUID ...int) int {
	*observed = userScopedObservation{}
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.RemoteAddr = "127.0.0.1:54321"
	uid := 1001
	if len(peerUID) != 0 {
		uid = peerUID[0]
	}
	req = req.WithContext(context.WithValue(req.Context(), acpConnPeerKey{}, &acpConnPeer{uid: uid, known: true}))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response.Code
}

// A copied credential must not turn another process account into a verified user.
func TestUserScopedCredentialRequiresTheConnectingAccount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no loopback TCP caller UID")
	}
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{User: "alice", UID: userScopedTestUID(1001), Connector: "codex", OK: true})
	_, handler, observed := newUserScopedTestServer(t, true, ledger, map[string]string{"1001": "alice"})
	alice := userScopedTestToken(t, connector.UserScopedHookCredential, "codex", "1001")
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", alice, nil, 1002); code != http.StatusForbidden || observed.called {
		t.Fatalf("copied credential: status %d called=%v", code, observed.called)
	}
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", alice, nil, -1); code != http.StatusForbidden || observed.called {
		t.Fatalf("unverified caller: status %d called=%v", code, observed.called)
	}
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", alice, nil, 1001); code != http.StatusOK || observed.userID != "1001" {
		t.Fatalf("credential owner: status %d identity=%q", code, observed.userID)
	}
}

// A per-user hook credential authenticates only its own connector, is
// attributed to the uid it is bound to, and is refused when the request's
// identity headers name another user. User A's credential therefore cannot
// post an event attributed to user B.
func TestUserScopedHookCredentialIsBoundToItsUser(t *testing.T) {
	ledger := &userScopedTestLedger{}
	ledger.set(
		managedHookLedgerTarget{User: "alice", UID: userScopedTestUID(1001), Connector: "codex", OK: true},
		managedHookLedgerTarget{User: "bob", UID: userScopedTestUID(1002), Connector: "codex", OK: true},
	)
	api, handler, observed := newUserScopedTestServer(t, true, ledger, map[string]string{"1001": "alice", "1002": "bob"})
	alice := userScopedTestToken(t, connector.UserScopedHookCredential, "codex", "1001")

	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", alice, nil); code != http.StatusOK || !observed.called {
		t.Fatalf("own credential: status %d called=%v", code, observed.called)
	}
	if observed.userID != "1001" || observed.userName != "alice" || observed.ctxUserID != "1001" ||
		observed.ctxName != "alice" || observed.idKind != useridentity.KindPOSIXUID || observed.connector != "codex" {
		t.Fatalf("event not attributed to the bound uid: %+v", *observed)
	}
	matching := map[string]string{llmEventUserIDHeader: "1001", llmEventUserNameHeader: "alice"}
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", alice, matching); code != http.StatusOK || observed.userID != "1001" {
		t.Fatalf("matching identity headers: status %d %+v", code, *observed)
	}

	for name, headers := range map[string]map[string]string{
		"trusted id":   {llmEventUserIDHeader: "1002"},
		"trusted name": {llmEventUserNameHeader: "bob"},
		"generic id":   {"X-User-Id": "1002"},
		"generic user": {"X-User": "bob@example.com"},
		"generic name": {"X-Username": "bob"},
		"sid":          {llmEventUserIDHeader: "S-1-5-21-1-2-3-1002"},
	} {
		if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", alice, headers); code != http.StatusForbidden || observed.called {
			t.Fatalf("%s: a header naming another user must be refused; status %d called=%v", name, code, observed.called)
		}
	}

	// The credential is scoped to its connector.
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/claude-code/hook", alice, nil); code != http.StatusUnauthorized || observed.called {
		t.Fatalf("another connector's route: status %d called=%v", code, observed.called)
	}
	// An OTLP credential is not a hook credential.
	aliceOTLP := userScopedTestToken(t, connector.UserScopedOTLPCredential, "codex", "1001")
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", aliceOTLP, nil); code != http.StatusUnauthorized || observed.called {
		t.Fatalf("OTLP credential on a hook route: status %d called=%v", code, observed.called)
	}

	// The connector-wide credential every user used to share no longer
	// authenticates in the standalone profile.
	wide, err := connector.EnsureHookAPIToken(api.configDataDir(), "codex")
	if err != nil {
		t.Fatal(err)
	}
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", wide, nil); code != http.StatusUnauthorized || observed.called {
		t.Fatalf("connector-wide credential: status %d called=%v", code, observed.called)
	}

	// Revocation follows the ledger.
	ledger.set(managedHookLedgerTarget{User: "bob", UID: userScopedTestUID(1002), Connector: "codex", OK: true})
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", alice, nil); code != http.StatusUnauthorized || observed.called {
		t.Fatalf("revoked user: status %d called=%v", code, observed.called)
	}
	bob := userScopedTestToken(t, connector.UserScopedHookCredential, "codex", "1002")
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", bob, nil, 1002); code != http.StatusOK || observed.userID != "1002" {
		t.Fatalf("remaining user: status %d %+v", code, *observed)
	}
}

// The inspect routes accept a per-user hook credential for the named
// connector with the same identity binding.
func TestUserScopedInspectCredentialIsBoundToItsUser(t *testing.T) {
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{User: "alice", UID: userScopedTestUID(1001), Connector: "codex", OK: true})
	api, handler, observed := newUserScopedTestServer(t, true, ledger, map[string]string{"1001": "alice"})
	api.SetConnectorRegistry(connector.NewDefaultRegistry())
	alice := userScopedTestToken(t, connector.UserScopedHookCredential, "codex", "1001")
	headers := map[string]string{"X-DefenseClaw-Connector": "codex"}
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/inspect/tool", alice, headers); code != http.StatusOK || observed.userID != "1001" {
		t.Fatalf("inspect with own credential: status %d %+v", code, *observed)
	}
	headers[llmEventUserIDHeader] = "1002"
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/inspect/tool", alice, headers); code != http.StatusForbidden || observed.called {
		t.Fatalf("inspect naming another user: status %d called=%v", code, observed.called)
	}

	// The connector-wide credential every user of the connector used to
	// share does not open the inspect routes either, whatever identity the
	// request names.
	wide, err := connector.EnsureHookAPIToken(api.configDataDir(), "codex")
	if err != nil {
		t.Fatal(err)
	}
	for name, identity := range map[string]map[string]string{
		"no identity":     {"X-DefenseClaw-Connector": "codex"},
		"another user":    {"X-DefenseClaw-Connector": "codex", llmEventUserIDHeader: "1002"},
		"the bound user":  {"X-DefenseClaw-Connector": "codex", llmEventUserIDHeader: "1001"},
		"an account name": {"X-DefenseClaw-Connector": "codex", llmEventUserNameHeader: "alice"},
	} {
		if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/inspect/tool", wide, identity); code != http.StatusUnauthorized || observed.called {
			t.Fatalf("connector-wide credential on inspect (%s): status %d called=%v", name, code, observed.called)
		}
	}
}

// Per-user OTLP credentials cover the header form (Codex, Claude Code,
// OpenHands) and the path form (Omnigent here).
func TestUserScopedOTLPCredentialIsBoundToItsUser(t *testing.T) {
	ledger := &userScopedTestLedger{}
	ledger.set(
		managedHookLedgerTarget{User: "alice", UID: userScopedTestUID(1001), Connector: "codex", OK: true},
		managedHookLedgerTarget{User: "alice", UID: userScopedTestUID(1001), Connector: "omnigent", OK: true},
	)
	api, handler, observed := newUserScopedTestServer(t, true, ledger, map[string]string{"1001": "alice"})
	codex := userScopedTestToken(t, connector.UserScopedOTLPCredential, "codex", "1001")
	source := map[string]string{otelSourceHeader: "codex"}
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/v1/logs", codex, source); code != http.StatusOK || observed.userID != "1001" || observed.source != "codex" {
		t.Fatalf("header-form OTLP: status %d %+v", code, *observed)
	}
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/v1/logs", codex, map[string]string{otelSourceHeader: "codex", "X-User-Id": "1002"}); code != http.StatusForbidden || observed.called {
		t.Fatalf("header-form OTLP naming another user: status %d called=%v", code, observed.called)
	}
	wide, err := connector.EnsureOTLPPathToken(api.configDataDir(), connector.OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/v1/logs", wide, source); code != http.StatusUnauthorized || observed.called {
		t.Fatalf("connector-wide OTLP credential: status %d called=%v", code, observed.called)
	}
	wideOmnigent, err := connector.EnsureOTLPPathToken(api.configDataDir(), connector.OTLPScopeOmnigent)
	if err != nil {
		t.Fatal(err)
	}
	omnigent := userScopedTestToken(t, connector.UserScopedOTLPCredential, "omnigent", "1001")
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/otlp/omnigent/"+omnigent+"/v1/logs", "", nil); code != http.StatusOK || observed.userID != "1001" {
		t.Fatalf("path-form OTLP: status %d %+v", code, *observed)
	}
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/otlp/omnigent/"+wideOmnigent+"/v1/logs", "", nil); code != http.StatusUnauthorized || observed.called {
		t.Fatalf("connector-wide path credential: status %d called=%v", code, observed.called)
	}
	// Codex's credential does not open Omnigent's source.
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/otlp/omnigent/"+codex+"/v1/logs", "", nil); code != http.StatusUnauthorized || observed.called {
		t.Fatalf("another source's credential: status %d called=%v", code, observed.called)
	}
}

// Windows rows bind credentials to the SID; account names compare
// case-insensitively.
func TestUserScopedCredentialBindsWindowsSID(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("SID credentials are served only on Windows")
	}
	const sid = "S-1-5-21-1111-2222-3333-1001"
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{User: "alice", SID: strings.ToLower(sid), Connector: "codex", OK: true})
	_, handler, observed := newUserScopedTestServer(t, true, ledger, map[string]string{sid: "Alice"})
	alice := userScopedTestToken(t, connector.UserScopedHookCredential, "codex", sid)
	headers := map[string]string{llmEventUserIDHeader: sid, llmEventUserNameHeader: "alice"}
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", alice, headers); code != http.StatusOK ||
		observed.userID != sid || observed.idKind != useridentity.KindWindowsSID || observed.userName != "Alice" {
		t.Fatalf("SID-bound credential: status %d %+v", code, *observed)
	}
	// GAP-0907, GAP-0702: after Rename-LocalUser the hook still sends the
	// name its user signed in with, which no account has now; the SID
	// matches, so it is served and the records carry the current name.
	headers[llmEventUserNameHeader] = "old-alice"
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", alice, headers); code != http.StatusOK ||
		observed.userID != sid || observed.userName != "Alice" {
		t.Fatalf("renamed account: status %d %+v", code, *observed)
	}
	headers[llmEventUserNameHeader] = "alice"
	headers[llmEventUserIDHeader] = "S-1-5-21-1111-2222-3333-1002"
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", alice, headers); code != http.StatusForbidden || observed.called {
		t.Fatalf("SID naming another user: status %d called=%v", code, observed.called)
	}
}

// GAP-0290: a directory account the host names qualified keeps its per-user
// credential when the caller sends the bare account name.
func TestUserScopedNamesCompareBareAccounts(t *testing.T) {
	if !userScopedNamesEqual("4545", "alice", "alice@corp.example.com") ||
		!userScopedNamesEqual("4545", "alice@corp.example.com", "alice@corp.example.com") {
		t.Fatal("the bare account of a qualified host name was refused")
	}
	if userScopedNamesEqual("4545", "bob", "alice@corp.example.com") || userScopedNamesEqual("4545", "Alice", "alice") {
		t.Fatal("another account, or another case of a POSIX name, matched")
	}
}

// Outside the standalone profile nothing changes: connector-wide
// credentials authenticate and per-user credentials do not exist.
func TestUserScopedCredentialsOnlyInStandaloneProfile(t *testing.T) {
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{User: "alice", UID: userScopedTestUID(1001), Connector: "codex", OK: true})
	api, handler, observed := newUserScopedTestServer(t, false, ledger, nil)
	wide, err := connector.EnsureHookAPIToken(api.configDataDir(), "codex")
	if err != nil {
		t.Fatal(err)
	}
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", wide, nil); code != http.StatusOK || !observed.called {
		t.Fatalf("connector-wide credential outside standalone: status %d", code)
	}
	api.SetConnectorRegistry(connector.NewDefaultRegistry())
	inspect := map[string]string{"X-DefenseClaw-Connector": "codex"}
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/inspect/tool", wide, inspect); code != http.StatusOK || !observed.called {
		t.Fatalf("connector-wide credential on inspect outside standalone: status %d", code)
	}
	alice := userScopedTestToken(t, connector.UserScopedHookCredential, "codex", "1001")
	if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", alice, nil); code != http.StatusUnauthorized || observed.called {
		t.Fatalf("per-user credential outside standalone: status %d called=%v", code, observed.called)
	}
}

// A ledger row without a uid (the guardian omits uid 0) resolves through the
// account database; a row that cannot be resolved grants nothing.
func TestUserScopedLedgerIdentity(t *testing.T) {
	restore := userScopedLookupAccount
	t.Cleanup(func() { userScopedLookupAccount = restore })
	userScopedLookupAccount = rootOnlyAccountLookup
	for _, tc := range []struct {
		target managedHookLedgerTarget
		want   string
		ok     bool
	}{
		{managedHookLedgerTarget{User: "alice", UID: userScopedTestUID(1001)}, "1001", true},
		{managedHookLedgerTarget{User: "root"}, "0", true},
		{managedHookLedgerTarget{User: "ghost"}, "", false},
		{managedHookLedgerTarget{User: "alice", SID: "s-1-5-21-9-9-9-1001"}, "S-1-5-21-9-9-9-1001", true},
		{managedHookLedgerTarget{}, "", false},
	} {
		got, ok := userScopedLedgerIdentity(tc.target)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%+v: got %q/%v, want %q/%v", tc.target, got, ok, tc.want, tc.ok)
		}
	}
}

func rootOnlyAccountLookup(name string) (*user.User, error) {
	if name == "root" {
		return &user.User{Uid: "0", Gid: "0", Username: "root"}, nil
	}
	return nil, errors.New("unknown user")
}

// A credential rotation stages the next key beside the committed one. Until
// it commits, the credentials of both keys authenticate and /health names
// both keys, so users the guardian has already moved to the new key and
// users it has not reached yet keep working; after the commit renames the
// staged key over the committed one, the old key's credentials are refused.
// A staged key that fails its trust checks never authenticates.
func TestUserScopedCredentialsFollowAKeyRotation(t *testing.T) {
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{User: "alice", UID: userScopedTestUID(1001), Connector: "codex", OK: true})
	api, handler, observed := newUserScopedTestServer(t, true, ledger, map[string]string{"1001": "alice"})
	const stagedKey = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	committed, pending, pendingErr := userScopedTestKey, "", error(nil)
	api.userScopedCredentials.loadKey = func(string) (string, error) { return committed, nil }
	api.userScopedCredentials.loadPendingKey = func(string) (string, error) { return pending, pendingErr }
	credential := func(key string) string {
		token, err := connector.UserScopedHookAPIToken(key, "codex", "1001")
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	previous, next := credential(userScopedTestKey), credential(stagedKey)
	check := func(label string, wantPrevious, wantNext bool, wantKeys ...string) {
		t.Helper()
		for token, want := range map[string]bool{previous: wantPrevious, next: wantNext} {
			if code := serveUserScopedTest(handler, observed, http.MethodPost, "/api/v1/codex/hook", token, nil); (code == http.StatusOK) != want {
				t.Fatalf("%s: status %d, want accepted=%v", label, code, want)
			}
		}
		response := httptest.NewRecorder()
		api.handleHealth(response, httptest.NewRequest(http.MethodGet, "/health", nil))
		var health struct {
			UserScoped struct {
				KeyIDs []string `json:"key_ids"`
			} `json:"user_scoped_credentials"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &health); err != nil {
			t.Fatal(err)
		}
		want := []string{}
		for _, key := range wantKeys {
			want = append(want, connector.UserScopedTokenKeyFingerprint(key))
		}
		if !slices.Equal(health.UserScoped.KeyIDs, want) {
			t.Fatalf("%s: /health key_ids = %v, want %v", label, health.UserScoped.KeyIDs, want)
		}
	}
	check("before the rotation", true, false, userScopedTestKey)
	pending = stagedKey
	check("staged", true, true, userScopedTestKey, stagedKey)
	pendingErr = errors.New("untrusted owner")
	check("untrusted staged key", true, false, userScopedTestKey)
	// A rollback retires the staged key: it still authenticates until the
	// guardian has moved every user back.
	retiring := stagedKey
	api.userScopedCredentials.loadRetiringKey = func(string) (string, error) { return retiring, nil }
	pending, pendingErr = "", nil
	check("retiring", true, true, userScopedTestKey, stagedKey)
	retiring = ""
	committed = stagedKey
	check("committed", false, true, stagedKey)
}
