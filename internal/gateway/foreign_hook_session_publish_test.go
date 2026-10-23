// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// foreignHookPublished is one protected record write of the gateway: keyID
// names the key its MAC was made with ("" for none).
type foreignHookPublished struct {
	root, identity string
	key            enterprisepolicy.SessionKey
	deny           bool
	keyID          string
}

// foreignHookTestTrust names the gateway service for the test record key.
var foreignHookTestTrust = enterprisepolicy.PublishedSessionTrust{ServiceAccount: `NT SERVICE\` + managed.StandaloneWindowsGatewaySvc}

func foreignHookRecorder(writes *[]foreignHookPublished, result func() error) func(string, string, enterprisepolicy.SessionKey, enterprisepolicy.GuardDecision, enterprisepolicy.SessionRecordKey, time.Time) error {
	return func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey, _ time.Time) error {
		*writes = append(*writes, foreignHookPublished{r, identity, key, decision.Deny, recordKey.ID()})
		if result != nil {
			return result()
		}
		return nil
	}
}

// GAP-0352: every session exchange of a standalone gateway writes its answer
// into the caller's protected session record, for the verified caller only:
// a block for the session start that found an unapproved hook, the block it
// then enforces, and the allow of another account. The block removed the
// blocked account's key only: the other account's allow still carries its
// own key, and every later denial of the blocked account removes its key
// again (a new one the guardian made included).
func TestForeignHookSessionGatewayPublishesTheProtectedRecord(t *testing.T) {
	var writes []foreignHookPublished
	server := newForeignHookPublishTestServer(t, foreignHookRecorder(&writes, nil))
	alice, bob := server.alice, server.bob
	bobKey := server.keyID(bob)
	if server.keyID(alice) == "" || bobKey == "" {
		t.Fatal("the test record folder has no keys")
	}
	key := map[string]any{"connector": "claudecode", "session": "s-1", "process": "process-1"}
	server.call(server.aliceToken, map[string]any{"key": key, "session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: project hook",
			"findings": []map[string]any{{"connector": "claudecode", "scope": "project", "path": "/repo/.claude/settings.json", "digest": "abcd"}}}})
	if server.keyID(alice) != "" || server.keyID(bob) != bobKey {
		t.Fatalf("the block must remove the blocked account's key only (alice %q, bob %q)", server.keyID(alice), server.keyID(bob))
	}
	server.call(server.aliceToken, map[string]any{"key": key, "decision": map[string]any{"deny": false}})
	server.call(server.bobToken, map[string]any{"key": key, "decision": map[string]any{"deny": false}})
	server.newKey(alice)
	server.call(server.aliceToken, map[string]any{"key": key, "decision": map[string]any{"deny": false}})
	if server.keyID(alice) != "" {
		t.Fatal("a later denial must remove the account's new key too")
	}
	root := server.root
	sessionKey := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: "process-1"}
	want := []foreignHookPublished{
		{root, alice, sessionKey, true, ""},
		{root, alice, sessionKey, true, ""},
		{root, bob, sessionKey, false, bobKey},
		{root, alice, sessionKey, true, ""},
	}
	if len(writes) != len(want) {
		t.Fatalf("published %+v, want %+v", writes, want)
	}
	for i := range want {
		if writes[i] != want[i] {
			t.Fatalf("publish %d = %+v, want %+v", i, writes[i], want[i])
		}
	}
}

// Kill switch (GAP-0352): the gateway reads the account's record key before
// the guardian's removals, both under the account's lock. A removal that
// still lands between the two (one whose drain wait ran out) rotated the
// key first, so the exchange reads its ledger and is denied, the denial is
// published after the gateway removed the account's key, and the allow
// published under the earlier key proves nothing any more.
func TestForeignHookSessionGatewayReadsTheKeyBeforeTheRemovals(t *testing.T) {
	var writes []foreignHookPublished
	server := newForeignHookPublishTestServer(t, foreignHookRecorder(&writes, nil))
	early := runtime.GOOS + ":b:1:100"
	allow := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-1", "process": early}, "decision": map[string]any{"deny": false}}
	first := server.keyID(server.alice)
	if got := server.call(server.aliceToken, allow); got.Deny {
		t.Fatalf("no ledger allows: %+v", got)
	}
	if len(writes) != 1 || writes[0].deny || writes[0].keyID != first || first == "" {
		t.Fatalf("the allow carries the key read under the lock (%s): %+v", first, writes)
	}
	previousKey := foreignHookSessionKey
	foreignHookSessionKey = func(r, identity string) (enterprisepolicy.SessionRecordKey, error) {
		key, err := previousKey(r, identity)
		foreignHookSessionKey = previousKey
		server.guardian(server.alice, "/home/alice/.claude/settings.json")
		return key, err
	}
	t.Cleanup(func() { foreignHookSessionKey = previousKey })
	if got := server.call(server.aliceToken, allow); !got.Deny || !strings.Contains(got.Reason, "started before DefenseClaw removed") {
		t.Fatalf("an exchange that read the key before the guardian's removal reads the new ledger and is denied: %+v", got)
	}
	if last := writes[len(writes)-1]; len(writes) != 2 || !last.deny || last.keyID != "" || server.keyID(server.alice) != "" {
		t.Fatalf("the denial is published after a kill: %+v (key %q)", writes, server.keyID(server.alice))
	}
	server.newKey(server.alice)
	if current := server.keyID(server.alice); current == first {
		t.Fatalf("the allow's key %s is still current", first)
	}
	if got := server.call(server.aliceToken, allow); !got.Deny || !strings.Contains(got.Reason, "started before DefenseClaw removed") {
		t.Fatalf("the next exchange must be denied: %+v", got)
	}
}

// foreignHookPublishTestServer is a standalone user-scoped gateway with two
// enrolled accounts whose protected-record writes go to publish. Each
// account has a key in its record folder that the test account made.
type foreignHookPublishTestServer struct {
	alice, bob           string
	aliceToken, bobToken string
	guardianDir          string
	dataDir              string
	root                 string
	api                  *APIServer
	call                 func(token string, update map[string]any) enterprisepolicy.GuardDecision
	t                    *testing.T
}

// keyID names identity's current record key ("" for none).
func (s *foreignHookPublishTestServer) keyID(identity string) string {
	key, err := enterprisepolicy.ReadPublishedSessionKey(s.root, identity)
	if err != nil {
		return ""
	}
	return key.ID()
}

// newKey gives identity a key when it has none, as the guardian does at
// every pass.
func (s *foreignHookPublishTestServer) newKey(identity string) {
	s.t.Helper()
	if err := enterprisepolicy.EnsurePublishedSessionKey(s.root, identity, foreignHookTestTrust); err != nil {
		s.t.Fatal(err)
	}
	if s.keyID(identity) == "" {
		s.t.Fatalf("%s has no key", identity)
	}
}

// encode is a removal ledger with one removal of identity's file.
func (s *foreignHookPublishTestServer) encode(identity, file string) []byte {
	s.t.Helper()
	now := time.Now().UTC()
	data, err := enterprisepolicy.EncodeForeignHookRemovals(nil, []enterprisepolicy.ForeignHookRemoval{{
		Identity: identity, Connector: "claudecode", Path: file, At: now.Format(time.RFC3339), Mark: runtime.GOOS + ":b:200",
	}}, now)
	if err != nil {
		s.t.Fatal(err)
	}
	return data
}

// ledger replaces the removal ledger with one removal of identity's file.
func (s *foreignHookPublishTestServer) ledger(identity, file string) {
	s.t.Helper()
	path := filepath.Join(s.guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	if err := os.WriteFile(path+".tmp", s.encode(identity, file), 0o640); err != nil {
		s.t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		s.t.Fatal(err)
	}
}

// guardian records a removal the way the guardian's commit does, without
// the account's lock (the caller holds it, or its drain wait ran out): the
// account's key is rotated first, then the ledger is written.
func (s *foreignHookPublishTestServer) guardian(identity, file string) {
	s.t.Helper()
	if err := enterprisepolicy.RotatePublishedSessionKey(s.root, identity, foreignHookTestTrust); err != nil {
		s.t.Fatal(err)
	}
	s.ledger(identity, file)
}

// direct runs one exchange of identity straight into the handler, writing
// to w (no token: the identity is the verified caller).
func (s *foreignHookPublishTestServer) direct(w http.ResponseWriter, identity string, update map[string]any) {
	s.t.Helper()
	data, err := json.Marshal(update)
	if err != nil {
		s.t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", bytes.NewReader(data))
	ctx := withAuthenticatedHookConnector(req.Context(), "claudecode")
	ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
	s.api.handleForeignHookSession(w, req.WithContext(ctx))
}

func newForeignHookPublishTestServer(t *testing.T, publish func(string, string, enterprisepolicy.SessionKey, enterprisepolicy.GuardDecision, enterprisepolicy.SessionRecordKey, time.Time) error) *foreignHookPublishTestServer {
	t.Helper()
	root := filepath.Join(t.TempDir(), "sessions")
	if err := os.Mkdir(root, 0o711); err != nil {
		t.Fatal(err)
	}
	server := &foreignHookPublishTestServer{root: root, t: t}
	ledger := &userScopedTestLedger{}
	alice, bob := "1001", "1002"
	if runtime.GOOS == "windows" {
		alice, bob = "S-1-5-21-1111-2222-3333-1001", "S-1-5-21-1111-2222-3333-1002"
		ledger.set(
			managedHookLedgerTarget{User: "alice", SID: alice, Connector: "claudecode", OK: true},
			managedHookLedgerTarget{User: "bob", SID: bob, Connector: "claudecode", OK: true},
		)
	} else {
		ledger.set(
			managedHookLedgerTarget{User: "alice", UID: userScopedTestUID(1001), Connector: "claudecode", OK: true},
			managedHookLedgerTarget{User: "bob", UID: userScopedTestUID(1002), Connector: "claudecode", OK: true},
		)
	}
	server.alice, server.bob = alice, bob
	server.guardianDir = foreignHookGuardianDirForTest(t)
	// The gateway accepts only root's, SYSTEM's or Administrators' keys; the
	// test account made these.
	restoreOwner := enterprisepolicy.OverridePublishedSessionKeyOwnerForTest(func(path string) (bool, error) {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return info.Mode().IsRegular(), nil
	})
	previousPublish, previousKey, previousKill := foreignHookSessionPublish, foreignHookSessionKey, foreignHookSessionKill
	previousDataDirRoot := foreignHookSessionRootForDataDir
	// The test's data directory names the test's record folder.
	foreignHookSessionRootForDataDir = func(string) (string, bool) { return root, true }
	foreignHookSessionPublish = publish
	t.Cleanup(func() {
		restoreOwner()
		foreignHookSessionPublish, foreignHookSessionKey, foreignHookSessionKill = previousPublish, previousKey, previousKill
		foreignHookSessionRootForDataDir = previousDataDirRoot
	})
	server.newKey(alice)
	server.newKey(bob)
	api, _, _ := newUserScopedTestServer(t, true, ledger, map[string]string{alice: "alice", bob: "bob"})
	if api.scannerCfg == nil || !api.scannerCfg.StandaloneEnterprise() {
		t.Skip("the user-scoped test server is not a standalone deployment")
	}
	server.api = api
	server.dataDir = api.configDataDir()
	handler := api.tokenAuth(api.managedHookSocketMux())
	aliceToken := userScopedTestToken(t, connector.UserScopedHookCredential, "claudecode", alice)
	bobToken := userScopedTestToken(t, connector.UserScopedHookCredential, "claudecode", bob)
	server.aliceToken, server.bobToken = aliceToken, bobToken
	peerUIDs := map[string]int{aliceToken: 1001, bobToken: 1002}
	server.call = func(token string, update map[string]any) enterprisepolicy.GuardDecision {
		t.Helper()
		data, err := json.Marshal(update)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", bytes.NewReader(data))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "foreign-hook-guard/1.0")
		req.Header.Set("Authorization", "Bearer "+token)
		req = req.WithContext(context.WithValue(req.Context(), acpConnPeerKey{}, &acpConnPeer{uid: peerUIDs[token], known: true}))
		// Every gateway listener's connection can bound a write; an allow
		// is refused on one that cannot.
		response := newDeadlineRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("exchange: %d %s", response.Code, response.Body.String())
		}
		var decision enterprisepolicy.GuardDecision
		if err := json.Unmarshal(response.Body.Bytes(), &decision); err != nil {
			t.Fatalf("exchange answer %q: %v", response.Body.String(), err)
		}
		return decision
	}
	return server
}

// Review P1 (1.0.4 guard loop round 1, finding 1): the record folder is the
// one the gateway's data directory names, a function of its configuration
// alone, so the gateway always finds again a folder it published an allow
// to. A gateway whose data directory names none publishes nothing at all,
// allow or block, and removes no key: no allow of it exists that it could
// later fail to find and revoke, and the hook finds no record and blocks
// during an outage. Its online answers are its own. A record folder whose
// key cannot be read is published to without a key, so that allow proves
// nothing during an outage.
func TestForeignHookSessionGatewayPublishesOnlyWhereItsDataDirectoryNamesTheFolder(t *testing.T) {
	var writes []foreignHookPublished
	server := newForeignHookPublishTestServer(t, foreignHookRecorder(&writes, nil))
	var kills []string
	previousKill := foreignHookSessionKill
	foreignHookSessionKill = func(r, identity string) error {
		kills = append(kills, r+"|"+identity)
		return previousKill(r, identity)
	}
	named := false
	foreignHookSessionRootForDataDir = func(dataDir string) (string, bool) {
		return server.root, named && dataDir == server.dataDir
	}
	process := runtime.GOOS + ":b:1:500"
	if got := server.call(server.aliceToken, foreignHookTestCall("s-1", process, false)); got.Deny {
		t.Fatalf("the online answer is the gateway's own: %+v", got)
	}
	if got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-2", process)); !got.Deny {
		t.Fatalf("the session start that found the hook is blocked: %+v", got)
	}
	if len(writes) != 0 || len(kills) != 0 {
		t.Fatalf("a gateway whose data directory names no record folder publishes and removes nothing: %+v %v", writes, kills)
	}
	key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: process}
	if _, err := enterprisepolicy.CheckPublishedForeignHookSession(server.root, server.alice, key, enterprisepolicy.GuardDecision{}, func(string) error { return nil }); err == nil {
		t.Fatal("no record of this gateway may prove a process during an outage")
	}
	named = true
	other := runtime.GOOS + ":b:2:500"
	if got := server.call(server.aliceToken, foreignHookTestCall("s-3", other, false)); got.Deny || len(writes) != 1 || writes[0].root != server.root ||
		writes[0].keyID == "" || writes[0].keyID != server.keyID(server.alice) {
		t.Fatalf("where its data directory names the folder, the allow is published there with the key: %+v %+v", got, writes)
	}
	foreignHookSessionKey = func(string, string) (enterprisepolicy.SessionRecordKey, error) {
		return enterprisepolicy.SessionRecordKey{}, errors.New("the key file is not root's")
	}
	if got := server.call(server.aliceToken, foreignHookTestCall("s-3", other, false)); got.Deny || len(writes) != 2 || writes[1].keyID != "" {
		t.Fatalf("without a key the allow is published without one: %+v %+v", got, writes)
	}
}

// foreignHookPublishTestBlock is a session start of process in session that
// found an unapproved project hook.
func foreignHookPublishTestBlock(session, process string) map[string]any {
	return map[string]any{"key": map[string]any{"connector": "claudecode", "session": session, "process": process}, "session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: project hook",
			"findings": []map[string]any{{"connector": "claudecode", "scope": "project", "path": "/repo/.claude/settings.json", "digest": "abcd"}}}}
}

// foreignHookTestStoreRecord is the private session store record of one key
// part (enterprisepolicy sessionPathInDir).
func foreignHookTestStoreRecord(dataDir, identity, connectorName, kind, id string) string {
	digest := sha256.Sum256([]byte(connectorName + "\x00" + kind + "\x00" + id))
	return filepath.Join(enterprisepolicy.ForeignHookSessionStoreDir(dataDir, identity), kind+"-"+hex.EncodeToString(digest[:])[:40]+".json")
}

// Kill switch (round 2 and 3 scenarios): the exchange that records a block
// in the gateway's private store removes the account's record key first,
// under the account's lock. A gateway that stops after the store write and
// before it publishes the block (here: the publication is lost), or whose
// publication fails, leaves no allow the hook would honor during the
// outage: the earlier allow carries the removed key. An exchange that
// records no block removes nothing, and the gateway, back, denies from its
// store and publishes the block.
func TestForeignHookSessionGatewayKillsTheKeyBeforeItRecordsABlock(t *testing.T) {
	var writes []foreignHookPublished
	lost := false
	server := newForeignHookPublishTestServer(t, func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey, _ time.Time) error {
		if lost {
			return errors.New("the gateway stopped")
		}
		writes = append(writes, foreignHookPublished{r, identity, key, decision.Deny, recordKey.ID()})
		return nil
	})
	kills := 0
	previousKill := foreignHookSessionKill
	blockedRecord := foreignHookTestStoreRecord(server.dataDir, server.alice, "claudecode", "s", "s-2")
	foreignHookSessionKill = func(r, identity string) error {
		kills++
		if r != server.root || identity != server.alice {
			t.Errorf("killed the key of %s under %s, want %s under %s", identity, r, server.alice, server.root)
		}
		if _, err := os.Lstat(blockedRecord); kills == 1 && !errors.Is(err, fs.ErrNotExist) {
			t.Error("the block must not be in the private store before the key is removed")
		}
		return previousKill(r, identity)
	}
	process := map[string]any{"connector": "claudecode", "session": "s-1", "process": "process-1"}
	if got := server.call(server.aliceToken, map[string]any{"key": process, "session_start": true, "decision": map[string]any{"deny": false}}); got.Deny {
		t.Fatalf("a clean session start is allowed: %+v", got)
	}
	allowedUnder := server.keyID(server.alice)
	if kills != 0 || len(writes) != 1 || writes[0].deny || writes[0].keyID != allowedUnder {
		t.Fatalf("a clean exchange publishes its allow and removes nothing: %d %+v", kills, writes)
	}
	lost = true
	if got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-2", "process-1")); !got.Deny {
		t.Fatalf("the session start that found the hook is blocked: %+v", got)
	}
	if kills != 1 || server.keyID(server.alice) != "" {
		t.Fatalf("the key the earlier allow carries must be gone before the block (%d kills, key %q)", kills, server.keyID(server.alice))
	}
	if _, err := os.Lstat(blockedRecord); err != nil {
		t.Fatalf("the block is in the private store: %v", err)
	}
	lost = false
	server.newKey(server.alice)
	if got := server.call(server.aliceToken, map[string]any{"key": process, "decision": map[string]any{"deny": false}}); !got.Deny {
		t.Fatalf("the gateway, back, denies from its store: %+v", got)
	}
	if last := writes[len(writes)-1]; !last.deny || last.keyID != "" || server.keyID(server.alice) != "" {
		t.Fatalf("the block is published after a kill: %+v (key %q)", last, server.keyID(server.alice))
	}
}
