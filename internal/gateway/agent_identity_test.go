// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

func agentIdentityTestSetup(t *testing.T) {
	t.Helper()
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	setAgentIdentityConfig(nil)
	t.Cleanup(func() { setAgentIdentityConfig(nil) })
	InstallSharedAgentRegistry("", "")
}

// GAP-0097: an agent identity records the account as the host names it, so
// an SSSD account keeps its qualified name for the admin views.
func TestHookAgentIdentityKeepsQualifiedAccountName(t *testing.T) {
	agentIdentityTestSetup(t)
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 4545, Name: "dcad-alice@dclab.test", Home: t.TempDir()})
	facts := resolveHookAgentIdentity(peer, agentHookRequest{ConnectorName: "codex"})
	if facts.ID == "" || facts.UserName != "dcad-alice@dclab.test" {
		t.Fatalf("agent identity = %q user %q, want the qualified account name", facts.ID, facts.UserName)
	}

	// GAP-0107: a per-user gateway names itself from the same account
	// database, the bare Windows account rather than os/user's DOMAIN\user.
	restoreName := userScopedIdentityName
	userScopedIdentityName = func(id string) string {
		if id == "4646" {
			return "dcad-bob@dclab.test"
		}
		return "dcw-std1"
	}
	gatewaySelf.once = sync.Once{}
	t.Cleanup(func() { userScopedIdentityName, gatewaySelf.once = restoreName, sync.Once{} })
	if self := gatewaySelfUser(); self.Name != "dcw-std1" {
		t.Fatalf("gateway self user = %q, want the account database name", self.Name)
	}

	// GAP-0103: a row an older build stored with the bare name reads with
	// the host's name for its uid.
	stored := []inventory.AgentIdentityRecord{{AgentID: "agt-00000000000000b0", UserID: "4646", UserName: "dcad-bob", Connector: "claudecode"}}
	rows := mergeAgentIdentityRows(stored, nil, nil, inventory.AgentIdentityFilter{})
	if nameAgentIdentityRows(rows); len(rows) != 1 || rows[0].UserName != "dcad-bob@dclab.test" {
		t.Fatalf("listed rows = %+v, want the host's account name", rows)
	}
	// GAP-0278: the IDE plugin rows of the same account read the same.
	plugins := []inventory.IDEPlugin{{UserID: "4646", UserName: "dcad-bob"}}
	installs := []inventory.IDEInstallation{{UserID: "4646", UserName: "dcad-bob"}}
	if nameIDERows(plugins, installs); plugins[0].UserName != "dcad-bob@dclab.test" || installs[0].UserName != "dcad-bob@dclab.test" {
		t.Fatalf("IDE rows = %+v %+v, want the host's account name", plugins, installs)
	}
}

// GAP-0947: a uid handed to a new account, even with the removed account's
// home, gets new agent identities. The listing keeps the removed account's
// identity under its own name, retired, and an inventory record of that
// account names no agent identity.
func TestAgentIdentityDoesNotCrossAUIDReassignment(t *testing.T) {
	agentIdentityTestSetup(t)
	home, holder := t.TempDir(), "o3x"
	restoreName, restoreAccount, restoreHome := userScopedIdentityName, agentIdentityAccountName, userScopedIdentityHome
	t.Cleanup(func() {
		userScopedIdentityName, agentIdentityAccountName, userScopedIdentityHome = restoreName, restoreAccount, restoreHome
	})
	userScopedIdentityName = func(id string) string { return map[string]string{"2301": holder}[id] }
	agentIdentityAccountName = userScopedIdentityName
	userScopedIdentityHome = func(string) string { return home }
	hook := func(name string) agentIdentityFacts {
		peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 2301, Name: name, Home: home})
		return resolveHookAgentIdentity(peer, agentHookRequest{ConnectorName: "claudecode"})
	}
	removed := hook("o3x")
	holder = "o3y"
	reused := hook("o3y")
	if removed.ID == "" || reused.ID == removed.ID {
		t.Fatalf("agent identity after the uid was reassigned = %q, removed account's %q; want a new one", reused.ID, removed.ID)
	}
	record := func(facts agentIdentityFacts, name string) inventory.AgentIdentityRecord {
		return inventory.AgentIdentityRecord{AgentID: facts.ID, UserID: facts.UserID, UserName: name,
			Connector: facts.Connector, InstallFP: facts.InstallFP, MachineHash: facts.MachineHash}
	}
	for _, name := range []string{"o3x", ""} {
		rows := mergeAgentIdentityRows([]inventory.AgentIdentityRecord{record(removed, name), record(reused, "o3y")},
			nil, nil, inventory.AgentIdentityFilter{})
		nameAgentIdentityRows(rows)
		for _, row := range rows {
			if want := row.AgentID == removed.ID; row.Retired != want || want && row.UserName != name || !want && row.UserName != "o3y" {
				t.Fatalf("recorded as %q: listed %+v, want only the removed account's identity retired under its own name", name, row)
			}
		}
	}
	if got := inventoryAgentIdentityID("claudecode", "2301", "o3x"); got != "" {
		t.Fatalf("inventory record of the removed account names agent identity %q, want none", got)
	}
	if got := inventoryAgentIdentityID("claudecode", "2301", "o3y"); got != reused.ID {
		t.Fatalf("inventory record of the uid's account names %q, want %q", got, reused.ID)
	}

	// GAP-1222: the account is deleted, leaving uid 2301 to no account, and
	// its name is re-hired under uid 2302. The new account gets identities of
	// its own; once the guardian keeps no identity record for uid 2301 the
	// old identity is retired, both listed under the name. A gateway without
	// a guardian retires none.
	names := map[string]string{"2302": "o3x"}
	userScopedIdentityName = func(id string) string { return names[id] }
	agentIdentityAccountName = userScopedIdentityName
	rehiredPeer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 2302, Name: "o3x", Home: home})
	rehired := resolveHookAgentIdentity(rehiredPeer, agentHookRequest{ConnectorName: "claudecode"})
	if rehired.ID == "" || rehired.ID == removed.ID {
		t.Fatalf("re-hired account's agent identity = %q, deleted account's %q; want a new one", rehired.ID, removed.ID)
	}
	list := func() []agentIdentityRow {
		rows := mergeAgentIdentityRows([]inventory.AgentIdentityRecord{record(removed, "o3x"), record(rehired, "o3x")},
			nil, nil, inventory.AgentIdentityFilter{})
		nameAgentIdentityRows(rows)
		return rows
	}
	restoreSpool := currentIdentitySpoolDir()
	t.Cleanup(func() { setIdentitySpoolDir(restoreSpool) })
	for _, spool := range []string{"", t.TempDir()} {
		setIdentitySpoolDir(spool)
		for _, row := range list() {
			if want := spool != "" && row.AgentID == removed.ID; row.Retired != want || row.UserName != "o3x" {
				t.Fatalf("guardian spool %q: listed %+v; want only the deleted account's identity retired, both as o3x", spool, row)
			}
		}
	}
}

// The agent identity comes from verified facts only: forged identity headers
// and a claimed config dir in the payload change neither it nor the session
// instance, which is keyed by (agent identity, session) and survives a
// restart. A sub-agent sharing its parent's session gets a derived instance.
func TestHookAgentIdentityIgnoresClaimsAndKeysInstances(t *testing.T) {
	agentIdentityTestSetup(t)
	restoreAccount := agentIdentityAccountName
	agentIdentityAccountName = func(id string) string { return map[string]string{"4242": "alice", "4343": "bob"}[id] }
	t.Cleanup(func() { agentIdentityAccountName = restoreAccount })
	home := t.TempDir()
	alice := withManagedHookPeer(context.Background(), managedHookPeer{UID: 4242, Name: "alice", Home: home})
	req := agentHookRequest{
		ConnectorName: "claudecode", SessionID: "sess-shared", HookEventName: "PreToolUse",
		CorrelationProfileVersion: connector.CorrelationProfileClaudeCodeV1,
		Payload:                   map[string]interface{}{},
	}
	first := agentIdentityForGenericHook(alice, req)

	machine, machineVerified := agentidentity.HostMachineHash()
	want := agentidentity.AgentID(agentidentity.Inputs{
		MachineHash: machine, UserID: "4242", Account: "alice", Connector: "claudecode", InstallFP: filepath.Join(home, ".claude"),
	})
	if first.IdentityID == "" || first.IdentityID != want || first.IdentityVerified != machineVerified {
		t.Fatalf("identity = %q verified=%v, want %q verified=%v", first.IdentityID, first.IdentityVerified, want, machineVerified)
	}
	if id, verified := agentIdentityFromContext(ContextWithAgentIdentity(context.Background(), first)); id != want || verified != machineVerified {
		t.Fatalf("agentIdentityFromContext = %q, %v", id, verified)
	}
	if first.AgentInstanceID != agentidentity.InstanceID(want, "sess-shared") {
		t.Fatalf("instance = %q, want ais- derived from (agent, session)", first.AgentInstanceID)
	}

	// Forged headers and a claimed config root move nothing; the claim is
	// kept as a hint.
	claimed := ContextWithAgentIdentity(alice, AgentIdentity{UserID: "999", UserName: "mallory"})
	claimedReq := req
	claimedReq.Payload = map[string]interface{}{
		"transcript_path": "/srv/elsewhere/.claude/projects/p/s.jsonl",
	}
	again := agentIdentityForGenericHook(claimed, claimedReq)
	if again.IdentityID != want || again.AgentInstanceID != first.AgentInstanceID {
		t.Fatalf("claims moved the identity: %q/%q, want %q/%q", again.IdentityID, again.AgentInstanceID, want, first.AgentInstanceID)
	}
	if _, hints := sharedAgentIdentities.snapshot(); hints[want] != "/srv/elsewhere/.claude" {
		t.Fatalf("install hint = %q", hints[want])
	}

	// Another user sending the same session id gets another instance.
	bob := withManagedHookPeer(context.Background(), managedHookPeer{UID: 4343, Name: "bob", Home: t.TempDir()})
	if other := agentIdentityForGenericHook(bob, req); other.AgentInstanceID == first.AgentInstanceID || other.IdentityID == want {
		t.Fatalf("two users collided on one session: %+v", other)
	}

	// A restarted gateway derives the same instance.
	restarted, minted := NewAgentRegistry("", "").ResolveForAgentIdentity(alice, want, "sess-shared", "")
	if !minted || restarted.AgentInstanceID != first.AgentInstanceID {
		t.Fatalf("instance after restart = %q, want %q", restarted.AgentInstanceID, first.AgentInstanceID)
	}

	// An agent id correlation minted for the main agent (not in the
	// payload) keeps the session's instance.
	mintedAgent := req
	mintedAgent.AgentID = "019a0000-0000-7000-8000-000000000001"
	if got := agentIdentityForGenericHook(alice, mintedAgent).AgentInstanceID; got != first.AgentInstanceID {
		t.Fatalf("minted agent id moved the instance: %q, want %q", got, first.AgentInstanceID)
	}

	sub := req
	sub.AgentID = "subagent-1"
	sub.Payload = map[string]interface{}{"agent_id": "subagent-1"}
	if got := agentIdentityForGenericHook(alice, sub).AgentInstanceID; got != agentidentity.SubagentInstanceID(first.AgentInstanceID, "subagent-1") {
		t.Fatalf("sub-agent instance = %q", got)
	}

	// Codex names the sub-agent on every hook of it, not only on its start
	// and stop, so a tool call of the sub-agent has the sub-agent's instance
	// too (GAP-0137).
	codexMain := agentHookRequest{
		ConnectorName: "codex", SessionID: "sess-codex", HookEventName: "PreToolUse",
		Payload: map[string]interface{}{},
	}
	codexSub := codexMain
	codexSub.AgentID = "thread-sub"
	codexSub.Payload = map[string]interface{}{"agent_id": "thread-sub"}
	mainInstance := agentIdentityForGenericHook(alice, codexMain).AgentInstanceID
	if got := agentIdentityForGenericHook(alice, codexSub).AgentInstanceID; got == mainInstance ||
		got != agentidentity.SubagentInstanceID(mainInstance, "thread-sub") {
		t.Fatalf("codex sub-agent tool call instance = %q, main %q", got, mainInstance)
	}

	rec := httptest.NewRecorder()
	(&APIServer{}).handleAgentIdentities(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agents/identities?user=alice&connector=claudecode", nil))
	var body struct {
		Enabled    bool               `json:"enabled"`
		Identities []agentIdentityRow `json:"identities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || !body.Enabled {
		t.Fatalf("identities response %d %s", rec.Code, rec.Body.String())
	}
	found := false
	for _, row := range body.Identities {
		if row.AgentID == want {
			found = row.UserID == "4242" && row.InstallHint == "/srv/elsewhere/.claude" && row.SessionsSeen >= 1
		}
		if row.UserID != "4242" {
			t.Fatalf("user filter returned %+v", row)
		}
	}
	if !found {
		t.Fatalf("identity %s missing from %+v", want, body.Identities)
	}
}

// A session id is caller supplied. A shared gateway cannot use it to
// attribute a different user's hook identity to the current caller.
func TestSharedGatewaySessionJoinDoesNotCrossUsers(t *testing.T) {
	agentIdentityTestSetup(t)
	registry := SharedAgentRegistry()
	owner := withManagedHookPeer(t.Context(), managedHookPeer{UID: 4242, Name: "bob"})
	identity := agentIdentityForGenericHook(owner, agentHookRequest{
		ConnectorName: "codex", SessionID: "thread-bob", HookEventName: "PreToolUse",
		Payload: map[string]interface{}{},
	})
	if identity.IdentityID == "" || identity.AgentInstanceID == "" {
		t.Fatalf("hook identity = %+v", identity)
	}
	caller := withManagedHookPeer(withServiceAccountGateway(ContextWithSessionID(t.Context(), "thread-bob")),
		managedHookPeer{UID: 4343, Name: "alice"})
	if got := agentIdentityIDForTraffic(caller, AgentIdentity{}); got != "" {
		t.Fatalf("joined another user's identity %q", got)
	}
	if got := registry.ResolvePeek(caller, "thread-bob", "").AgentInstanceID; got != "" {
		t.Fatalf("peeked another user's instance %q", got)
	}
	if got := registry.Resolve(caller, "thread-bob", "").AgentInstanceID; got != "" {
		t.Fatalf("minted another user's instance %q", got)
	}
	joined := withSessionAgentInstance(caller, "thread-bob")
	if got := audit.EnvelopeFromContext(joined).AgentInstanceID; got != "" {
		t.Fatalf("joined another user's instance %q", got)
	}
	if got := registry.AgentIdentityForSession(owner, "thread-bob"); got != identity.IdentityID {
		t.Fatalf("hook session identity = %q, want %q", got, identity.IdentityID)
	}
}

// The session registry is in memory, so a session resumed after a gateway
// restart is minted again; it is not counted twice. Doctor's hook probe is
// not agent use and is not recorded (GAP-0086).
func TestAgentIdentitySessionsSurviveRestartAndSkipDoctorProbe(t *testing.T) {
	agentIdentityTestSetup(t)
	store, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	recorder := &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	facts := agentIdentityFacts{ID: "agt-00000000000000c1", UserID: "4545", Connector: "claudecode", MachineHash: "m"}
	// Two sessions are open when the gateway restarts (GAP-0139).
	recorder.observe(facts, "sess-a", true)
	recorder.observe(facts, "sess-b", true)
	if err := recorder.flush(ctx, store); err != nil {
		t.Fatal(err)
	}
	// After the restart both are resumed, one of them twice, and a third starts.
	recorder.observe(facts, "sess-a", true)
	recorder.observe(facts, "sess-b", true)
	recorder.observe(facts, "sess-a", false)
	recorder.observe(facts, "sess-c", true)
	// The previous chat hooks once more after the new one started, as Codex's
	// does after /new: the last session stays the newest (GAP-0395).
	recorder.observe(facts, "sess-b", false)
	if err := recorder.flush(ctx, store); err != nil {
		t.Fatal(err)
	}
	if rows, _, err := store.ListAgentIdentities(ctx, inventory.AgentIdentityFilter{}); err != nil || len(rows) != 1 ||
		rows[0].SessionsSeen != 3 || rows[0].LastSessionID != "sess-c" {
		t.Fatalf("stored rows = %+v, err %v; want 3 sessions, last sess-c", rows, err)
	}

	dave := withManagedHookPeer(ctx, managedHookPeer{UID: 4646, Name: "dave", Home: t.TempDir()})
	probe := agentIdentityForGenericHook(dave, agentHookRequest{
		ConnectorName: "claudecode", SessionID: doctorProbeSessionID, HookEventName: "SessionStart",
		Payload: map[string]interface{}{},
	})
	if pending, _ := sharedAgentIdentities.snapshot(); probe.IdentityID == "" || pending[probe.IdentityID].AgentID != "" {
		t.Fatalf("doctor probe recorded identity %q: %+v", probe.IdentityID, pending[probe.IdentityID])
	}
}

// A child can hook before its parent link is known and the inventory flush can
// complete before that link arrives. The persisted ledger must retract it.
func TestAgentIdentityLateChildLinkCorrectsFlushedSession(t *testing.T) {
	store, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	recorder := &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	facts := agentIdentityFacts{ID: "agt-late-child", UserID: "1001", Connector: "codex", MachineHash: "m"}
	recorder.observe(facts, "a-parent", true)
	recorder.observe(facts, "b-parent", true)
	recorder.observe(facts, "z-child", true)
	if err := recorder.flush(ctx, store); err != nil {
		t.Fatal(err)
	}
	recorder.markSubagentSession(facts.ID, "z-child")
	recorder.markSubagentSession(facts.ID, "z-child")
	if err := recorder.flush(ctx, store); err != nil {
		t.Fatal(err)
	}
	rows, _, err := store.ListAgentIdentities(ctx, inventory.AgentIdentityFilter{AgentIDs: []string{facts.ID}})
	if err != nil || len(rows) != 1 || rows[0].SessionsSeen != 2 || rows[0].LastSessionID != "b-parent" {
		t.Fatalf("late child link left stored rows = %+v, err %v; want two parent chats, last b-parent", rows, err)
	}
}

// GAP-0258: a Codex thread without a transcript (transcript_path null, the
// helper thread a managed install's hooks reach) is not counted as a session;
// a chat with a transcript is.
func TestCodexTranscriptlessThreadIsNotASession(t *testing.T) {
	agentIdentityTestSetup(t)
	prev := sharedAgentIdentities
	sharedAgentIdentities = &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	t.Cleanup(func() { sharedAgentIdentities = prev })
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 4747, Name: "erin", Home: t.TempDir()})
	hook := func(session string, transcript any) AgentIdentity {
		return agentIdentityForGenericHook(peer, agentHookRequest{
			ConnectorName: "codex", SessionID: session, HookEventName: "SessionStart",
			Payload: map[string]interface{}{"transcript_path": transcript},
		})
	}
	chat := hook("thread-chat", "/home/erin/.codex/sessions/rollout.jsonl")
	hook("thread-helper", nil)
	pending, _ := sharedAgentIdentities.snapshot()
	if rec := pending[chat.IdentityID]; rec.SessionsSeen != 1 || rec.LastSessionID != "thread-chat" {
		t.Fatalf("recorded %+v, want only the chat counted", rec)
	}
}

// A final flush must survive AI Discovery closing its store first.
func TestAgentIdentityFinalFlushAfterDiscoveryStoreCloses(t *testing.T) {
	agentIdentityTestSetup(t)
	dir := t.TempDir()
	store, err := inventory.NewInventoryStore(filepath.Join(dir, "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	recorder := &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	token := recorder.setStoreSource(func() *inventory.InventoryStore { return store }, func() string { return dir }, func() int { return 7 })
	recorder.observe(agentIdentityFacts{ID: "agt-final-flush", UserID: "1001", Connector: "codex", MachineHash: "m"}, "s-1", true)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	recorder.runFlusher(ctx, time.Hour, token)
	reopened, err := inventory.NewInventoryStore(filepath.Join(dir, "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	rows, _, err := reopened.ListAgentIdentities(context.Background(), inventory.AgentIdentityFilter{})
	if err != nil || len(rows) != 1 || rows[0].AgentID != "agt-final-flush" {
		t.Fatalf("final flush rows = %+v, err %v", rows, err)
	}
}

// GAP-0289: with AI discovery off the recorder's own inventory.db is pruned
// by last seen like discovery's history, so the ledger does not grow
// without bound.
func TestAgentIdentityLedgerPrunedWithDiscoveryOff(t *testing.T) {
	agentIdentityTestSetup(t)
	dir := t.TempDir()
	ctx := context.Background()
	recorder := &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	token := recorder.setStoreSource(func() *inventory.InventoryStore { return nil },
		func() string { return dir }, func() int { return 1 })
	t.Cleanup(func() { recorder.clearStoreSource(token) })
	now := time.Now().UTC()
	old := now.Add(-72 * time.Hour)
	store := recorder.store()
	if store == nil {
		t.Fatal("recorder opened no store")
	}
	if err := store.UpsertAgentIdentities(ctx, []inventory.AgentIdentityRecord{
		{AgentID: "agt-00000000000000d1", UserID: "4545", Connector: "codex", FirstSeen: old, LastSeen: old, SessionIDs: []string{"sess-old"}},
		{AgentID: "agt-00000000000000d2", UserID: "4545", Connector: "claudecode", FirstSeen: now, LastSeen: now, SessionIDs: []string{"sess-new"}},
	}); err != nil {
		t.Fatal(err)
	}
	clock := now
	recorder.ownSweep.Now = func() time.Time { return clock }
	recorder.sweepOwnStore(ctx) // starts the cadence
	clock = clock.Add(3 * time.Minute)
	recorder.sweepOwnStore(ctx)
	rows, _, err := store.ListAgentIdentities(ctx, inventory.AgentIdentityFilter{})
	if err != nil || len(rows) != 1 || rows[0].AgentID != "agt-00000000000000d2" {
		t.Fatalf("rows after the sweep = %+v, err %v; want only the identity seen now", rows, err)
	}
}

// GAP-0152: the route pages the stored and buffered identities instead of
// stopping silently at 1000 rows, and says how many there are.
func TestAgentIdentitiesRoutePages(t *testing.T) {
	agentIdentityTestSetup(t)
	store, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	prev := sharedAgentIdentities
	sharedAgentIdentities = &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	sharedAgentIdentities.setStoreSource(func() *inventory.InventoryStore { return store }, nil, nil)
	t.Cleanup(func() { sharedAgentIdentities = prev })
	base := time.Now().Add(-48 * time.Hour)
	batch := make([]inventory.AgentIdentityRecord, 0, agentIdentitiesPageLimit+1)
	for i := range agentIdentitiesPageLimit + 1 {
		batch = append(batch, inventory.AgentIdentityRecord{AgentID: fmt.Sprintf("agt-%016x", i), UserID: "4242",
			Connector: "claudecode", MachineHash: "m", LastSeen: base.Add(time.Duration(i) * time.Minute)})
	}
	if err := store.UpsertAgentIdentities(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	sharedAgentIdentities.observe(agentIdentityFacts{ID: "agt-ffffffffffffffff", UserID: "4242", Connector: "codex", MachineHash: "m"}, "s-1", true)
	// The oldest stored identity is seen again: it moves to the top and is
	// counted once.
	sharedAgentIdentities.observe(agentIdentityFacts{ID: "agt-0000000000000000", UserID: "4242", Connector: "claudecode", MachineHash: "m"}, "s-2", true)

	get := func(query string) (int, []agentIdentityRow, int, string) {
		rec := httptest.NewRecorder()
		(&APIServer{}).handleAgentIdentities(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agents/identities"+query, nil))
		var body struct {
			Identities []agentIdentityRow `json:"identities"`
			Total      int                `json:"total"`
			NextCursor string             `json:"next_cursor"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body.Identities, body.Total, body.NextCursor
	}
	code, rows, total, next := get("")
	if code != http.StatusOK || len(rows) != agentIdentitiesPageLimit || total != agentIdentitiesPageLimit+2 || next != "1000" ||
		rows[0].AgentID != "agt-0000000000000000" || rows[1].AgentID != "agt-ffffffffffffffff" {
		t.Fatalf("first page: %d, %d rows, total %d, next %q", code, len(rows), total, next)
	}
	// The last page, before and after the flush (the store pages then).
	for _, flushed := range []bool{false, true} {
		if flushed {
			if err := sharedAgentIdentities.flush(context.Background(), store); err != nil {
				t.Fatal(err)
			}
		}
		if code, rows, total, next := get("?cursor=1000&limit=5000"); code != http.StatusOK || len(rows) != 2 ||
			total != agentIdentitiesPageLimit+2 || next != "" || rows[1].AgentID != "agt-0000000000000001" {
			t.Fatalf("last page (flushed %v): %d, %+v, total %d, next %q", flushed, code, rows, total, next)
		}
	}
	if code, _, _, _ = get("?limit=0"); code != http.StatusBadRequest {
		t.Fatalf("limit=0 answered %d, want 400", code)
	}
}

// GAP-0380: a config root the agent claims is shown to an admin; control and
// bidi formatting characters in it are replaced, as ESC already was.
func TestClaimedInstallHintReplacesDisplayControls(t *testing.T) {
	hint := claimedInstallHint(map[string]interface{}{"config_dir": "/home/m/cfg-x\x1b[31mRED-\u202eend\u2066\u200f\u0085"})
	if hint != "/home/m/cfg-x [31mRED- end" {
		t.Fatalf("hint = %q, want controls and bidi characters replaced", hint)
	}
}

// GAP-0393: when inventory.db cannot be written, agent identities run from
// memory. The route says persisted false with the reason, and /health carries
// it for status and doctor.
func TestAgentIdentityLedgerWriteFailureIsReported(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a file mode the test user cannot write through")
	}
	agentIdentityTestSetup(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.db")
	store, err := inventory.NewInventoryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755); _ = os.Chmod(path, 0o644) })
	prev := sharedAgentIdentities
	sharedAgentIdentities = &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	token := sharedAgentIdentities.setStoreSource(func() *inventory.InventoryStore { return nil },
		func() string { return dir }, func() int { return 1 })
	t.Cleanup(func() { sharedAgentIdentities.clearStoreSource(token); sharedAgentIdentities = prev })
	sharedAgentIdentities.observe(agentIdentityFacts{ID: "agt-0000000000000393", UserID: "4393", Connector: "claudecode", MachineHash: "m"}, "s-1", true)

	rec := httptest.NewRecorder()
	(&APIServer{}).handleAgentIdentities(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agents/identities", nil))
	var body struct {
		Persisted    bool   `json:"persisted"`
		PersistError string `json:"persist_error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK || body.Persisted ||
		body.PersistError == "" {
		t.Fatalf("route = %d %s, want persisted false with the reason", rec.Code, rec.Body.String())
	}
	if ledger := agentIdentityLedgerHealth(); ledger == nil || ledger["persisted"] != false || ledger["error"] == "" {
		t.Fatalf("/health agent_identities = %v, want the write failure", ledger)
	}
}

// Under the Secure Client integration nothing changes: instances stay random
// UUIDs, no agent identity is derived or recorded, and the API reports the
// feature off.
func TestHookAgentIdentitySecureClientUnchanged(t *testing.T) {
	agentIdentityTestSetup(t)
	setManagedEnterpriseRedactionPosture(true)
	t.Cleanup(func() { setManagedEnterpriseRedactionPosture(false) })
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 4444, Name: "carol", Home: t.TempDir()})
	pendingBefore := sharedAgentIdentities.pendingCount()
	got := agentIdentityForGenericHook(ctx, agentHookRequest{ConnectorName: "claudecode", SessionID: "sess-sc", AgentID: "sub", HookEventName: "SubagentStart"})
	if got.IdentityID != "" || got.IdentityVerified {
		t.Fatalf("Secure Client derived an agent identity: %+v", got)
	}
	if _, err := uuid.Parse(got.AgentInstanceID); err != nil {
		t.Fatalf("Secure Client instance %q is not a UUID", got.AgentInstanceID)
	}
	if agentIdentityV8FromContext(ContextWithAgentIdentity(ctx, got)).IsPresent() {
		t.Fatalf("Secure Client record would carry defenseclaw.agent.identity.id")
	}
	if sharedAgentIdentities.pendingCount() != pendingBefore {
		t.Fatalf("Secure Client recorded an agent identity")
	}
	rec := httptest.NewRecorder()
	(&APIServer{}).handleAgentIdentities(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agents/identities", nil))
	if rec.Body.String() != "{\"enabled\":false,\"identities\":[]}\n" {
		t.Fatalf("Secure Client identities response = %q", rec.Body.String())
	}
}

func TestPerUserAgentIdentityIgnoresGatewayEnvironmentOverrides(t *testing.T) {
	agentIdentityTestSetup(t)
	self := agentIdentityUser{ID: "1001", Home: t.TempDir(), Self: true, Verified: true}
	for _, tc := range []struct{ connector, variable string }{
		{"claudecode", "CLAUDE_CONFIG_DIR"}, {"codex", "CODEX_HOME"},
		{"hermes", "HERMES_HOME"}, {"opencode", "OPENCODE_CONFIG_DIR"},
		{"omnigent", "OMNIGENT_CONFIG_HOME"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			t.Setenv(tc.variable, "")
			baseline := agentIdentityInstallFP(tc.connector, self)
			t.Setenv(tc.variable, t.TempDir())
			if got := agentIdentityInstallFP(tc.connector, self); got != baseline {
				t.Fatalf("gateway environment changed %s fingerprint: %q -> %q", tc.connector, baseline, got)
			}
		})
	}
}
