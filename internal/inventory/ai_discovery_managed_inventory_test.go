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

package inventory

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func managedInventoryReport() AIDiscoveryReport {
	return AIDiscoveryReport{
		Summary: AIDiscoverySummary{ScanID: "scan-managed"},
		Signals: []AISignal{
			{SignalID: "a", Category: SignalPackageDependency, State: AIStateNew},
			{SignalID: "b", Category: SignalPackageDependency, State: AIStateSeen},
			{SignalID: "c", Category: SignalPackageDependency, State: AIStateGone},
		},
	}
}

// TestManagedInventoryEmitHookTracksLiveModeTransitions pins the reload
// boundary without changing AI-discovery options: installing the callback on
// unmanaged->managed enables every later cadence, and clearing it on
// managed->unmanaged disables the cadence immediately.
func TestManagedInventoryEmitHookTracksLiveModeTransitions(t *testing.T) {
	var calls int
	service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{ManagedEnterprise: false}}

	service.fanoutReport(t.Context(), managedInventoryReport(), true)
	if calls != 0 {
		t.Fatalf("unmanaged cadence calls=%d want=0", calls)
	}

	service.SetManagedInventoryEmitHook(func(context.Context) { calls++ })
	service.fanoutReport(t.Context(), managedInventoryReport(), true)
	service.fanoutReport(t.Context(), managedInventoryReport(), true)
	if calls != 2 {
		t.Fatalf("managed cadences after live install=%d want=2", calls)
	}

	service.SetManagedInventoryEmitHook(nil)
	service.fanoutReport(t.Context(), managedInventoryReport(), true)
	if calls != 2 {
		t.Fatalf("unmanaged cadence after live clear=%d want=2", calls)
	}
}

// TestFanoutReport_ManagedSkipsNonFullTick pins the AI-Defense publish
// cadence: in managed_enterprise the fanout — both the canonical v8
// EmitReport (which carries the endpoint inventory to AI Defense) and
// the connector/MCP inventory hook — runs on the FULL-scan cadence
// only (ScanIntervalMin). The intra-cycle process-only tick
// (ProcessIntervalSec) is a local refresh and must not re-publish.
// Prior to this contract every process tick re-shipped the full
// endpoint inventory, flooding the AID event-ingest endpoint at
// ProcessIntervalSec cadence instead of ScanIntervalMin cadence.
func TestFanoutReport_ManagedSkipsNonFullTick(t *testing.T) {
	var hookCalls int
	capture := &captureAIDiscoveryV8{}
	service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{ManagedEnterprise: true}}
	service.BindObservabilityV8(capture)
	service.SetManagedInventoryEmitHook(func(context.Context) { hookCalls++ })

	service.fanoutReport(t.Context(), managedInventoryReport(), false)

	if hookCalls != 0 {
		t.Fatalf("non-full tick in managed_enterprise must not fire the connector/MCP inventory hook, got %d calls", hookCalls)
	}
	if len(capture.reports) != 0 {
		t.Fatalf("non-full tick in managed_enterprise must not publish an AI Defense report, got %d", len(capture.reports))
	}

	service.fanoutReport(t.Context(), managedInventoryReport(), true)
	if hookCalls != 1 {
		t.Fatalf("full tick in managed_enterprise must fire the hook exactly once, got %d", hookCalls)
	}
	if len(capture.reports) != 1 {
		t.Fatalf("full tick in managed_enterprise must publish one report, got %d", len(capture.reports))
	}
}

// TestFanoutReport_NonManagedIgnoresFullFlag pins that non-managed
// mode (live: no managedInventoryEmit hook installed) publishes on
// every tick regardless of full. The cadence gate must key on the
// live hook presence — not on any construction-time hint — so a
// service without a managed callback keeps feeding local v8 sinks on
// the intra-cycle process tick.
func TestFanoutReport_NonManagedIgnoresFullFlag(t *testing.T) {
	for _, full := range []bool{true, false} {
		full := full
		t.Run(map[bool]string{true: "full", false: "process"}[full], func(t *testing.T) {
			capture := &captureAIDiscoveryV8{}
			service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{ManagedEnterprise: false}}
			service.BindObservabilityV8(capture)
			// No managed hook installed => live unmanaged. Both tick kinds
			// must emit the v8 report to local sinks.
			service.fanoutReport(t.Context(), managedInventoryReport(), full)
			if len(capture.reports) != 1 {
				t.Fatalf("non-managed (no hook) must emit v8 report for full=%v, got %d", full, len(capture.reports))
			}
		})
	}
}

// TestFanoutReport_LiveTransitionsGateNonFullTick pins that the
// fanoutReport cadence gate follows the live managed-mode signal
// (hook presence), not the construction-time opts.ManagedEnterprise
// hint. On unmanaged->managed the process tick begins to skip
// immediately after SetManagedInventoryEmitHook is called; on
// managed->unmanaged the process tick resumes emitting as soon as
// the hook is cleared. Guards against drift when a config reload
// swaps the hook without rebuilding the discovery service.
func TestFanoutReport_LiveTransitionsGateNonFullTick(t *testing.T) {
	t.Run("unmanaged_to_managed_live_install_skips_non_full_tick", func(t *testing.T) {
		capture := &captureAIDiscoveryV8{}
		var hookCalls int
		// Construction-time opts flag is intentionally the OPPOSITE of
		// the live-managed target below, to prove the gate does not key
		// on it.
		service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{ManagedEnterprise: false}}
		service.BindObservabilityV8(capture)

		// Baseline: no hook (live unmanaged). Process tick emits.
		service.fanoutReport(t.Context(), managedInventoryReport(), false)
		if len(capture.reports) != 1 {
			t.Fatalf("baseline live-unmanaged process tick must emit v8 report, got %d", len(capture.reports))
		}

		// Live install: managed callback wired without a service
		// rebuild. Subsequent process ticks must skip both v8 emission
		// and the callback fire.
		service.SetManagedInventoryEmitHook(func(context.Context) { hookCalls++ })
		service.fanoutReport(t.Context(), managedInventoryReport(), false)
		if len(capture.reports) != 1 {
			t.Fatalf("after live managed install, process tick must skip v8 emission (still %d reports); got %d", 1, len(capture.reports))
		}
		if hookCalls != 0 {
			t.Fatalf("after live managed install, process tick must skip hook fire, got %d calls", hookCalls)
		}

		// Full-scan tick after live install must both emit and fire.
		service.fanoutReport(t.Context(), managedInventoryReport(), true)
		if len(capture.reports) != 2 {
			t.Fatalf("full tick after live managed install must emit v8 report, got %d", len(capture.reports))
		}
		if hookCalls != 1 {
			t.Fatalf("full tick after live managed install must fire hook once, got %d", hookCalls)
		}
	})

	t.Run("managed_to_unmanaged_live_clear_resumes_non_full_tick", func(t *testing.T) {
		capture := &captureAIDiscoveryV8{}
		var hookCalls int
		// Construction-time opts flag is intentionally the OPPOSITE of
		// the live-unmanaged target below.
		service := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{ManagedEnterprise: true}}
		service.BindObservabilityV8(capture)
		service.SetManagedInventoryEmitHook(func(context.Context) { hookCalls++ })

		// Baseline: hook installed (live managed). Process tick skips.
		service.fanoutReport(t.Context(), managedInventoryReport(), false)
		if len(capture.reports) != 0 || hookCalls != 0 {
			t.Fatalf("baseline live-managed process tick must skip: reports=%d hookCalls=%d", len(capture.reports), hookCalls)
		}

		// Live clear: hook removed without a service rebuild. Process
		// ticks must resume emitting the v8 report; no hook to fire.
		service.SetManagedInventoryEmitHook(nil)
		service.fanoutReport(t.Context(), managedInventoryReport(), false)
		if len(capture.reports) != 1 {
			t.Fatalf("after live managed clear, process tick must resume v8 emission, got %d", len(capture.reports))
		}
		if hookCalls != 0 {
			t.Fatalf("after live managed clear, hook must not fire, got %d calls", hookCalls)
		}
	})
}

func lifecycleTestSignal(fingerprint, user string) AISignal {
	return AISignal{
		Fingerprint: fingerprint, Category: SignalActiveProcess, Detector: "process",
		SignatureID: "claudecode", EvidenceHash: "h1", UserID: user, UserName: user,
	}
}

func lifecycleStates(t *testing.T, report AIDiscoveryReport) map[string]string {
	t.Helper()
	if detail := report.Summary.DetectorErrors["state_store"]; detail != "" {
		t.Fatalf("state store: %s", detail)
	}
	states := map[string]string{}
	for _, signal := range report.Signals {
		states[signal.Fingerprint] = signal.State
	}
	return states
}

// GAP-1738: in managed mode a process-only tick publishes nothing, so it must
// not persist what it classified; the next full scan reports the process as
// new (one discovered record) instead of seen.
func TestManagedProcessTickLeavesLifecycleToTheFullScan(t *testing.T) {
	service := &ContinuousDiscoveryService{
		opts:  AIDiscoveryOptions{Mode: "passive", ManagedEnterprise: true},
		store: NewAIStateStore(filepath.Join(t.TempDir(), "state.json")),
	}
	service.SetManagedInventoryEmitHook(func(context.Context) {})
	stats := func() scanStats {
		return scanStats{DetectorErrors: map[string]string{}, DetectorDurations: map[string]int{}}
	}
	load := func() aiStateFile {
		prev, err := service.store.Load()
		if err != nil {
			t.Fatal(err)
		}
		return prev
	}
	service.classifyAndPersist("full-1", "test", time.Now(), nil, stats(), load(), true)
	tick := service.classifyAndPersist("tick", "test", time.Now(),
		[]AISignal{lifecycleTestSignal("fp-claude", "dcw-std2")}, stats(), load(), false)
	if lifecycleStates(t, tick)["fp-claude"] != AIStateNew {
		t.Fatalf("tick states = %v", lifecycleStates(t, tick))
	}
	full := service.classifyAndPersist("full-2", "test", time.Now(),
		[]AISignal{lifecycleTestSignal("fp-claude", "dcw-std2")}, stats(), load(), true)
	if got := lifecycleStates(t, full)["fp-claude"]; got != AIStateNew || full.Summary.NewSignals != 1 {
		t.Fatalf("full scan after a managed process tick: state %q new %d", got, full.Summary.NewSignals)
	}

	// Without the managed hook the tick publishes and persists as before.
	service.SetManagedInventoryEmitHook(nil)
	service.classifyAndPersist("tick-2", "test", time.Now(),
		[]AISignal{lifecycleTestSignal("fp-claude", "dcw-std2"), lifecycleTestSignal("fp-hermes", "dcw-std1")}, stats(), load(), false)
	full = service.classifyAndPersist("full-3", "test", time.Now(),
		[]AISignal{lifecycleTestSignal("fp-claude", "dcw-std2"), lifecycleTestSignal("fp-hermes", "dcw-std1")}, stats(), load(), true)
	if got := lifecycleStates(t, full)["fp-hermes"]; got != AIStateSeen {
		t.Fatalf("unmanaged tick was not persisted: state %q", got)
	}
}

// GAP-1739: a signal stored without an account by a build from before
// per-user attribution is reported once as new when it gains its user, then
// seen.
func TestSignalGainingItsAccountIsReportedOnceAsNew(t *testing.T) {
	service := &ContinuousDiscoveryService{
		opts:  AIDiscoveryOptions{Mode: "passive"},
		store: NewAIStateStore(filepath.Join(t.TempDir(), "state.json")),
	}
	stats := scanStats{DetectorErrors: map[string]string{}, DetectorDurations: map[string]int{}}
	firstSeen := time.Now().Add(-48 * time.Hour).UTC()
	legacy := lifecycleTestSignal("fp-copilot", "")
	legacy.FirstSeen = firstSeen
	prev := aiStateFile{Signals: map[string]aiStoredSignal{"fp-copilot": {AISignal: legacy}}}
	report := service.classifyAndPersist("full-1", "test", time.Now(),
		[]AISignal{lifecycleTestSignal("fp-copilot", "dcw-std1")}, stats, prev, true)
	if len(report.Signals) != 1 || report.Signals[0].State != AIStateNew || report.Signals[0].UserName != "dcw-std1" ||
		!report.Signals[0].FirstSeen.Equal(firstSeen) {
		t.Fatalf("signals = %+v", report.Signals)
	}
	lifecycleStates(t, report)
	next, err := service.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	report = service.classifyAndPersist("full-2", "test", time.Now(),
		[]AISignal{lifecycleTestSignal("fp-copilot", "dcw-std1")}, stats, next, true)
	if report.Signals[0].State != AIStateSeen {
		t.Fatalf("second scan state = %q", report.Signals[0].State)
	}
}

// A managed gateway reads the profile list again at every full scan, so an
// account created after it started is scanned without a restart (GAP-0707).
func TestManagedDiscoveryRereadsTheProfileListEachFullScan(t *testing.T) {
	root := t.TempDir()
	owners := []discoveryHomeOwner{{Home: filepath.Join(root, "alice"), UserID: "S-1-5-21-1-2-3-1001", UserName: "alice"}}
	previous := discoveryHomeOwnersLookup
	t.Cleanup(func() { discoveryHomeOwnersLookup = previous })
	discoveryHomeOwnersLookup = func(bool) []discoveryHomeOwner { return owners }
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, ManagedEnterprise: true, DataDir: filepath.Join(root, "data"),
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)
	owners = append(owners, discoveryHomeOwner{Home: filepath.Join(root, "bob"), UserID: "S-1-5-21-1-2-3-1002", UserName: "bob"})
	if _, err := svc.runScan(context.Background(), true, "test"); err != nil {
		t.Fatal(err)
	}
	if homes := svc.homesToScan(); len(homes) != 2 || homes[1] != owners[1].Home {
		t.Fatalf("homes = %v, want the profile created after the gateway started", homes)
	}
}

func TestManagedDiscoveryRemovesDeletedLastProfileOnce(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "deleted-user")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	owners := []discoveryHomeOwner{{Home: home, UserID: "S-1-5-21-1-2-3-1125", UserName: "deleted-user"}}
	previous := discoveryHomeOwnersLookup
	t.Cleanup(func() { discoveryHomeOwnersLookup = previous })
	discoveryHomeOwnersLookup = func(bool) []discoveryHomeOwner { return owners }
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, ManagedEnterprise: true, StandaloneEnterprise: true, DataDir: filepath.Join(root, "data"),
	}, []AISignature{{ID: "claudecode", Name: "Claude Code", SupportedConnector: "claudecode", ConfigPaths: []string{"~/.claude"}}})
	cleanupPreparedDiscoveryService(t, svc)
	first, err := svc.runScan(context.Background(), true, "test")
	if err != nil || first.Summary.ActiveSignals == 0 {
		t.Fatalf("first scan = %+v, %v", first.Summary, err)
	}
	owners = []discoveryHomeOwner{} // successful ProfileList read, no resolvable SID
	second, err := svc.runScan(context.Background(), true, "test")
	if err != nil || second.Summary.GoneSignals == 0 || second.Summary.ActiveSignals != 0 {
		t.Fatalf("deleted account scan = %+v, %v", second.Summary, err)
	}
	third, err := svc.runScan(context.Background(), true, "test")
	if err != nil || third.Summary.GoneSignals != 0 || third.Summary.ActiveSignals != 0 {
		t.Fatalf("repeated deletion scan = %+v, %v", third.Summary, err)
	}
}

// ai_discovery.home_dirs adds folders to a managed scan's profile list. It
// replaced the list, so every IDE row and signal lost its owner (GAP-0969).
func TestManagedDiscoveryHomeDirsAddToTheProfileList(t *testing.T) {
	root := t.TempDir()
	alice := discoveryHomeOwner{Home: filepath.Join(root, "alice"), UserID: "S-1-5-21-1-2-3-1001", UserName: "alice"}
	bob := discoveryHomeOwner{Home: filepath.Join(root, "bob"), UserID: "S-1-5-21-1-2-3-1002", UserName: "bob"}
	previous := discoveryHomeOwnersLookup
	t.Cleanup(func() { discoveryHomeOwnersLookup = previous })
	discoveryHomeOwnersLookup = func(bool) []discoveryHomeOwner { return []discoveryHomeOwner{alice, bob} }
	extra := filepath.Join(root, "shared")
	opts := normalizeAIDiscoveryOptions(AIDiscoveryOptions{
		Enabled: true, ManagedEnterprise: true, StandaloneEnterprise: true, DataDir: filepath.Join(root, "data"),
		HomeDirs: []string{alice.Home, bob.Home, extra},
	})
	svc := &ContinuousDiscoveryService{opts: opts}
	homes := svc.homesToScan()
	if len(homes) != 3 || homes[0] != alice.Home || homes[1] != bob.Home || homes[2] != extra {
		t.Fatalf("homes = %v, want both profiles and the extra folder", homes)
	}
	if owner, ok := svc.homeOwnerForPath(filepath.Join(bob.Home, ".vscode", "extensions")); !ok || owner.UserName != "bob" {
		t.Fatalf("owner of a folder in bob's profile = %+v, %t", owner, ok)
	}
}

// makeDiscoveryDirLink makes link a directory junction to target on Windows
// (what a standard user can create without a privilege) and a symbolic link
// elsewhere.
func makeDiscoveryDirLink(t *testing.T, target, link string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Skipf("junction creation unavailable: %v: %s", err, output)
		}
	} else if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
}

// A standard user who makes their .codex a junction to another enrolled
// account's .codex gets no record of that account's Codex config or MCP
// servers, and a home_dirs folder that is a junction is not scanned
// (GAP-1097).
func TestManagedDiscoveryRefusesProfileJunctions(t *testing.T) {
	root := t.TempDir()
	owner := discoveryHomeOwner{Home: filepath.Join(root, "o4w1"), UserID: "S-1-5-21-1-2-3-1001", UserName: "o4w1"}
	planter := discoveryHomeOwner{Home: filepath.Join(root, "o4wd"), UserID: "S-1-5-21-1-2-3-1002", UserName: "o4wd"}
	codex := filepath.Join(owner.Home, ".codex")
	elsewhere := filepath.Join(root, "elsewhere")
	for _, dir := range []string{codex, planter.Home, filepath.Join(elsewhere, ".codex")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{codex, filepath.Join(elsewhere, ".codex")} {
		if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[mcp_servers.private]\ncommand = \"x\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	makeDiscoveryDirLink(t, codex, filepath.Join(planter.Home, ".codex"))
	extra := filepath.Join(root, "shared")
	makeDiscoveryDirLink(t, elsewhere, extra)
	previous := discoveryHomeOwnersLookup
	t.Cleanup(func() { discoveryHomeOwnersLookup = previous })
	discoveryHomeOwnersLookup = func(bool) []discoveryHomeOwner { return []discoveryHomeOwner{owner, planter} }
	svc := &ContinuousDiscoveryService{
		catalog: []AISignature{{ID: "codex", Name: "Codex", SupportedConnector: "codex",
			ConfigPaths: []string{"~/.codex/config.toml"}, MCPPaths: []string{"~/.codex/config.toml"}}},
		opts: normalizeAIDiscoveryOptions(AIDiscoveryOptions{
			Enabled: true, ManagedEnterprise: true, StandaloneEnterprise: true, DataDir: filepath.Join(root, "data"),
			HomeDirs: []string{extra},
		}),
	}
	svc.refreshPlatformHomes()
	if homes := svc.homesToScan(); len(homes) != 2 || homes[0] != owner.Home || homes[1] != planter.Home {
		t.Fatalf("homes = %v, want the two profiles without the linked home_dirs folder", homes)
	}
	signals := append(svc.detectConfigPaths(), svc.detectMCPPaths()...)
	if len(signals) != 2 {
		t.Fatalf("signals = %+v, want the owner's Codex config and MCP signals only", signals)
	}
	for _, sig := range signals {
		if sig.UserID != owner.UserID {
			t.Fatalf("signal %s/%s attributed to %q, want only %q", sig.Detector, sig.Category, sig.UserName, owner.UserName)
		}
	}
}

// enterprise.enrollment.exclude_users takes a profile off a managed scan:
// its folders, a home_dirs folder inside it and its processes (GAP-1024).
func TestManagedDiscoverySkipsExcludedAccounts(t *testing.T) {
	root := t.TempDir()
	alice := discoveryHomeOwner{Home: filepath.Join(root, "alice"), UserID: "S-1-5-21-1-2-3-1001", UserName: "alice"}
	bob := discoveryHomeOwner{Home: filepath.Join(root, "bob"), UserID: "S-1-5-21-1-2-3-1002", UserName: "bob", Domain: "HOST"}
	previous := discoveryHomeOwnersLookup
	t.Cleanup(func() { discoveryHomeOwnersLookup = previous })
	discoveryHomeOwnersLookup = func(bool) []discoveryHomeOwner { return []discoveryHomeOwner{alice, bob} }
	svc := &ContinuousDiscoveryService{opts: normalizeAIDiscoveryOptions(AIDiscoveryOptions{
		Enabled: true, ManagedEnterprise: true, StandaloneEnterprise: true, DataDir: filepath.Join(root, "data"),
		ExcludeUsers: []string{`host\BOB`}, HomeDirs: []string{filepath.Join(bob.Home, "work")},
	})}
	if homes := svc.homesToScan(); len(homes) != 1 || homes[0] != alice.Home {
		t.Fatalf("homes = %v, want only alice's profile", homes)
	}
	procs := svc.withoutExcludedAccounts([]processInfo{
		{PID: 1, Comm: "claude.exe", SessionOwnerID: alice.UserID},
		{PID: 2, Comm: "claude.exe", SessionOwnerID: bob.UserID},
	})
	if len(procs) != 1 || procs[0].PID != 1 {
		t.Fatalf("processes = %+v, want only alice's", procs)
	}
}

// A managed Windows scan puts on each owned Claude Code or Codex signal the
// address the enumerator published for its owner, and on no other signal
// (GAP-1025).
func TestManagedDiscoveryStampsThePublishedOwnerEmail(t *testing.T) {
	alice := discoveryHomeOwner{Home: filepath.Join(t.TempDir(), "alice"), UserID: "S-1-5-21-1-2-3-1001", UserName: "alice"}
	t.Cleanup(SetOwnerEmailLookup(func(sid, connector string) string {
		if sid == alice.UserID && connector == "codex" {
			return "o3a.codex@example.test"
		}
		return ""
	}))
	svc := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{IncludeUserEmail: true, homeOwners: []discoveryHomeOwner{alice}}}
	signals := []AISignal{
		{SignalID: "owned", SupportedConnector: "codex", UserID: alice.UserID},
		{SignalID: "unowned", SupportedConnector: "codex"},
		{SignalID: "other-connector", SupportedConnector: "cursor", UserID: alice.UserID},
	}
	svc.stampOwnerEmails(signals)
	if signals[0].UserEmail != "o3a.codex@example.test" || signals[1].UserEmail != "" || signals[2].UserEmail != "" {
		t.Fatalf("emails = %q %q %q", signals[0].UserEmail, signals[1].UserEmail, signals[2].UserEmail)
	}
}
