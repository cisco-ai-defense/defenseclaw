//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func stubAccountsGone(t *testing.T, gone ...string) {
	t.Helper()
	previous, previousHeld := guardianAccountConfirmedGone, guardianAccountsAtHome
	t.Cleanup(func() { guardianAccountConfirmedGone, guardianAccountsAtHome = previous, previousHeld })
	guardianAccountsAtHome = func(string) ([]unixidentity.HomeAccount, error) { return nil, nil }
	guardianAccountConfirmedGone = func(user string, _ int) bool {
		for _, name := range gone {
			if user == name {
				return true
			}
		}
		return false
	}
}

// GAP-0777: a Copilot Local hook file in the home of an account the
// directory confirms gone is not an enrollment conflict, whether the account
// is still in the eligible record, or only in the guardian record of the
// accounts it wrote Local files for. A live account keeps both verdicts.
func TestCopilotAccountScopeSkipsConfirmedGoneAccounts(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath),
				`{"version":1,"accounts":[{"user":"alice","uid":501,"home":"/home/alice"},{"user":"bob","uid":502,"home":"/home/bob"},{"user":"carol","uid":503,"home":"/home/carol"}]}`)
			writeHostFile(t, h, filepath.Join(h.env.Layout.GuardianAuthDir, enterprisehooks.UnixCopilotVSCodeAccountsFileName),
				`{"version":1,"accounts":[{"user":"dave","uid":504,"home":"/home/dave"},{"user":"erin","uid":505,"home":"/home/erin"}]}`)
			writeHostFile(t, h, h.env.Layout.ManifestPath,
				"version: 1\ntargets:\n  - user: alice\n    uid: 501\n    user_home: /home/alice\n    connector: copilot\n  - user: bob\n    uid: 502\n    user_home: /home/bob\n    connector: copilot\n")
			cfg := &config.Config{}
			cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"copilot": {}}
			cfg.Enterprise.Enrollment.Mode = config.EnterpriseEnrollmentManifest
			cfg.Enterprise.Enrollment.ExcludeUsers = []string{"bob"}
			homes := func() ([]string, []string) {
				scoped, out, err := (&policyManager{env: h.env}).copilotAccountHomes(cfg)
				if err != nil {
					t.Fatal(err)
				}
				return scoped, out
			}
			p := h.env.P

			// Every account answers: nothing is skipped.
			scoped, out := homes()
			if !reflect.DeepEqual(scoped, []string{p("/home/alice")}) ||
				!reflect.DeepEqual(out, []string{p("/home/bob"), p("/home/carol"), p("/home/dave"), p("/home/erin")}) {
				t.Fatalf("live accounts: scoped=%v out=%v", scoped, out)
			}

			// bob (excluded, in the eligible record) and dave (only in the
			// guardian record) are gone: their leftover homes drop out.
			stubAccountsGone(t, "bob", "dave")
			scoped, out = homes()
			if !reflect.DeepEqual(scoped, []string{p("/home/alice")}) ||
				!reflect.DeepEqual(out, []string{p("/home/carol"), p("/home/erin")}) {
				t.Fatalf("gone accounts: scoped=%v out=%v", scoped, out)
			}

			// An enrolled account that is gone is not expected to hold the file.
			stubAccountsGone(t, "alice")
			scoped, out = homes()
			if len(scoped) != 0 || !reflect.DeepEqual(out, []string{p("/home/bob"), p("/home/carol"), p("/home/dave"), p("/home/erin")}) {
				t.Fatalf("enrolled gone account: scoped=%v out=%v", scoped, out)
			}
		})
	}
}

// A home carries the verdict of every account recorded at it: a live account
// that took the home over from a deleted one (a shared home, or a record that
// still lists the deleted uid first) keeps it scoped, in either order; the
// home of accounts that are all gone drops out.
func TestCopilotAccountScopeKeepsAHomeWithALiveAccount(t *testing.T) {
	for _, order := range []struct {
		name     string
		accounts string
	}{
		{"deleted account first", `{"user":"alice","uid":501,"home":"/home/shared"},{"user":"carol","uid":502,"home":"/home/shared"}`},
		{"live account first", `{"user":"carol","uid":502,"home":"/home/shared"},{"user":"alice","uid":501,"home":"/home/shared"}`},
	} {
		t.Run(order.name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath),
				`{"version":1,"accounts":[`+order.accounts+`]}`)
			cfg := &config.Config{}
			cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"copilot": {}}
			homes := func() ([]string, []string) {
				scoped, out, err := (&policyManager{env: h.env}).copilotAccountHomes(cfg)
				if err != nil {
					t.Fatal(err)
				}
				// Two accounts at one home list it twice; the verdict is the home's.
				return slices.Compact(scoped), slices.Compact(out)
			}
			shared := h.env.P("/home/shared")

			stubAccountsGone(t, "alice")
			if scoped, out := homes(); !reflect.DeepEqual(scoped, []string{shared}) || len(out) != 0 {
				t.Fatalf("a live account is at the home of a deleted one: scoped=%v out=%v", scoped, out)
			}
			stubAccountsGone(t, "alice", "carol")
			if scoped, out := homes(); len(scoped) != 0 || len(out) != 0 {
				t.Fatalf("every account at the home is gone: scoped=%v out=%v", scoped, out)
			}
			stubAccountsGone(t)
			if scoped, _ := homes(); !reflect.DeepEqual(scoped, []string{shared}) {
				t.Fatalf("every account answers: scoped=%v", scoped)
			}
		})
	}
}

// A deleted account that enrollment left out does not put the home of a live
// enrolled account at the same home out of scope: the live account's Local
// hook is the one verify expects there, in either record order.
func TestCopilotAccountScopeDeletedExcludedAccountLeavesALiveSharedHomeInScope(t *testing.T) {
	for _, order := range []struct {
		name     string
		accounts string
	}{
		{"deleted account first", `{"user":"old","uid":501,"home":"/home/shared"},{"user":"live","uid":502,"home":"/home/shared"}`},
		{"live account first", `{"user":"live","uid":502,"home":"/home/shared"},{"user":"old","uid":501,"home":"/home/shared"}`},
	} {
		t.Run(order.name, func(t *testing.T) {
			h := newTestHost(t, "darwin")
			writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath),
				`{"version":1,"accounts":[`+order.accounts+`]}`)
			cfg := &config.Config{}
			cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"copilot": {}}
			cfg.Enterprise.Enrollment.ExcludeUsers = []string{"old"}
			homes := func() ([]string, []string) {
				scoped, out, err := (&policyManager{env: h.env}).copilotAccountHomes(cfg)
				if err != nil {
					t.Fatal(err)
				}
				return slices.Compact(scoped), slices.Compact(out)
			}
			shared := h.env.P("/home/shared")

			// Benign twin: both accounts answer, the excluded one conflicts.
			stubAccountsGone(t)
			if scoped, out := homes(); !reflect.DeepEqual(scoped, []string{shared}) || !reflect.DeepEqual(out, []string{shared}) {
				t.Fatalf("both live: scoped=%v out=%v", scoped, out)
			}
			stubAccountsGone(t, "old")
			if scoped, out := homes(); !reflect.DeepEqual(scoped, []string{shared}) || len(out) != 0 {
				t.Fatalf("deleted excluded account: scoped=%v out=%v, want scoped=[%s] out=[]", scoped, out, shared)
			}
		})
	}
}

// The eligible record can lag a replacement: the recorded uid is gone while
// a live account holds the same home. A home a fresh read finds in use is not
// dropped, and a read that does not answer does not drop it either; one the
// read finds free is.
func TestCopilotAccountScopeKeepsAReusedHomeBeforeTheRecordRefreshes(t *testing.T) {
	h := newTestHost(t, "darwin")
	writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath),
		`{"version":1,"accounts":[{"user":"alice","uid":501,"home":"/home/alice"},{"user":"bob","uid":503,"home":"/home/bob"}]}`)
	cfg := &config.Config{}
	cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"copilot": {}}
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{"bob"}
	homes := func() ([]string, []string) {
		scoped, out, err := (&policyManager{env: h.env}).copilotAccountHomes(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return scoped, out
	}
	stubAccountsGone(t, "alice", "bob")
	var failure error
	guardianAccountsAtHome = func(string) ([]unixidentity.HomeAccount, error) { return nil, failure }

	if scoped, out := homes(); len(scoped) != 0 || len(out) != 0 {
		t.Fatalf("homes no live account holds: scoped=%v out=%v", scoped, out)
	}
	// A directory that does not answer is not proof that a home is free, nor
	// a reason to call a hook file there drift: the homes are unclear.
	failure = errors.New("directory does not answer")
	scoped, out := homes()
	if len(scoped) != 0 || len(out) != 0 {
		t.Fatalf("a directory that does not answer puts no home in a list: scoped=%v out=%v", scoped, out)
	}
	scope, err := (&policyManager{env: h.env}).copilotAccountScope(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(scope.unclear, []string{h.env.P("/home/alice"), h.env.P("/home/bob")}) {
		t.Fatalf("a directory that does not answer leaves both homes unclear: %v", scope.unclear)
	}
}

// A deleted account whose home holders the directory answers unclearly leaves
// status and verify pending, never verify_failed: the missing Local hook of
// the deleted account is not drift (the guardian removed it), and the home is
// neither called free nor failed. A clear answer, empty or not, leaves no
// warning.
func TestUnclearHomeHoldersLeaveStatusAndVerifyPending(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "copilot")}))
	writeFreshLedger(t, h)
	eligible := enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath)
	guardian := filepath.Join(h.env.Layout.GuardianAuthDir, enterprisehooks.UnixCopilotVSCodeAccountsFileName)
	for _, record := range []string{eligible, guardian} {
		writeHostFile(t, h, record, `{"version":1,"accounts":[{"user":"alice","uid":501,"home":"/home/alice"}]}`)
		if err := os.Chmod(h.env.P(record), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(h.env.P("/home/alice"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubAccountsGone(t, "alice")
	for _, action := range []string{ActionStatus, ActionVerify} {
		// Benign twin: a clear answer that nobody holds the home is free.
		guardianAccountsAtHome = func(string) ([]unixidentity.HomeAccount, error) { return nil, nil }
		clear := h.run(Options{Action: action})
		if clear.ExitCode != 0 || hasWarning(clear, codeCopilotHomeUnclear) {
			t.Fatalf("%s, clear empty answer: exit=%d errors=%v warnings=%v", action, clear.ExitCode, clear.Errors, clear.Warnings)
		}
		guardianAccountsAtHome = func(string) ([]unixidentity.HomeAccount, error) { return nil, errors.New("unclear plist") }
		unclear := h.run(Options{Action: action})
		if unclear.ExitCode != 0 || len(unclear.Errors) != 0 {
			t.Fatalf("%s, unclear answer failed: exit=%d errors=%v", action, unclear.ExitCode, unclear.Errors)
		}
		if !hasWarning(unclear, codeCopilotHomeUnclear) || unclear.SecurityComplete {
			t.Fatalf("%s, unclear answer is not reported pending: complete=%v warnings=%v", action, unclear.SecurityComplete, unclear.Warnings)
		}
	}
}

// An unclear read of who holds a home is pending even where a recorded
// account is live there: the live account does not prove the home has no
// other holder. The live account keeps its own check (its home stays in
// scope), and the benign twin, a clear read of no other holder, reports
// nothing.
func TestUnclearHomeReadBesideARecordedLiveAccountIsPending(t *testing.T) {
	h := newTestHost(t, "darwin")
	writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath),
		`{"version":1,"accounts":[{"user":"old","uid":501,"home":"/home/shared"},{"user":"live","uid":502,"home":"/home/shared"}]}`)
	cfg := &config.Config{}
	cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"copilot": {}}
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{"old"}
	shared := h.env.P("/home/shared")
	scopeOf := func() copilotHomeScope {
		scope, err := (&policyManager{env: h.env}).copilotAccountScope(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return scope
	}
	stubAccountsGone(t, "old")
	clear := scopeOf()
	if len(clear.unclear) != 0 || !reflect.DeepEqual(slices.Compact(clear.scoped), []string{shared}) {
		t.Fatalf("a clear read: scoped=%v unclear=%v", clear.scoped, clear.unclear)
	}
	guardianAccountsAtHome = func(string) ([]unixidentity.HomeAccount, error) { return nil, errors.New("unclear plist") }
	unclear := scopeOf()
	if !reflect.DeepEqual(unclear.unclear, []string{shared}) {
		t.Fatalf("an unclear read beside a recorded live account is pending: unclear=%v", unclear.unclear)
	}
	if !reflect.DeepEqual(slices.Compact(unclear.scoped), []string{shared}) || len(unclear.outOfScope) != 0 {
		t.Fatalf("the recorded live account keeps its own check: scoped=%v out=%v", unclear.scoped, unclear.outOfScope)
	}
}

// A home is scoped by the account that holds it now, not by the deleted one
// the record still names (GAP-0777 review 3): the replacement is judged by
// its own uid and name, whether enrollment excludes it, and whether the
// manifest enrolls it. The replacement may be a local or a directory account;
// the fresh read covers both.
func TestCopilotAccountScopeJudgesAReusedHomeByTheAccountThatHoldsItNow(t *testing.T) {
	const shared = "/home/shared"
	const target = "  - user: alice\n    uid: %UID%\n    user_home: /home/shared\n    connector: copilot\n"
	cases := []struct {
		name         string
		exclude      []string
		manifest     string
		replacement  []unixidentity.HomeAccount
		wantScoped   bool
		wantOutScope bool
	}{
		{"new account excluded by uid, old one enrolled", []string{"502"}, "", []unixidentity.HomeAccount{{Name: "alice", UID: 502}}, false, true},
		{"old account excluded by uid, new one enrolled", []string{"501"}, "", []unixidentity.HomeAccount{{Name: "alice", UID: 502}}, true, false},
		{"old account excluded by name, new one under another name enrolled", []string{"alice"}, "", []unixidentity.HomeAccount{{Name: "alicia", UID: 502}}, true, false},
		{"new account excluded by name", []string{"alicia"}, "", []unixidentity.HomeAccount{{Name: "alicia", UID: 502}}, false, true},
		{"nobody excluded", nil, "", []unixidentity.HomeAccount{{Name: "alice", UID: 502}}, true, false},
		{"manifest enrolls the old uid only", nil, strings.Replace(target, "%UID%", "501", 1), []unixidentity.HomeAccount{{Name: "alicia", UID: 502}}, false, true},
		{"manifest enrolls the new uid", nil, strings.Replace(target, "%UID%", "502", 1), []unixidentity.HomeAccount{{Name: "alice", UID: 502}}, true, false},
		{"two accounts hold the home, one excluded", []string{"503"}, "", []unixidentity.HomeAccount{{Name: "alice", UID: 502}, {Name: "carol", UID: 503}}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHost(t, "darwin")
			writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath),
				`{"version":1,"accounts":[{"user":"alice","uid":501,"home":"`+shared+`"}]}`)
			cfg := &config.Config{}
			cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"copilot": {}}
			cfg.Enterprise.Enrollment.ExcludeUsers = tc.exclude
			if tc.manifest != "" {
				writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n"+tc.manifest)
				cfg.Enterprise.Enrollment.Mode = config.EnterpriseEnrollmentManifest
			}
			stubAccountsGone(t, "alice")
			reads := 0
			guardianAccountsAtHome = func(home string) ([]unixidentity.HomeAccount, error) {
				reads++
				if home != shared {
					t.Fatalf("read the accounts of %s", home)
				}
				return tc.replacement, nil
			}
			scoped, out, err := (&policyManager{env: h.env}).copilotAccountHomes(cfg)
			if err != nil {
				t.Fatal(err)
			}
			scoped, out = slices.Compact(scoped), slices.Compact(out)
			p := h.env.P(shared)
			if got := slices.Contains(scoped, p); got != tc.wantScoped {
				t.Errorf("scoped=%v, want home scoped: %v", scoped, tc.wantScoped)
			}
			if got := slices.Contains(out, p); got != tc.wantOutScope {
				t.Errorf("out=%v, want home out of scope: %v", out, tc.wantOutScope)
			}
			if reads != 1 {
				t.Errorf("the home was read %d times, want once", reads)
			}
		})
	}
}

// goneAccountHost installs a host whose enumerator enrolled alice (uid 1001)
// for Hermes, with the guardian state written by writeState.
func goneAccountHost(t *testing.T, goos string) (*testHost, func(row map[string]any)) {
	t.Helper()
	h := newTestHost(t, goos)
	file, home := "linux-standalone.yaml", "/home/alice"
	if goos == "darwin" {
		file, home = "macos-standalone.yaml", "/Users/alice"
	}
	raw := strings.Replace(string(readSampleConfig(t, file)), "    claudecode: {}", "    claudecode: {}\n    hermes: {}", 1)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, []byte(raw))}))
	writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n"+
		"  - user: alice\n    uid: 1001\n    user_home: "+home+"\n    connector: hermes\n    agent_version: 0.21.0\n")
	writeFreshLedger(t, h)
	h.env.Runner = &readinessReportsEnrolledHermes{Runner: h.env.Runner, readiness: "defenseclaw-gateway enterprise hooks readiness --manifest " + h.env.Layout.ManifestPath + " --json",
		report: `{"ok":true,"scope":"machine_hook_registration","hermes_session_coverage":"not_covered","results":[{"connector":"hermes","user":"alice","user_home":"` + home + `","uid":1001,"ok":true}]}`}
	writeState := func(row map[string]any) {
		t.Helper()
		row["user"], row["user_home"], row["connector"] = "alice", home, "hermes"
		data, err := json.Marshal(map[string]any{"results": []map[string]any{row}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return h, writeState
}

// readinessReportsEnrolledHermes answers the readiness check with a report
// that proves the enrolled Hermes target, so a run's verdict rests on the
// guardian state and the account checks alone.
type readinessReportsEnrolledHermes struct {
	Runner
	readiness, report string
}

func (r *readinessReportsEnrolledHermes) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if filepath.Base(name)+" "+strings.Join(args, " ") != r.readiness {
		return r.Runner.Run(ctx, name, args...)
	}
	return CommandResult{Stdout: []byte(r.report)}, nil
}

// removedRow is the row the Unix guardian records for a target whose account
// is gone (runEnterpriseHookReconcileOnceStandaloneUnix).
func removedRow(uid int) map[string]any {
	return map[string]any{"ok": false, "removed": true, "uid": uid,
		"error": `enterprise hooks: target account "alice" does not exist: no such account`}
}

// GAP-0777: verify run right after an enrolled account was deleted failed
// between the delete and the guardian next reconcile, which still reported
// the target protected. Verify waits, bounded by GuardianReconcileTimeout,
// for the guardian to record the target as removed and then exits 0; a live
// account is never waited for, and a guardian that does not record it is
// named.
func TestVerifyWaitsForTheGuardianToRecordAConfirmedRemoval(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h, writeState := goneAccountHost(t, goos)
			writeState(map[string]any{"ok": true, "uid": 1001})
			h.env.GuardianReconcileTimeout = 10 * time.Second
			h.env.PollInterval = 10 * time.Millisecond

			// Benign twin: a live account is not waited for, whatever the state says.
			started := time.Now()
			live := h.run(Options{Action: ActionVerify})
			if elapsed := time.Since(started); elapsed > 3*time.Second {
				t.Fatalf("verify waited %s for a live account", elapsed)
			}
			if live.ExitCode != 0 || !live.OK {
				t.Fatalf("verify of a live account: exit=%d errors=%+v", live.ExitCode, live.Errors)
			}
			if got := messagesOf(live.Warnings, codeGuardianReportPending); got != "" {
				t.Fatalf("a live account was reported pending: %q", got)
			}

			// The account is gone; the guardian records the removal 300 ms in.
			stubAccountsGone(t, "alice")
			previousFresh := guardianFreshAccountRecordGone
			guardianFreshAccountRecordGone = func(_ context.Context, user string) bool { return user == "alice" }
			t.Cleanup(func() { guardianFreshAccountRecordGone = previousFresh })
			recorded := make(chan struct{})
			go func() {
				time.Sleep(300 * time.Millisecond)
				writeState(removedRow(1001))
				close(recorded)
			}()
			started = time.Now()
			r := h.run(Options{Action: ActionVerify})
			<-recorded
			if elapsed := time.Since(started); elapsed < 250*time.Millisecond {
				t.Fatalf("verify did not wait for the guardian to record the removal (%s)", elapsed)
			}
			if got := messagesOf(r.Warnings, codeGuardianReportPending); got != "" {
				t.Fatalf("a removal recorded in time was reported pending: %q", got)
			}
			if r.ExitCode != 0 || !r.OK {
				t.Fatalf("verify after the guardian recorded the removal: exit=%d errors=%+v", r.ExitCode, r.Errors)
			}

			// A guardian that never records it: verify stops at the bound and
			// names the account.
			writeState(map[string]any{"ok": true, "uid": 1001})
			h.env.GuardianReconcileTimeout = 100 * time.Millisecond
			started = time.Now()
			stuck := h.run(Options{Action: ActionVerify})
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("verify waited %s, past its bound", elapsed)
			}
			if !strings.Contains(messagesOf(stuck.Warnings, codeGuardianReportPending), "has not recorded the removal of alice") {
				t.Fatalf("verify did not name the unrecorded removal: %+v", stuck.Warnings)
			}

			// status never waits.
			h.env.GuardianReconcileTimeout = 10 * time.Second
			started = time.Now()
			h.run(Options{Action: ActionStatus})
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("status waited %s for the guardian", elapsed)
			}
		})
	}
}

// A removal recorded for an earlier account of the same name is no proof for
// the account that took the name over: the manifest enrolled alice as uid
// 1002, and only a row recorded for uid 1002 retires it.
func TestVerifyDoesNotTakeAnEarlierAccountsRemovalForTheCurrentOne(t *testing.T) {
	h, writeState := goneAccountHost(t, "linux")
	writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n"+
		"  - user: alice\n    uid: 1002\n    user_home: /home/alice\n    connector: hermes\n    agent_version: 0.21.0\n")
	stubAccountsGone(t, "alice")
	h.env.GuardianReconcileTimeout = 100 * time.Millisecond
	h.env.PollInterval = 10 * time.Millisecond

	writeState(removedRow(1001))
	earlier := h.run(Options{Action: ActionVerify})
	if !strings.Contains(messagesOf(earlier.Warnings, codeGuardianReportPending), "has not recorded the removal of alice") {
		t.Fatalf("the removal of uid 1001 retired uid 1002: %+v", earlier.Warnings)
	}

	writeState(removedRow(1002))
	current := h.run(Options{Action: ActionVerify})
	if got := messagesOf(current.Warnings, codeGuardianReportPending); got != "" {
		t.Fatalf("the removal recorded for the current uid was reported pending: %q", got)
	}
}

// The enumerator revokes the deleted account's target and rewrites the
// manifest; the guardian reconciles it up to a minute later. Verify waits for
// that reconcile longer than the guardian-report bound a change uses, and
// exits 0 once the activation names the manifest.
func TestVerifyWaitsOutTheGuardianMinuteAfterATargetIsRevoked(t *testing.T) {
	h, writeState := goneAccountHost(t, "linux")
	writeState(map[string]any{"ok": true, "uid": 1001})
	current := manifestDigest(t, h)
	writeActivation(t, h, strings.Repeat("0", 64))
	h.env.GuardianReportTimeout = 50 * time.Millisecond
	h.env.GuardianReconcileTimeout = 10 * time.Second
	h.env.PollInterval = 10 * time.Millisecond
	reconciled := make(chan error, 1)
	go func() {
		time.Sleep(300 * time.Millisecond)
		reconciled <- publishActivation(h, current)
	}()
	r := h.run(Options{Action: ActionVerify})
	if err := <-reconciled; err != nil {
		t.Fatal(err)
	}
	if r.ExitCode != 0 || !r.OK {
		t.Fatalf("verify did not wait for the guardian to reconcile the revoked target's manifest: exit=%d errors=%+v", r.ExitCode, r.Errors)
	}
	if got := messagesOf(r.Warnings, codeGuardianReportPending); got != "" {
		t.Fatalf("a reconcile that came in time was reported pending: %q", got)
	}
}

// The default bound covers one guardian reconcile (each minute) with margin,
// and a change's own guardian-report bound is unchanged.
func TestGuardianReconcileTimeoutCoversTheGuardianMinute(t *testing.T) {
	env := &Env{}
	env.fillDefaults()
	if env.GuardianReconcileTimeout < 60*time.Second+10*time.Second {
		t.Fatalf("GuardianReconcileTimeout %s does not cover a one-minute guardian reconcile", env.GuardianReconcileTimeout)
	}
	if env.GuardianReportTimeout != 30*time.Second {
		t.Fatalf("GuardianReportTimeout %s, want 30s", env.GuardianReportTimeout)
	}
}

// A recorded live account at a reused home does not stand in for the accounts
// a fresh read finds there: an excluded account that moved in beside it is
// outside enrollment, and a holder the record already names, an enrolled
// newcomer or an unanswering directory change nothing.
func TestCopilotAccountScopeSearchesTheHomeEvenWhenARecordedAccountIsLive(t *testing.T) {
	cases := []struct {
		name      string
		holders   []unixidentity.HomeAccount
		failure   error
		wantOut   bool
		wantReads int
	}{
		{"an excluded account moved in", []unixidentity.HomeAccount{{Name: "carol", UID: 503}, {Name: "bob", UID: 502}}, nil, true, 1},
		{"only the recorded live account holds it", []unixidentity.HomeAccount{{Name: "carol", UID: 503}}, nil, false, 1},
		{"an enrolled account moved in", []unixidentity.HomeAccount{{Name: "carol", UID: 503}, {Name: "dave", UID: 504}}, nil, false, 1},
		{"the directory does not answer", nil, errors.New("timed out"), false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHost(t, "darwin")
			writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath),
				`{"version":1,"accounts":[{"user":"alice","uid":501,"home":"/Users/shared"},{"user":"carol","uid":503,"home":"/Users/shared"}]}`)
			cfg := &config.Config{}
			cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"copilot": {}}
			cfg.Enterprise.Enrollment.ExcludeUsers = []string{"502"}
			stubAccountsGone(t, "alice")
			reads := 0
			guardianAccountsAtHome = func(string) ([]unixidentity.HomeAccount, error) {
				reads++
				return tc.holders, tc.failure
			}
			scoped, out, err := (&policyManager{env: h.env}).copilotAccountHomes(cfg)
			if err != nil {
				t.Fatal(err)
			}
			shared := h.env.P("/Users/shared")
			wantOut := []string(nil)
			if tc.wantOut {
				wantOut = []string{shared}
			}
			if !reflect.DeepEqual(slices.Compact(scoped), []string{shared}) || !reflect.DeepEqual(slices.Compact(out), wantOut) || reads != tc.wantReads {
				t.Fatalf("scoped=%v out=%v reads=%d; want scoped=[%s] out=%v reads=%d", scoped, out, reads, shared, wantOut, tc.wantReads)
			}
		})
	}
}
