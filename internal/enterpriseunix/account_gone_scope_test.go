//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func stubAccountsGone(t *testing.T, gone ...string) {
	t.Helper()
	previous := guardianAccountConfirmedGone
	t.Cleanup(func() { guardianAccountConfirmedGone = previous })
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

// GAP-0777: verify run right after an enrolled account was deleted failed
// between the delete and the guardian next reconcile, which still reported
// the target protected. Verify waits, bounded by GuardianRetireTimeout, for
// the guardian to record the target as removed; a live account is never
// waited for, and a guardian that does not record it is named.
func TestVerifyWaitsForTheGuardianToRecordAConfirmedRemoval(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
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
			writeState(map[string]any{"ok": true})
			h.env.GuardianRetireTimeout = 10 * time.Second
			h.env.PollInterval = 10 * time.Millisecond

			// Benign twin: a live account is not waited for, whatever the state says.
			started := time.Now()
			live := h.run(Options{Action: ActionVerify})
			if elapsed := time.Since(started); elapsed > 3*time.Second {
				t.Fatalf("verify waited %s for a live account", elapsed)
			}
			if got := messagesOf(live.Warnings, codeGuardianReportPending); got != "" {
				t.Fatalf("a live account was reported pending: %q", got)
			}

			// The account is gone; the guardian records the removal 300 ms in.
			stubAccountsGone(t, "alice")
			recorded := make(chan struct{})
			go func() {
				time.Sleep(300 * time.Millisecond)
				writeState(map[string]any{"ok": false, "removed": true, "error": "enterprise hooks: target account or profile removed"})
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

			// A guardian that never records it: verify stops at the bound and
			// names the account.
			writeState(map[string]any{"ok": true})
			h.env.GuardianRetireTimeout = 100 * time.Millisecond
			started = time.Now()
			stuck := h.run(Options{Action: ActionVerify})
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("verify waited %s, past its bound", elapsed)
			}
			if !strings.Contains(messagesOf(stuck.Warnings, codeGuardianReportPending), "has not recorded the removal of alice") {
				t.Fatalf("verify did not name the unrecorded removal: %+v", stuck.Warnings)
			}

			// status never waits.
			h.env.GuardianRetireTimeout = 10 * time.Second
			started = time.Now()
			h.run(Options{Action: ActionStatus})
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("status waited %s for the guardian", elapsed)
			}
		})
	}
}
