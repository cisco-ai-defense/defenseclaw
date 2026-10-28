package enterpriseunix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readinessFollowsActivation answers `enterprise hooks readiness` the way
// the real command does: until the guardian's activation receipt names the
// current manifest bytes it reports "activation does not cover the current
// manifest bytes" and exits 1.
type readinessFollowsActivation struct {
	Runner
	h          *testHost
	readiness  string
	ok, stale  string
	staleCalls int
}

func (r *readinessFollowsActivation) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if filepath.Base(name)+" "+strings.Join(args, " ") != r.readiness {
		return r.Runner.Run(ctx, name, args...)
	}
	if guardianNamesManifest(r.h) {
		return CommandResult{Stdout: []byte(r.ok)}, nil
	}
	r.staleCalls++
	return CommandResult{Stdout: []byte(r.stale), ExitCode: 1}, errors.New("readiness exited 1")
}

func manifestDigest(t *testing.T, h *testHost) string {
	t.Helper()
	data, err := os.ReadFile(h.env.P(h.env.Layout.ManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func guardianNamesManifest(h *testHost) bool {
	data, err := os.ReadFile(h.env.P(filepath.Join(h.env.Layout.GuardianAuthDir, guardianActivationFile)))
	if err != nil {
		return false
	}
	manifest, err := os.ReadFile(h.env.P(h.env.Layout.ManifestPath))
	if err != nil {
		return false
	}
	var activation struct {
		ManifestSHA256 string `json:"manifest_sha256"`
	}
	digest := sha256.Sum256(manifest)
	return json.Unmarshal(data, &activation) == nil && activation.ManifestSHA256 == hex.EncodeToString(digest[:])
}

func writeActivation(t *testing.T, h *testHost, manifestSHA256 string) {
	t.Helper()
	if err := publishActivation(h, manifestSHA256); err != nil {
		t.Fatal(err)
	}
}

func publishActivation(h *testHost, manifestSHA256 string) error {
	data, err := json.Marshal(map[string]any{"version": 1, "updated_at": time.Now().UTC().Format(time.RFC3339Nano), "manifest_sha256": manifestSHA256, "ok": true})
	if err != nil {
		return err
	}
	path := h.env.P(filepath.Join(h.env.Layout.GuardianAuthDir, guardianActivationFile))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// GAP-2176: verify run right after a fresh pkg install (the enumerator has
// just enrolled every eligible account, the guardian has not reconciled that
// manifest yet) exited 1 with "live registration check did not prove the
// current managed Hermes target" and passed 20 s later. Verify waits, bounded
// by GuardianReportTimeout, for the guardian to reconcile the current
// manifest; a reconcile that does not come keeps the failure and names the
// pending guardian report.
func TestVerifyWaitsForTheGuardianToReconcileANewManifest(t *testing.T) {
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
			state, err := json.Marshal(map[string]any{"results": []map[string]any{{
				"user": "alice", "user_home": home, "connector": "hermes", "ok": true,
			}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), state, 0o640); err != nil {
				t.Fatal(err)
			}
			current := manifestDigest(t, h)
			runner := &readinessFollowsActivation{
				Runner:    h.env.Runner,
				h:         h,
				readiness: "defenseclaw-gateway enterprise hooks readiness --manifest " + h.env.Layout.ManifestPath + " --json",
				ok:        `{"ok":true,"scope":"machine_hook_registration","hermes_session_coverage":"not_covered","results":[{"connector":"hermes","user":"alice","user_home":"` + home + `","uid":1001,"ok":true}]}`,
				stale:     `{"ok":false,"scope":"machine_hook_registration","hermes_session_coverage":"not_covered","authorization_error":"protected hook guardian activation does not cover the current manifest bytes","results":[{"connector":"hermes","user":"alice","user_home":"` + home + `","uid":1001,"ok":false}]}`,
			}
			h.env.Runner = runner
			h.env.GuardianReportTimeout = 10 * time.Second
			h.env.PollInterval = 10 * time.Millisecond

			// The guardian reconciles the new manifest 300 ms after verify starts.
			writeActivation(t, h, strings.Repeat("0", 64))
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
				t.Fatalf("verify right after a manifest change failed instead of waiting for the guardian: exit=%d errors=%+v", r.ExitCode, r.Errors)
			}
			if runner.staleCalls != 0 {
				t.Fatalf("verify ran the registration check %d time(s) before the guardian reconciled the manifest", runner.staleCalls)
			}
			if got := messagesOf(r.Warnings, codeGuardianReportPending); got != "" {
				t.Fatalf("a reconcile that came in time was reported pending: %q", got)
			}

			// A guardian that never reconciles: verify stops waiting at the
			// bound, still fails, and names the pending reconcile.
			h.env.GuardianReportTimeout = 100 * time.Millisecond
			writeActivation(t, h, strings.Repeat("0", 64))
			started := time.Now()
			stuck := h.run(Options{Action: ActionVerify})
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("verify waited %s, past its bound", elapsed)
			}
			if stuck.ExitCode == 0 || !strings.Contains(messagesOf(stuck.Errors, codeVerify), "managed Hermes hook registration") {
				t.Fatalf("verify passed with a guardian that never reconciled the manifest: %+v", stuck.Errors)
			}
			if !strings.Contains(messagesOf(stuck.Warnings, codeGuardianReportPending), "has not reconciled the current enrollment manifest") {
				t.Fatalf("verify did not name the pending guardian reconcile: %+v", stuck.Warnings)
			}

			// status never waits.
			h.env.GuardianReportTimeout = 10 * time.Second
			started = time.Now()
			h.run(Options{Action: ActionStatus})
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("status waited %s for the guardian", elapsed)
			}
		})
	}
}
