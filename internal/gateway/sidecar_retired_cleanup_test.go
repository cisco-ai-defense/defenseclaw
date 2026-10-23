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

package gateway

// until 1.1: how boot treats a removed connector. Its teardown changes only
// its hook script (it becomes the stub that blocks every call) and its
// tokens; after verification the lifecycle caller removes only its lock
// entry. No boot path changes the agent config, import path or shared hook
// state. A teardown that fails is kept and
// retried. Delete with internal/gateway/connector/removed.go.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const retiredOmnigentModule = "defenseclaw_omnigent_policy"

// writeRetiredSetupRecord writes the backup record an older release's setup
// left for path: the bytes it found (nil = none) and the bytes it wrote.
func writeRetiredSetupRecord(t *testing.T, dataDir, connectorName, logical, path string, found []byte, wrote string) {
	t.Helper()
	sum := func(data []byte) string {
		digest := sha256.Sum256(data)
		return hex.EncodeToString(digest[:])
	}
	record := map[string]any{
		"version":         1,
		"connector":       connectorName,
		"logical_name":    logical,
		"path":            path,
		"existed":         found != nil,
		"mode":            0o600,
		"pristine_sha256": "missing",
		"post_sha256":     sum([]byte(wrote)),
		"captured_at":     "2026-10-01T00:00:00Z",
	}
	if found != nil {
		record["pristine_sha256"] = sum(found)
		record["pristine_bytes"] = found
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectDirectory(filepath.Join(dataDir, "connector_backups", connectorName)); err != nil {
		t.Fatal(err)
	}
	writeRetiredFile(t, filepath.Join(dataDir, "connector_backups", connectorName, logical+".json"), string(data))
	writeRetiredFile(t, path, wrote)
}

func writeRetiredFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// retiredSnapshot reads every file, link and folder under roots, except the
// paths in skip and the token writers' shared lock.
func retiredSnapshot(t *testing.T, roots []string, skip ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			for _, skipped := range skip {
				if path == skipped {
					return nil
				}
			}
			if entry.Name() == ".hook-api-token-publish.lock" {
				return nil
			}
			switch {
			case entry.Type()&fs.ModeSymlink != 0:
				target, err := os.Readlink(path)
				if err != nil {
					return err
				}
				out[path] = "symlink:" + target
			case entry.IsDir():
				out[path] = "<dir>"
			default:
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				out[path] = string(data)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

type retiredOmnigentHost struct {
	home, dataDir, configPath, modulePath, pthPath string
}

const (
	retiredOperatorConfig = "policy_modules: [corp_policy]\n"
	retiredPatchedConfig  = "policy_modules: [corp_policy, " + retiredOmnigentModule + "]\n" +
		"policies:\n  defenseclaw_guardrail:\n    handler: " + retiredOmnigentModule + ".defenseclaw_policy\n"
	retiredOmnigentModuleBody = "# defenseclaw-managed-policy v1\ndef defenseclaw_policy(event):\n    return {\"result\": \"ALLOW\"}\n"
)

// stageRetiredOmnigent leaves what an older release's OmniGent setup wrote:
// the patched config.yaml, the .pth file, the policy module, their backup
// records, the shared hook state, the connector's hook token and a hook
// contract lock with its entry and Codex's.
func stageRetiredOmnigent(t *testing.T) retiredOmnigentHost {
	t.Helper()
	home := testenv.PrivateTempDir(t)
	restoreHome, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	t.Setenv("OMNIGENT_CONFIG_HOME", "")
	t.Setenv("OMNIGENT_CONFIG", "")
	h := retiredOmnigentHost{home: home, dataDir: filepath.Join(home, ".defenseclaw")}
	h.configPath = filepath.Join(home, ".omnigent", "config.yaml")
	h.modulePath = filepath.Join(h.dataDir, "hooks", retiredOmnigentModule+".py")
	h.pthPath = filepath.Join(home, "venv", "site-packages", "defenseclaw_omnigent.pth")
	writeRetiredSetupRecord(t, h.dataDir, "omnigent", "config", h.configPath, []byte(retiredOperatorConfig), retiredPatchedConfig)
	writeRetiredSetupRecord(t, h.dataDir, "omnigent", "pth", h.pthPath, nil, filepath.Dir(h.modulePath)+"\n")
	writeRetiredSetupRecord(t, h.dataDir, "omnigent", "module", h.modulePath, nil, retiredOmnigentModuleBody)
	writeRetiredFile(t, filepath.Join(h.dataDir, "hooks", ".hookcfg"), "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=closed\n")
	writeRetiredFile(t, filepath.Join(h.dataDir, "hook_contract_lock.json"), `{"version":2,"updated_at":"2026-10-01T00:00:00Z","connectors":{`+
		`"codex":{"connector":"codex","contract_id":"codex-hooks-v1","defenseclaw_version":"1.0.3","hook_fail_mode":"closed","updated_at":"2026-10-01T00:00:00Z"},`+
		`"omnigent":{"connector":"omnigent","contract_id":"omnigent-policy-v1","defenseclaw_version":"1.0.3","hook_fail_mode":"closed","updated_at":"2026-10-01T00:00:00Z"}}}`+"\n")
	if got := connector.LoadHookContractLockEntry(h.dataDir, "omnigent"); got.Connector != "omnigent" {
		t.Fatalf("staged omnigent lock entry did not load: %+v", got)
	}
	if _, err := connector.EnsureHookAPIToken(h.dataDir, "omnigent"); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h retiredOmnigentHost) token(t *testing.T) string {
	t.Helper()
	path, err := connector.HookAPITokenFilePath(h.dataDir, "omnigent")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// snapshot is everything on the host but the module, token and retired lock.
func (h retiredOmnigentHost) snapshot(t *testing.T) map[string]string {
	t.Helper()
	return retiredSnapshot(t, []string{h.home}, h.modulePath, h.token(t), filepath.Join(h.dataDir, "hook_contract_lock.json"))
}

func (h retiredOmnigentHost) requireStub(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(h.modulePath)
	if err != nil || !strings.Contains(string(data), "disabled tombstone") || !strings.Contains(string(data), `"DENY"`) {
		t.Fatalf("policy module = %q, %v; want the stub that denies every request", data, err)
	}
	if _, err := os.Lstat(h.token(t)); !os.IsNotExist(err) {
		t.Fatalf("omnigent token survived: %v", err)
	}
}

// readOnlyRetiredHooks makes the hook folder and the module read-only, so the
// stub can be neither written into the module nor renamed over it.
func readOnlyRetiredHooks(t *testing.T, h retiredOmnigentHost) func() {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory modes do not stop writes here")
	}
	dir := filepath.Dir(h.modulePath)
	if err := os.Chmod(h.modulePath, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		_ = os.Chmod(dir, 0o700)
		_ = os.Chmod(h.modulePath, 0o600)
	}
	t.Cleanup(restore)
	return restore
}

// Every boot path that meets a removed connector whose teardown fails (the
// stub cannot be written) returns the failure and keeps the name for the
// next boot, with no file changed; once the cause is gone, the retry
// finishes, and changes only the module, token and retired lock entry.
func TestRetiredConnectorCleanupFailureIsKeptForRetry(t *testing.T) {
	ctx := context.Background()
	registry := connector.NewDefaultRegistry()

	t.Run("direct", func(t *testing.T) {
		h := stageRetiredOmnigent(t)
		before := retiredSnapshot(t, []string{h.home})
		restore := readOnlyRetiredHooks(t, h)
		err := retireOrDropUnregisteredConnector(ctx, registry, h.dataDir, "omnigent", "removed", nil)
		if err == nil || !strings.Contains(err.Error(), "omnigent") {
			t.Fatalf("retire = %v, want the cleanup failure", err)
		}
		restore()
		if got := retiredSnapshot(t, []string{h.home}); !reflect.DeepEqual(got, before) {
			t.Fatalf("a failed cleanup changed files:\n got %v\nwant %v", got, before)
		}
		kept := h.snapshot(t)
		if err := retireOrDropUnregisteredConnector(ctx, registry, h.dataDir, "omnigent", "removed", nil); err != nil {
			t.Fatalf("retry: %v", err)
		}
		h.requireStub(t)
		if got := h.snapshot(t); !reflect.DeepEqual(got, kept) {
			t.Fatalf("the retry changed more than the module and the token:\n got %v\nwant %v", got, kept)
		}
	})

	t.Run("removed from the roster", func(t *testing.T) {
		h := stageRetiredOmnigent(t)
		readOnlyRetiredHooks(t, h)
		failed, dropped := teardownRemovedConnectorsReport(registry, []string{"omnigent"}, nil, connector.SetupOpts{DataDir: h.dataDir}, ctx)
		if !reflect.DeepEqual(failed, []string{"omnigent"}) || len(dropped) != 0 {
			t.Fatalf("failed=%v dropped=%v, want omnigent kept for retry", failed, dropped)
		}
	})

	t.Run("removed from the roster with rollback authority", func(t *testing.T) {
		h := stageRetiredOmnigent(t)
		readOnlyRetiredHooks(t, h)
		s := multiBootSidecar(t)
		s.cfg.DataDir = h.dataDir
		lockState, err := connector.CaptureHookContractLockSnapshot(h.dataDir)
		if err != nil {
			t.Fatal(err)
		}
		candidates, unavailable := s.removedConnectorRollbackCandidates(
			registry, []string{"omnigent"}, []string{"codex"},
			"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key", lockState,
		)
		if len(candidates) != 0 || !reflect.DeepEqual(unavailable, []string{"omnigent"}) {
			t.Fatalf("candidates=%v unavailable=%v, want omnigent kept for retry", candidates, unavailable)
		}
	})

	t.Run("lock only", func(t *testing.T) {
		h := stageRetiredOmnigent(t)
		readOnlyRetiredHooks(t, h)
		roster := []string{"codex"}
		if err := connector.SaveActiveConnectors(h.dataDir, roster); err != nil {
			t.Fatal(err)
		}
		err := reconcileOrphanedConnectorRegistrations(ctx, registry, h.dataDir, roster, orphanConnectorReconcileOps{
			resolveOpts: func(conn connector.Connector) (connector.SetupOpts, error) {
				return connector.SetupOpts{DataDir: h.dataDir}, nil
			},
			clearLock: connector.ClearHookContractLockEntry,
		})
		if err == nil || !strings.Contains(err.Error(), "omnigent") {
			t.Fatalf("reconcile = %v, want the cleanup failure", err)
		}
		if got := connector.LoadActiveConnectors(h.dataDir); !reflect.DeepEqual(got, roster) {
			t.Fatalf("active roster = %v, want %v", got, roster)
		}
	})
}

// Review fixes (G-deadcode loop round 1, simplified teardown): every boot
// path put the removed connector's config.yaml back, removed the .pth file,
// the backups and the manual-cleanup record, and cleared the shared hook
// contract lock and .hookcfg with the per-user writer. Each path now keeps
// agent config, backups and shared hook state, while removing the retired
// lock entry only after its stub and token cleanup verify.
func TestRemovedConnectorBootChangesOnlyOwnedCleanupState(t *testing.T) {
	ctx := context.Background()
	registry := connector.NewDefaultRegistry()
	for _, path := range []struct {
		name string
		run  func(t *testing.T, h retiredOmnigentHost)
	}{
		{"direct", func(t *testing.T, h retiredOmnigentHost) {
			if err := retireOrDropUnregisteredConnector(ctx, registry, h.dataDir, "omnigent", "removed", nil); err != nil {
				t.Fatalf("retire: %v", err)
			}
		}},
		{"removed from the roster", func(t *testing.T, h retiredOmnigentHost) {
			failed, dropped := teardownRemovedConnectorsReport(registry, []string{"omnigent", "codex"}, []string{"codex"}, connector.SetupOpts{DataDir: h.dataDir}, ctx)
			if len(failed) != 0 || !reflect.DeepEqual(dropped, []string{"omnigent"}) {
				t.Fatalf("failed=%v dropped=%v, want omnigent dropped", failed, dropped)
			}
		}},
		{"single connector switch", func(t *testing.T, h retiredOmnigentHost) {
			if err := teardownPreviousConnector(registry, "codex", connector.SetupOpts{DataDir: h.dataDir}, ctx); err != nil {
				t.Fatalf("switch to codex = %v, want it to go on", err)
			}
		}},
		{"lock only", func(t *testing.T, h retiredOmnigentHost) {
			audited := []string{}
			for run := 1; run <= 2; run++ {
				err := reconcileOrphanedConnectorRegistrations(ctx, registry, h.dataDir, []string{"codex"}, orphanConnectorReconcileOps{
					resolveOpts: func(conn connector.Connector) (connector.SetupOpts, error) {
						return connector.SetupOpts{DataDir: h.dataDir}, nil
					},
					clearLock: connector.ClearHookContractLockEntry,
					audit:     func(name string) { audited = append(audited, name) },
				})
				if err != nil {
					t.Fatalf("reconcile run %d: %v", run, err)
				}
			}
			if !reflect.DeepEqual(audited, []string{"omnigent"}) {
				t.Fatalf("audited %v, want the one teardown that changed something", audited)
			}
		}},
	} {
		t.Run(path.name, func(t *testing.T) {
			h := stageRetiredOmnigent(t)
			roster := []string{"codex"}
			if path.name == "single connector switch" {
				roster = []string{"omnigent"}
			}
			if err := connector.SaveActiveConnectors(h.dataDir, roster); err != nil {
				t.Fatal(err)
			}
			before := h.snapshot(t)
			path.run(t, h)
			h.requireStub(t)
			after := h.snapshot(t)
			// The active roster is the gateway's own bookkeeping of the names
			// it still sets up.
			rosterFile := filepath.Join(h.dataDir, "active_connector.json")
			delete(before, rosterFile)
			delete(after, rosterFile)
			if !reflect.DeepEqual(after, before) {
				for file, body := range before {
					if after[file] != body {
						t.Errorf("%s changed:\n got %q\nwant %q", file, after[file], body)
					}
				}
				for file := range after {
					if _, ok := before[file]; !ok {
						t.Errorf("%s was created", file)
					}
				}
			}
			if got := connector.LoadHookContractLockEntry(h.dataDir, "omnigent"); got.Connector != "" {
				t.Fatalf("the retired lock entry survived: %+v", got)
			}
			if got := connector.LoadHookContractLockEntry(h.dataDir, "codex"); got.Connector != "codex" {
				t.Fatalf("the surviving Codex lock entry changed: %+v", got)
			}
		})
	}
}

// A 1.0.3 Codex+OmniGent roster can become a one-target Codex setup after
// migration. The gateway must remove the retired lock peer before publishing
// Codex's fresh roster, or the CLI wait fails with "peer is not inactive".
func TestRetiredOmnigentSingleConnectorUpgradeLeavesOneLockTarget(t *testing.T) {
	h := stageRetiredOmnigent(t)
	if err := connector.SaveActiveConnectors(h.dataDir, []string{"codex", "omnigent"}); err != nil {
		t.Fatal(err)
	}
	sharedBefore, err := os.ReadFile(filepath.Join(h.dataDir, "hooks", ".hookcfg"))
	if err != nil {
		t.Fatal(err)
	}
	peerBefore := connector.LoadHookContractLockEntry(h.dataDir, "codex")
	s := multiBootSidecar(t)
	s.cfg.DataDir = h.dataDir
	registry := connector.NewDefaultRegistry()
	requested, ok := registry.Get("codex")
	if !ok {
		t.Fatal("Codex is unavailable")
	}
	if _, err := s.prepareSingleConnectorSetupTransaction(
		context.Background(), registry, connector.SetupOpts{DataDir: h.dataDir}, requested,
		"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key",
	); err != nil {
		t.Fatalf("prepare one-target Codex setup: %v", err)
	}
	h.requireStub(t)
	entries, err := connector.LoadProtectedHookContractLockEntries(h.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !reflect.DeepEqual(entries["codex"], peerBefore) {
		t.Fatalf("one-target lock = %+v, want only unchanged Codex", entries)
	}
	if body, err := os.ReadFile(filepath.Join(h.dataDir, "hooks", ".hookcfg")); err != nil || !reflect.DeepEqual(body, sharedBefore) {
		t.Fatalf("shared hook runtime = %q, %v; want %q", body, err, sharedBefore)
	}
}

// GAP-0564: the upgrade cleanup of a removed connector logs each file it
// leaves for the user, with the step: an OmniGent config.yaml that still
// names the policy module, here with a second handler key the user added
// under DefenseClaw's policy (so it is not valid YAML any more).
func TestRetiredConnectorCleanupLogsTheConfigItLeaves(t *testing.T) {
	h := stageRetiredOmnigent(t)
	writeRetiredFile(t, h.configPath, retiredPatchedConfig+"    handler: corp_policy.check\n")
	var err error
	out := captureStderr(t, func() {
		err = retireOrDropUnregisteredConnector(context.Background(), connector.NewDefaultRegistry(), h.dataDir, "omnigent", "removed", nil)
	})
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "removed connector omnigent left "+h.configPath+":") &&
			strings.Contains(line, "defenseclaw_guardrail") {
			return
		}
	}
	t.Fatalf("no log line names %s and the defenseclaw_guardrail policy:\n%s", h.configPath, out)
}

// rel-1-0-4 GAP-0661 (the T7 live cell L7-dead-ro): with ~/.omnigent
// read-only the first 1.0.4 start still finishes the cleanup, which never
// writes the agent's config: the module becomes the stub, the token goes, the
// retired lock entry is cleared, and one line names config.yaml with its step. Making the
// folder writable and starting again changes nothing: what is left is the
// user's to remove (the leftover list), never DefenseClaw's to delete.
func TestRetiredConnectorCleanupNeverWritesAReadOnlyAgentConfig(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory modes do not stop writes here")
	}
	h := stageRetiredOmnigent(t)
	configDir := filepath.Dir(h.configPath)
	if err := os.Chmod(configDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(configDir, 0o755) })
	before := h.snapshot(t)
	var err error
	out := captureStderr(t, func() {
		err = retireOrDropUnregisteredConnector(context.Background(), connector.NewDefaultRegistry(), h.dataDir, "omnigent", "removed", nil)
	})
	if err != nil {
		t.Fatalf("retire with a read-only config folder: %v", err)
	}
	h.requireStub(t)
	if got := h.snapshot(t); !reflect.DeepEqual(got, before) {
		t.Fatalf("the cleanup changed more than the module and the token:\n got %v\nwant %v", got, before)
	}
	if got := connector.LoadHookContractLockEntry(h.dataDir, "omnigent"); got.Connector != "" {
		t.Fatalf("retired lock entry = %+v, want it removed", got)
	}
	if n := strings.Count(out, "removed connector omnigent left "+h.configPath+":"); n != 1 {
		t.Fatalf("%d log lines name %s, want 1:\n%s", n, h.configPath, out)
	}
	if err := os.Chmod(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	after := retiredSnapshot(t, []string{h.home})
	if err := retireOrDropUnregisteredConnector(context.Background(), connector.NewDefaultRegistry(), h.dataDir, "omnigent", "removed", nil); err != nil {
		t.Fatalf("second start: %v", err)
	}
	if got := retiredSnapshot(t, []string{h.home}); !reflect.DeepEqual(got, after) {
		t.Fatalf("the second start changed files:\n got %v\nwant %v", got, after)
	}
}
