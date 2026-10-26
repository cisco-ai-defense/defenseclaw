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

// until 1.1: how boot treats OpenHands and OmniGent on a host an older
// release set up. Every boot path removes what DefenseClaw wrote for them and
// drops the name; none fails or keeps the name for a retry, even when a file
// cannot be removed. Delete with internal/gateway/connector/removed.go.

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

type removedBootHost struct {
	home, dataDir, hooksJSON, script, omnigentConfig, module string
}

func stageRemovedBootHost(t *testing.T) removedBootHost {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("OMNIGENT_CONFIG", "")
	t.Setenv("OMNIGENT_CONFIG_HOME", "")
	h := removedBootHost{home: home, dataDir: filepath.Join(home, ".defenseclaw")}
	h.script = filepath.Join(h.dataDir, "hooks", "openhands-hook.sh")
	h.module = filepath.Join(h.dataDir, "hooks", "defenseclaw_omnigent_policy.py")
	h.hooksJSON = filepath.Join(home, ".openhands", "hooks.json")
	h.omnigentConfig = filepath.Join(home, ".omnigent", "config.yaml")
	for path, body := range map[string]string{
		// The 1.0.4 deny stub and the 1.0.3 policy module.
		h.script: "#!/bin/sh -p\n# defenseclaw-managed-hook v0 (disabled tombstone)\n# OpenHands support was removed in DefenseClaw 1.0.4.\nexit 2\n",
		h.module: "# defenseclaw-managed-policy v3\nPOLICY_REGISTRY = []\n",
		h.hooksJSON: `{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":` + strconv.Quote(h.script) +
			`},{"type":"command","command":"/opt/mine/hook"}]}]}`,
		h.omnigentConfig: "policy_modules:\n  - defenseclaw_omnigent_policy\npolicies:\n  defenseclaw_guardrail:\n" +
			"    handler: defenseclaw_omnigent_policy.defenseclaw_policy\nmodel: m\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h removedBootHost) requireRemoved(t *testing.T) {
	t.Helper()
	for _, path := range []string{h.script, h.module} {
		if _, err := os.Lstat(path); err == nil {
			t.Errorf("%s is still there", path)
		}
	}
	for path, mine := range map[string]string{h.hooksJSON: "/opt/mine/hook", h.omnigentConfig: "model: m"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if strings.Contains(text, "openhands-hook.sh") || strings.Contains(text, "defenseclaw_omnigent_policy") || !strings.Contains(text, mine) {
			t.Errorf("%s after boot:\n%s", path, text)
		}
	}
}

// The roster path: a previous roster that named OpenHands and OmniGent drops
// both, removes what DefenseClaw wrote, and keeps nothing for a retry.
func TestRemovedConnectorBootRemovesWhatDefenseClawWrote(t *testing.T) {
	h := stageRemovedBootHost(t)
	registry := connector.NewDefaultRegistry()
	failed, dropped := teardownRemovedConnectorsReport(registry, []string{"openhands", "omnigent", "codex"}, []string{"codex"},
		connector.SetupOpts{DataDir: h.dataDir}, "", context.Background())
	sort.Strings(dropped)
	if len(failed) != 0 || !reflect.DeepEqual(dropped, []string{"omnigent", "openhands"}) {
		t.Fatalf("failed=%v dropped=%v, want both dropped and none failed", failed, dropped)
	}
	h.requireRemoved(t)
}

// The lock-only path: a 1.0.4 host kept the OpenHands and OmniGent lock
// entries (and the deny stubs and registrations) after it dropped them from
// the roster. A 1.0.5 boot runs their teardown there too and drops the
// entries, so the next boot finds no orphan (GAP-1843).
func TestRemovedConnectorLockOnlyBootRemovesWhatDefenseClawWrote(t *testing.T) {
	h := stageRemovedBootHost(t)
	restore, err := connector.BindUserHomeDir(h.home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	lock := `{"version":2,"updated_at":"2026-10-01T00:00:00Z","connectors":{` +
		`"codex":{"connector":"codex","contract_id":"codex-hooks-v1","defenseclaw_version":"1.0.4","hook_fail_mode":"open","updated_at":"2026-10-01T00:00:00Z"},` +
		`"openhands":{"connector":"openhands","contract_id":"openhands-hooks-v1","defenseclaw_version":"1.0.3","hook_fail_mode":"open","updated_at":"2026-10-01T00:00:00Z"},` +
		`"omnigent":{"connector":"omnigent","contract_id":"omnigent-policy-v1","defenseclaw_version":"1.0.3","hook_fail_mode":"open","updated_at":"2026-10-01T00:00:00Z"}}}` + "\n"
	if err := os.WriteFile(filepath.Join(h.dataDir, "hook_contract_lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := connector.SaveActiveConnectors(h.dataDir, []string{"codex"}); err != nil {
		t.Fatal(err)
	}
	ops := orphanConnectorReconcileOps{
		resolveOpts: func(connector.Connector) (connector.SetupOpts, error) {
			return connector.SetupOpts{DataDir: h.dataDir}, nil
		},
		clearLock: connector.ClearHookContractLockEntry,
	}
	for boot := 1; boot <= 2; boot++ {
		if err := reconcileOrphanedConnectorRegistrations(context.Background(), connector.NewDefaultRegistry(), h.dataDir, []string{"codex"}, ops); err != nil {
			t.Fatalf("boot %d: reconcile = %v, want no failure", boot, err)
		}
		h.requireRemoved(t)
		for _, name := range []string{"openhands", "omnigent"} {
			if got := connector.LoadHookContractLockEntry(h.dataDir, name); got.Connector != "" {
				t.Errorf("boot %d: the %s lock entry is still there", boot, name)
			}
		}
	}
	if got := connector.LoadHookContractLockEntry(h.dataDir, "codex"); got.Connector != "codex" {
		t.Errorf("the codex lock entry went: %+v", got)
	}
}

// A removal that cannot finish (the hooks folder is read-only) never fails a
// boot path and never keeps the name: nothing of it blocks, and doctor lists
// what is left as information.
func TestRemovedConnectorBootNeverFailsOnALeftover(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX folder permissions that bind the test user")
	}
	h := stageRemovedBootHost(t)
	hooks := filepath.Dir(h.script)
	if err := os.Chmod(hooks, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hooks, 0o700) })
	ctx := context.Background()
	registry := connector.NewDefaultRegistry()
	for _, name := range []string{"openhands", "omnigent"} {
		if err := retireOrDropUnregisteredConnector(ctx, registry, connector.SetupOpts{DataDir: h.dataDir}, name, "removed", nil); err != nil {
			t.Fatalf("retire %s = %v, want no failure", name, err)
		}
	}
	if left, _ := connector.RemovedConnectorLeftovers("openhands", connector.SetupOpts{DataDir: h.dataDir}); len(left) == 0 {
		t.Fatal("the script the teardown could not remove is not listed")
	}
	if _, err := os.Lstat(h.script); err != nil {
		t.Fatalf("read-only hooks folder: %v", err)
	}
}
