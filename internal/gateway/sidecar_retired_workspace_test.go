// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

// until 1.1: T8 smoke review loop round 3. Boot tore a removed connector down
// with the data directory only, so a workspace-pinned 1.0.x OpenHands
// registration (<workspace>/.openhands/hooks.json) whose script was gone
// passed as clean, and OpenHands let its calls through. Every boot path now
// gives the teardown the configured workspace. Delete with
// internal/gateway/connector/removed.go.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

type retiredWorkspaceHost struct {
	dataDir, workspace, script string
	sidecar                    *Sidecar
}

// stageRetiredWorkspaceOpenHands leaves a 1.0.x OpenHands registration in a
// pinned workspace whose hook script, backup records and lock entry are gone,
// with the workspace pinned in config.yaml (claw.workspace_dir).
func stageRetiredWorkspaceOpenHands(t *testing.T, lockEntry bool) retiredWorkspaceHost {
	t.Helper()
	home := testenv.PrivateTempDir(t)
	restoreHome, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	h := retiredWorkspaceHost{dataDir: filepath.Join(home, ".defenseclaw"), workspace: filepath.Join(home, "repo")}
	h.script = filepath.Join(h.dataDir, "hooks", "openhands-hook.sh")
	if err := os.MkdirAll(filepath.Join(h.dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeRetiredFile(t, filepath.Join(h.workspace, ".openhands", "hooks.json"),
		`{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"`+h.script+`","timeout":60}]}]}`)
	if lockEntry {
		writeRetiredFile(t, filepath.Join(h.dataDir, "hook_contract_lock.json"), `{"version":2,"updated_at":"2026-10-01T00:00:00Z","connectors":{`+
			`"openhands":{"connector":"openhands","defenseclaw_version":"1.0.3","hook_fail_mode":"closed","updated_at":"2026-10-01T00:00:00Z"}}}`+"\n")
	}
	h.sidecar = &Sidecar{cfg: &config.Config{DataDir: h.dataDir, Claw: config.ClawConfig{WorkspaceDir: h.workspace}}}
	return h
}

func (h retiredWorkspaceHost) requireStub(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(h.script)
	if err != nil || !strings.Contains(string(data), "OpenHands support was removed in DefenseClaw 1.0.4") {
		t.Fatalf("%s = %q, %v; want the stub that blocks every call", h.script, data, err)
	}
	if entry := connector.LoadHookContractLockEntry(h.dataDir, "openhands"); entry.HookScriptDigests["openhands-hook.sh"] == "" {
		t.Fatalf("the lock does not seal the stub: %+v", entry)
	}
}

func TestRetiredConnectorBootChecksTheConfiguredWorkspace(t *testing.T) {
	ctx := context.Background()
	registry := connector.NewDefaultRegistry()
	pinned := &config.Config{DataDir: "/d", Claw: config.ClawConfig{WorkspaceDir: "/w"}}
	if got := (&Sidecar{cfg: pinned}).retiredConnectorOpts(); got != retiredConnectorOpts("/d", pinned.ConnectorWorkspaceDir()) || got.WorkspaceDir == "" {
		t.Fatalf("retiredConnectorOpts = %+v, want the data directory and the configured workspace", got)
	}
	if got := (&Sidecar{}).retiredConnectorOpts(); got.DataDir != "" || got.WorkspaceDir != "" {
		t.Fatalf("retiredConnectorOpts with no config = %+v", got)
	}

	t.Run("removed from the roster", func(t *testing.T) {
		h := stageRetiredWorkspaceOpenHands(t, false)
		failed, _ := teardownRemovedConnectorsReport(registry, []string{"openhands"}, nil,
			connector.SetupOpts{DataDir: h.dataDir}, h.sidecar.currentConfig().ConnectorWorkspaceDir(), ctx)
		if len(failed) != 0 {
			t.Fatalf("failed = %v", failed)
		}
		h.requireStub(t)
	})
	t.Run("previous or rollback candidate", func(t *testing.T) {
		h := stageRetiredWorkspaceOpenHands(t, false)
		if err := retireOrDropUnregisteredConnector(ctx, registry, h.sidecar.retiredConnectorOpts(), "openhands", "removed", nil); err != nil {
			t.Fatal(err)
		}
		h.requireStub(t)
	})
	t.Run("lock only", func(t *testing.T) {
		h := stageRetiredWorkspaceOpenHands(t, true)
		if removedConnectorAlreadyTornDown(h.sidecar.retiredConnectorOpts(), "openhands") {
			t.Fatal("a workspace registration whose script is gone counted as torn down")
		}
		if err := connector.SaveActiveConnectors(h.dataDir, []string{"codex"}); err != nil {
			t.Fatal(err)
		}
		err := reconcileOrphanedConnectorRegistrations(ctx, registry, h.dataDir, []string{"codex"}, orphanConnectorReconcileOps{
			resolveOpts: func(conn connector.Connector) (connector.SetupOpts, error) {
				return connector.SetupOpts{DataDir: h.dataDir}, nil
			},
			clearLock:    connector.ClearHookContractLockEntry,
			workspaceDir: h.sidecar.currentConfig().ConnectorWorkspaceDir(),
		})
		if err != nil {
			t.Fatal(err)
		}
		h.requireStub(t)
		if !removedConnectorAlreadyTornDown(h.sidecar.retiredConnectorOpts(), "openhands") {
			t.Fatal("not torn down after the reconcile")
		}
	})
}
