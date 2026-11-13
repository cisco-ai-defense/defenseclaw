// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The fixture keeps the real connector's setup-time artifact declaration but
// leaves its agent configuration out of this hook-directory ownership test.
type setupRemoveFilesConnector struct {
	connector.Connector
	scriptNames []string
}

func (c setupRemoveFilesConnector) Teardown(context.Context, connector.SetupOpts) error { return nil }
func (c setupRemoveFilesConnector) VerifyClean(connector.SetupOpts) error               { return nil }
func (c setupRemoveFilesConnector) HookScriptNames(opts connector.SetupOpts) []string {
	if c.scriptNames != nil {
		return c.scriptNames
	}
	if owner, ok := c.Connector.(connector.HookScriptOwner); ok {
		return owner.HookScriptNames(opts)
	}
	return nil
}
func (c setupRemoveFilesConnector) ManagedPluginArtifacts(opts connector.SetupOpts) []string {
	return connector.ManagedPluginArtifacts(c.Connector, opts)
}

func TestSetupRemoveClearsWrittenHookFilesForEveryBuiltin(t *testing.T) {
	testenv.IsolateAccount(t)
	builtins := connector.NewDefaultRegistry()
	for _, name := range builtins.Names() {
		t.Run(name, func(t *testing.T) {
			original, _ := builtins.Get(name)
			dataDir := t.TempDir()
			opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token", HookAPIToken: "test-token", HookAPITokenScoped: true}
			hookDir := filepath.Join(dataDir, "hooks")
			var written []string
			if len(connector.ManagedPluginArtifacts(original, opts)) == 0 {
				if err := connector.WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, original); err != nil {
					t.Fatalf("write setup hook files: %v", err)
				}
				entries, err := os.ReadDir(hookDir)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					written = append(written, entry.Name())
				}
			} else {
				// Plugin Setup writes the shared gateway helper record, but no
				// shell hook scripts. Seed that one setup artifact directly.
				if err := os.MkdirAll(hookDir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(hookDir, ".gateway-helper"), []byte("helper\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				written = append(written, ".gateway-helper")
			}
			probe := setupRemoveFilesConnector{Connector: original}
			reg := connector.NewRegistry()
			reg.RegisterBuiltin(probe)
			failed, _ := teardownRemovedConnectorsReport(reg, []string{name}, nil, opts, "", context.Background())
			if len(failed) != 0 {
				t.Fatalf("remove failed: %v", failed)
			}
			for _, name := range written {
				if _, err := os.Lstat(filepath.Join(hookDir, name)); !os.IsNotExist(err) {
					t.Errorf("setup-written %s remains: %v", name, err)
				}
			}
		})
	}
}

func TestSetupRemovePreservesSharedHookFilesForConfiguredPeer(t *testing.T) {
	testenv.IsolateAccount(t)
	builtins := connector.NewDefaultRegistry()
	removed, _ := builtins.Get("devin")
	peer, _ := builtins.Get("kiro")
	dataDir := t.TempDir()
	opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token", HookAPIToken: "test-token", HookAPITokenScoped: true}
	hookDir := filepath.Join(dataDir, "hooks")
	for _, conn := range []connector.Connector{removed, peer} {
		if err := connector.WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
			t.Fatal(err)
		}
	}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(setupRemoveFilesConnector{Connector: removed})
	reg.RegisterBuiltin(setupRemoveFilesConnector{Connector: peer})
	failed, _ := teardownRemovedConnectorsReport(reg, []string{"devin", "kiro"}, []string{"kiro"}, opts, "", context.Background())
	if len(failed) != 0 {
		t.Fatalf("remove failed: %v", failed)
	}
	if _, err := os.Lstat(filepath.Join(hookDir, "devin-hook.sh")); !os.IsNotExist(err) {
		t.Errorf("removed connector script remains: %v", err)
	}
	for _, name := range []string{"kiro-hook.sh", "inspect-tool.sh", "_hardening.sh"} {
		if _, err := os.Stat(filepath.Join(hookDir, name)); err != nil {
			t.Errorf("configured peer's %s was removed: %v", name, err)
		}
	}
}

func TestSetupRemoveKeepsHookScriptNamedByConfiguredPeer(t *testing.T) {
	testenv.IsolateAccount(t)
	builtins := connector.NewDefaultRegistry()
	removed, _ := builtins.Get("devin")
	peer, _ := builtins.Get("kiro")
	dataDir := t.TempDir()
	opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token", HookAPIToken: "test-token", HookAPITokenScoped: true}
	hookDir := filepath.Join(dataDir, "hooks")
	if err := connector.WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, removed); err != nil {
		t.Fatal(err)
	}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(setupRemoveFilesConnector{Connector: removed})
	reg.RegisterBuiltin(setupRemoveFilesConnector{Connector: peer, scriptNames: []string{"devin-hook.sh"}})
	failed, _ := teardownRemovedConnectorsReport(reg, []string{"devin", "kiro"}, []string{"kiro"}, opts, "", context.Background())
	if len(failed) != 0 {
		t.Fatalf("remove failed: %v", failed)
	}
	if _, err := os.Stat(filepath.Join(hookDir, "devin-hook.sh")); err != nil {
		t.Fatalf("removed a script the configured peer still names: %v", err)
	}
}

func TestSetupRemoveTransactionalTeardownClearsWrittenHookFile(t *testing.T) {
	testenv.IsolateAccount(t)
	builtins := connector.NewDefaultRegistry()
	original, _ := builtins.Get("devin")
	probe := setupRemoveFilesConnector{Connector: original}
	dataDir := t.TempDir()
	opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token", HookAPIToken: "test-token", HookAPITokenScoped: true}
	hookDir := filepath.Join(dataDir, "hooks")
	if err := connector.WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, original); err != nil {
		t.Fatal(err)
	}
	point := multiConnectorSetupRollbackPoint{
		conn:         probe,
		opts:         opts,
		previousLock: connector.NewHookContractLockEntry(opts, probe, "test-build"),
	}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(probe)
	removed, failed := teardownRemovedConnectorCandidates([]multiConnectorSetupRollbackPoint{point}, context.Background(),
		func(conn connector.Connector, priorOpts connector.SetupOpts) error {
			return removeTeardownHookFiles(reg, conn, nil, priorOpts)
		})
	if len(failed) != 0 || len(removed) != 1 {
		t.Fatalf("transactional removal: removed=%d failed=%v", len(removed), failed)
	}
	if _, err := os.Lstat(filepath.Join(hookDir, "devin-hook.sh")); !os.IsNotExist(err) {
		t.Fatalf("transactional removal left setup-written hook: %v", err)
	}
}

func TestDisabledConnectorKeepsCachedHookPath(t *testing.T) {
	builtins := connector.NewDefaultRegistry()
	original, _ := builtins.Get("devin")
	dataDir := t.TempDir()
	opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token", HookAPIToken: "test-token", HookAPITokenScoped: true}
	hookDir := filepath.Join(dataDir, "hooks")
	if err := connector.WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, original); err != nil {
		t.Fatal(err)
	}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(setupRemoveFilesConnector{Connector: original})
	failed, _ := teardownRemovedConnectorsReport(reg, []string{"devin"}, nil, opts, "", context.Background(), []string{"devin"})
	if len(failed) != 0 {
		t.Fatalf("disable failed: %v", failed)
	}
	if _, err := os.Stat(filepath.Join(hookDir, "devin-hook.sh")); err != nil {
		t.Fatalf("disabled connector's cached hook path was removed: %v", err)
	}
}

func TestManagedReconcileKeepsManagedHookScripts(t *testing.T) {
	builtins := connector.NewDefaultRegistry()
	original, _ := builtins.Get("devin")
	dataDir := t.TempDir()
	perUser := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token", HookAPIToken: "test-token", HookAPITokenScoped: true}
	hookDir := filepath.Join(dataDir, "hooks")
	if err := connector.WriteHookScriptsForConnectorObjectWithOpts(hookDir, perUser, original); err != nil {
		t.Fatal(err)
	}
	if err := connector.SaveActiveConnectors(dataDir, []string{"devin"}); err != nil {
		t.Fatal(err)
	}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(setupRemoveFilesConnector{Connector: original})
	s := &Sidecar{cfg: &config.Config{DataDir: dataDir, DeploymentMode: string(config.DeploymentModeManagedEnterprise)}}
	if err := s.reconcileUnconfiguredConnectors(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(hookDir, "devin-hook.sh")); err != nil {
		t.Fatalf("managed hook script changed during reconciliation: %v", err)
	}
}
