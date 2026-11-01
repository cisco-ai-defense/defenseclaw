// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// until 1.1: OmniGent was removed in 1.0.4 (#1182). A native 1.0.x install
// that configured it must still repair, upgrade and uninstall: Setup reads its
// state and tears it down, but never selects it again.

func TestRetiredOmnigentInstallStateLoadsForTeardown(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	state := testInstallState(installRoot, dataRoot, maintenancePath, testPreviousTransactionID, "1.0.3")
	state.Connector = "omnigent"
	state.OmnigentConfigHome = filepath.Join(filepath.Dir(dataRoot), ".omnigent")
	writeInstallTree(t, installRoot, state)
	raw, err := os.ReadFile(filepath.Join(installRoot, "installer", "install-state.json"))
	if err != nil || !strings.Contains(string(raw), `"omnigent_config_home"`) {
		t.Fatalf("fixture lacks the 1.0.x omnigent_config_home key (err=%v): %s", err, raw)
	}

	loaded, err := loadInstallStateFromTreeForRoots(installRoot, installRoot, dataRoot, maintenancePath)
	if err != nil {
		t.Fatalf("1.0.x OmniGent install state was rejected: %v", err)
	}
	if loaded.Connector != "omnigent" || loaded.OmnigentConfigHome != state.OmnigentConfigHome {
		t.Fatalf("loaded state = %+v", loaded)
	}

	state.OmnigentConfigHome = "relative-omnigent"
	writeInstallTree(t, installRoot, state)
	if _, err := loadInstallStateFromTreeForRoots(installRoot, installRoot, dataRoot, maintenancePath); err == nil ||
		!strings.Contains(err.Error(), "OmniGent configuration home") {
		t.Fatalf("relative OmniGent home = %v, want it rejected", err)
	}
}

func TestRetiredOmnigentIsNeverSelected(t *testing.T) {
	if validConnector("omnigent") || !validPreviousConnector("omnigent") || !isRetiredNativeConnector("omnigent") {
		t.Fatal("omnigent must be a previous-only connector")
	}
	if _, err := parseArgs([]string{"/quiet", "INSTALLSCOPE=user", "CONNECTOR=omnigent"}); err == nil ||
		!strings.Contains(err.Error(), `invalid CONNECTOR "omnigent"`) {
		t.Fatalf("CONNECTOR=omnigent = %v, want it rejected", err)
	}

	old := &installState{Connector: "omnigent", Mode: "action", Version: "1.0.3"}
	for _, action := range []string{"repair", "upgrade"} {
		got := applyExistingInstallSelection(options{Action: action, Connector: "none", Mode: "observe"}, old)
		if got.Connector != "none" || got.PreserveConnectorConfiguration || got.Mode != "action" {
			t.Fatalf("%s from an OmniGent install = %+v, want connector none, not preserved, mode kept", action, got)
		}
	}
	if got := applyExistingInstallSelection(options{Action: "upgrade"}, old); got.FromVersion != "1.0.3" {
		t.Fatalf("upgrade from version = %q", got.FromVersion)
	}
	chosen := applyExistingInstallSelection(options{Action: "repair", Connector: "codex", ConnectorSet: true}, old)
	if chosen.Connector != "codex" {
		t.Fatalf("explicit choice over an OmniGent install = %q", chosen.Connector)
	}
	// A supported connector is still carried forward and preserved.
	kept := applyExistingInstallSelection(options{Action: "repair", Connector: "none"}, &installState{Connector: "codex", Mode: "observe"})
	if kept.Connector != "codex" || !kept.PreserveConnectorConfiguration {
		t.Fatalf("repair from a Codex install = %+v", kept)
	}
}

func TestConnectorsForNativeUninstallFindsRetiredOmnigent(t *testing.T) {
	write := func(t *testing.T, path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name  string
		state *installState
		write func(*testing.T, string)
	}{
		{name: "installer state", state: &installState{Connector: "omnigent"}},
		{name: "active roster", write: func(t *testing.T, dataRoot string) {
			write(t, filepath.Join(dataRoot, "active_connector.json"), `{"version":3,"names":["omnigent"]}`)
		}},
		{name: "configured roster", write: func(t *testing.T, dataRoot string) {
			write(t, filepath.Join(dataRoot, "config.yaml"), "guardrail:\n  connectors:\n    omnigent:\n      mode: action\n")
		}},
	}
	for _, logicalName := range []string{"config", "module", "pth"} {
		logicalName := logicalName
		tests = append(tests, struct {
			name  string
			state *installState
			write func(*testing.T, string)
		}{name: "managed " + logicalName + " backup", write: func(t *testing.T, dataRoot string) {
			write(t, filepath.Join(dataRoot, "connector_backups", "omnigent", logicalName+".json"), "{}")
		}})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dataRoot := t.TempDir()
			if test.write != nil {
				test.write(t, dataRoot)
			}
			got, err := connectorsForNativeUninstall(test.state, dataRoot)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, []string{"omnigent"}) {
				t.Fatalf("connectors = %v, want [omnigent]", got)
			}
		})
	}
}

func TestRetiredOmnigentTeardownBindsItsConfigHome(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "Profile", ".defenseclaw")
	home := filepath.Join(root, "Profile", ".omnigent")
	for _, action := range []string{"teardown", "verify"} {
		args, err := connectorLifecycleCommandArgs(dataRoot, "omnigent", action, []string{"OMNIGENT_CONFIG_HOME=" + home})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{
			"connector", action,
			"--connector", "omnigent",
			"--data-dir", dataRoot,
			"--config-home", home,
			"--json",
		}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("%s args = %q, want %q", action, args, want)
		}
	}
	if _, err := connectorLifecycleConfigHome(nil, "omnigent"); err == nil ||
		!strings.Contains(err.Error(), "OMNIGENT_CONFIG_HOME is empty") {
		t.Fatalf("missing OmniGent home = %v, want it rejected", err)
	}
	transaction := setupTransaction{DataRoot: dataRoot, PreviousOmnigentConfigHome: home}
	if got := envValue(transactionPreviousChildEnv(transaction), "OMNIGENT_CONFIG_HOME"); got != home {
		t.Fatalf("previous child env OMNIGENT_CONFIG_HOME = %q, want %q", got, home)
	}
	if homes := connectorCleanupHomes(transaction, "omnigent"); len(homes) == 0 || homes[0] != home {
		t.Fatalf("cleanup homes = %v, want %s first", homes, home)
	}
	if err := validateConnectorReconciliationIdentity("omnigent", home); err != nil {
		t.Fatalf("OmniGent reconciliation residue rejected: %v", err)
	}
}

// A connector-preserving repair keeps the supported roster but tears the
// removed OmniGent down instead of reconciling it.
func TestReconcilePreservedConnectorsTearsDownRetiredOmnigent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	home := filepath.Join(root, ".omnigent")
	transaction := setupTransaction{
		ID:                         strings.Repeat("a", 32),
		DataRoot:                   filepath.Join(root, "data"),
		PreviousConnectors:         []string{"codex", "omnigent"},
		PreviousCodexHome:          filepath.Join(root, "codex"),
		CodexHome:                  filepath.Join(root, "codex"),
		PreviousOmnigentConfigHome: home,
		OmnigentConfigHome:         home,
	}
	var calls []string
	recorder := reconcilePreservedConnectors(
		transaction,
		filepath.Join(root, "defenseclaw-gateway.exe"),
		transactionPreviousChildEnv(transaction),
		transactionChildEnv(transaction),
		func(_, _, connector, action string, env []string) error {
			calls = append(calls, connector+":"+action+":"+envValue(env, "OMNIGENT_CONFIG_HOME"))
			return nil
		},
	)
	want := []string{"codex:reconcile:" + home, "omnigent:teardown:" + home, "omnigent:verify:" + home}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("preserved calls = %v, want %v", calls, want)
	}
	if len(recorder.attempts) != 3 || len(recorder.failures) != 0 {
		t.Fatalf("reconciliation = %+v", recorder)
	}
}
