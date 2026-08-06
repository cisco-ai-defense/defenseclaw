// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
)

func TestOmnigentSetupSelectionAndLifecycleBinding(t *testing.T) {
	opts, err := parseArgs([]string{
		"/quiet",
		"/norestart",
		"INSTALLSCOPE=user",
		"CONNECTOR=omnigent",
		"MODE=action",
		"STARTGATEWAY=1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Connector != "omnigent" || !opts.ConnectorSet || opts.Mode != "action" ||
		!opts.StartGateway || !validConnector(opts.Connector) {
		t.Fatalf("OmniGent Setup selection was not preserved: %+v", opts)
	}
	if !requestedServices(opts, serviceState{}).Gateway {
		t.Fatal("OmniGent Setup selection did not require the native gateway")
	}
	initArgs := initialConfigurationArgs(opts)
	wantInitArgs := []string{
		"init", "--skip-install", "--non-interactive", "--yes",
		"--connector", "omnigent",
		"--profile", "action",
		"--no-start-gateway", "--no-verify",
	}
	if !slices.Equal(initArgs, wantInitArgs) {
		t.Fatalf("OmniGent canonical initialization args = %q, want %q", initArgs, wantInitArgs)
	}

	dataRoot := filepath.Join(t.TempDir(), ".defenseclaw")
	configHome := filepath.Join(t.TempDir(), ".omnigent")
	args, err := connectorLifecycleCommandArgs(
		dataRoot,
		"omnigent",
		"reconcile",
		[]string{"OMNIGENT_CONFIG_HOME=" + configHome},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"connector", "reconcile",
		"--connector", "omnigent",
		"--data-dir", dataRoot,
		"--config-home", configHome,
		"--json",
	}
	if !slices.Equal(args, want) {
		t.Fatalf("OmniGent lifecycle arguments = %q, want %q", args, want)
	}
	if _, err := connectorLifecycleConfigHome(nil, "omnigent"); err == nil ||
		!strings.Contains(err.Error(), "OMNIGENT_CONFIG_HOME is empty") {
		t.Fatalf("missing OmniGent home was not rejected: %v", err)
	}
}

func TestOmnigentNativeUninstallDiscoversEveryCustodyAuthority(t *testing.T) {
	tests := []struct {
		name  string
		state *installState
		write func(*testing.T, string)
	}{
		{
			name:  "installer state",
			state: &installState{Connector: "omnigent"},
		},
		{
			name: "active roster",
			write: func(t *testing.T, dataRoot string) {
				t.Helper()
				if err := os.WriteFile(
					filepath.Join(dataRoot, "active_connector.json"),
					[]byte(`{"version":3,"names":["omnigent"]}`),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "configured roster",
			write: func(t *testing.T, dataRoot string) {
				t.Helper()
				if err := os.WriteFile(
					filepath.Join(dataRoot, "config.yaml"),
					[]byte("guardrail:\n  connectors:\n    omnigent:\n      mode: action\n"),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, logicalName := range []string{"config", "module", "pth"} {
		logicalName := logicalName
		tests = append(tests, struct {
			name  string
			state *installState
			write func(*testing.T, string)
		}{
			name: "managed " + logicalName + " backup",
			write: func(t *testing.T, dataRoot string) {
				t.Helper()
				path := filepath.Join(
					dataRoot,
					"connector_backups",
					"omnigent",
					logicalName+".json",
				)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		})
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
			if !slices.Contains(got, "omnigent") {
				t.Fatalf("native uninstall connectors = %v, want OmniGent", got)
			}
		})
	}
}

func TestOmnigentTransactionBindsManagedHomeAndLifecycleEnvironment(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, ".defenseclaw")
	previousHome := filepath.Join(root, "omnigent-previous")
	stateHome := filepath.Join(root, "omnigent-state")
	currentHome := filepath.Join(root, "omnigent-current")
	backupPath := filepath.Join(dataRoot, "connector_backups", "omnigent", "config.json")
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{
		"path": filepath.Join(previousHome, "config.yaml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	resolved, err := resolvePreviousConnectorHome(
		stateHome,
		[]string{"omnigent"},
		dataRoot,
		"omnigent",
		"config",
		currentHome,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !samePath(resolved, previousHome) {
		t.Fatalf("managed OmniGent home = %q, want %q", resolved, previousHome)
	}

	transaction := setupTransaction{
		DataRoot:                   dataRoot,
		PreviousOmnigentConfigHome: previousHome,
		OmnigentConfigHome:         currentHome,
		PreviousState: &installState{
			OmnigentConfigHome: stateHome,
		},
	}
	homes := connectorCleanupHomes(transaction, "omnigent")
	wantHomes := []string{previousHome, stateHome, currentHome}
	if !slices.Equal(homes, wantHomes) {
		t.Fatalf("OmniGent cleanup homes = %q, want %q", homes, wantHomes)
	}
	if !connectorHomeChanged(transaction, "omnigent") {
		t.Fatal("OmniGent home change was not detected")
	}
	env := connectorLifecycleEnvForHome(transaction, "omnigent", currentHome)
	if got := envValue(env, "OMNIGENT_CONFIG_HOME"); !samePath(got, currentHome) {
		t.Fatalf("OmniGent lifecycle home = %q, want %q", got, currentHome)
	}
}

func TestOmnigentRepairUpgradePreservesExactHomeAndReconciles(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	previous.Connector = "omnigent"
	previous.Mode = "observe"
	previous.OmnigentConfigHome = filepath.Join(filepath.Dir(dataRoot), ".omnigent")

	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreserveConnectorConfiguration = true
	transaction.PreviousConnectors = []string{"omnigent"}
	transaction.TargetConnector = "omnigent"
	transaction.TargetServices.Gateway = true
	transaction.PreviousOmnigentConfigHome = previous.OmnigentConfigHome
	transaction.OmnigentConfigHome = previous.OmnigentConfigHome
	expected := setupTransactionExpectations{
		InstallRoot:     installRoot,
		DataRoot:        dataRoot,
		MaintenancePath: maintenancePath,
	}
	if err := validateSetupTransaction(transaction, expected); err != nil {
		t.Fatalf("valid OmniGent-preserving transaction rejected: %v", err)
	}

	var calls []string
	recorder := reconcilePreservedConnectors(
		transaction,
		filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe"),
		transactionPreviousChildEnv(transaction),
		transactionChildEnv(transaction),
		func(_, _, connectorName, action string, env []string) error {
			calls = append(calls, connectorName+":"+action+":"+envValue(env, "OMNIGENT_CONFIG_HOME"))
			return nil
		},
	)
	wantCall := "omnigent:reconcile:" + previous.OmnigentConfigHome
	if len(recorder.failures) != 0 || !slices.Equal(calls, []string{wantCall}) {
		t.Fatalf("OmniGent preserved reconciliation = %q, failures = %+v", calls, recorder.failures)
	}

	changed := transaction
	changed.OmnigentConfigHome = filepath.Join(filepath.Dir(dataRoot), "moved-omnigent")
	if err := validateSetupTransaction(changed, expected); err == nil {
		t.Fatal("connector-preserving transaction accepted a changed OmniGent home")
	}
}

func TestOmnigentHomeMoveTearsDownTheExactPreviousHome(t *testing.T) {
	previousHome := `C:\Users\tester\omnigent-a`
	currentHome := `C:\Users\tester\omnigent-b`
	transaction := setupTransaction{
		DataRoot:                   `C:\Users\tester\.defenseclaw`,
		PreviousConnectors:         []string{"omnigent"},
		TargetConnector:            "omnigent",
		PreviousOmnigentConfigHome: previousHome,
		OmnigentConfigHome:         currentHome,
	}
	var calls []string
	err := teardownSupersededConnectors(
		transaction,
		`C:\Program Files\DefenseClaw\defenseclaw-gateway.exe`,
		transactionPreviousChildEnv(transaction),
		func(_, _, connectorName, action string, env []string) error {
			calls = append(calls, connectorName+":"+action+":"+envValue(env, "OMNIGENT_CONFIG_HOME"))
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"omnigent:teardown:" + previousHome,
		"omnigent:verify:" + previousHome,
	}
	if !slices.Equal(calls, want) {
		t.Fatalf("OmniGent home-move lifecycle = %q, want %q", calls, want)
	}
}

func TestOmnigentDeferredUninstallConnectorSetIsAccepted(t *testing.T) {
	fixture := newDeferredCleanupFixture(t)
	record := fixture.record
	record.VerifiedConnectors = []string{"claudecode", "codex", "omnigent"}
	paths := hookruntime.Paths{
		Root:     record.RuntimeRoot,
		Launcher: record.LauncherPath,
		State:    record.StatePath,
	}
	if err := validateDeferredUninstallCleanupRecord(
		record,
		paths,
		record.InstallerStateRoot,
		record.MaintenancePath,
		record.RunValueName,
		record.RunCommand,
	); err != nil {
		t.Fatalf("OmniGent deferred-uninstall custody rejected: %v", err)
	}
}
