// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestConnectorReconciliationRecordsAndClearsPerConfigHome(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "private", connectorReconciliationFileName)
	codexHome := filepath.Join(root, "codex")
	claudeHome := filepath.Join(root, "claude")
	codexID := strings.Repeat("a", 32)
	claudeID := strings.Repeat("b", 32)

	codexAttempt := connectorReconciliationAttempt{Connector: "codex", ConfigHome: codexHome}
	codexFailure := connectorReconciliationFailure{
		Connector:     "codex",
		Operation:     "payload-missing",
		ConfigHome:    codexHome,
		Message:       "gateway quarantined",
		TransactionID: codexID,
	}
	if err := updateConnectorReconciliationAt(path, []connectorReconciliationAttempt{codexAttempt}, []connectorReconciliationFailure{codexFailure}); err != nil {
		t.Fatal(err)
	}

	claudeAttempt := connectorReconciliationAttempt{Connector: "claudecode", ConfigHome: claudeHome}
	claudeFailure := connectorReconciliationFailure{
		Connector:     "claudecode",
		Operation:     "teardown",
		ConfigHome:    claudeHome,
		Message:       "settings file is locked",
		TransactionID: claudeID,
	}
	if err := updateConnectorReconciliationAt(path, []connectorReconciliationAttempt{claudeAttempt}, []connectorReconciliationFailure{claudeFailure}); err != nil {
		t.Fatal(err)
	}

	if err := updateConnectorReconciliationAt(path, []connectorReconciliationAttempt{codexAttempt}, nil); err != nil {
		t.Fatal(err)
	}
	state, err := readConnectorReconciliationAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || len(state.Failures) != 1 || state.Failures[0].Connector != "claudecode" {
		t.Fatalf("successful Codex retry removed the wrong residue: %+v", state)
	}

	if err := updateConnectorReconciliationAt(path, []connectorReconciliationAttempt{claudeAttempt}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reconciliation marker survived complete cleanup: %v", err)
	}
}

func TestConnectorReconciliationRecorderCapturesMissingPayload(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "private", connectorReconciliationFileName)
	home := filepath.Join(root, "codex")
	transactionID := strings.Repeat("c", 32)
	recorder := connectorReconciliationRecorder{}
	if recorder.run(transactionID, "codex", home, "payload-missing", func() error {
		return errors.New("installed gateway payload is missing")
	}) {
		t.Fatal("missing payload was reported as a successful connector operation")
	}
	if err := updateConnectorReconciliationAt(path, recorder.attempts, recorder.failures); err != nil {
		t.Fatal(err)
	}
	state, err := readConnectorReconciliationAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || len(state.Failures) != 1 {
		t.Fatalf("missing-payload residue was not durable: %+v", state)
	}
	failure := state.Failures[0]
	if failure.Operation != "payload-missing" || failure.TransactionID != transactionID {
		t.Fatalf("unexpected missing-payload residue: %+v", failure)
	}
}

func TestReconcileRemovedConnectorsTreatsUnavailableMaintenancePayloadAsResidue(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	transaction := setupTransaction{
		ID:                 strings.Repeat("e", 32),
		DataRoot:           filepath.Join(root, "data"),
		PreviousConnectors: []string{"codex"},
		PreviousCodexHome:  filepath.Join(root, "codex"),
	}
	called := false
	recorder := reconcileRemovedConnectorsWithMaintenance(
		transaction,
		nil,
		func() (connectorMaintenanceGateway, error) {
			return connectorMaintenanceGateway{}, errors.New("embedded payload is unavailable")
		},
		func(_, _, _, _ string, _ []string) error {
			called = true
			return nil
		},
	)
	if called {
		t.Fatal("connector command ran without a Setup-owned maintenance payload")
	}
	if len(recorder.failures) != 1 || recorder.failures[0].Operation != "payload-missing" {
		t.Fatalf("missing maintenance gateway was not reduced to durable residue: %+v", recorder.failures)
	}
}

func TestReconcileRemovedConnectorsAlwaysUsesMaintenanceGateway(t *testing.T) {
	t.Parallel()
	for _, installedState := range []string{"normal", "missing", "corrupt", "foreign"} {
		t.Run(installedState, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			installedGateway := filepath.Join(root, "install", "bin", "defenseclaw-gateway.exe")
			switch installedState {
			case "normal":
				if err := os.MkdirAll(filepath.Dir(installedGateway), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(installedGateway, []byte("installed fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.MkdirAll(filepath.Dir(installedGateway), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(installedGateway, []byte("not a PE"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				if err := os.MkdirAll(filepath.Dir(installedGateway), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(installedGateway, []byte("foreign replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			maintenanceGateway := filepath.Join(root, "installer-temp", "defenseclaw-gateway.exe")
			if err := os.MkdirAll(filepath.Dir(maintenanceGateway), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(maintenanceGateway, []byte("verified maintenance fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			transaction := setupTransaction{
				ID:                 strings.Repeat("1", 32),
				InstallRoot:        filepath.Join(root, "install"),
				TrashPath:          filepath.Join(root, "install.uninstall."+strings.Repeat("1", 32)),
				DataRoot:           filepath.Join(root, "data"),
				PreviousConnectors: []string{"codex"},
				PreviousCodexHome:  filepath.Join(root, "codex"),
			}
			cleanupCalls := 0
			var paths, actions []string
			recorder := reconcileRemovedConnectorsWithMaintenance(
				transaction,
				nil,
				func() (connectorMaintenanceGateway, error) {
					return connectorMaintenanceGateway{
						path: maintenanceGateway,
						cleanup: func() {
							cleanupCalls++
						},
					}, nil
				},
				func(path, _, _, action string, _ []string) error {
					paths = append(paths, path)
					actions = append(actions, action)
					return nil
				},
			)
			if len(recorder.failures) != 0 {
				t.Fatalf("maintenance reconciliation failures: %+v", recorder.failures)
			}
			if strings.Join(actions, ",") != "teardown,verify" {
				t.Fatalf("connector actions = %v, want teardown,verify", actions)
			}
			for _, path := range paths {
				if !samePath(path, maintenanceGateway) || samePath(path, installedGateway) {
					t.Fatalf("connector lifecycle executable = %q, want only %q", path, maintenanceGateway)
				}
			}
			if cleanupCalls != 1 {
				t.Fatalf("maintenance cleanup calls = %d, want 1", cleanupCalls)
			}
		})
	}
}

func TestReconcileRemovedConnectorsMaintenanceFailureRetainsResidueAndCleansTemp(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	transaction := setupTransaction{
		ID:                      strings.Repeat("2", 32),
		DataRoot:                filepath.Join(root, "data"),
		PreviousConnectors:      []string{"claudecode"},
		PreviousClaudeConfigDir: filepath.Join(root, "claude"),
	}
	cleanupCalls := 0
	var actions []string
	recorder := reconcileRemovedConnectorsWithMaintenance(
		transaction,
		nil,
		func() (connectorMaintenanceGateway, error) {
			return connectorMaintenanceGateway{
				path: filepath.Join(root, "maintenance", "defenseclaw-gateway.exe"),
				cleanup: func() {
					cleanupCalls++
				},
			}, nil
		},
		func(_, _, _, action string, _ []string) error {
			actions = append(actions, action)
			return errors.New("settings file is locked")
		},
	)
	if strings.Join(actions, ",") != "teardown" {
		t.Fatalf("connector actions = %v, want teardown only", actions)
	}
	if len(recorder.failures) != 1 || recorder.failures[0].Operation != "teardown" {
		t.Fatalf("teardown failure was not retained as residue: %+v", recorder.failures)
	}
	if cleanupCalls != 1 {
		t.Fatalf("maintenance cleanup calls = %d, want 1", cleanupCalls)
	}
}

func TestReconcileRemovedConnectorsDoesNotLetClientFailureEscape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	gatewayPath := filepath.Join(root, "defenseclaw-gateway.exe")
	if err := os.WriteFile(gatewayPath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	transaction := setupTransaction{
		ID:                      strings.Repeat("f", 32),
		DataRoot:                filepath.Join(root, "data"),
		PreviousConnectors:      []string{"claudecode"},
		PreviousClaudeConfigDir: filepath.Join(root, "claude"),
	}
	var actions []string
	recorder := reconcileRemovedConnectors(transaction, gatewayPath, nil, func(_, _, _, action string, _ []string) error {
		actions = append(actions, action)
		return errors.New("third-party settings are read-only")
	})
	if strings.Join(actions, ",") != "teardown" {
		t.Fatalf("connector actions = %v, want teardown only after failure", actions)
	}
	if len(recorder.failures) != 1 || recorder.failures[0].Operation != "teardown" {
		t.Fatalf("third-party failure was not isolated as residue: %+v", recorder.failures)
	}
}

func TestReconcileRemovedConnectorsCleansValidatedCurrentHomeAfterHistoricalRestore(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	historicalHome := filepath.Join(root, "historical-codex")
	currentHome := filepath.Join(root, "current-codex")
	transaction := setupTransaction{
		ID:                 strings.Repeat("7", 32),
		DataRoot:           filepath.Join(root, "data"),
		PreviousConnectors: []string{"codex"},
		PreviousCodexHome:  historicalHome,
		CodexHome:          currentHome,
		PreviousState: &installState{
			CodexHome: currentHome,
		},
	}
	verifyCalls := map[string]int{}
	var calls []string
	run := func(_, _, connectorName, action string, env []string) error {
		home := envValue(env, "CODEX_HOME")
		calls = append(calls, action+":"+home)
		if connectorName != "codex" {
			return fmt.Errorf("unexpected connector %s", connectorName)
		}
		if action == "verify" {
			verifyCalls[home]++
			if home == currentHome && verifyCalls[home] == 1 {
				return errors.New("strict product residue remains")
			}
		}
		return nil
	}

	recorder := reconcileRemovedConnectors(
		transaction,
		filepath.Join(root, "gateway.exe"),
		transactionPreviousChildEnv(transaction),
		run,
	)
	want := []string{
		"teardown:" + historicalHome,
		"verify:" + historicalHome,
		"verify:" + currentHome,
		"teardown:" + currentHome,
		"verify:" + currentHome,
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("multi-home cleanup calls = %v, want %v", calls, want)
	}
	if len(recorder.failures) != 0 {
		t.Fatalf("healed current-home residue was retained: %+v", recorder.failures)
	}
}

func TestReconcileRemovedConnectorsCleansDefaultHomeAfterLegacyBackupLosesBinding(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	staleHome := filepath.Join(root, "stale-codex-override")
	defaultHome := filepath.Join(root, ".codex")
	transaction := setupTransaction{
		ID:                 strings.Repeat("6", 32),
		DataRoot:           filepath.Join(root, ".defenseclaw"),
		PreviousConnectors: []string{"codex"},
		PreviousCodexHome:  staleHome,
		CodexHome:          staleHome,
		PreviousState: &installState{
			CodexHome: staleHome,
		},
	}
	verifyCalls := map[string]int{}
	var calls []string
	run := func(_, _, connectorName, action string, env []string) error {
		home := envValue(env, "CODEX_HOME")
		calls = append(calls, action+":"+home)
		if connectorName != "codex" {
			return fmt.Errorf("unexpected connector %s", connectorName)
		}
		if action == "verify" {
			verifyCalls[home]++
			if home == defaultHome && verifyCalls[home] == 1 {
				return errors.New("strict product residue remains")
			}
		}
		return nil
	}

	recorder := reconcileRemovedConnectors(
		transaction,
		filepath.Join(root, "gateway.exe"),
		transactionPreviousChildEnv(transaction),
		run,
	)
	want := []string{
		"teardown:" + staleHome,
		"verify:" + staleHome,
		"verify:" + defaultHome,
		"teardown:" + defaultHome,
		"verify:" + defaultHome,
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("legacy default-home cleanup calls = %v, want %v", calls, want)
	}
	if len(recorder.failures) != 0 {
		t.Fatalf("healed default-home residue was retained: %+v", recorder.failures)
	}
}

func TestConnectorCleanupHomesDoesNotAddDefaultFallbackWithManagedBinding(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dataRoot := filepath.Join(root, ".defenseclaw")
	backupPath := filepath.Join(dataRoot, "connector_backups", "codex", "config.toml.json")
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, []byte("synthetic binding"), 0o600); err != nil {
		t.Fatal(err)
	}
	staleHome := filepath.Join(root, "stale-codex-override")
	homes := connectorCleanupHomes(setupTransaction{
		DataRoot:          dataRoot,
		PreviousCodexHome: staleHome,
		CodexHome:         staleHome,
	}, "codex")
	if !reflect.DeepEqual(homes, []string{staleHome}) {
		t.Fatalf("managed binding cleanup homes = %v, want only %s", homes, staleHome)
	}
}

func TestConnectorDefaultHomeBesideDataRootIsStrictlyBound(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dataRoot := filepath.Join(root, ".defenseclaw")
	for connectorName, want := range map[string]string{
		"codex":      filepath.Join(root, ".codex"),
		"claudecode": filepath.Join(root, ".claude"),
	} {
		if got := connectorDefaultHomeBesideDataRoot(dataRoot, connectorName); !samePath(got, want) {
			t.Fatalf("%s default home = %q, want %q", connectorName, got, want)
		}
	}
	for _, test := range []struct {
		dataRoot string
		name     string
	}{
		{dataRoot: filepath.Join(root, "data"), name: "codex"},
		{dataRoot: ".defenseclaw", name: "codex"},
		{dataRoot: dataRoot, name: "openclaw"},
	} {
		if got := connectorDefaultHomeBesideDataRoot(test.dataRoot, test.name); got != "" {
			t.Fatalf("unbound default home for %q/%q = %q", test.dataRoot, test.name, got)
		}
	}
}

func TestReconcileRemovedConnectorsDoesNotMutateCleanFallbackHome(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	historicalHome := filepath.Join(root, "historical-claude")
	currentHome := filepath.Join(root, "current-claude")
	transaction := setupTransaction{
		ID:                      strings.Repeat("8", 32),
		DataRoot:                filepath.Join(root, "data"),
		PreviousConnectors:      []string{"claudecode"},
		PreviousClaudeConfigDir: historicalHome,
		ClaudeConfigDir:         currentHome,
	}
	var calls []string
	run := func(_, _, _ string, action string, env []string) error {
		calls = append(calls, action+":"+envValue(env, "CLAUDE_CONFIG_DIR"))
		return nil
	}

	recorder := reconcileRemovedConnectors(
		transaction,
		filepath.Join(root, "gateway.exe"),
		transactionPreviousChildEnv(transaction),
		run,
	)
	want := []string{
		"teardown:" + historicalHome,
		"verify:" + historicalHome,
		"verify:" + currentHome,
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("clean fallback calls = %v, want verify-only %v", calls, want)
	}
	if len(recorder.failures) != 0 {
		t.Fatalf("clean fallback produced residue: %+v", recorder.failures)
	}
}

func TestReconcileRemovedConnectorsRetainsFallbackFailureAtExactHome(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	historicalHome := filepath.Join(root, "historical-codex")
	persistedHome := filepath.Join(root, "persisted-codex")
	transaction := setupTransaction{
		ID:                 strings.Repeat("9", 32),
		DataRoot:           filepath.Join(root, "data"),
		PreviousConnectors: []string{"codex"},
		PreviousCodexHome:  historicalHome,
		PreviousState: &installState{
			CodexHome: persistedHome,
		},
	}
	var calls []string
	run := func(_, _, _ string, action string, env []string) error {
		home := envValue(env, "CODEX_HOME")
		calls = append(calls, action+":"+home)
		if home == persistedHome {
			return errors.New("strict product residue remains")
		}
		return nil
	}

	recorder := reconcileRemovedConnectors(
		transaction,
		filepath.Join(root, "gateway.exe"),
		transactionChildEnvForHomes(transaction, historicalHome, ""),
		run,
	)
	want := []string{
		"teardown:" + historicalHome,
		"verify:" + historicalHome,
		"verify:" + persistedHome,
		"teardown:" + persistedHome,
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("fallback failure calls = %v, want %v", calls, want)
	}
	if len(recorder.failures) != 1 || recorder.failures[0].Operation != "teardown" || recorder.failures[0].ConfigHome != persistedHome {
		t.Fatalf("fallback failure was not retained at exact home: %+v", recorder.failures)
	}
}

func TestReconcilePreservedConnectorsRefreshesEntireExistingRoster(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	transaction := setupTransaction{
		ID:                      strings.Repeat("a", 32),
		DataRoot:                filepath.Join(root, "data"),
		PreviousConnectors:      []string{"codex", "claudecode"},
		PreviousCodexHome:       filepath.Join(root, "codex"),
		PreviousClaudeConfigDir: filepath.Join(root, "claude"),
	}
	var calls []string
	recorder := reconcilePreservedConnectors(
		transaction,
		filepath.Join(root, "defenseclaw-gateway.exe"),
		[]string{"PRESERVED=1"},
		func(_, _, connector, action string, env []string) error {
			calls = append(calls, connector+":"+action+":"+strings.Join(env, ","))
			return nil
		},
	)
	want := "codex:reconcile:PRESERVED=1,claudecode:reconcile:PRESERVED=1"
	if got := strings.Join(calls, ","); got != want {
		t.Fatalf("preserved connector calls = %q, want %q", got, want)
	}
	if len(recorder.attempts) != 2 || len(recorder.failures) != 0 {
		t.Fatalf("preserved connector reconciliation = %+v", recorder)
	}
}

func TestRetryPendingConnectorReconciliationClearsCleanUnattemptedIdentity(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	claudeHome := filepath.Join(root, "claude")
	transaction := setupTransaction{
		ID:       strings.Repeat("1", 32),
		DataRoot: filepath.Join(root, "data"),
	}
	recorder := connectorReconciliationRecorder{attempts: []connectorReconciliationAttempt{{
		Connector: "codex", ConfigHome: filepath.Join(root, "codex"),
	}}}
	state := &connectorReconciliationState{
		SchemaVersion: connectorReconciliationSchemaVersion,
		Failures: []connectorReconciliationFailure{{
			Connector: "claudecode", Operation: "verify", ConfigHome: claudeHome,
			Message: "old failure", TransactionID: strings.Repeat("2", 32),
		}},
	}
	var actions []string
	err := retryPendingConnectorReconciliation(
		transaction,
		filepath.Join(root, "gateway.exe"),
		&recorder,
		func() (*connectorReconciliationState, error) { return state, nil },
		func(_, _, connector, action string, env []string) error {
			actions = append(actions, connector+":"+action)
			if envValue(env, "CLAUDE_CONFIG_DIR") != claudeHome || envValue(env, "CODEX_HOME") != "" {
				t.Fatalf("stale Claude retry env = %q", env)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(actions, ","); got != "claudecode:verify" {
		t.Fatalf("stale clean retry actions = %q", got)
	}
	if len(recorder.attempts) != 2 || len(recorder.failures) != 0 {
		t.Fatalf("stale clean retry recorder = %+v", recorder)
	}
}

func TestRetryPendingConnectorReconciliationHealsDirtyIdentity(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	home := filepath.Join(root, "claude")
	transaction := setupTransaction{ID: strings.Repeat("3", 32), DataRoot: filepath.Join(root, "data")}
	recorder := connectorReconciliationRecorder{}
	state := &connectorReconciliationState{
		SchemaVersion: connectorReconciliationSchemaVersion,
		Failures: []connectorReconciliationFailure{{
			Connector: "claudecode", Operation: "teardown", ConfigHome: home,
			Message: "locked", TransactionID: strings.Repeat("4", 32),
		}},
	}
	var actions []string
	err := retryPendingConnectorReconciliation(
		transaction, filepath.Join(root, "gateway.exe"), &recorder,
		func() (*connectorReconciliationState, error) { return state, nil },
		func(_, _, _, action string, _ []string) error {
			actions = append(actions, action)
			if len(actions) == 1 {
				return errors.New("still dirty")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(actions, ","); got != "verify,teardown,verify" {
		t.Fatalf("dirty retry actions = %q", got)
	}
	if len(recorder.attempts) != 1 || len(recorder.failures) != 0 {
		t.Fatalf("healed retry recorder = %+v", recorder)
	}
}

func TestRetryPendingConnectorReconciliationRetainsTerminalFailure(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	home := filepath.Join(root, "codex")
	transaction := setupTransaction{ID: strings.Repeat("5", 32), DataRoot: filepath.Join(root, "data")}
	recorder := connectorReconciliationRecorder{}
	state := &connectorReconciliationState{
		SchemaVersion: connectorReconciliationSchemaVersion,
		Failures: []connectorReconciliationFailure{{
			Connector: "codex", Operation: "verify", ConfigHome: home,
			Message: "old failure", TransactionID: strings.Repeat("6", 32),
		}},
	}
	verifyCalls := 0
	err := retryPendingConnectorReconciliation(
		transaction, filepath.Join(root, "gateway.exe"), &recorder,
		func() (*connectorReconciliationState, error) { return state, nil },
		func(_, _, _, action string, _ []string) error {
			if action == "verify" {
				verifyCalls++
				if verifyCalls == 2 {
					return nil
				}
			}
			return fmt.Errorf("%s failed", action)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.failures) != 1 {
		t.Fatalf("terminal retry failures = %+v", recorder.failures)
	}
	failure := recorder.failures[0]
	if failure.TransactionID != transaction.ID || failure.Operation != "teardown" ||
		!strings.Contains(failure.Message, "teardown retry") {
		t.Fatalf("terminal retry failure = %+v", failure)
	}
}

func TestRetryPendingConnectorReconciliationDoesNotTeardownTouchedConnectorAtAnotherHome(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	oldHome := filepath.Join(root, "old-codex")
	transaction := setupTransaction{ID: strings.Repeat("7", 32), DataRoot: filepath.Join(root, "data")}
	recorder := connectorReconciliationRecorder{attempts: []connectorReconciliationAttempt{{
		Connector: "codex", ConfigHome: filepath.Join(root, "current-codex"),
	}}}
	state := &connectorReconciliationState{
		SchemaVersion: connectorReconciliationSchemaVersion,
		Failures: []connectorReconciliationFailure{{
			Connector: "codex", Operation: "verify", ConfigHome: oldHome,
			Message: "old failure", TransactionID: strings.Repeat("8", 32),
		}},
	}
	var actions []string
	err := retryPendingConnectorReconciliation(
		transaction, filepath.Join(root, "gateway.exe"), &recorder,
		func() (*connectorReconciliationState, error) { return state, nil },
		func(_, _, _, action string, _ []string) error {
			actions = append(actions, action)
			return errors.New("still dirty")
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(actions, ","); got != "verify" {
		t.Fatalf("same-connector retry actions = %q", got)
	}
	if len(recorder.failures) != 1 || recorder.failures[0].TransactionID != transaction.ID {
		t.Fatalf("same-connector failure was not refreshed: %+v", recorder.failures)
	}
}

func TestRetryPendingConnectorReconciliationPropagatesReaderError(t *testing.T) {
	t.Parallel()
	want := errors.New("marker access denied")
	err := retryPendingConnectorReconciliation(
		setupTransaction{}, "", &connectorReconciliationRecorder{},
		func() (*connectorReconciliationState, error) { return nil, want },
		func(_, _, _, _ string, _ []string) error { return nil },
	)
	if !errors.Is(err, want) {
		t.Fatalf("reader error = %v, want %v", err, want)
	}
}

func TestBoundedReconciliationMessageIsSingleLineValidUTF8(t *testing.T) {
	t.Parallel()
	message := boundedReconciliationMessage("  locked\r\n" + strings.Repeat("é", maxConnectorReconciliationMessage))
	if strings.ContainsAny(message, "\r\n\t") {
		t.Fatalf("message retained control whitespace: %q", message)
	}
	if len(message) > maxConnectorReconciliationMessage {
		t.Fatalf("message length = %d, want <= %d", len(message), maxConnectorReconciliationMessage)
	}
	if !utf8.ValidString(message) {
		t.Fatal("bounded message is not valid UTF-8")
	}
}

func TestValidateConnectorReconciliationRejectsUnsafeState(t *testing.T) {
	t.Parallel()
	state := &connectorReconciliationState{
		SchemaVersion: connectorReconciliationSchemaVersion,
		Failures: []connectorReconciliationFailure{{
			Connector:     "codex",
			Operation:     "shell",
			ConfigHome:    filepath.Join(t.TempDir(), "codex"),
			Message:       "unexpected operation",
			TransactionID: strings.Repeat("d", 32),
		}},
	}
	if err := validateConnectorReconciliationState(state); err == nil {
		t.Fatal("unsupported connector operation was accepted")
	}
}
