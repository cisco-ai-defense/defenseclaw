// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

type deferredVerifyFixture struct {
	command       *cobra.Command
	connectorName string
	parentPath    string
	recordPath    string
	journalPath   string
	childPath     string
	dataRoot      string
	configHome    string
	transactionID string
	record        deferredVerifyCleanupRecord
	journal       deferredVerifyJournal
}

func newDeferredVerifyFixture(t *testing.T) deferredVerifyFixture {
	return newDeferredVerifyFixtureForConnector(t, "claudecode")
}

func newDeferredVerifyFixtureForConnector(t *testing.T, connectorName string) deferredVerifyFixture {
	t.Helper()
	root := t.TempDir()
	localRoot := filepath.Join(root, "DefenseClaw")
	stateRoot := filepath.Join(localRoot, "InstallerState")
	cacheRoot := filepath.Join(localRoot, "InstallerCache")
	childRoot := filepath.Join(root, "payload", "maintenance", "bin")
	for _, path := range []string{stateRoot, cacheRoot, childRoot} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fixture := deferredVerifyFixture{
		connectorName: connectorName,
		parentPath:    filepath.Join(cacheRoot, deferredVerifySetupName),
		recordPath:    filepath.Join(stateRoot, "uninstall-cleanup.json"),
		journalPath:   filepath.Join(stateRoot, "setup-transaction.json"),
		childPath:     filepath.Join(childRoot, deferredVerifyGatewayName),
		dataRoot:      filepath.Join(root, "profile", ".defenseclaw"),
		transactionID: "0123456789abcdef0123456789abcdef",
	}
	switch connectorName {
	case "codex":
		fixture.configHome = filepath.Join(root, "profile", ".codex")
	case "claudecode":
		fixture.configHome = filepath.Join(root, "profile", ".claude")
	case "amp":
		fixture.configHome = filepath.Join(root, "profile", ".config", "amp")
	default:
		t.Fatalf("unsupported fixture connector %q", connectorName)
	}
	for _, path := range []string{fixture.parentPath, fixture.childPath} {
		if err := os.WriteFile(path, []byte("private executable fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256([]byte("private executable fixture"))
	fixture.record = deferredVerifyCleanupRecord{
		SchemaVersion:      1,
		Status:             "pending-reboot",
		TransactionID:      fixture.transactionID,
		MaintenancePath:    fixture.parentPath,
		MaintenanceSHA256:  hex.EncodeToString(digest[:]),
		InstallerStateRoot: stateRoot,
		JournalPath:        fixture.journalPath,
		RecordPath:         fixture.recordPath,
		CacheAckPath:       filepath.Join(cacheRoot, "uninstall-cleanup-ack.json"),
		VerifiedConnectors: []string{connectorName},
	}
	transaction := deferredVerifyTransaction{
		ID:                        fixture.transactionID,
		Action:                    "uninstall",
		DataRoot:                  fixture.dataRoot,
		MaintenancePath:           fixture.parentPath,
		PreviousMaintenanceSHA256: fixture.record.MaintenanceSHA256,
		PreviousConnectors:        []string{connectorName},
	}
	if connectorName == "codex" {
		transaction.PreviousCodexHome = fixture.configHome
	}
	if connectorName == "claudecode" {
		transaction.PreviousClaudeConfigDir = fixture.configHome
	}
	fixture.journal = deferredVerifyJournal{
		SchemaVersion: 2,
		Phase:         "converged",
		Transaction:   transaction,
	}
	fixture.write(t)

	parent := &cobra.Command{Use: "connector"}
	fixture.command = &cobra.Command{Use: "verify"}
	parent.AddCommand(fixture.command)
	fixture.command.Flags().String("connector", "", "")
	fixture.command.Flags().String("data-dir", "", "")
	fixture.command.Flags().String("config-home", "", "")
	fixture.command.Flags().Bool("json", false, "")
	fixture.command.Flags().String("internal-setup-parent", "", "")
	fixture.command.Flags().String("internal-deferred-cleanup-record", "", "")
	fixture.command.Flags().String("internal-deferred-cleanup-transaction", "", "")
	for name, value := range map[string]string{
		"connector":                             connectorName,
		"data-dir":                              fixture.dataRoot,
		"config-home":                           fixture.configHome,
		"json":                                  "true",
		"internal-setup-parent":                 fixture.parentPath,
		"internal-deferred-cleanup-record":      fixture.recordPath,
		"internal-deferred-cleanup-transaction": fixture.transactionID,
	} {
		if err := fixture.command.Flags().Set(name, value); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
	}
	return fixture
}

func (fixture deferredVerifyFixture) write(t *testing.T) {
	t.Helper()
	for path, value := range map[string]any{
		fixture.recordPath:  fixture.record,
		fixture.journalPath: fixture.journal,
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func withDeferredVerifyFixtureGlobals(t *testing.T, fixture deferredVerifyFixture) {
	t.Helper()
	oldParent := connectorVerifySetupParent
	oldRecord := connectorVerifyCleanupRecord
	oldTransaction := connectorVerifyCleanupTransaction
	oldName := connectorFlagName
	oldJSON := connectorFlagJSON
	oldDataDir := connectorFlagDataDir
	oldConfigHome := connectorFlagConfigHome
	oldExit := connectorExit
	oldExecutable := deferredVerifyExecutable
	oldParentImage := deferredVerifyParent
	oldPrivate := deferredVerifyPrivateFile
	t.Cleanup(func() {
		connectorVerifySetupParent = oldParent
		connectorVerifyCleanupRecord = oldRecord
		connectorVerifyCleanupTransaction = oldTransaction
		connectorFlagName = oldName
		connectorFlagJSON = oldJSON
		connectorFlagDataDir = oldDataDir
		connectorFlagConfigHome = oldConfigHome
		connectorExit = oldExit
		deferredVerifyExecutable = oldExecutable
		deferredVerifyParent = oldParentImage
		deferredVerifyPrivateFile = oldPrivate
	})
	connectorVerifySetupParent = fixture.parentPath
	connectorVerifyCleanupRecord = fixture.recordPath
	connectorVerifyCleanupTransaction = fixture.transactionID
	connectorFlagName = fixture.connectorName
	connectorFlagJSON = true
	connectorFlagDataDir = fixture.dataRoot
	connectorFlagConfigHome = fixture.configHome
	connectorExit = func(code int) { t.Fatalf("unexpected connector exit %d", code) }
	deferredVerifyExecutable = func() (string, error) { return fixture.childPath, nil }
	deferredVerifyParent = func(int) (string, error) { return fixture.parentPath, nil }
	deferredVerifyPrivateFile = func(string) error { return nil }
}

func TestDeferredUninstallVerifyAuthenticatesWithoutV8Config(t *testing.T) {
	fixture := newDeferredVerifyFixture(t)
	withDeferredVerifyFixtureGlobals(t, fixture)
	if err := os.MkdirAll(fixture.configHome, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture.command.SetOut(io.Discard)
	fixture.command.SetErr(io.Discard)
	if err := runConnectorVerifyPersistentPreRunE(fixture.command, nil); err != nil {
		t.Fatalf("authenticated configless pre-run: %v", err)
	}
	if cfg != nil {
		t.Fatal("authenticated configless pre-run loaded a runtime config")
	}
	if err := runConnectorVerify(fixture.command, nil); err != nil {
		t.Fatalf("Claude Code VerifyClean without v8 config: %v", err)
	}
	if _, err := os.Lstat(fixture.dataRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("configless verification recreated deleted data root: %v", err)
	}
}

func TestDeferredUninstallVerifyAuthenticatesAmpWithoutV8Config(t *testing.T) {
	fixture := newDeferredVerifyFixtureForConnector(t, "amp")
	withDeferredVerifyFixtureGlobals(t, fixture)
	if err := os.MkdirAll(fixture.configHome, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture.command.SetOut(io.Discard)
	fixture.command.SetErr(io.Discard)
	if err := runConnectorVerifyPersistentPreRunE(fixture.command, nil); err != nil {
		t.Fatalf("authenticated configless Amp pre-run: %v", err)
	}
	exitCode := 0
	connectorExit = func(code int) { exitCode = code }
	if err := runConnectorVerify(fixture.command, nil); err != nil {
		t.Fatalf("Amp VerifyClean without v8 config: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("clean Amp verification exit = %d, want 0", exitCode)
	}
	if _, err := os.Lstat(fixture.dataRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("configless Amp verification recreated deleted data root: %v", err)
	}
}

func TestDeferredVerifyConfigHomeBindingCoversNativeRoster(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "profile")
	transaction := deferredVerifyTransaction{
		DataRoot:                filepath.Join(profile, ".defenseclaw"),
		PreviousCodexHome:       filepath.Join(profile, "codex-before"),
		CodexHome:               filepath.Join(profile, "codex-after"),
		PreviousClaudeConfigDir: filepath.Join(profile, "claude-before"),
		ClaudeConfigDir:         filepath.Join(profile, "claude-after"),
		PreviousState:           &deferredVerifyInstallState{CodexHome: filepath.Join(profile, "codex-state"), ClaudeConfigDir: filepath.Join(profile, "claude-state")},
	}
	tests := []struct {
		connector string
		home      string
		want      bool
	}{
		{connector: "codex", home: transaction.PreviousCodexHome, want: true},
		{connector: "codex", home: transaction.CodexHome, want: true},
		{connector: "codex", home: transaction.PreviousState.CodexHome, want: true},
		{connector: "codex", home: filepath.Join(profile, ".codex"), want: true},
		{connector: "claudecode", home: transaction.PreviousClaudeConfigDir, want: true},
		{connector: "claudecode", home: transaction.ClaudeConfigDir, want: true},
		{connector: "claudecode", home: transaction.PreviousState.ClaudeConfigDir, want: true},
		{connector: "claudecode", home: filepath.Join(profile, ".claude"), want: true},
		{connector: "amp", home: filepath.Join(profile, ".config", "amp"), want: true},
		{connector: "amp", home: filepath.Join(profile, ".config", "foreign"), want: false},
		{connector: "foreign", home: filepath.Join(profile, ".codex"), want: false},
	}
	for _, test := range tests {
		name := test.connector + "_" + filepath.Base(test.home)
		t.Run(name, func(t *testing.T) {
			if got := deferredVerifyConfigHomeBound(transaction, test.connector, test.home); got != test.want {
				t.Fatalf("config home binding = %t, want %t", got, test.want)
			}
		})
	}
}

func TestDeferredUninstallVerifyBlocksExternalConnectorResidueWithoutV8Config(t *testing.T) {
	tests := []struct {
		connector string
		write     func(*testing.T, deferredVerifyFixture)
	}{
		{
			connector: "codex",
			write: func(t *testing.T, fixture deferredVerifyFixture) {
				if err := os.MkdirAll(fixture.configHome, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fixture.configHome, "config.toml"), []byte("[hooks\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			connector: "claudecode",
			write: func(t *testing.T, fixture deferredVerifyFixture) {
				if err := os.MkdirAll(fixture.configHome, 0o700); err != nil {
					t.Fatal(err)
				}
				settings := []byte(`{"env":{"OTEL_RESOURCE_ATTRIBUTES":"defenseclaw.connector=claudecode,service.name=claudecode"}}`)
				if err := os.WriteFile(filepath.Join(fixture.configHome, "settings.json"), settings, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			connector: "amp",
			write: func(t *testing.T, fixture deferredVerifyFixture) {
				plugin := filepath.Join(fixture.configHome, "plugins", "defenseclaw.ts")
				if err := os.MkdirAll(filepath.Dir(plugin), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(plugin, []byte("// defenseclaw-managed-plugin v2\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.connector, func(t *testing.T) {
			fixture := newDeferredVerifyFixtureForConnector(t, test.connector)
			withDeferredVerifyFixtureGlobals(t, fixture)
			test.write(t, fixture)
			fixture.command.SetOut(io.Discard)
			fixture.command.SetErr(io.Discard)
			if err := runConnectorVerifyPersistentPreRunE(fixture.command, nil); err != nil {
				t.Fatalf("authenticated configless pre-run: %v", err)
			}
			exitCode := 0
			connectorExit = func(code int) { exitCode = code }
			if err := runConnectorVerify(fixture.command, nil); err != nil {
				t.Fatalf("configless VerifyClean: %v", err)
			}
			if exitCode != 1 {
				t.Fatalf("connector residue exit = %d, want 1", exitCode)
			}
			if _, err := os.Lstat(fixture.dataRoot); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("residue verification recreated deleted data root: %v", err)
			}
		})
	}
}

func TestDeferredUninstallVerifyRejectsBindingDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *deferredVerifyFixture)
		want   string
	}{
		{
			name: "transaction",
			mutate: func(_ *testing.T, fixture *deferredVerifyFixture) {
				connectorVerifyCleanupTransaction = "fedcba9876543210fedcba9876543210"
			},
			want: "cleanup record",
		},
		{
			name: "parent",
			mutate: func(_ *testing.T, fixture *deferredVerifyFixture) {
				deferredVerifyParent = func(int) (string, error) { return filepath.Join(filepath.Dir(fixture.parentPath), "foreign.exe"), nil }
			},
			want: "live parent",
		},
		{
			name: "manifest digest",
			mutate: func(t *testing.T, fixture *deferredVerifyFixture) {
				fixture.record.MaintenanceSHA256 = strings.Repeat("0", 64)
				fixture.write(t)
			},
			want: "digest",
		},
		{
			name: "data root",
			mutate: func(_ *testing.T, fixture *deferredVerifyFixture) {
				connectorFlagDataDir = filepath.Join(filepath.Dir(fixture.dataRoot), "foreign", ".defenseclaw")
			},
			want: "journal",
		},
		{
			name: "config home",
			mutate: func(_ *testing.T, fixture *deferredVerifyFixture) {
				connectorFlagConfigHome = filepath.Join(filepath.Dir(fixture.configHome), ".foreign")
			},
			want: "config home",
		},
		{
			name: "private file",
			mutate: func(_ *testing.T, fixture *deferredVerifyFixture) {
				deferredVerifyPrivateFile = func(path string) error {
					if sameDeferredVerifyPath(path, fixture.parentPath) {
						return errors.New("unsafe ACL")
					}
					return nil
				}
			},
			want: "private file",
		},
		{
			name: "journal path",
			mutate: func(t *testing.T, fixture *deferredVerifyFixture) {
				fixture.record.JournalPath = filepath.Join(filepath.Dir(fixture.journalPath), "foreign.json")
				fixture.write(t)
			},
			want: "cleanup record",
		},
		{
			name: "connector roster",
			mutate: func(t *testing.T, fixture *deferredVerifyFixture) {
				fixture.record.VerifiedConnectors = []string{"codex"}
				fixture.write(t)
			},
			want: "roster",
		},
		{
			name: "reparse binding",
			mutate: func(_ *testing.T, fixture *deferredVerifyFixture) {
				deferredVerifyPrivateFile = func(path string) error {
					if sameDeferredVerifyPath(path, fixture.recordPath) {
						return errors.New("reparse point")
					}
					return nil
				}
			},
			want: "private file",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeferredVerifyFixture(t)
			withDeferredVerifyFixtureGlobals(t, fixture)
			test.mutate(t, &fixture)
			err := validateDeferredUninstallConnectorVerify(fixture.command)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("binding drift error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestOrdinaryConnectorVerifyRetainsStrictRootPreRun(t *testing.T) {
	oldParent := connectorVerifySetupParent
	oldRecord := connectorVerifyCleanupRecord
	oldTransaction := connectorVerifyCleanupTransaction
	oldRoot := connectorVerifyRootPersistentPreRun
	t.Cleanup(func() {
		connectorVerifySetupParent = oldParent
		connectorVerifyCleanupRecord = oldRecord
		connectorVerifyCleanupTransaction = oldTransaction
		connectorVerifyRootPersistentPreRun = oldRoot
	})
	connectorVerifySetupParent = ""
	connectorVerifyCleanupRecord = ""
	connectorVerifyCleanupTransaction = ""
	called := false
	connectorVerifyRootPersistentPreRun = func(*cobra.Command, []string) error {
		called = true
		return errors.New("strict v8 config required")
	}
	err := runConnectorVerifyPersistentPreRunE(&cobra.Command{Use: "verify"}, nil)
	if !called || err == nil || !strings.Contains(err.Error(), "strict v8 config required") {
		t.Fatalf("ordinary connector verify pre-run = called:%t err:%v", called, err)
	}
}

func TestDeferredConnectorVerifyRejectsPartialPrivateAuthorization(t *testing.T) {
	fixture := newDeferredVerifyFixture(t)
	withDeferredVerifyFixtureGlobals(t, fixture)
	connectorVerifyCleanupRecord = ""
	err := runConnectorVerifyPersistentPreRunE(fixture.command, nil)
	if err == nil || !strings.Contains(err.Error(), "cleanup record path") {
		t.Fatalf("partial private authorization error = %v", err)
	}
}
