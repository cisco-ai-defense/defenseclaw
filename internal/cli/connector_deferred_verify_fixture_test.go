// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

// The deferred-uninstall verifier fixture. The authorization and VerifyClean
// paths it drives are portable (only the live parent-process lookup is
// Windows code, and the fixture stubs it), so these tests run on every OS.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
	startIdentity string
	record        deferredVerifyCleanupRecord
	journal       deferredVerifyJournal
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
		startIdentity: "133713371337",
	}
	switch connectorName {
	case "codex":
		fixture.configHome = filepath.Join(root, "profile", ".codex")
	case "claudecode":
		fixture.configHome = filepath.Join(root, "profile", ".claude")
	case "amp":
		fixture.configHome = filepath.Join(root, "profile", ".config", "amp")
	case "omnigent": // until 1.1: Setup tears down a 1.0.x OmniGent install at uninstall
		fixture.configHome = filepath.Join(root, "profile", ".omnigent")
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
	if connectorName == "omnigent" {
		transaction.PreviousOmnigentConfigHome = fixture.configHome
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
	fixture.command.Flags().String("internal-setup-start-identity", "", "")
	fixture.command.Flags().String("internal-deferred-cleanup-record", "", "")
	fixture.command.Flags().String("internal-deferred-cleanup-transaction", "", "")
	for name, value := range map[string]string{
		"connector":                             connectorName,
		"data-dir":                              fixture.dataRoot,
		"config-home":                           fixture.configHome,
		"json":                                  "true",
		"internal-setup-parent":                 fixture.parentPath,
		"internal-setup-start-identity":         fixture.startIdentity,
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
	oldStartIdentity := connectorVerifySetupStartIdentity
	oldRecord := connectorVerifyCleanupRecord
	oldTransaction := connectorVerifyCleanupTransaction
	oldName := connectorFlagName
	oldJSON := connectorFlagJSON
	oldDataDir := connectorFlagDataDir
	oldConfigHome := connectorFlagConfigHome
	oldHookExe := connectorFlagHookExe
	oldExit := connectorExit
	oldExecutable := deferredVerifyExecutable
	oldParentImage := deferredVerifyParent
	oldPrivate := deferredVerifyPrivateFile
	t.Cleanup(func() {
		connectorVerifySetupParent = oldParent
		connectorVerifySetupStartIdentity = oldStartIdentity
		connectorVerifyCleanupRecord = oldRecord
		connectorVerifyCleanupTransaction = oldTransaction
		connectorFlagName = oldName
		connectorFlagJSON = oldJSON
		connectorFlagDataDir = oldDataDir
		connectorFlagConfigHome = oldConfigHome
		connectorFlagHookExe = oldHookExe
		connectorExit = oldExit
		deferredVerifyExecutable = oldExecutable
		deferredVerifyParent = oldParentImage
		deferredVerifyPrivateFile = oldPrivate
	})
	connectorVerifySetupParent = fixture.parentPath
	connectorVerifySetupStartIdentity = fixture.startIdentity
	connectorVerifyCleanupRecord = fixture.recordPath
	connectorVerifyCleanupTransaction = fixture.transactionID
	connectorFlagName = fixture.connectorName
	connectorFlagJSON = true
	connectorFlagDataDir = fixture.dataRoot
	connectorFlagConfigHome = fixture.configHome
	connectorFlagHookExe = ""
	connectorExit = func(code int) { t.Fatalf("unexpected connector exit %d", code) }
	deferredVerifyExecutable = func() (string, error) { return fixture.childPath, nil }
	deferredVerifyParent = func(int) (deferredVerifyProcessIdentity, error) {
		return deferredVerifyProcessIdentity{
			ImagePath:     fixture.parentPath,
			StartIdentity: fixture.startIdentity,
			requireLive:   func() error { return nil },
			close:         func() error { return nil },
		}, nil
	}
	deferredVerifyPrivateFile = func(string) error { return nil }
}

// until 1.1: a Windows uninstall deferred to after a reboot keeps a 1.0.x
// OmniGent install in its roster (Setup still tears it down), so the private
// verifier must bind OmniGent's home the way Setup's journal records it.
// Every home Setup may hand over binds; a foreign one does not.
func TestDeferredVerifyConfigHomeBindsAPriorOmnigentInstall(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "profile")
	// The journal as native Setup writes it (cmd/defenseclaw-setup
	// transaction.go and main.go JSON names).
	journal := []byte(`{"schema_version":2,"phase":"converged","transaction":{` +
		`"id":"0123456789abcdef0123456789abcdef","action":"uninstall",` +
		`"data_root":` + jsonString(t, filepath.Join(profile, ".defenseclaw")) + `,` +
		`"previous_connectors":["omnigent"],` +
		`"previous_omnigent_config_home":` + jsonString(t, filepath.Join(profile, "omnigent-before")) + `,` +
		`"omnigent_config_home":` + jsonString(t, filepath.Join(profile, "omnigent-after")) + `,` +
		`"previous_state":{"omnigent_config_home":` + jsonString(t, filepath.Join(profile, "omnigent-state")) + `}}}`)
	var decoded deferredVerifyJournal
	if err := json.Unmarshal(journal, &decoded); err != nil {
		t.Fatal(err)
	}
	transaction := decoded.Transaction
	for _, test := range []struct {
		connector, home string
		want            bool
	}{
		{"omnigent", filepath.Join(profile, "omnigent-before"), true},
		{"omnigent", filepath.Join(profile, "omnigent-after"), true},
		{"omnigent", filepath.Join(profile, "omnigent-state"), true},
		{"omnigent", filepath.Join(profile, ".omnigent"), true},
		{"omnigent", filepath.Join(profile, ".foreign"), false},
		{"omnigent", filepath.Join(profile, ".codex"), false},
		{"codex", filepath.Join(profile, "omnigent-before"), false},
	} {
		t.Run(test.connector+"_"+filepath.Base(test.home), func(t *testing.T) {
			if got := deferredVerifyConfigHomeBound(transaction, test.connector, test.home); got != test.want {
				t.Fatalf("config home binding = %t, want %t", got, test.want)
			}
		})
	}
}

func jsonString(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The whole deferred path for a prior OmniGent install: the private
// authorization accepts the bound home, and VerifyClean then runs the
// teardown-only OmniGent check. Both exit 0: a config that still names
// DefenseClaw's module is a leftover the teardown lists for the user, never
// residue that holds the uninstall (until 1.1).
func TestDeferredUninstallVerifyAuthenticatesPriorOmnigentInstall(t *testing.T) {
	for _, test := range []struct {
		name     string
		residue  bool
		wantExit int
	}{
		{name: "clean", wantExit: 0},
		{name: "config still names the module", residue: true, wantExit: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeferredVerifyFixtureForConnector(t, "omnigent")
			withDeferredVerifyFixtureGlobals(t, fixture)
			restoreHome, err := connector.BindUserHomeDir(filepath.Dir(fixture.dataRoot))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(restoreHome)
			t.Setenv("OMNIGENT_CONFIG_HOME", "")
			t.Setenv("OMNIGENT_CONFIG", "")
			if err := os.MkdirAll(fixture.configHome, 0o700); err != nil {
				t.Fatal(err)
			}
			if test.residue {
				config := "policy_modules:\n  - defenseclaw_omnigent_policy\n"
				if err := os.WriteFile(filepath.Join(fixture.configHome, "config.yaml"), []byte(config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			fixture.command.SetOut(io.Discard)
			fixture.command.SetErr(io.Discard)
			if err := runConnectorVerifyPersistentPreRunE(fixture.command, nil); err != nil {
				t.Fatalf("authenticated configless OmniGent pre-run: %v", err)
			}
			exitCode := 0
			connectorExit = func(code int) { exitCode = code }
			if err := runConnectorVerify(fixture.command, nil); err != nil {
				t.Fatalf("OmniGent VerifyClean without v8 config: %v", err)
			}
			if exitCode != test.wantExit {
				t.Fatalf("OmniGent verification exit = %d, want %d", exitCode, test.wantExit)
			}
			if _, err := os.Lstat(fixture.dataRoot); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("configless OmniGent verification recreated deleted data root: %v", err)
			}
		})
	}
}
