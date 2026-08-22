// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const (
	testProtectedCodexVersion      = "codex-cli 0.146.0"
	testProtectedPriorCodexVersion = "codex-cli 0.145.0"
)

type protectedSelectionInstallerConnector struct {
	name                 string
	configPath           string
	requireReceipt       bool
	setupErr             error
	afterSetup           func()
	hardeningFailurePath string
	setupCalls           int
	setupOpts            connector.SetupOpts
}

func (c *protectedSelectionInstallerConnector) Name() string {
	if c.name != "" {
		return c.name
	}
	return "codex"
}
func (c *protectedSelectionInstallerConnector) Description() string {
	return "enterprise protected-selection installer fixture"
}
func (c *protectedSelectionInstallerConnector) ToolInspectionMode() connector.ToolInspectionMode {
	return connector.ToolModeBoth
}
func (c *protectedSelectionInstallerConnector) SubprocessPolicy() connector.SubprocessPolicy {
	return connector.SubprocessNone
}
func (c *protectedSelectionInstallerConnector) Authenticate(*http.Request) bool { return false }
func (c *protectedSelectionInstallerConnector) Route(*http.Request, []byte) (*connector.ConnectorSignals, error) {
	return nil, nil
}
func (c *protectedSelectionInstallerConnector) SetCredentials(string, string) {}
func (c *protectedSelectionInstallerConnector) VerifyClean(connector.SetupOpts) error {
	return nil
}
func (c *protectedSelectionInstallerConnector) HookScriptNames(connector.SetupOpts) []string {
	return []string{"codex-hook.sh"}
}
func (c *protectedSelectionInstallerConnector) HookCapabilities(connector.SetupOpts) connector.HookCapability {
	return connector.HookCapability{
		CanBlock:           true,
		SupportsFailClosed: true,
		Scope:              "user",
		ConfigPath:         c.configPath,
	}
}
func (c *protectedSelectionInstallerConnector) AgentPaths(opts connector.SetupOpts) connector.AgentPaths {
	paths := connector.AgentPaths{
		PatchedFiles: []string{c.configPath},
		HookScripts:  []string{filepath.Join(opts.DataDir, "hooks", "codex-hook.sh")},
	}
	if c.hardeningFailurePath != "" {
		paths.GeneratedFiles = []string{c.hardeningFailurePath}
	}
	return paths
}
func (c *protectedSelectionInstallerConnector) Setup(_ context.Context, opts connector.SetupOpts) error {
	c.setupCalls++
	c.setupOpts = opts
	if c.requireReceipt {
		if _, err := os.Stat(filepath.Join(opts.DataDir, "agent_selection.json")); err != nil {
			return fmt.Errorf("setup did not observe protected receipt: %w", err)
		}
	}
	if c.setupErr != nil {
		return c.setupErr
	}
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		return err
	}
	hookPath := filepath.Join(hookDir, "codex-hook.sh")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.configPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(c.configPath, []byte("hook = \""+hookPath+"\"\n"), 0o600); err != nil {
		return err
	}
	if c.hardeningFailurePath != "" {
		if err := os.MkdirAll(c.hardeningFailurePath, 0o700); err != nil {
			return err
		}
	}
	if c.afterSetup != nil {
		c.afterSetup()
	}
	return nil
}
func (c *protectedSelectionInstallerConnector) Teardown(context.Context, connector.SetupOpts) error {
	return nil
}

func TestInstallProtectedSelectionPublishesSealsAndConsumes(t *testing.T) {
	skipIfRoot(t)
	home, executable, fixture, opts := newProtectedSelectionInstallFixture(t, testProtectedCodexVersion)
	fixture.requireReceipt = true

	result, err := Install(context.Background(), opts)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if fixture.setupCalls != 1 || fixture.setupOpts.AgentExecutable != executable ||
		fixture.setupOpts.AgentVersion != testProtectedCodexVersion {
		t.Fatalf("Setup calls/options = %d, %+v", fixture.setupCalls, fixture.setupOpts)
	}
	if result.AgentVersion != testProtectedCodexVersion {
		t.Fatalf("result agent version = %q", result.AgentVersion)
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	dataInfo, err := os.Lstat(dataDir)
	if err != nil || !dataInfo.IsDir() || dataInfo.Mode().Perm() != 0o700 {
		t.Fatalf("fresh protected data dir = (%v, %v), want private directory", dataInfo, err)
	}
	if stat, ok := dataInfo.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		t.Fatalf("fresh protected data dir owner = %+v, want uid %d", stat, os.Getuid())
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "agent_selection.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("setup selection receipt remains after success: %v", err)
	}
	entries, err := connector.LoadProtectedHookContractLockEntries(dataDir)
	if err != nil {
		t.Fatalf("LoadProtectedHookContractLockEntries: %v", err)
	}
	entry := entries["codex"]
	if gotPath, gotVersion, ok := connector.ProtectedSetupAgentSelectionFromLock(entry, "codex"); !ok || gotPath != executable || gotVersion != testProtectedCodexVersion {
		t.Fatalf("sealed selection = (%q, %q, %t), entry=%+v", gotPath, gotVersion, ok, entry)
	}
}

func TestInstallProtectedSelectionRejectsMissingEvidenceBeforeSetup(t *testing.T) {
	skipIfRoot(t)
	tests := []struct {
		name       string
		version    string
		executable func(home, existing string) string
		want       string
	}{
		{
			name:       "missing executable path",
			version:    testProtectedCodexVersion,
			executable: func(home, _ string) string { return filepath.Join(home, "missing", "codex") },
			want:       "stable canonical regular file",
		},
		{
			name:       "missing paired version",
			executable: func(_, existing string) string { return existing },
			want:       "requires agent_version with agent_executable",
		},
		{
			name:       "no explicit or durable evidence",
			executable: func(_, _ string) string { return "" },
			want:       "valid durable protected setup evidence",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, existing, fixture, opts := newProtectedSelectionInstallFixture(t, test.version)
			opts.AgentExecutable = test.executable(opts.UserHome, existing)
			_, err := Install(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Install error = %v, want %q", err, test.want)
			}
			if fixture.setupCalls != 0 {
				t.Fatalf("Setup called %d times before evidence refusal", fixture.setupCalls)
			}
		})
	}
}

func TestInstallRejectsUnsignedOpenHandsEnterpriseAdmission(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	fixture := &protectedSelectionInstallerConnector{
		name:       "openhands",
		configPath: filepath.Join(home, ".openhands", "hooks.json"),
	}
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(fixture)
	_, err := Install(context.Background(), InstallOptions{
		ConnectorName: "openhands",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		Registry:      registry,
	})
	if err == nil || !strings.Contains(err.Error(), "unsigned native image") {
		t.Fatalf("OpenHands enterprise admission error = %v", err)
	}
	if fixture.setupCalls != 0 {
		t.Fatalf("OpenHands Setup called %d times", fixture.setupCalls)
	}
}

func TestInstallProtectedSelectionRepairUsesOnlyCapturedDurableLock(t *testing.T) {
	skipIfRoot(t)
	home, executable, fixture, opts := newProtectedSelectionInstallFixture(t, testProtectedCodexVersion)
	dataDir := filepath.Join(home, ".defenseclaw")
	seedProtectedSelectionLock(t, fixture, dataDir, executable, testProtectedCodexVersion, true)
	fixture.setupCalls = 0
	fixture.setupOpts = connector.SetupOpts{}
	opts.AgentExecutable = ""
	opts.AgentVersion = ""

	decoyDir := filepath.Join(home, "decoy-bin")
	if err := os.MkdirAll(decoyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(home, "path-decoy-executed")
	decoy := filepath.Join(decoyDir, "codex")
	if err := os.WriteFile(decoy, []byte("#!/bin/sh\ntouch \""+marker+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", decoyDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("repair Install: %v", err)
	}
	if fixture.setupOpts.AgentExecutable != executable || fixture.setupOpts.AgentVersion != testProtectedCodexVersion {
		t.Fatalf("repair Setup options = %+v", fixture.setupOpts)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PATH decoy executed during protected repair: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "agent_selection.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock-only repair created a setup receipt: %v", err)
	}
}

func TestInstallProtectedSelectionRepairRejectsExecutableDriftAfterSetup(t *testing.T) {
	skipIfRoot(t)
	home, executable, fixture, opts := newProtectedSelectionInstallFixture(t, testProtectedCodexVersion)
	dataDir := filepath.Join(home, ".defenseclaw")
	seedProtectedSelectionLock(t, fixture, dataDir, executable, testProtectedCodexVersion, true)
	entries, err := connector.LoadProtectedHookContractLockEntries(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	prior := entries["codex"]
	fixture.setupCalls = 0
	fixture.afterSetup = func() {
		if err := os.WriteFile(executable, []byte("swapped after connector validation\n"), 0o500); err != nil {
			t.Fatal(err)
		}
	}
	opts.AgentExecutable = ""
	opts.AgentVersion = ""

	_, err = Install(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "identity changed during lock-only repair") {
		t.Fatalf("repair drift error = %v", err)
	}
	after, loadErr := connector.LoadProtectedHookContractLockEntries(dataDir)
	if loadErr != nil || !reflect.DeepEqual(after["codex"], prior) {
		t.Fatalf("durable authority changed after drift: err=%v got=%+v want=%+v", loadErr, after["codex"], prior)
	}
}

func TestInstallProtectedSelectionFailuresRestorePriorReceiptAndLock(t *testing.T) {
	skipIfRoot(t)
	tests := []struct {
		name   string
		inject func(t *testing.T, fixture *protectedSelectionInstallerConnector)
	}{
		{
			name: "setup",
			inject: func(_ *testing.T, fixture *protectedSelectionInstallerConnector) {
				fixture.setupErr = errors.New("injected setup failure")
			},
		},
		{
			name: "lock save after publication",
			inject: func(t *testing.T, _ *protectedSelectionInstallerConnector) {
				original := saveEnterpriseHookContractLock
				calls := 0
				saveEnterpriseHookContractLock = func(dataDir string, entry connector.HookContractLockEntry) error {
					calls++
					if err := original(dataDir, entry); err != nil {
						return err
					}
					if calls == 1 {
						return errors.New("injected post-publication lock save failure")
					}
					return nil
				}
				t.Cleanup(func() { saveEnterpriseHookContractLock = original })
			},
		},
		{
			name: "post-save hardening",
			inject: func(_ *testing.T, fixture *protectedSelectionInstallerConnector) {
				fixture.hardeningFailurePath = filepath.Join(filepath.Dir(filepath.Dir(fixture.configPath)), "hardening-directory")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home, _, fixture, opts := newProtectedSelectionInstallFixture(t, testProtectedCodexVersion)
			priorExecutable := writeProtectedSelectionExecutable(t, home, "prior-codex")
			dataDir := filepath.Join(home, ".defenseclaw")
			priorPublication, priorEntry := seedProtectedSelectionLock(
				t, fixture, dataDir, priorExecutable, testProtectedPriorCodexVersion, false,
			)
			priorReceipt, err := os.ReadFile(filepath.Join(dataDir, "agent_selection.json"))
			if err != nil {
				t.Fatalf("read prior receipt: %v", err)
			}
			fixture.setupCalls = 0
			fixture.setupOpts = connector.SetupOpts{}
			test.inject(t, fixture)

			if _, err := Install(context.Background(), opts); err == nil {
				t.Fatal("Install error = nil, want injected failure")
			}
			restoredReceipt, err := os.ReadFile(filepath.Join(dataDir, "agent_selection.json"))
			if err != nil || !reflect.DeepEqual(restoredReceipt, priorReceipt) {
				t.Fatalf("restored receipt differs: err=%v\n got=%q\nwant=%q", err, restoredReceipt, priorReceipt)
			}
			entries, err := connector.LoadProtectedHookContractLockEntries(dataDir)
			if err != nil {
				t.Fatalf("load restored lock: %v", err)
			}
			if got := entries["codex"]; !reflect.DeepEqual(got, priorEntry) {
				t.Fatalf("restored lock entry differs:\n got=%+v\nwant=%+v", got, priorEntry)
			}
			if err := priorPublication.Consume(); err != nil {
				t.Fatalf("consume restored prior publication: %v", err)
			}
		})
	}
}

func TestInstallProtectedSelectionPostSuccessConsumeErrorStaysCoherentlyCommitted(t *testing.T) {
	skipIfRoot(t)
	home, executable, fixture, opts := newProtectedSelectionInstallFixture(t, testProtectedCodexVersion)
	original := consumeEnterpriseAgentSelection
	consumeEnterpriseAgentSelection = func(publication *connector.SetupAgentSelectionPublication) error {
		if err := original(publication); err != nil {
			return err
		}
		return errors.New("injected post-success consume wrapper failure")
	}
	t.Cleanup(func() { consumeEnterpriseAgentSelection = original })

	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("fully committed Install returned hybrid failure: %v", err)
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	if _, err := os.Lstat(filepath.Join(dataDir, "agent_selection.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("committed receipt remains: %v", err)
	}
	entries, err := connector.LoadProtectedHookContractLockEntries(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath, gotVersion, ok := connector.ProtectedSetupAgentSelectionFromLock(entries["codex"], "codex"); !ok || gotPath != executable || gotVersion != testProtectedCodexVersion {
		t.Fatalf("committed lock identity = (%q, %q, %t)", gotPath, gotVersion, ok)
	}
	if fixture.setupCalls != 1 {
		t.Fatalf("Setup calls = %d", fixture.setupCalls)
	}
}

func TestInstallProtectedSelectionPublicationFailureLeavesPriorStateUntouched(t *testing.T) {
	skipIfRoot(t)
	home, _, fixture, opts := newProtectedSelectionInstallFixture(t, testProtectedCodexVersion)
	priorExecutable := writeProtectedSelectionExecutable(t, home, "prior-codex")
	dataDir := filepath.Join(home, ".defenseclaw")
	priorPublication, priorEntry := seedProtectedSelectionLock(
		t, fixture, dataDir, priorExecutable, testProtectedPriorCodexVersion, false,
	)
	priorReceipt, err := os.ReadFile(filepath.Join(dataDir, "agent_selection.json"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.setupCalls = 0
	original := publishEnterpriseAgentSelection
	publishEnterpriseAgentSelection = func(dataDir, name, executable, version string) (*connector.SetupAgentSelectionPublication, error) {
		publication, err := original(dataDir, name, executable, version)
		if err != nil {
			return nil, err
		}
		return publication, errors.New("injected post-publication failure")
	}
	t.Cleanup(func() { publishEnterpriseAgentSelection = original })

	if _, err := Install(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "publication failure") {
		t.Fatalf("Install error = %v", err)
	}
	if fixture.setupCalls != 0 {
		t.Fatalf("Setup called %d times after publication failure", fixture.setupCalls)
	}
	if got, err := os.ReadFile(filepath.Join(dataDir, "agent_selection.json")); err != nil || !reflect.DeepEqual(got, priorReceipt) {
		t.Fatalf("prior receipt changed: err=%v got=%q want=%q", err, got, priorReceipt)
	}
	entries, err := connector.LoadProtectedHookContractLockEntries(dataDir)
	if err != nil || !reflect.DeepEqual(entries["codex"], priorEntry) {
		t.Fatalf("prior lock changed: err=%v got=%+v want=%+v", err, entries["codex"], priorEntry)
	}
	if err := priorPublication.Consume(); err != nil {
		t.Fatalf("consume prior publication: %v", err)
	}
}

func newProtectedSelectionInstallFixture(
	t *testing.T,
	version string,
) (home, executable string, fixture *protectedSelectionInstallerConnector, opts InstallOptions) {
	t.Helper()
	home = newTestHome(t)
	executable = writeProtectedSelectionExecutable(t, home, "codex")
	fixture = &protectedSelectionInstallerConnector{configPath: filepath.Join(home, ".codex", "config.toml")}
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(fixture)
	return home, executable, fixture, InstallOptions{
		ConnectorName:   "codex",
		UserHome:        home,
		OwnerUID:        os.Getuid(),
		OwnerGID:        os.Getgid(),
		APIAddr:         "127.0.0.1:18970",
		ProxyAddr:       "127.0.0.1:4000",
		GuardrailMode:   "observe",
		HookFailMode:    "closed",
		AgentVersion:    version,
		AgentExecutable: executable,
		Registry:        registry,
	}
}

func writeProtectedSelectionExecutable(t *testing.T, home, name string) string {
	t.Helper()
	path := filepath.Join(home, "clients", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("protected native image fixture\n"), 0o500); err != nil {
		t.Fatal(err)
	}
	return path
}

func seedProtectedSelectionLock(
	t *testing.T,
	fixture *protectedSelectionInstallerConnector,
	dataDir, executable, version string,
	consume bool,
) (*connector.SetupAgentSelectionPublication, connector.HookContractLockEntry) {
	t.Helper()
	publication, err := connector.PublishSetupAgentSelection(dataDir, "codex", executable, version)
	if err != nil {
		t.Fatalf("PublishSetupAgentSelection: %v", err)
	}
	opts := connector.SetupOpts{
		DataDir:           dataDir,
		ManagedEnterprise: true,
		AgentVersion:      version,
		AgentExecutable:   executable,
		HookFailMode:      "closed",
		GuardrailMode:     "observe",
	}
	if err := fixture.Setup(context.Background(), opts); err != nil {
		t.Fatalf("seed fixture Setup: %v", err)
	}
	entry := connector.NewHookContractLockEntry(opts, fixture, "test")
	if err := connector.SaveHookContractLockEntry(dataDir, entry); err != nil {
		t.Fatalf("SaveHookContractLockEntry: %v", err)
	}
	entries, err := connector.LoadProtectedHookContractLockEntries(dataDir)
	if err != nil {
		t.Fatalf("LoadProtectedHookContractLockEntries: %v", err)
	}
	entry = entries["codex"]
	if consume {
		if err := publication.Consume(); err != nil {
			t.Fatalf("consume seeded selection: %v", err)
		}
	}
	return publication, entry
}
