//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Read-back sees only transaction-local evidence under both probe capabilities.
func TestGAP0083HermesInstallUsesPendingDigestBeforeRegistrationReadback(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)

	for _, tc := range []struct {
		name           string
		containedProbe bool
	}{
		{name: "contained probe", containedProbe: true},
		{name: "sealed readback", containedProbe: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := newTestHome(t)
			opts := hermesStandaloneOptions(t, home)
			previous := installOwnedHooksPresent
			t.Cleanup(func() { installOwnedHooksPresent = previous })
			var observedPendingDigest bool
			installOwnedHooksPresent = func(conn connector.Connector, setup connector.SetupOpts, pending connector.HookContractLockEntry) (bool, error) {
				if conn.Name() != "hermes" {
					return previous(conn, setup, pending)
				}
				if entry := connector.LoadHookContractLockEntry(setup.DataDir, "hermes"); entry.Connector != "" {
					return false, fmt.Errorf("registration read-back saw a published contract lock")
				}
				want := pending.HookScriptDigests["hermes-hook.sh"]
				body, err := os.ReadFile(filepath.Join(setup.DataDir, "hooks", "hermes-hook.sh"))
				if err != nil {
					return false, err
				}
				digest := sha256.Sum256(body)
				observedPendingDigest = want != "" && want == fmt.Sprintf("sha256:%x", digest)
				if !tc.containedProbe {
					return observedPendingDigest, nil
				}
				return true, nil
			}
			if _, err := Install(context.Background(), opts); err != nil {
				t.Fatalf("fresh Hermes Install: %v", err)
			}
			if !observedPendingDigest {
				t.Fatal("registration read-back lacked the pending script digest")
			}
			if _, err := Verify(context.Background(), opts); err != nil {
				t.Fatalf("Hermes Verify after Install: %v", err)
			}
		})
	}
}

func TestGAP0083RejectedReadbackDoesNotPublishFreshInstallLock(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := hermesStandaloneOptions(t, home)
	previous := installOwnedHooksPresent
	t.Cleanup(func() { installOwnedHooksPresent = previous })
	var observedPendingDigest bool
	installOwnedHooksPresent = func(conn connector.Connector, setup connector.SetupOpts, pending connector.HookContractLockEntry) (bool, error) {
		observedPendingDigest = pending.HookScriptDigests["hermes-hook.sh"] != ""
		if entry := connector.LoadHookContractLockEntry(setup.DataDir, conn.Name()); entry.Connector != "" {
			return false, fmt.Errorf("rejected read-back saw a published lock")
		}
		return false, nil
	}
	if _, err := Install(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "hook verification failed") {
		t.Fatalf("rejected registration read-back = %v, want install refusal", err)
	}
	if !observedPendingDigest {
		t.Fatal("registration read-back lacked the pending digest")
	}
	if entry := connector.LoadHookContractLockEntry(filepath.Join(home, ".defenseclaw"), "hermes"); entry.Connector != "" {
		t.Fatalf("failed fresh install retained hook contract entry for %s", entry.Connector)
	}
}

func TestGAP0083RejectedReadbackPreservesPeerContractLock(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"test\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	codexOpts := standaloneOptions(home, "codex", "observe", "codex-cli 0.150.0")
	if _, err := Install(context.Background(), codexOpts); err != nil {
		t.Fatalf("Codex peer install: %v", err)
	}
	lockPath := filepath.Join(home, ".defenseclaw", "hook_contract_lock.json")
	before, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	hermesOpts := hermesStandaloneOptions(t, home)
	previous := installOwnedHooksPresent
	t.Cleanup(func() { installOwnedHooksPresent = previous })
	installOwnedHooksPresent = func(conn connector.Connector, setup connector.SetupOpts, pending connector.HookContractLockEntry) (bool, error) {
		if conn.Name() != "hermes" {
			return previous(conn, setup, pending)
		}
		if pending.HookScriptDigests["hermes-hook.sh"] == "" {
			return false, fmt.Errorf("pending Hermes digest is missing")
		}
		return false, nil
	}
	if _, err := Install(context.Background(), hermesOpts); err == nil || !strings.Contains(err.Error(), "hook verification failed") {
		t.Fatalf("rejected Hermes install = %v, want read-back refusal", err)
	}
	after, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("rejected connector changed the peer contract lock")
	}
	if _, err := Verify(context.Background(), codexOpts); err != nil {
		t.Fatalf("Codex peer Verify after rejected install: %v", err)
	}
}

func TestGAP0083InterruptedReadbackDoesNotPublishLock(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	const childHomeEnv = "DC_GAP0083_INTERRUPTED_HOME"
	if home := os.Getenv(childHomeEnv); home != "" {
		opts := hermesStandaloneOptions(t, home)
		installOwnedHooksPresent = func(conn connector.Connector, setup connector.SetupOpts, pending connector.HookContractLockEntry) (bool, error) {
			if pending.HookScriptDigests["hermes-hook.sh"] == "" {
				os.Exit(17)
			}
			os.Exit(0)
			return false, nil
		}
		if _, err := Install(context.Background(), opts); err != nil {
			t.Fatalf("child Install before read-back: %v", err)
		}
		t.Fatal("child Install returned without read-back")
	}
	home := newTestHome(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestGAP0083InterruptedReadbackDoesNotPublishLock$")
	cmd.Env = append(os.Environ(), childHomeEnv+"="+home)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("interrupted read-back child: %v: %s", err, output)
	}
	if entry := connector.LoadHookContractLockEntry(filepath.Join(home, ".defenseclaw"), "hermes"); entry.Connector != "" {
		t.Fatalf("interrupted read-back published a %s lock", entry.Connector)
	}
}

func TestGAP0083UncertainLockWriteKeepsVerifiedRegistration(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := hermesStandaloneOptions(t, home)
	previous := installSaveHookContractLockEntry
	t.Cleanup(func() { installSaveHookContractLockEntry = previous })
	installSaveHookContractLockEntry = func(dataDir string, entry connector.HookContractLockEntry, managed bool) error {
		if err := previous(dataDir, entry, managed); err != nil {
			return err
		}
		return errors.New("injected lock durability error")
	}
	if _, err := Install(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "injected lock durability error") {
		t.Fatalf("uncertain lock write = %v, want the reported error", err)
	}
	if entry := connector.LoadHookContractLockEntry(filepath.Join(home, ".defenseclaw"), "hermes"); entry.Connector != "hermes" {
		t.Fatalf("post-publication error lost the Hermes lock: %+v", entry)
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("post-publication error left an unverified registration: %v", err)
	}
}

func TestGAP0083FailedLockWriteBeforePublicationRollsBack(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := hermesStandaloneOptions(t, home)
	previous := installSaveHookContractLockEntry
	t.Cleanup(func() { installSaveHookContractLockEntry = previous })
	installSaveHookContractLockEntry = func(string, connector.HookContractLockEntry, bool) error {
		return errors.New("injected pre-publication error")
	}
	if _, err := Install(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "injected pre-publication error") {
		t.Fatalf("failed lock write = %v, want the reported error", err)
	}
	if entry := connector.LoadHookContractLockEntry(filepath.Join(home, ".defenseclaw"), "hermes"); entry.Connector != "" {
		t.Fatalf("failed lock write published a %s lock", entry.Connector)
	}
	if _, err := os.Stat(filepath.Join(home, ".defenseclaw", "hooks", "hermes-hook.sh")); !os.IsNotExist(err) {
		t.Fatalf("failed lock write retained the hook script: %v", err)
	}
	installSaveHookContractLockEntry = previous
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("recovery Install: %v", err)
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("recovery Verify: %v", err)
	}
}

func TestGAP0083FailedRepairRestoresExistingScopedToken(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := standaloneOptions(home, "amp", "observe", "0.0.1785334225")
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("initial Amp install: %v", err)
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	previousToken, err := connector.LoadHookAPIToken(dataDir, "amp")
	if err != nil || previousToken != opts.APIToken {
		t.Fatalf("initial Amp token missing: %v", err)
	}
	lockPath := filepath.Join(dataDir, "hook_contract_lock.json")
	previousLock, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	opts.APIToken = strings.Repeat("b", 64)
	previousSave := installSaveHookContractLockEntry
	t.Cleanup(func() { installSaveHookContractLockEntry = previousSave })
	installSaveHookContractLockEntry = func(string, connector.HookContractLockEntry, bool) error {
		return errors.New("injected prepublication lock error")
	}
	if _, err := Install(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "injected prepublication lock error") {
		t.Fatalf("Amp repair = %v, want lock error", err)
	}
	if token, err := connector.LoadHookAPIToken(dataDir, "amp"); err != nil || token != previousToken {
		t.Fatalf("failed repair did not restore previous Amp token: present=%t err=%v", token == previousToken, err)
	}
	if lock, err := os.ReadFile(lockPath); err != nil || string(lock) != string(previousLock) {
		t.Fatalf("failed repair changed the previous lock: equal=%t err=%v", string(lock) == string(previousLock), err)
	}
	installSaveHookContractLockEntry = previousSave
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("successful Amp repair: %v", err)
	}
	if token, err := connector.LoadHookAPIToken(dataDir, "amp"); err != nil || token != opts.APIToken {
		t.Fatalf("successful repair did not publish the requested token: present=%t err=%v", token == opts.APIToken, err)
	}
	committedLock, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	opts.APIToken = strings.Repeat("c", 64)
	opts.GuardrailMode, opts.HookFailMode = "action", "closed"
	installSaveHookContractLockEntry = func(dataDir string, entry connector.HookContractLockEntry, managed bool) error {
		if err := previousSave(dataDir, entry, managed); err != nil {
			return err
		}
		return errors.New("injected postpublication lock error")
	}
	if _, err := Install(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "injected postpublication lock error") {
		t.Fatalf("uncertain Amp repair = %v, want lock error", err)
	}
	if lock, err := os.ReadFile(lockPath); err != nil || string(lock) == string(committedLock) {
		t.Fatalf("postpublication error did not change the lock: changed=%t err=%v", string(lock) != string(committedLock), err)
	}
	if token, err := connector.LoadHookAPIToken(dataDir, "amp"); err != nil || token != opts.APIToken {
		t.Fatalf("published lock did not retain the matching Amp token: present=%t err=%v", token == opts.APIToken, err)
	}
}

func TestGAP0083ExistingDataDirectoryWithoutHooksAllowsAmpInstall(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "hooks")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no hook directory before install: %v", err)
	}
	opts := standaloneOptions(home, "amp", "observe", "0.0.1785334225")
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("fresh Amp install in an existing data directory: %v", err)
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("fresh Amp verification: %v", err)
	}
}
