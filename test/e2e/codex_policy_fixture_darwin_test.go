// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package e2e

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

const (
	e2eCodexDarwinExecutableEnv = "DEFENSECLAW_E2E_CODEX_NATIVE_EXECUTABLE"
	e2eCodexDarwinVersionEnv    = "DEFENSECLAW_E2E_CODEX_RAW_VERSION"
)

func runCodexPolicyFixtureIfRequested() (bool, int) { return false, 0 }

// seedCodexPolicyFixture publishes through the same short-lived,
// executable-bound selection interface used by trusted native setup. The
// contract workflow supplies an exact official npm image; Codex Setup remains
// responsible for applying its normal macOS signature, architecture,
// quarantine, ACL, owner, version, and digest checks before it starts
// app-server. No production validation is stubbed.
func seedCodexPolicyFixture(
	t *testing.T,
	dataDir string,
	conn connector.Connector,
	opts *connector.SetupOpts,
) *codexPolicyFixtureFinalizer {
	t.Helper()

	executable := strings.TrimSpace(os.Getenv(e2eCodexDarwinExecutableEnv))
	rawVersion := strings.TrimSpace(os.Getenv(e2eCodexDarwinVersionEnv))
	if executable == "" || rawVersion == "" {
		if strings.EqualFold(strings.TrimSpace(os.Getenv("DC_E2E_OS")), "macos") {
			t.Fatalf(
				"authenticated Codex lifecycle fixture is incomplete: %s and %s must both be set",
				e2eCodexDarwinExecutableEnv,
				e2eCodexDarwinVersionEnv,
			)
		}
		t.Skip("macOS Codex lifecycle requires the authenticated contract-workflow fixture")
	}

	lockSnapshot, err := connector.CaptureHookContractLockSnapshot(dataDir)
	if err != nil {
		t.Fatalf("capture Codex lifecycle contract lock: %v", err)
	}
	publication, err := connector.PublishSetupAgentSelection(
		dataDir,
		"codex",
		executable,
		rawVersion,
	)
	if err != nil {
		t.Fatalf("publish protected Codex lifecycle selection: %v", err)
	}
	selectionFinalized := false
	lockRestored := false
	restoreLock := func() error {
		if lockRestored {
			return nil
		}
		err := lockSnapshot.Restore()
		if err == nil {
			lockRestored = true
		}
		return err
	}
	rollbackSelection := func() error {
		if selectionFinalized {
			return nil
		}
		err := publication.Rollback()
		if err == nil {
			selectionFinalized = true
		}
		return err
	}
	rollbackSetup := func() error {
		return errors.Join(rollbackSelection(), restoreLock())
	}
	t.Cleanup(func() {
		if err := errors.Join(rollbackSelection(), restoreLock()); err != nil {
			t.Errorf("restore Codex lifecycle selection and lock: %v", err)
		}
	})

	if got := connector.LoadCachedAgentExecutable(dataDir, "codex"); got != executable {
		t.Fatalf("receipt-backed Codex executable = %q, want %q", got, executable)
	}
	if got := connector.LoadCachedAgentVersion(dataDir, "codex"); got != rawVersion {
		t.Fatalf("receipt-backed Codex version = %q, want %q", got, rawVersion)
	}
	resolution := connector.ResolveHookContract("codex", rawVersion)
	if resolution.Status != connector.HookCompatibilityKnown {
		t.Fatalf("Codex lifecycle fixture version is outside a known hook contract: %+v", resolution)
	}

	opts.AgentExecutable = executable
	opts.AgentVersion = rawVersion
	opts.HookContractID = resolution.Contract.ContractID
	t.Setenv("CODEX_HOME", filepath.Dir(connector.CodexConfigPathOverride))

	return &codexPolicyFixtureFinalizer{
		afterSetup: func(setupSucceeded bool) error {
			if !setupSucceeded {
				return rollbackSetup()
			}
			lockEntry := connector.NewHookContractLockEntry(
				*opts,
				conn,
				version.Current().BinaryVersion,
			)
			if err := connector.SaveHookContractLockEntry(dataDir, lockEntry); err != nil {
				return errors.Join(
					fmt.Errorf("save Codex lifecycle hook contract lock: %w", err),
					rollbackSetup(),
				)
			}
			if err := publication.Consume(); err != nil {
				return errors.Join(
					fmt.Errorf("consume Codex lifecycle setup selection: %w", err),
					rollbackSetup(),
				)
			}
			selectionFinalized = true
			return nil
		},
		afterTeardown: restoreLock,
	}
}
