// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1839, GAP-1840: a native OTLP exporter the managed install could not
// take back (a share-linked .codex of a signed-out account) passed verify and
// status silently. The account's take-back-pending marker now makes the
// guardian record a notice that status and verify word as a warning, and a
// cleared marker clears it.
func TestGuardianWordsANativeOTLPExporterTheInstallCouldNotTakeBack(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	guardianDir := t.TempDir()
	writeEnterpriseHookGuardianNotices(io.Discard, guardianDir, []enterpriseHookGuardianNotice{
		{User: "dcw-std2", Connector: "codex", AgentConfig: "native_otlp_take_back_pending"},
		{User: "dcw-std3", Connector: "claudecode", AgentConfig: "native_otlp_take_back_pending"},
		{User: "dcw-std4", Connector: "hermes", AgentConfig: "native_otlp_take_back_pending"},
	})
	got := enterpriseHookGuardianNoticeMessages(guardianDir)
	if len(got) != 2 ||
		!strings.HasPrefix(got[1], `codex for user dcw-std2: the account's .codex\config.toml still holds the native OTLP exporter`) ||
		!strings.HasPrefix(got[0], `claudecode for user dcw-std3: the account's .claude\settings.json still holds the native OTLP exporter`) {
		t.Fatalf("messages = %q", got)
	}
	for _, message := range got {
		if !strings.Contains(message, "as that user, remove") || !strings.Contains(message, "credential is revoked") {
			t.Fatalf("message does not name the step: %q", message)
		}
	}

	userDataDir := t.TempDir()
	result := enterprisehooks.InstallResult{Connector: "codex", DataDir: userDataDir}
	if code := enterpriseHookAgentConfigNotice(result); code != "" {
		t.Fatalf("notice without a marker = %q", code)
	}
	if err := os.WriteFile(filepath.Join(userDataDir, "native-otlp-take-back-pending-codex.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := enterpriseHookAgentConfigNotice(result); code != connector.AgentConfigNativeOTLPTakeBackPending {
		t.Fatalf("notice with a marker = %q", code)
	}
	if code := enterpriseHookAgentConfigNotice(enterprisehooks.InstallResult{Connector: "claudecode", DataDir: userDataDir}); code != "" {
		t.Fatalf("the codex marker reported claudecode: %q", code)
	}
	hermes := enterprisehooks.InstallResult{Connector: "codex", DataDir: userDataDir, AgentConfig: connector.AgentConfigSettingsLost}
	if code := enterpriseHookAgentConfigNotice(hermes); code != connector.AgentConfigSettingsLost {
		t.Fatalf("the result's own notice was replaced: %q", code)
	}
	if err := connector.ClearNativeOTLPTakeBackPending(userDataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	if code := enterpriseHookAgentConfigNotice(result); code != "" {
		t.Fatalf("notice after the marker was cleared = %q", code)
	}
}

// GAP-1839, GAP-1840, GAP-1170: Verify passes while the take-back-pending
// marker is set, so the guardian's repair (and ensure and `enterprise
// repair`, which run the guardian) never reached the take-back, which only
// the installer runs, and the warning stayed until the next upgrade. A
// verified target with the marker and an available session now runs the
// installer once per pass; a failure keeps the verified row. No marker, or
// no session, runs nothing.
func TestGuardianRetriesThePendingNativeOTLPTakeBackOncePerPass(t *testing.T) {
	previousVerifier, previousInstaller, previousSession := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller, enterpriseHookReconcileSessionAvailable
	t.Cleanup(func() {
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller, enterpriseHookReconcileSessionAvailable = previousVerifier, previousInstaller, previousSession
	})
	userDataDir := t.TempDir()
	verified := enterprisehooks.InstallResult{Connector: "codex", DataDir: userDataDir, UserHome: "verified"}
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return verified, nil
	}
	sessionAvailable, sessionAsked := true, 0
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) {
		sessionAsked++
		return sessionAvailable, nil
	}
	installs := 0
	var installErr error
	enterpriseHookReconcileInstaller = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs++
		if installErr != nil {
			return enterprisehooks.InstallResult{}, installErr
		}
		if err := connector.ClearNativeOTLPTakeBackPending(userDataDir, "codex"); err != nil {
			t.Fatal(err)
		}
		return enterprisehooks.InstallResult{Connector: "codex", DataDir: userDataDir, UserHome: "installed"}, nil
	}
	target := enterprisehooks.ManifestTarget{Connector: "codex"}
	opts := enterprisehooks.InstallOptions{ConnectorName: "codex"}
	pass := func() enterprisehooks.InstallResult {
		t.Helper()
		result, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), target, opts, true)
		if err != nil || repaired {
			t.Fatalf("verified target: repaired=%v err=%v, want ok and not a repair", repaired, err)
		}
		return result
	}
	marker := filepath.Join(userDataDir, "native-otlp-take-back-pending-codex.json")
	writeMarker := func() {
		t.Helper()
		if err := os.WriteFile(marker, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if got := pass(); installs != 0 || sessionAsked != 0 || got.UserHome != "verified" {
		t.Fatalf("no marker: installs=%d sessionAsked=%d result=%q, want nothing run", installs, sessionAsked, got.UserHome)
	}

	writeMarker()
	sessionAvailable = false
	if got := pass(); installs != 0 || got.UserHome != "verified" {
		t.Fatalf("marker, signed out: installs=%d result=%q, want no retry", installs, got.UserHome)
	}

	sessionAvailable = true
	installErr = errors.New("config.toml is locked")
	if got := pass(); installs != 1 || got.UserHome != "verified" ||
		enterpriseHookAgentConfigNotice(got) != connector.AgentConfigNativeOTLPTakeBackPending {
		t.Fatalf("failed retry: installs=%d result=%q, want one try that keeps the verified row and its warning", installs, got.UserHome)
	}

	installErr = nil
	if got := pass(); installs != 2 || got.UserHome != "installed" || enterpriseHookAgentConfigNotice(got) != "" {
		t.Fatalf("retry: installs=%d result=%q notice=%q, want one install that clears the warning",
			installs, got.UserHome, enterpriseHookAgentConfigNotice(got))
	}
	if got := pass(); installs != 2 || got.UserHome != "verified" {
		t.Fatalf("after the marker cleared: installs=%d, want no further install", installs)
	}
}
