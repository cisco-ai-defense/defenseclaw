// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
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
