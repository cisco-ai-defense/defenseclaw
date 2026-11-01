//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const gap2376ProductToken = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

// The managed Unix guardian removes, as the user, a Codex exporter that
// carries the product gateway token to a port no DefenseClaw process serves,
// and keeps the user's own exporter (GAP-2376).
func TestRemoveManagedUserNativeOTLPRemovesTheProductExporterAndKeepsTheUsersOwn(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".codex", "config.toml")
	input := "model = \"gpt-5\"\n\n[otel]\nenvironment = \"pc2376\"\n\n" +
		"[otel.exporter.otlp-http]\nendpoint = \"http://127.0.0.1:18971/v1/logs\"\nprotocol = \"json\"\n\n" +
		"[otel.exporter.otlp-http.headers]\nAuthorization = \"Bearer " + gap2376ProductToken + "\"\n\n" +
		"[otel.trace_exporter.otlp-http]\nendpoint = \"http://127.0.0.1:18972/v1/traces\"\nprotocol = \"json\"\n\n" +
		"[otel.trace_exporter.otlp-http.headers]\nAuthorization = \"Bearer foreign-collector-0123456789abcdef\"\n"
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, _ := connector.NativeOTLPCredentialDigestOf(gap2376ProductToken)
	opts := enterprisehooks.InstallOptions{ConnectorName: "codex", UserHome: home}
	if err := removeManagedUserNativeOTLP(opts, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != input {
		t.Fatalf("changed the config without a known credential:\n%s", got)
	}
	if err := removeManagedUserNativeOTLP(opts, []connector.NativeOTLPCredentialDigest{digest}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), gap2376ProductToken) || strings.Contains(string(got), "18971") {
		t.Fatalf("the product exporter is still there:\n%s", got)
	}
	if !strings.Contains(string(got), "foreign-collector-0123456789abcdef") || !strings.Contains(string(got), "model = \"gpt-5\"") {
		t.Fatalf("the user's own exporter or settings were lost:\n%s", got)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode changed: %v", info.Mode())
	}
	// Absent configuration and a connector without an exporter.
	if err := removeManagedUserNativeOTLP(enterprisehooks.InstallOptions{ConnectorName: "claudecode", UserHome: home}, []connector.NativeOTLPCredentialDigest{digest}); err != nil {
		t.Fatalf("absent Claude Code settings: %v", err)
	}
	if err := removeManagedUserNativeOTLP(enterprisehooks.InstallOptions{ConnectorName: "amp", UserHome: home}, nil); err == nil {
		t.Fatal("a connector without a native exporter was accepted")
	}
	// A configuration that leads out of the home is refused, not followed.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(outside, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if err := removeManagedUserNativeOTLP(opts, []connector.NativeOTLPCredentialDigest{digest}); err == nil || !strings.Contains(err.Error(), "outside the enrolled home") {
		t.Fatalf("a config outside the home was not refused: %v", err)
	}
	if got, _ := os.ReadFile(outside); string(got) != input {
		t.Fatal("the file outside the home was changed")
	}
}

// The managed Unix guardian's foreign cleanup covers every eligible account,
// enrolled or covered by machine policy only (the default managed RHEL host
// has an empty manifest). Its real as-the-user worker removes the product
// exporter from Codex and Claude Code and keeps the user's own, and gets the
// gateway token's digest only (GAP-2376).
func TestStandaloneForeignCleanupRemovesTheUserNativeOTLPExporterForAnEligibleAccount(t *testing.T) {
	home := foreignCleanupRealWorkerPass(t, true)
	digest, _ := connector.NativeOTLPCredentialDigestOf(gap2376ProductToken)
	previous := enterpriseHookStandaloneProductCredentialDigests
	t.Cleanup(func() { enterpriseHookStandaloneProductCredentialDigests = previous })
	enterpriseHookStandaloneProductCredentialDigests = func() []connector.NativeOTLPCredentialDigest {
		return []connector.NativeOTLPCredentialDigest{digest}
	}
	codex := filepath.Join(home, ".codex", "config.toml")
	claude := filepath.Join(home, ".claude", "settings.json")
	for path, body := range map[string]string{
		codex: "model = \"gpt-5\"\n\n[otel.exporter.otlp-http]\nendpoint = \"http://127.0.0.1:18971/v1/logs\"\n\n" +
			"[otel.exporter.otlp-http.headers]\nAuthorization = \"Bearer " + gap2376ProductToken + "\"\n\n" +
			"[otel.trace_exporter.otlp-http]\nendpoint = \"http://127.0.0.1:18972/v1/traces\"\n\n" +
			"[otel.trace_exporter.otlp-http.headers]\nAuthorization = \"Bearer foreign-collector-0123456789abcdef\"\n",
		claude: `{"model":"haiku","env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:18971",` +
			`"OTEL_EXPORTER_OTLP_HEADERS":"Authorization=Bearer ` + gap2376ProductToken + `"}}`,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	queued := map[string]int{}
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		for _, target := range request.Targets {
			if target.Mode != enterpriseHookWorkerModeRemoveUserNativeOTLP {
				continue
			}
			if target.Options.UserHome != home || len(target.Options.ProductCredentials) != 1 ||
				target.Options.ProductCredentials[0] != digest || target.Options.APIToken != "" || target.Options.OTLPPathToken != "" {
				t.Errorf("the worker must get the account and the digest only: %+v", target.Options)
			}
			queued[target.Options.ConnectorName]++
		}
		return runEnterpriseHookWorker(ctx, account, request)
	}
	var log strings.Builder
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Now(), enterprisehooks.Manifest{}, map[string]map[string]bool{}, "")
	if strings.Contains(log.String(), "does not take mode") || strings.Contains(log.String(), "native OTLP") {
		t.Fatalf("the worker refused or failed the removal:\n%s", log.String())
	}
	if queued["codex"] != 1 || queued["claudecode"] != 1 {
		t.Fatalf("removals queued = %v, want one Codex and one Claude Code", queued)
	}
	for _, path := range []string{codex, claude} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(got), gap2376ProductToken) {
			t.Fatalf("%s still carries the product credential:\n%s", path, got)
		}
		if !strings.Contains(string(got), "gpt-5") && !strings.Contains(string(got), "haiku") {
			t.Fatalf("%s lost the user's settings:\n%s", path, got)
		}
	}
	if got, _ := os.ReadFile(codex); !strings.Contains(string(got), "foreign-collector-0123456789abcdef") {
		t.Fatalf("the user's own exporter was removed:\n%s", got)
	}
}
