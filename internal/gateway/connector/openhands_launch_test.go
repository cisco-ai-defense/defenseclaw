// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

type fakeOpenHandsNativeProcess struct {
	started bool
	waited  bool
}

func TestProtectedSetupSelectionScopeIncludesOnlyOpenHandsOnDarwin(t *testing.T) {
	for _, test := range []struct {
		name      string
		connector string
		goos      string
		want      bool
	}{
		{name: "Darwin OpenHands", connector: "openhands", goos: "darwin", want: true},
		{name: "Linux OpenHands", connector: "openhands", goos: "linux", want: false},
		{name: "Windows OpenHands", connector: "openhands", goos: "windows", want: false},
		{name: "Darwin Codex", connector: "codex", goos: "darwin", want: false},
		{name: "Windows Codex", connector: "codex", goos: "windows", want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := protectedSetupSelectionConnectorForOS(test.connector, test.goos); got != test.want {
				t.Fatalf("protectedSetupSelectionConnectorForOS(%q, %q) = %t, want %t", test.connector, test.goos, got, test.want)
			}
		})
	}
}

func TestOpenHandsDarwinSetupExecutableAdmissionConsumesProtectedReceipt(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	dataDir := filepath.Join(root, "state")
	trustedDir := filepath.Join(root, "trusted")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(trustedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(trustedDir, "openhands")
	if err := os.WriteFile(executable, []byte("protected setup executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executable, 0o700); err != nil {
		t.Fatal(err)
	}
	stablePath, digest, ok := setupSelectedAgentExecutableEvidence(executable)
	if !ok {
		t.Fatal("capture setup-selected executable evidence")
	}
	now := time.Now().UTC().Truncate(time.Second)
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		UpdatedAt:     now.Format(time.RFC3339),
		Selections: map[string]agentSelectionEvidence{
			"openhands": {
				Connector:         "openhands",
				Source:            "setup-selected",
				Executable:        stablePath,
				RawVersion:        "OpenHands CLI 1.16.0",
				NormalizedVersion: "1.16.0",
				SHA256:            digest,
				SelectedAt:        now.Format(time.RFC3339),
				ExpiresAt:         now.Add(10 * time.Minute).Format(time.RFC3339),
			},
		},
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, agentSelectionFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{
		DataDir:         dataDir,
		AgentVersion:    "OpenHands CLI 1.16.0",
		AgentExecutable: stablePath,
	}
	if got, err := validateOpenHandsDarwinExecutable(opts, false); err != nil || got != stablePath {
		t.Fatalf("receipt-backed admission = %q, %v", got, err)
	}
	entry := NewHookContractLockEntry(opts, NewOpenHandsConnector(), "test")
	entry.AgentExecutable = stablePath
	entry.AgentExecutableSource = "setup-selected"
	entry.AgentExecutableSHA256 = digest
	if err := validateOpenHandsDarwinLockPublication(dataDir, entry); err != nil {
		t.Fatalf("receipt-backed lock publication: %v", err)
	}
	if err := os.WriteFile(executable, []byte("replacement setup executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := validateOpenHandsDarwinExecutable(opts, false); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("mutated receipt-backed executable admission error = %v, want digest refusal", err)
	}
	if err := validateOpenHandsDarwinLockPublication(dataDir, entry); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("mutated lock publication error = %v, want digest refusal", err)
	}
}

func (p *fakeOpenHandsNativeProcess) Start() error {
	p.started = true
	return nil
}

func (p *fakeOpenHandsNativeProcess) Wait() error {
	p.waited = true
	return nil
}

func newProtectedOpenHandsLaunchFixture(t *testing.T) (SetupOpts, string, string) {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	dataDir := filepath.Join(root, "state")
	trustedDir := filepath.Join(root, "trusted")
	if err := os.MkdirAll(trustedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(trustedDir, "openhands")
	if err := os.WriteFile(executable, []byte("protected OpenHands executable fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executable, 0o700); err != nil {
		t.Fatal(err)
	}
	stablePath, digest, ok := setupSelectedAgentExecutableEvidence(executable)
	if !ok {
		t.Fatal("could not capture executable evidence")
	}

	configPath := filepath.Join(root, ".openhands", "hooks.json")
	previousPath := OpenHandsHooksPathOverride
	OpenHandsHooksPathOverride = configPath
	t.Cleanup(func() { OpenHandsHooksPathOverride = previousPath })

	opts := SetupOpts{
		DataDir:         dataDir,
		WorkspaceDir:    root,
		APIAddr:         "127.0.0.1:18970",
		AgentVersion:    "OpenHands CLI 1.16.0",
		AgentExecutable: stablePath,
	}
	conn := NewOpenHandsConnector()
	if err := conn.setup(context.Background(), opts, ""); err != nil {
		t.Fatalf("seed OpenHands hook registration: %v", err)
	}
	entry := NewHookContractLockEntry(opts, conn, "test")
	entry.AgentExecutable = stablePath
	entry.AgentExecutableSource = "setup-selected"
	entry.AgentExecutableSHA256 = digest
	if err := SaveFreshHookContractLockEntry(dataDir, entry); err != nil {
		t.Fatalf("seed OpenHands protected lock: %v", err)
	}
	if err := SaveActiveConnectors(dataDir, []string{"openhands"}); err != nil {
		t.Fatalf("seed active OpenHands state: %v", err)
	}
	token, err := EnsureOTLPPathToken(dataDir, OTLPScopeOpenHands)
	if err != nil {
		t.Fatalf("seed OpenHands OTLP token: %v", err)
	}
	return opts, token, filepath.Join(dataDir, "hooks", "openhands-hook.sh")
}

func TestOpenHandsProtectedLaunchKeepsScopedTokenOutOfArgvAndOutput(t *testing.T) {
	opts, token, _ := newProtectedOpenHandsLaunchFixture(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://attacker.invalid")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=hostile")
	t.Setenv("PYTHONPATH", filepath.Join(opts.WorkspaceDir, "hostile-python"))
	t.Setenv("PYTHONUSERBASE", filepath.Join(opts.WorkspaceDir, "hostile-user-base"))
	t.Setenv("DYLD_INSERT_LIBRARIES", filepath.Join(opts.WorkspaceDir, "hostile.dylib"))

	originalFactory := newOpenHandsNativeProcess
	process := &fakeOpenHandsNativeProcess{}
	var capturedExecutable string
	var capturedArgs, capturedEnv []string
	newOpenHandsNativeProcess = func(
		_ context.Context,
		executable string,
		args []string,
		env []string,
		_ io.Reader,
		_ io.Writer,
		_ io.Writer,
	) openHandsNativeProcess {
		capturedExecutable = executable
		capturedArgs = append([]string(nil), args...)
		capturedEnv = append([]string(nil), env...)
		return process
	}
	t.Cleanup(func() { newOpenHandsNativeProcess = originalFactory })

	args := []string{"--headless", "-t", "inspect this workspace"}
	var stdout, stderr bytes.Buffer
	if err := launchOpenHandsWithNativeOTLPForOS(
		context.Background(), opts, args, strings.NewReader(""), &stdout, &stderr, "darwin",
	); err != nil {
		t.Fatalf("launchOpenHandsWithNativeOTLPForOS: %v", err)
	}
	if capturedExecutable != opts.AgentExecutable || !reflect.DeepEqual(capturedArgs, args) {
		t.Fatalf("launched executable/args = %q %v, want %q %v", capturedExecutable, capturedArgs, opts.AgentExecutable, args)
	}
	if strings.Contains(strings.Join(capturedArgs, "\x00"), token) {
		t.Fatal("scoped token leaked into OpenHands argv")
	}
	envText := strings.Join(capturedEnv, "\n")
	if !strings.Contains(envText, token) ||
		!strings.Contains(envText, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:18970/v1/traces") ||
		!strings.Contains(envText, "OTEL_METRICS_EXPORTER=none") ||
		!strings.Contains(envText, "OTEL_LOGS_EXPORTER=none") {
		t.Fatalf("protected launch environment is incomplete: %s", envText)
	}
	for _, hostile := range []string{"attacker.invalid", "authorization=hostile", "PYTHONPATH=", "PYTHONUSERBASE=", "DYLD_INSERT_LIBRARIES="} {
		if strings.Contains(envText, hostile) {
			t.Fatalf("hostile inherited environment survived launch rendering: %s", hostile)
		}
	}
	if stdout.Len() != 0 || stderr.Len() != 0 || strings.Contains(stdout.String()+stderr.String(), token) {
		t.Fatalf("launch boundary emitted secret/output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !process.started || !process.waited {
		t.Fatalf("child lifecycle = started:%t waited:%t", process.started, process.waited)
	}
}

func TestOpenHandsProtectedLaunchFailsClosedOnCustodyDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, opts SetupOpts, hookPath string)
	}{
		{
			name: "executable digest",
			mutate: func(t *testing.T, opts SetupOpts, _ string) {
				t.Helper()
				if err := os.WriteFile(opts.AgentExecutable, []byte("replaced executable\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hook digest",
			mutate: func(t *testing.T, _ SetupOpts, hookPath string) {
				t.Helper()
				file, err := os.OpenFile(hookPath, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.WriteString("# drift\n"); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing token",
			mutate: func(t *testing.T, opts SetupOpts, _ string) {
				t.Helper()
				if err := RemoveOTLPPathToken(opts.DataDir, OTLPScopeOpenHands); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "inactive registration",
			mutate: func(t *testing.T, opts SetupOpts, _ string) {
				t.Helper()
				if _, err := MarkConnectorInactive(opts.DataDir, "openhands"); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts, token, hookPath := newProtectedOpenHandsLaunchFixture(t)
			test.mutate(t, opts, hookPath)
			_, _, err := prepareOpenHandsNativeLaunchLocked(opts, "darwin")
			if err == nil {
				t.Fatal("launch preparation accepted drifted protected state")
			}
			if strings.Contains(err.Error(), token) {
				t.Fatalf("launch error leaked scoped token: %v", err)
			}
		})
	}
}

func TestOpenHandsProtectedLaunchRejectsNonDarwinAndNonLoopback(t *testing.T) {
	opts, token, _ := newProtectedOpenHandsLaunchFixture(t)
	for _, test := range []struct {
		goos    string
		apiAddr string
	}{
		{goos: "linux", apiAddr: opts.APIAddr},
		{goos: "windows", apiAddr: opts.APIAddr},
		{goos: "darwin", apiAddr: "192.0.2.10:18970"},
		{goos: "darwin", apiAddr: "localhost:18970"},
	} {
		t.Run(fmt.Sprintf("%s-%s", test.goos, strings.ReplaceAll(test.apiAddr, ":", "_")), func(t *testing.T) {
			candidate := opts
			candidate.APIAddr = test.apiAddr
			_, _, err := prepareOpenHandsNativeLaunchLocked(candidate, test.goos)
			if err == nil {
				t.Fatal("launch preparation accepted unsupported platform or endpoint")
			}
			if strings.Contains(err.Error(), token) {
				t.Fatalf("launch error leaked scoped token: %v", err)
			}
		})
	}
}
