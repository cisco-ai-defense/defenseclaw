// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const (
	codexPolicyHangHelperEnv       = "DEFENSECLAW_CODEX_POLICY_HANG_HELPER"
	codexPolicyTreeHelperEnv       = "DEFENSECLAW_CODEX_POLICY_TREE_HELPER"
	codexPolicyGrandchildHelperEnv = "DEFENSECLAW_CODEX_POLICY_GRANDCHILD_HELPER"
	codexPolicyEntryPathEnv        = "DEFENSECLAW_CODEX_POLICY_ENTRY_PATH"
	codexPolicyReadyPathEnv        = "DEFENSECLAW_CODEX_POLICY_READY_PATH"
	codexPolicyMarkerPathEnv       = "DEFENSECLAW_CODEX_POLICY_MARKER_PATH"
)

func TestBoundedDiagnosticBufferConcurrentAccess(t *testing.T) {
	const limit = 1024
	buffer := &boundedDiagnosticBuffer{limit: limit}
	var workers sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for write := 0; write < 64; write++ {
				if _, err := buffer.Write([]byte("diagnostic-output\n")); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
				_ = buffer.String()
			}
		}()
	}
	workers.Wait()
	if got := len(buffer.String()); got != limit {
		t.Fatalf("bounded diagnostic length = %d, want %d", got, limit)
	}
}

func TestEnforceCodexUserHookPolicy(t *testing.T) {
	original := codexPolicyInspector
	t.Cleanup(func() { codexPolicyInspector = original })

	blocked := true
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{
			AllowManagedHooksOnly: &blocked,
			Source:                `C:\ProgramData\OpenAI\Codex\requirements.toml`,
		}, nil
	}
	err := enforceCodexUserHookPolicy(context.Background(), SetupOpts{})
	if runtime.GOOS == "windows" {
		if err != nil {
			t.Fatalf("managed-only Windows policy rejected source-trusted registration: %v", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "allow_managed_hooks_only") ||
		!strings.Contains(err.Error(), `C:\ProgramData\OpenAI\Codex\requirements.toml`) {
		t.Fatalf("blocked user-hook policy error = %v", err)
	}

	blocked = false
	if err := enforceCodexUserHookPolicy(context.Background(), SetupOpts{}); err != nil {
		t.Fatalf("explicitly permitted policy: %v", err)
	}

	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{}, errors.New("policy unavailable")
	}
	if err := enforceCodexUserHookPolicy(context.Background(), SetupOpts{}); err == nil ||
		!strings.Contains(err.Error(), "policy unavailable") {
		t.Fatalf("inspection failure = %v", err)
	}
}

func TestInspectCodexSystemRequirements(t *testing.T) {
	original := codexSystemRequirementsPathForInspection
	t.Cleanup(func() { codexSystemRequirementsPathForInspection = original })
	path := filepath.Join(t.TempDir(), "requirements.toml")
	codexSystemRequirementsPathForInspection = func() (string, error) { return path, nil }

	policy, err := inspectCodexSystemRequirements()
	if err != nil || policy.AllowManagedHooksOnly != nil || policy.Source != path {
		t.Fatalf("missing requirements: policy=%+v err=%v", policy, err)
	}

	if err := os.WriteFile(path, []byte("allow_managed_hooks_only = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err = inspectCodexSystemRequirements()
	if err != nil || policy.AllowManagedHooksOnly == nil || !*policy.AllowManagedHooksOnly {
		t.Fatalf("managed-only requirements: policy=%+v err=%v", policy, err)
	}

	if err := os.WriteFile(path, []byte("allow_managed_hooks_only = [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectCodexSystemRequirements(); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("malformed requirements error = %v", err)
	}

	if err := os.WriteFile(path, make([]byte, codexPolicyMessageLimit+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectCodexSystemRequirements(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized requirements error = %v", err)
	}
}

func TestInspectUnmanagedCodexSystemRequirementsRetainsLegacySymlinkBehavior(t *testing.T) {
	original := codexSystemRequirementsPathForInspection
	t.Cleanup(func() { codexSystemRequirementsPathForInspection = original })
	root := t.TempDir()
	target := filepath.Join(root, "requirements-target.toml")
	path := filepath.Join(root, "requirements.toml")
	if err := os.WriteFile(target, []byte("allow_managed_hooks_only = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	codexSystemRequirementsPathForInspection = func() (string, error) { return path, nil }

	policy, err := inspectCodexSystemRequirementsForMode(false)
	if err != nil {
		t.Fatalf("unmanaged legacy symlink was rejected: %v", err)
	}
	if policy.AllowManagedHooksOnly == nil || !*policy.AllowManagedHooksOnly {
		t.Fatalf("unmanaged symlink policy = %+v, want managed-only=true", policy)
	}
}

func TestInspectUnmanagedCodexSystemRequirementsMissingParentRemainsAbsent(t *testing.T) {
	original := codexSystemRequirementsPathForInspection
	t.Cleanup(func() { codexSystemRequirementsPathForInspection = original })
	path := filepath.Join(t.TempDir(), "missing", "Codex", "requirements.toml")
	codexSystemRequirementsPathForInspection = func() (string, error) { return path, nil }

	policy, err := inspectCodexSystemRequirementsForMode(false)
	if err != nil {
		t.Fatalf("unmanaged missing-parent requirements: %v", err)
	}
	if policy.AllowManagedHooksOnly != nil || policy.Source != path {
		t.Fatalf("unmanaged missing-parent policy = %+v, want absent source %s", policy, path)
	}
}

func TestReadBoundedCodexSystemRequirementsRejectsReplacementBeforeOpen(t *testing.T) {
	originalOpen := codexSystemRequirementsFileOpen
	t.Cleanup(func() { codexSystemRequirementsFileOpen = originalOpen })
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.toml")
	replacement := filepath.Join(dir, "replacement.toml")
	for _, candidate := range []string{path, replacement} {
		if err := os.WriteFile(candidate, []byte("allow_managed_hooks_only = true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	codexSystemRequirementsFileOpen = func(string) (*os.File, error) {
		return os.Open(replacement)
	}

	if _, _, err := readBoundedCodexSystemRequirements(path); err == nil ||
		!strings.Contains(err.Error(), "changed identity") {
		t.Fatalf("replacement read error = %v, want changed-identity refusal", err)
	}
}

func TestInspectManagedCodexSystemRequirementsRejectsUserWritableSource(t *testing.T) {
	original := codexSystemRequirementsPathForInspection
	t.Cleanup(func() { codexSystemRequirementsPathForInspection = original })
	path := filepath.Join(t.TempDir(), "requirements.toml")
	if err := os.WriteFile(path, []byte("allow_managed_hooks_only = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	codexSystemRequirementsPathForInspection = func() (string, error) { return path, nil }

	if _, err := inspectCodexSystemRequirementsForMode(true); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "untrusted") {
		t.Fatalf("managed user-writable requirements error = %v", err)
	}
}

func TestInspectManagedCodexSystemRequirementsMissingParentPlatformContract(t *testing.T) {
	original := codexSystemRequirementsPathForInspection
	t.Cleanup(func() { codexSystemRequirementsPathForInspection = original })
	path := filepath.Join(t.TempDir(), "missing", "Codex", "requirements.toml")
	codexSystemRequirementsPathForInspection = func() (string, error) { return path, nil }

	policy, err := inspectCodexSystemRequirementsForMode(true)
	if runtime.GOOS != "windows" {
		if err != nil || policy.AllowManagedHooksOnly != nil || policy.Source != path {
			t.Fatalf("managed missing-parent Unix policy=%+v err=%v, want absent source", policy, err)
		}
		return
	}
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "parent") ||
		!strings.Contains(strings.ToLower(err.Error()), "pre-provision") {
		t.Fatalf("managed missing-parent Windows requirements error = %v", err)
	}
}

func TestInspectManagedCodexPolicyNeverExecutesUserWritableBinary(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "codex.exe")
	if err := os.WriteFile(executable, []byte("not a trusted binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executable, 0o777); err != nil {
		t.Fatal(err)
	}
	originalCommand := codexAppServerCommand
	called := false
	codexAppServerCommand = func(ctx context.Context, executable string) *exec.Cmd {
		called = true
		return originalCommand(ctx, executable)
	}
	t.Cleanup(func() { codexAppServerCommand = originalCommand })

	_, err := inspectCodexEffectivePolicy(context.Background(), SetupOpts{
		AgentExecutable:   executable,
		ManagedEnterprise: true,
	})
	errText := strings.ToLower(fmt.Sprint(err))
	if err == nil ||
		(!strings.Contains(errText, "untrusted") &&
			!strings.Contains(errText, "protected setup-selected executable evidence")) {
		t.Fatalf("managed user-writable executable error = %v", err)
	}
	if called {
		t.Fatal("managed policy inspection executed a user-writable Codex binary")
	}
}

func TestInspectCodexPolicyFailsClosedForLegacyLockEvidence(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected Codex lock authority is native-Windows-only")
	}
	dir := testenv.PrivateTempDir(t)
	body := []byte(`{"version":2,"updated_at":"2026-07-14T00:00:00Z","connectors":{"codex":{"connector":"codex","updated_at":"2026-07-14T00:00:00Z"}}}`)
	if err := atomicWriteFile(filepath.Join(dir, hookContractLockFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectCodexEffectivePolicy(context.Background(), SetupOpts{DataDir: dir}); err == nil ||
		!strings.Contains(err.Error(), "repair") {
		t.Fatalf("legacy lock inspection error = %v, want repair refusal", err)
	}
}

func TestInspectCodexPolicyWithAppServer(t *testing.T) {
	original := codexAppServerCommand
	t.Cleanup(func() { codexAppServerCommand = original })
	codexAppServerCommand = func(ctx context.Context, _ string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestCodexPolicyAppServerHelper", "--")
		cmd.Env = append(os.Environ(), "DEFENSECLAW_CODEX_POLICY_HELPER=1")
		return cmd
	}

	policy, err := inspectCodexPolicyWithAppServer(context.Background(), filepath.Join(t.TempDir(), "codex.exe"), t.TempDir())
	if err != nil {
		t.Fatalf("inspect app-server policy: %v", err)
	}
	if policy.AllowManagedHooksOnly == nil || !*policy.AllowManagedHooksOnly {
		t.Fatalf("policy = %+v", policy)
	}
	if !strings.Contains(policy.Source, "effective requirements") {
		t.Fatalf("source = %q", policy.Source)
	}
}

func TestInspectCodexPolicyWithAppServerDrainsLargeStderr(t *testing.T) {
	original := codexAppServerCommand
	t.Cleanup(func() { codexAppServerCommand = original })
	codexAppServerCommand = func(ctx context.Context, _ string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCodexPolicyAppServerHelper$", "--")
		cmd.Env = append(os.Environ(), "DEFENSECLAW_CODEX_POLICY_HELPER=stderr-flood")
		return cmd
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	policy, err := inspectCodexPolicyWithAppServer(ctx, filepath.Join(t.TempDir(), "codex.exe"), t.TempDir())
	if err != nil {
		t.Fatalf("large stderr blocked app-server policy: %v", err)
	}
	if policy.AllowManagedHooksOnly == nil || !*policy.AllowManagedHooksOnly {
		t.Fatalf("policy = %+v", policy)
	}
}

func TestDecodeCodexRPCFiltersFloodAndKeepsTerminalOrdered(t *testing.T) {
	var stream strings.Builder
	for id := 3; id < 2000; id++ {
		fmt.Fprintf(&stream, "{\"id\":%d,\"result\":{}}\n", id)
	}
	stream.WriteString("{\"method\":\"notice\"}\n")
	stream.WriteString("{\"id\":1,\"result\":{}}\n")
	stream.WriteString("{\"id\":1,\"result\":{\"duplicate\":true}}\n")
	stream.WriteString("{\"id\":2,\"result\":{}}\n")
	events := make(chan codexRPCEvent, 3)
	go decodeCodexRPC(strings.NewReader(stream.String()), events)

	first := <-events
	second := <-events
	terminal := <-events
	var firstID, secondID int
	_ = json.Unmarshal(first.Envelope.ID, &firstID)
	_ = json.Unmarshal(second.Envelope.ID, &secondID)
	if first.Err != nil || second.Err != nil || firstID != 1 || secondID != 2 {
		t.Fatalf("ordered filtered events = (%d,%v), (%d,%v)", firstID, first.Err, secondID, second.Err)
	}
	if !errors.Is(terminal.Err, io.EOF) {
		t.Fatalf("terminal event = %v, want EOF", terminal.Err)
	}
	if _, ok := <-events; ok {
		t.Fatal("event stream did not close after terminal event")
	}
}

func TestValidateCodexPolicyExecutableRejectsReplacement(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	executable := filepath.Join(dir, "codex.exe")
	if err := atomicWriteFile(executable, []byte("original-codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, digest, ok := setupSelectedAgentExecutableEvidence(executable)
	if !ok {
		t.Fatal("cannot hash fixture executable")
	}
	now := time.Now().UTC().Truncate(time.Second)
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		UpdatedAt:     now.Format(time.RFC3339),
		Selections: map[string]agentSelectionEvidence{
			"codex": {
				Connector:         "codex",
				Source:            "setup-selected",
				Executable:        executable,
				RawVersion:        "codex 0.144.3",
				NormalizedVersion: "0.144.3",
				SHA256:            digest,
				SelectedAt:        now.Format(time.RFC3339),
				ExpiresAt:         now.Add(agentSelectionMaxLifetime).Format(time.RFC3339),
			},
		},
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dir, agentSelectionFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: dir, AgentVersion: "codex 0.144.3", AgentExecutable: executable}
	if _, err := validateCodexPolicyExecutable(opts); err != nil {
		t.Fatalf("valid protected executable rejected: %v", err)
	}
	if err := os.WriteFile(executable, []byte("replaced-codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := validateCodexPolicyExecutable(opts); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("replacement error = %v, want digest refusal", err)
	}
}

func TestInspectCodexPolicyPreservesRPCErrorDuringCleanup(t *testing.T) {
	original := codexAppServerCommand
	t.Cleanup(func() { codexAppServerCommand = original })
	codexAppServerCommand = func(ctx context.Context, _ string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCodexPolicyAppServerHelper$", "--")
		cmd.Env = append(os.Environ(), "DEFENSECLAW_CODEX_POLICY_HELPER=rpc-error")
		return cmd
	}
	_, err := inspectCodexPolicyWithAppServer(context.Background(), filepath.Join(t.TempDir(), "codex.exe"), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "fixture policy denied") {
		t.Fatalf("inspection error = %v, want original RPC error", err)
	}
}

func TestCodexPolicyAppServerHelper(t *testing.T) {
	if os.Getenv(codexPolicyGrandchildHelperEnv) == "1" {
		time.Sleep(750 * time.Millisecond)
		_ = os.WriteFile(os.Getenv(codexPolicyMarkerPathEnv), []byte("survived"), 0o600)
		os.Exit(0)
	}
	if os.Getenv(codexPolicyTreeHelperEnv) == "1" {
		if entry := os.Getenv(codexPolicyEntryPathEnv); entry != "" {
			if err := os.WriteFile(entry, []byte("entered"), 0o600); err != nil {
				os.Exit(30)
			}
		}
		child := exec.Command(os.Args[0], "-test.run=^TestCodexPolicyAppServerHelper$", "--")
		child.Env = append(
			os.Environ(),
			codexPolicyGrandchildHelperEnv+"=1",
			codexPolicyMarkerPathEnv+"="+os.Getenv(codexPolicyMarkerPathEnv),
		)
		if err := child.Start(); err != nil {
			os.Exit(31)
		}
		if err := os.WriteFile(os.Getenv(codexPolicyReadyPathEnv), []byte("ready"), 0o600); err != nil {
			os.Exit(32)
		}
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	if os.Getenv(codexPolicyHangHelperEnv) == "1" {
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	mode := os.Getenv("DEFENSECLAW_CODEX_POLICY_HELPER")
	if mode == "" {
		return
	}
	if mode == "stderr-flood" {
		_, _ = os.Stderr.WriteString(strings.Repeat("diagnostic-flood", 16*1024))
	}
	reader := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for reader.Scan() {
		var request struct {
			Method string `json:"method"`
			ID     int    `json:"id"`
		}
		if err := json.Unmarshal(reader.Bytes(), &request); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		switch request.Method {
		case "initialize":
			if mode == "rpc-error" {
				_ = encoder.Encode(map[string]any{
					"id":    request.ID,
					"error": map[string]any{"code": -32000, "message": "fixture policy denied"},
				})
				os.Exit(4)
			}
			_ = encoder.Encode(map[string]any{"id": request.ID, "result": map[string]any{"codexHome": "fixture"}})
		case "initialized":
			_ = encoder.Encode(map[string]any{"method": "fixture/notification", "params": map[string]any{}})
		case "configRequirements/read":
			_ = encoder.Encode(map[string]any{
				"id": request.ID,
				"result": map[string]any{
					"requirements": map[string]any{"allowManagedHooksOnly": true},
				},
			})
			os.Exit(0)
		}
	}
	os.Exit(3)
}
