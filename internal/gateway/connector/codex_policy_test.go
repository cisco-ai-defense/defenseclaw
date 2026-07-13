// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
	if err == nil || !strings.Contains(err.Error(), "allow_managed_hooks_only") ||
		!strings.Contains(err.Error(), `C:\ProgramData\OpenAI\Codex\requirements.toml`) {
		t.Fatalf("blocked policy error = %v", err)
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

func TestCodexPolicyAppServerHelper(t *testing.T) {
	if os.Getenv("DEFENSECLAW_CODEX_POLICY_HELPER") != "1" {
		return
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
