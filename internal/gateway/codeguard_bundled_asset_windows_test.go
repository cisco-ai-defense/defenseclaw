// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

var bundledCodeGuardGatewayFiles = []string{"SKILL.md", "main.py", "skill.yaml"}

func TestBundledCodeGuardPackagedCopyScansCleanThroughWindowsConnectors(t *testing.T) {
	sourceDir := filepath.Join(bundledCodeGuardGatewayRepositoryRoot(t), "skills", "codeguard")
	packagedDir := filepath.Join(
		t.TempDir(),
		"site-packages",
		"defenseclaw",
		"_data",
		"skills",
		"codeguard",
	)
	bundledCodeGuardGatewayCopyExact(t, sourceDir, packagedDir)

	rulesDir := filepath.Join(t.TempDir(), "empty-codeguard-rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		connector   string
		destination string
		scan        func(*APIServer) *ToolInspectVerdict
	}{
		{
			name:        "codex",
			connector:   "codex",
			destination: filepath.Join(t.TempDir(), "codex-home", "skills", "codeguard"),
			scan: func(api *APIServer) *ToolInspectVerdict {
				return api.scanCodexChangedFiles(context.Background(), codexHookRequest{})
			},
		},
		{
			name:        "claude-code",
			connector:   "claudecode",
			destination: filepath.Join(t.TempDir(), "claude-config", "skills", "codeguard"),
			scan: func(api *APIServer) *ToolInspectVerdict {
				return api.scanClaudeCodeChangedFiles(context.Background(), claudeCodeHookRequest{})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundledCodeGuardGatewayCopyExact(t, packagedDir, test.destination)
			scanPaths := make([]string, 0, len(bundledCodeGuardGatewayFiles))
			for _, name := range bundledCodeGuardGatewayFiles {
				scanPaths = append(scanPaths, filepath.Join(test.destination, name))
			}

			cfg := &config.Config{
				Scanners: config.ScannersConfig{CodeGuard: rulesDir},
				ConnectorHooks: map[string]config.AgentHookConfig{
					test.connector: {ScanPaths: scanPaths},
				},
			}
			verdict := test.scan(&APIServer{scannerCfg: cfg})
			if verdict == nil {
				t.Fatal("connector scan returned a nil verdict")
			}
			if verdict.Action != "allow" || verdict.Severity != "NONE" || len(verdict.Findings) != 0 {
				t.Fatalf("connector scan self-flagged: %+v", verdict)
			}
		})
	}
}

func bundledCodeGuardGatewayRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate the connector asset test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}

func bundledCodeGuardGatewayCopyExact(t *testing.T, sourceDir, destinationDir string) {
	t.Helper()
	if err := os.MkdirAll(destinationDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range bundledCodeGuardGatewayFiles {
		source, err := os.ReadFile(filepath.Join(sourceDir, name))
		if err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(destinationDir, name)
		if err := os.WriteFile(destination, source, 0o600); err != nil {
			t.Fatal(err)
		}
		copied, err := os.ReadFile(destination)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(copied, source) {
			t.Fatalf("packaged connector asset %s is not an exact copy", name)
		}
	}
}
