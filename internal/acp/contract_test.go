// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateRuntimeContractBindsExecutableDigestsAndMetadata(t *testing.T) {
	dir := t.TempDir()
	agent := filepath.Join(dir, "agent")
	if err := os.WriteFile(agent, []byte("agent-v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	guard, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(clientConfig, []byte(`{"agent_servers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	clientDigest, _ := fileSHA256(clientConfig)
	agentDigest, _ := fileSHA256(agent)
	guardDigest, _ := fileSHA256(guard)
	lock := map[string]any{
		"version": 1, "generated_at": "2026-09-11T00:00:00Z",
		"protocol": map[string]any{"schema_version": SchemaVersion, "schema_sha256": SchemaSHA256},
		"client":   map[string]any{"id": "zed", "config_path": clientConfig, "config_sha256": clientDigest},
		"agent":    map[string]any{"id": "kiro", "path": agent, "sha256": agentDigest, "version": "test"},
		"guard":    map[string]any{"path": guard, "sha256": guardDigest},
		"profile":  "default", "mode": "action",
	}
	body, _ := json.Marshal(lock)
	path := filepath.Join(dir, "contract-lock.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRuntimeContract(path, "zed", "kiro", "default", ModeAction, agent); err != nil {
		t.Fatalf("valid contract rejected: %v", err)
	}
	if err := os.WriteFile(agent, []byte("agent-v2"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRuntimeContract(path, "zed", "kiro", "default", ModeAction, agent); err == nil {
		t.Fatal("changed agent executable was accepted")
	}
	if err := os.WriteFile(agent, []byte("agent-v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientConfig, []byte(`{"agent_servers":{"foreign":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRuntimeContract(path, "zed", "kiro", "default", ModeAction, agent); err == nil {
		t.Fatal("changed client configuration was accepted")
	}
}
