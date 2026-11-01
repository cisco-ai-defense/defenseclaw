// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestValidateRuntimeContractBindsExecutableDigestsAndMetadata(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
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
	if err := safefile.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRuntimeContract(path, "zed", "kiro", "default", ModeAction, agent); err != nil {
		t.Fatalf("valid contract rejected: %v", err)
	}
	lock["guard"] = map[string]any{"path": guard, "sha256": strings.Repeat("0", 64), "managed_custody": true}
	body, _ = json.Marshal(lock)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRuntimeContract(path, "zed", "kiro", "default", ModeAction, agent); err == nil {
		t.Fatal("managed-custody flag bypassed digest pinning for a user-owned guard")
	}
	lock["guard"] = map[string]any{"path": guard, "sha256": guardDigest}
	body, _ = json.Marshal(lock)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
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
	} else if !strings.Contains(err.Error(), "editor settings file") || strings.Contains(err.Error(), "executable") {
		// The settings file is not an executable (GAP-0391).
		t.Fatalf("changed client configuration error = %v", err)
	}
	// A managed lock pins the guarded entry: the editor rewriting the file
	// around it (a theme change) keeps it valid, an edit of the entry does
	// not (GAP-0708).
	entry := `"DefenseClaw · Kiro":{"command":"guard","args":["--agent","kiro"]}`
	if err := os.WriteFile(clientConfig, []byte(`{"agent_servers":{`+entry+`}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	entryDigest, err := ClientEntrySHA256(clientConfig, "zed", "kiro", "")
	if err != nil {
		t.Fatal(err)
	}
	lock["client"] = map[string]any{"id": "zed", "config_path": clientConfig, "config_sha256": EntryDigestPrefix + entryDigest}
	body, _ = json.Marshal(lock)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	rewritten := "// edited by the editor\n{\n  \"theme\": \"Gruvbox Dark\",\n  \"agent_servers\": {\n    " + entry + ",\n  },\n}\n"
	if err := os.WriteFile(clientConfig, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRuntimeContract(path, "zed", "kiro", "default", ModeAction, agent); err != nil {
		t.Fatalf("a rewrite of the settings around the guarded entry was refused: %v", err)
	}
	// A mode picked in Zed's agent panel is stored in the entry and keeps
	// it valid; an edit of what the editor launches does not (GAP-0900).
	uiChoice := strings.Replace(rewritten, `"command":"guard"`, `"default_mode":"accept_edits","command":"guard"`, 1)
	if err := os.WriteFile(clientConfig, []byte(uiChoice), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRuntimeContract(path, "zed", "kiro", "default", ModeAction, agent); err != nil {
		t.Fatalf("a mode chosen in the editor UI was refused: %v", err)
	}
	for _, edit := range []string{
		strings.Replace(uiChoice, `"kiro"]`, `"kiro","--x"]`, 1),
		strings.Replace(uiChoice, `"command":"guard"`, `"command":"other"`, 1),
	} {
		if err := os.WriteFile(clientConfig, []byte(edit), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ValidateRuntimeContract(path, "zed", "kiro", "default", ModeAction, agent); err == nil ||
			!strings.Contains(err.Error(), "DefenseClaw · Kiro entry") {
			t.Fatalf("an edited guarded entry: err = %v", err)
		}
	}
}

// enterprise acp verify and list check the executables with the guard's own
// rule: a changed agent or a changed user-owned guard fails both, and the
// unchanged pair passes both (GAP-1156).
func TestLockedExecutablesMatchAgreesWithTheGuard(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
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
	var lock RuntimeContractLock
	lock.Version = 1
	lock.Protocol.SchemaVersion, lock.Protocol.SchemaSHA256 = SchemaVersion, SchemaSHA256
	lock.Client.ID, lock.Client.ConfigPath, lock.Client.ConfigSHA256 = "zed", clientConfig, clientDigest
	lock.Agent.ID, lock.Agent.Path, lock.Agent.SHA256 = "kiro", agent, agentDigest
	lock.Guard.Path, lock.Guard.SHA256 = guard, guardDigest
	lock.Profile, lock.Mode = "default", "action"
	path := filepath.Join(dir, "contract-lock.json")
	write := func() {
		t.Helper()
		body, _ := json.Marshal(lock)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := safefile.ProtectFile(path); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if err := ValidateRuntimeContract(path, "zed", "kiro", "default", ModeAction, agent); err != nil {
		t.Fatalf("guard refused an unchanged contract: %v", err)
	}
	if err := LockedExecutablesMatch(lock, agent, guard); err != nil {
		t.Fatalf("verify refused an unchanged contract: %v", err)
	}
	if err := os.WriteFile(agent, []byte("agent-v1\n# changed\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	guardErr := ValidateRuntimeContract(path, "zed", "kiro", "default", ModeAction, agent)
	verifyErr := LockedExecutablesMatch(lock, agent, guard)
	if guardErr == nil || verifyErr == nil || guardErr.Error() != verifyErr.Error() {
		t.Fatalf("a changed agent: guard %v, verify %v; want the same refusal", guardErr, verifyErr)
	}
	if err := os.WriteFile(agent, []byte("agent-v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	lock.Guard.SHA256 = strings.Repeat("0", 64)
	write()
	guardErr = ValidateRuntimeContract(path, "zed", "kiro", "default", ModeAction, agent)
	verifyErr = LockedExecutablesMatch(lock, agent, guard)
	if guardErr == nil || verifyErr == nil || guardErr.Error() != verifyErr.Error() {
		t.Fatalf("a changed user-owned guard: guard %v, verify %v; want the same refusal", guardErr, verifyErr)
	}
	if err := LockedExecutablesMatch(lock, filepath.Join(dir, "other-agent"), guard); err == nil ||
		!strings.Contains(err.Error(), "agent executable path does not match") {
		t.Fatalf("another agent command passed: %v", err)
	}
	if got := EntryAgentCommand([]any{"--contract-lock", path, "--", agent, "acp"}, "kiro"); got != agent {
		t.Fatalf("EntryAgentCommand = %q, want %q", got, agent)
	}
	if got := EntryAgentCommand([]any{"--contract-lock", path}, "kiro"); got != "kiro-cli" {
		t.Fatalf("EntryAgentCommand without a command = %q, want the catalog command", got)
	}
}
