// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const codexSetupAppServerHelperEnv = "DEFENSECLAW_GATEWAY_CODEX_APP_SERVER_HELPER"

func stageCodexDiscoveryAuthorityFixture(
	_ *testing.T,
	_ string,
	_ connector.HookContractLockEntry,
) {
	// Windows tests deliberately prove that generic agent discovery is not
	// executable authority. Their caller persists the protected lock entry.
}

func TestMain(m *testing.M) {
	if os.Getenv(codexSetupAppServerHelperEnv) == "1" &&
		len(os.Args) == 3 && os.Args[1] == "app-server" && os.Args[2] == "--stdio" {
		os.Exit(runCodexSetupAppServerHelper())
	}
	os.Exit(m.Run())
}

func runCodexSetupAppServerHelper() int {
	if len(os.Args) != 3 || os.Args[1] != "app-server" || os.Args[2] != "--stdio" {
		return 64
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	encoder := json.NewEncoder(os.Stdout)
	for requestCount := 0; requestCount < 8; requestCount++ {
		var request struct {
			Method string `json:"method"`
			ID     int    `json:"id"`
		}
		if err := decoder.Decode(&request); err != nil {
			return 65
		}
		switch request.Method {
		case "initialize":
			if request.ID != 1 || encoder.Encode(map[string]any{
				"id": request.ID, "result": map[string]any{},
			}) != nil {
				return 66
			}
		case "initialized":
			// JSON-RPC notifications intentionally have no response.
		case "configRequirements/read":
			if request.ID != 2 || encoder.Encode(map[string]any{
				"id": request.ID,
				"result": map[string]any{
					"requirements": map[string]any{"allowManagedHooksOnly": false},
				},
			}) != nil {
				return 67
			}
			return 0
		default:
			return 68
		}
	}
	return 69
}

func prepareCodexSetupPolicyFixture(
	t *testing.T,
	dataDir string,
	opts *connector.SetupOpts,
) {
	t.Helper()
	entry := stageCodexExecutableEvidenceFixture(t, dataDir)
	if err := connector.SaveHookContractLockEntry(dataDir, entry); err != nil {
		t.Fatalf("save protected Codex executable evidence: %v", err)
	}
	opts.AgentVersion = entry.RawAgentVersion
	opts.AgentExecutable = entry.AgentExecutable
	opts.HookContractID = entry.ContractID
	t.Setenv(codexSetupAppServerHelperEnv, "1")
}

func publishCodexSetupSelectionFixture(
	t *testing.T,
	dataDir string,
	opts connector.SetupOpts,
) {
	t.Helper()
	body, err := os.ReadFile(opts.AgentExecutable)
	if err != nil {
		t.Fatalf("read selected Codex fixture executable: %v", err)
	}
	digest := sha256.Sum256(body)
	resolution := connector.ResolveHookContract("codex", opts.AgentVersion)
	now := time.Now().UTC().Truncate(time.Second)
	receipt := map[string]interface{}{
		"schema_version": 1,
		"updated_at":     now.Format(time.RFC3339),
		"selections": map[string]interface{}{
			"codex": map[string]interface{}{
				"connector":          "codex",
				"source":             "setup-selected",
				"executable":         opts.AgentExecutable,
				"raw_version":        resolution.RawVersion,
				"normalized_version": resolution.NormalizedVersion,
				"sha256":             hex.EncodeToString(digest[:]),
				"selected_at":        now.Format(time.RFC3339),
				"expires_at":         now.Add(15 * time.Minute).Format(time.RFC3339),
			},
		},
	}
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatalf("marshal Codex setup selection fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "agent_selection.json"), append(encoded, '\n'), 0o600); err != nil {
		t.Fatalf("publish Codex setup selection fixture: %v", err)
	}
}

func TestSinglePublicationRollbackUsesRawCodexLockBehindFreshSetupReceipt(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	artifactPath := filepath.Join(testenv.PrivateTempDir(t), "codex-registration-posture")
	conn := &registrationPostureConnector{bootStubConnector: bootStubConnector{
		stubConnector: stubConnector{name: "codex"},
		artifactPath:  artifactPath,
	}}
	evidence := stageCodexExecutableEvidenceFixture(t, dataDir)
	priorOpts := connector.SetupOpts{
		DataDir:         dataDir,
		GuardrailMode:   "observe",
		HILTEnabled:     false,
		HookFailMode:    "open",
		AgentVersion:    evidence.RawAgentVersion,
		AgentExecutable: evidence.AgentExecutable,
		HookContractID:  evidence.ContractID,
	}
	priorEntry := connector.NewHookContractLockEntry(priorOpts, conn, "prior-test-build")
	priorEntry.UpdatedAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	if err := connector.SaveHookContractLockEntry(dataDir, priorEntry); err != nil {
		t.Fatal(err)
	}
	if err := connector.SaveActiveConnectors(dataDir, []string{"codex"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("observe|hilt=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	priorLockBytes, err := os.ReadFile(filepath.Join(dataDir, "hook_contract_lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	priorActiveBytes, err := os.ReadFile(filepath.Join(dataDir, "active_connector.json"))
	if err != nil {
		t.Fatal(err)
	}
	publishCodexSetupSelectionFixture(t, dataDir, priorOpts)
	if filtered := connector.LoadHookContractLockEntry(dataDir, "codex"); filtered.Connector != "" {
		t.Fatalf("fresh setup receipt did not supersede ordinary Codex lock read: %+v", filtered)
	}

	currentOpts := priorOpts
	currentOpts.GuardrailMode = "action"
	currentOpts.HILTEnabled = true
	currentOpts.HookFailMode = "closed"
	authority, err := captureSingleConnectorRollbackAuthority(currentOpts, conn)
	if err != nil {
		t.Fatal(err)
	}
	if raw := authority.hookLockState.RawEntry("codex"); raw.Connector != "codex" || raw.RegistrationPosture == nil {
		t.Fatalf("raw rollback entry = %+v, want prior Codex posture behind filtered read", raw)
	}
	if err := conn.Setup(context.Background(), currentOpts); err != nil {
		t.Fatal(err)
	}
	makeActiveConnectorPublicationUnsafe(t, dataDir)
	s := &Sidecar{health: NewSidecarHealth()}
	err = s.saveSingleConnectorReadyState(context.Background(), currentOpts, conn, authority)
	if err == nil || !strings.Contains(err.Error(), "active state save failed") {
		t.Fatalf("publication error = %v, want active-state failure", err)
	}
	if !reflect.DeepEqual(conn.setupPostures, []string{"action|hilt=true", "observe|hilt=false"}) {
		t.Fatalf("registration postures = %v, want current then exact prior", conn.setupPostures)
	}
	if body, readErr := os.ReadFile(artifactPath); readErr != nil || string(body) != "observe|hilt=false\n" {
		t.Fatalf("restored registration = %q, %v", body, readErr)
	}
	if body, readErr := os.ReadFile(filepath.Join(dataDir, "hook_contract_lock.json")); readErr != nil || !reflect.DeepEqual(body, priorLockBytes) {
		t.Fatalf("restored lock = %q, %v; want exact prior bytes %q", body, readErr, priorLockBytes)
	}
	if body, readErr := os.ReadFile(filepath.Join(dataDir, "active_connector.json")); readErr != nil || !reflect.DeepEqual(body, priorActiveBytes) {
		t.Fatalf("restored active state = %q, %v; want exact prior bytes %q", body, readErr, priorActiveBytes)
	}
}

func TestMultiPublicationRollbackUsesRawCodexLockBehindFreshSetupReceipt(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	s.cfg.Guardrail.Enabled = true
	s.cfg.Guardrail.Mode = "action"
	s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {
			Mode: "action",
			HILT: &config.HILTConfig{Enabled: true, MinSeverity: "HIGH"},
		},
	}
	s.health = NewSidecarHealth()
	artifactPath := filepath.Join(testenv.PrivateTempDir(t), "codex-registration-posture")
	conn := &registrationPostureConnector{bootStubConnector: bootStubConnector{
		stubConnector: stubConnector{name: "codex"},
		artifactPath:  artifactPath,
	}}
	evidence := stageCodexExecutableEvidenceFixture(t, s.cfg.DataDir)
	priorOpts := connector.SetupOpts{
		DataDir:         s.cfg.DataDir,
		GuardrailMode:   "observe",
		HILTEnabled:     false,
		HookFailMode:    "open",
		AgentVersion:    evidence.RawAgentVersion,
		AgentExecutable: evidence.AgentExecutable,
		HookContractID:  evidence.ContractID,
	}
	priorEntry := connector.NewHookContractLockEntry(priorOpts, conn, "prior-test-build")
	priorEntry.UpdatedAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, priorEntry); err != nil {
		t.Fatal(err)
	}
	if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"codex"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("observe|hilt=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	priorLockBytes, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	priorActiveBytes, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json"))
	if err != nil {
		t.Fatal(err)
	}
	publishCodexSetupSelectionFixture(t, s.cfg.DataDir, priorOpts)
	if filtered := connector.LoadHookContractLockEntry(s.cfg.DataDir, "codex"); filtered.Connector != "" {
		t.Fatalf("fresh setup receipt did not supersede ordinary Codex lock read: %+v", filtered)
	}

	transaction, err := s.setupConnectorsIsolatedTransaction(
		context.Background(), []connector.Connector{conn},
		"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key",
		guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("setup transaction: %v", err)
	}
	if raw := transaction.applied[0].previousLock; raw.Connector != "codex" || raw.RegistrationPosture == nil {
		t.Fatalf("raw rollback entry = %+v, want prior Codex posture behind filtered read", raw)
	}
	makeActiveConnectorPublicationUnsafe(t, s.cfg.DataDir)
	err = s.publishMultiConnectorReadyState(context.Background(), transaction, []string{"codex"}, nil)
	if err == nil || !strings.Contains(err.Error(), "restored applied connectors") {
		t.Fatalf("publication error = %v, want restored transaction", err)
	}
	if !reflect.DeepEqual(conn.setupPostures, []string{"action|hilt=true", "observe|hilt=false"}) {
		t.Fatalf("registration postures = %v, want current then exact prior", conn.setupPostures)
	}
	if body, readErr := os.ReadFile(artifactPath); readErr != nil || string(body) != "observe|hilt=false\n" {
		t.Fatalf("restored registration = %q, %v", body, readErr)
	}
	if body, readErr := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json")); readErr != nil || !reflect.DeepEqual(body, priorLockBytes) {
		t.Fatalf("restored lock = %q, %v; want exact prior bytes %q", body, readErr, priorLockBytes)
	}
	if body, readErr := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json")); readErr != nil || !reflect.DeepEqual(body, priorActiveBytes) {
		t.Fatalf("restored active state = %q, %v; want exact prior bytes %q", body, readErr, priorActiveBytes)
	}
}
