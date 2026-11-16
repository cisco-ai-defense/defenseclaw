// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1839: the take-back-pending marker is per account data directory and
// connector, carries no exporter value, and is read without following a link.
func TestNativeOTLPTakeBackPendingMarker(t *testing.T) {
	dataDir := t.TempDir()
	if NativeOTLPTakeBackPending(dataDir, "codex") {
		t.Fatal("pending without a marker")
	}
	if err := RecordNativeOTLPTakeBackPending(dataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	if !NativeOTLPTakeBackPending(dataDir, "codex") || NativeOTLPTakeBackPending(dataDir, "claudecode") {
		t.Fatal("the marker is not per connector")
	}
	data, err := os.ReadFile(filepath.Join(dataDir, "native-otlp-take-back-pending-codex.json"))
	if err != nil || !strings.Contains(string(data), `"connector":"codex"`) {
		t.Fatalf("marker = %q, %v", data, err)
	}
	if err := RecordNativeOTLPTakeBackPending(dataDir, "hermes"); err == nil {
		t.Fatal("a marker for a connector without a native exporter")
	}
	if err := ClearNativeOTLPTakeBackPending(dataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	if NativeOTLPTakeBackPending(dataDir, "codex") {
		t.Fatal("pending after clear")
	}
	if err := ClearNativeOTLPTakeBackPending(dataDir, "codex"); err != nil {
		t.Fatalf("clearing an absent marker: %v", err)
	}
	if NativeOTLPTakeBackPending("", "codex") {
		t.Fatal("pending for an empty data dir")
	}
	if !ValidAgentConfigStatus(AgentConfigNativeOTLPTakeBackPending) {
		t.Fatal("the guardian drops the pending notice code")
	}
	if _, ok := AgentConfigNotice("opencode", "u", AgentConfigNativeOTLPTakeBackPending); ok {
		t.Fatal("worded a pending notice for a connector without a native exporter")
	}
}

// GAP-1839: the take-back revokes the scoped credential when it cannot clean
// the config, and that credential was the proof that the exporter is
// DefenseClaw's. The marker keeps its digest, so the retry still removes the
// exporter (and keeps the operator's keys), even after a second failure.
func TestNativeOTLPTakeBackRetryProvesTheExporterByTheRevokedCredentialDigest(t *testing.T) {
	home := t.TempDir()
	codexHome := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", codexHome)
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	token, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(codexHome, "config.toml")
	body := "model = \"o4\"\n\n[otel]\nlog_user_prompt = true\n\n[otel.exporter.otlp-http]\nendpoint = \"http://127.0.0.1:19010/v1/logs\"\n\n" +
		"[otel.exporter.otlp-http.headers]\nauthorization = \"Bearer " + token + "\"\n"
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: dataDir, ManagedEnterprise: true}
	if err := RecordNativeOTLPTakeBackPending(dataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dataDir, "native-otlp-take-back-pending-codex.json"))
	if err != nil || strings.Contains(string(data), token) {
		t.Fatalf("marker carries the credential: %q, %v", data, err)
	}
	sum := sha256.Sum256([]byte(token))
	if !strings.Contains(string(data), hex.EncodeToString(sum[:])) {
		t.Fatalf("marker has no credential digest: %q", data)
	}
	if err := RemoveOTLPPathToken(dataDir, OTLPScopeCodex); err != nil {
		t.Fatal(err)
	}
	// A second failed take-back, with the credential already revoked, keeps
	// the digest.
	if err := RecordNativeOTLPTakeBackPending(dataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	residue, err := UserNativeOTLPResidue("codex", opts)
	if err != nil || len(residue) == 0 {
		t.Fatalf("residue after the credential was revoked = %q, %v", residue, err)
	}
	if _, err := RemoveUserNativeOTLP("codex", opts); err != nil {
		t.Fatal(err)
	}
	cleaned, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cleaned), token) || strings.Contains(string(cleaned), "19010") || !strings.Contains(string(cleaned), `model = "o4"`) {
		t.Fatalf("config after the retried take-back = %q", cleaned)
	}
	// Without the marker nothing proves a revoked credential's exporter.
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ClearNativeOTLPTakeBackPending(dataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	if residue, err := UserNativeOTLPResidue("codex", opts); err != nil || len(residue) != 0 {
		t.Fatalf("residue without a marker or credential = %q, %v", residue, err)
	}
}
