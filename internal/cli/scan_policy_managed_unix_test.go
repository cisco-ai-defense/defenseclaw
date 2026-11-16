// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestManagedRootCodeScanKeepsServiceOwnedRedactionKey(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to reproduce a service-owned 0600 key")
	}
	for _, name := range []string{"SUDO_UID", "SUDO_GID", "SUDO_USER"} {
		t.Setenv(name, "")
	}
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "runtime")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dataDir, "redaction-correlation.key")
	key := bytes.Repeat([]byte{0x5b}, 32)
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dataDir, keyPath} {
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(dir, "benign.py")
	if err := os.WriteFile(target, []byte("print('ok')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousDeployment, previousConfig, previousLog := managedStandaloneAdminDeployment, cfg, auditLog
	previousJSON, previousRaw, previousSchema := scanOutputJSON, scanNoRedact, scanPrintSchema
	t.Cleanup(func() {
		managedStandaloneAdminDeployment, cfg, auditLog = previousDeployment, previousConfig, previousLog
		scanOutputJSON, scanNoRedact, scanPrintSchema = previousJSON, previousRaw, previousSchema
	})
	managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{DataDir: dataDir}, &managed.RuntimeDescriptor{ServiceUID: 65534}, nil
	}
	cfg = config.DefaultConfig()
	cfg.DataDir, cfg.DeploymentMode, cfg.Enterprise.Profile = dataDir, "managed_enterprise", "standalone"
	auditLog = nil
	scanOutputJSON, scanNoRedact, scanPrintSchema = true, false, false
	var output bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&output)
	if err := runScanCode(cmd, []string{target}); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil || document["schema_version"] != float64(7) {
		t.Fatalf("scan JSON: %v, %v", document, err)
	}
	after, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(after, key) {
		t.Fatal("scan replaced the service's redaction key")
	}
	info, err := os.Stat(keyPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("scan changed key custody: %v, %v", info, err)
	}
	if owner := info.Sys().(*syscall.Stat_t); owner.Uid != 65534 || owner.Gid != 65534 {
		t.Fatal("scan changed the service's key owner")
	}
	canonical, err := loadCodeScanRedactor(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	wantFingerprint, err := canonical.FingerprintRuntimeV8FindingContent("managed-directory-proof")
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(dir, "foreign")
	if err := os.MkdirAll(filepath.Join(foreign, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "redaction-correlation.key"), bytes.Repeat([]byte{0x6c}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(foreign, "child"), filepath.Join(dataDir, "redirect")); err != nil {
		t.Fatal(err)
	}
	// Clean matches the deployment, while a raw open follows redirect first.
	aliased, err := loadCodeScanRedactor(dataDir + "/redirect/..")
	if err != nil {
		t.Fatal(err)
	}
	gotFingerprint, err := aliased.FingerprintRuntimeV8FindingContent("managed-directory-proof")
	if err != nil || gotFingerprint != wantFingerprint {
		t.Fatal("managed scan selected a key outside its verified runtime directory")
	}
	managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{DataDir: dataDir}, &managed.RuntimeDescriptor{ServiceUID: 65533}, nil
	}
	repairCommand := "sudo " + managedHostGatewayCommand() + " enterprise " + managedHostPlatform() + " repair"
	if _, err := loadCodeScanRedactor(dataDir); err == nil || !strings.Contains(err.Error(), repairCommand) {
		t.Fatalf("unproven service owner did not refuse with the repair command: %v", err)
	}
	managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{DataDir: dataDir}, nil, errors.New("untrusted descriptor")
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCodeScanRedactor(dataDir); err == nil || !strings.Contains(err.Error(), repairCommand) {
		t.Fatalf("unproven managed deployment did not refuse with the repair command: %v", err)
	}
	if _, err := os.Lstat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("unproven deployment created a correlation key: %v", err)
	}
}

// GAP-0052: on a managed Linux or macOS host `scan code` and `policy test`
// take the config-only start of the other administrator policy commands,
// so they never open the audit store the gateway service account owns. A
// standard account is refused there as by `policy validate`; the full
// start would have opened the store first.
func TestManagedScanCodeAndPolicyTestSkipTheAuditStore(t *testing.T) {
	withManagedRecord(t, "/opt/defenseclaw/bin/defenseclaw-gateway", true, nil)
	previousUID := managedHostCallerUID
	managedHostCallerUID = func() int { return 4242 }
	t.Cleanup(func() { managedHostCallerUID = previousUID })
	want := policyConfigOnlyPreRunE(policyValidateCmd, nil)
	if want == nil {
		t.Fatal("policy validate admitted a standard account on a managed host")
	}
	for name, run := range map[string]func() error{
		"scan code":   func() error { return scanCodeCmd.PersistentPreRunE(scanCodeCmd, nil) },
		"policy test": func() error { return policyTestCmd.PersistentPreRunE(policyTestCmd, nil) },
	} {
		if err := run(); err == nil || err.Error() != want.Error() {
			t.Fatalf("%s start = %v, want the config-only start (%v)", name, err, want)
		}
	}
	if policyTestCmd.PersistentPostRun == nil || !strings.Contains(scanCodeCmd.Use, "code") {
		t.Fatal("policy test lost its config-only post-run")
	}
}

// An administrator's local JSON projection must not open or change the
// gateway service's correlation key, just as it must not open its audit DB.
func TestManagedCodeScanJSONLeavesServiceStateAlone(t *testing.T) {
	withManagedRecord(t, "/opt/defenseclaw/bin/defenseclaw-gateway", true, nil)
	oldConfig, oldAudit := cfg, auditLog
	oldJSON, oldRaw, oldSchema := scanOutputJSON, scanNoRedact, scanPrintSchema
	t.Cleanup(func() {
		cfg, auditLog = oldConfig, oldAudit
		scanOutputJSON, scanNoRedact, scanPrintSchema = oldJSON, oldRaw, oldSchema
	})
	cfg, auditLog = config.DefaultConfig(), nil
	scanOutputJSON, scanNoRedact, scanPrintSchema = true, false, false
	dir := t.TempDir()
	// An inaccessible service tree has the same boundary: local scans do
	// not need it at all. A file makes any attempted key open fail on every OS.
	cfg.DataDir = filepath.Join(dir, "service-state")
	const sentinel = "service-owned state remains unchanged"
	if err := os.WriteFile(cfg.DataDir, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "benign.py")
	if err := os.WriteFile(target, []byte("print('docs fixture')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&output)
	if err := runScanCode(cmd, []string{target}); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result["scanner"] != "codeguard" || result["schema_version"] != float64(7) {
		t.Fatalf("scan JSON=%s, error=%v", output.Bytes(), err)
	}
	if raw, err := os.ReadFile(cfg.DataDir); err != nil || string(raw) != sentinel {
		t.Fatalf("service state changed: %q, %v", raw, err)
	}
}
