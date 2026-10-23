// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/spf13/cobra"
)

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
