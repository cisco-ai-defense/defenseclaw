// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1048: a damaged audit DB aborted `connector teardown`, and with it the
// whole uninstall. Teardown and verify write no audit events, so they go on
// with a warning; other subcommands still fail.
func TestDamagedAuditStoreBlocksOnlyAuditUsingSubcommands(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv(managed.ConfigPathEnv, "")
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("config_version: 8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "audit.db"), bytes.Repeat([]byte("not a database "), 512), 0o600); err != nil {
		t.Fatal(err)
	}
	previousConfig, previousStore, previousLog := cfg, auditStore, auditLog
	t.Cleanup(func() {
		if auditStore != nil && auditStore != previousStore {
			_ = auditStore.Close()
		}
		cfg, auditStore, auditLog = previousConfig, previousStore, previousLog
	})

	parent := &cobra.Command{Use: "defenseclaw-gateway"}
	plain := &cobra.Command{Use: "status"}
	teardown := &cobra.Command{Use: "teardown", Annotations: connectorTeardownCmd.Annotations}
	parent.AddCommand(plain, teardown)

	if err := rootPersistentPreRunE(plain, nil); err == nil || !strings.Contains(err.Error(), "audit store") {
		t.Fatalf("plain subcommand with a damaged audit DB = %v, want the audit store error", err)
	}
	var stderr bytes.Buffer
	teardown.SetErr(&stderr)
	if err := rootPersistentPreRunE(teardown, nil); err != nil {
		t.Fatalf("teardown with a damaged audit DB = %v, want it to continue", err)
	}
	if auditStore != nil || auditLog != nil {
		t.Fatalf("teardown kept an audit store (%v) or logger (%v)", auditStore, auditLog)
	}
	if !strings.Contains(stderr.String(), "continuing without the audit store") {
		t.Fatalf("stderr = %q, want the audit store warning", stderr.String())
	}
	if connectorVerifyCmd.Annotations[auditOptionalAnnotation] != "true" {
		t.Fatal("connector verify must not need the audit store either")
	}
}
