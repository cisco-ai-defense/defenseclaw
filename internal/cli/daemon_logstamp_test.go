// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-2109: the daemon's pre-run opens the audit store before runSidecar
// runs, so the "[audit] ..." corrupt-store notice and migration lines must
// already go through the gateway.log time stamper.
func TestDaemonPreRunStampsAuditStoreLines(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv(managed.ConfigPathEnv, "")
	t.Setenv(daemon.EnvDaemon, "1")
	t.Setenv(daemon.EnvLogTimestamps, "")
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("config_version: 8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "audit.db"), bytes.Repeat([]byte("not a database "), 512), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(home, "gateway.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	origStderr, origStdout := os.Stderr, os.Stdout
	os.Stderr, os.Stdout = logFile, logFile
	previousConfig, previousStore, previousLog := cfg, auditStore, auditLog
	t.Cleanup(func() {
		stopDaemonLogStamp()
		os.Stderr, os.Stdout = origStderr, origStdout
		if auditStore != nil && auditStore != previousStore {
			_ = auditStore.Close()
		}
		cfg, auditStore, auditLog = previousConfig, previousStore, previousLog
	})

	root := &cobra.Command{Use: "defenseclaw-gateway"}
	if err := rootPersistentPreRunE(root, nil); err != nil {
		t.Fatalf("daemon pre-run = %v", err)
	}
	stopDaemonLogStamp()
	if os.Stderr != logFile {
		t.Fatal("stopping the stamper did not put the log file back")
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "[audit] WARNING: the audit store was corrupt") {
		t.Fatalf("gateway.log has no corrupt-store notice:\n%s", raw)
	}
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		stamp, _, _ := strings.Cut(line, " ")
		if _, err := time.Parse(time.RFC3339, stamp); err != nil {
			t.Errorf("gateway.log line has no time: %q", line)
		}
	}
}
