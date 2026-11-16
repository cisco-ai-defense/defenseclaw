// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestShellOutageWarningPrunesExpiredSessionMarkers(t *testing.T) {
	hooks := filepath.Join(t.TempDir(), "hooks")
	markers := filepath.Join(hooks, ".outage-warnings")
	if err := os.MkdirAll(markers, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(markers, "old-session")
	if err := os.WriteFile(old, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ago := time.Now().Add(-10 * 24 * time.Hour)
	if err := os.Chtimes(old, ago, ago); err != nil {
		t.Fatal(err)
	}
	session := ""
	for i := 0; i < 10000; i++ {
		candidate := fmt.Sprintf("session-%d", i)
		if sha256.Sum256([]byte(candidate))[0] == 0 {
			session = candidate
			break
		}
	}
	if session == "" {
		t.Fatal("no pruning session found")
	}
	digest := sha256.Sum256([]byte(session))
	script, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(t.TempDir(), "_hardening.sh")
	if err := os.WriteFile(scriptPath, script, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1"; defenseclaw_first_outage_warning`, "bash", scriptPath)
	cmd.Env = append(os.Environ(), "HOOK_DIR="+hooks, "PAYLOAD="+fmt.Sprintf(`{"session_id":%q}`, session))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shell warning: %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(markers, hex.EncodeToString(digest[:]))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("expired marker survived: %v", err)
	}
	if err := os.WriteFile(old, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(old, ago, ago); err != nil {
		t.Fatal(err)
	}
	repeated := exec.Command("bash", "-c", `source "$1"; defenseclaw_first_outage_warning && exit 1; exit 0`, "bash", scriptPath)
	repeated.Env = cmd.Env
	if out, err := repeated.CombinedOutput(); err != nil {
		t.Fatalf("repeated shell warning: %v: %s", err, out)
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("repeated shell session scanned old markers: %v", err)
	}
}
