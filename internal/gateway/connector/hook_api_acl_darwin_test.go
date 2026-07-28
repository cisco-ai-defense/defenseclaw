// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHookAPITokenRejectsWriteCapableDarwinACL(t *testing.T) {
	assertHookAPITokenRejectedByEnsureAndLoad(t, "macOS ACL", func(t *testing.T) string {
		dataDir := t.TempDir()
		if _, err := EnsureHookAPIToken(dataDir, "codex"); err != nil {
			t.Fatalf("seed token: %v", err)
		}
		hooksDir := filepath.Join(dataDir, "hooks")
		cmd := exec.Command("/bin/chmod", "+a", "everyone allow add_file,add_subdirectory,delete_child", hooksDir)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cannot create macOS ACL fixture: %v: %s", err, output)
		}
		t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-RN", hooksDir).Run() })
		return dataDir
	})
}

func TestHookAPITokenDarwinACLIgnoresAllowInPathname(t *testing.T) {
	path := filepath.Join(t.TempDir(), "path allow write")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir ACL fixture: %v", err)
	}
	if err := hookAPIValidateDirectoryACL(path); err != nil {
		t.Fatalf("pathname text was mistaken for an ACL entry: %v", err)
	}
}

func TestHookAPITokenDarwinACLInspectionTimesOut(t *testing.T) {
	err := hookAPIValidateDirectoryACLWithInspector("/fixture", time.Millisecond, func(ctx context.Context, _ string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err == nil || !strings.Contains(err.Error(), "timed out after 1ms") {
		t.Fatalf("ACL inspection error = %v, want bounded timeout", err)
	}
}
