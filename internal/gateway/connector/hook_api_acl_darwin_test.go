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

// An ACL added after a clean verdict changes the directory's status-change
// time, so the next check inspects it again and refuses the token path
// (rel-1-0-6 GAP-0129: the clean verdicts are reused, never a stale one).
func TestHookAPIDarwinACLVerdictRechecksAfterACLChange(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hooks")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := hookAPIValidateDirectoryACL(dir); err != nil {
			t.Fatalf("clean directory: %v", err)
		}
	}
	if output, err := exec.Command("/bin/chmod", "+a", "everyone allow add_file", dir).CombinedOutput(); err != nil {
		t.Fatalf("cannot create macOS ACL fixture: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-RN", dir).Run() })
	if err := hookAPIValidateDirectoryACL(dir); err == nil {
		t.Fatal("a write-capable ACL added after a clean verdict was accepted")
	}
	if output, err := exec.Command("/bin/chmod", "-N", dir).CombinedOutput(); err != nil {
		t.Fatalf("remove ACL: %v: %s", err, output)
	}
	if err := hookAPIValidateDirectoryACL(dir); err != nil {
		t.Fatalf("directory after the ACL was removed: %v", err)
	}
}

// BenchmarkLoadHookAPITokenParallel loads the hook API token from parallel
// goroutines, as a burst of hook requests does; uncached drops the kept ACL
// verdicts before every load (the 1.0.5 and rc1 cost: one /bin/ls per
// directory above the token).
func BenchmarkLoadHookAPITokenParallel(b *testing.B) {
	dataDir := b.TempDir()
	if _, err := EnsureHookAPIToken(dataDir, "claudecode"); err != nil {
		b.Fatal(err)
	}
	for _, uncached := range []bool{true, false} {
		name := "cached"
		if uncached {
			name = "uncached"
		}
		b.Run(name, func(b *testing.B) {
			b.SetParallelism(4)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if uncached {
						hookAPIDarwinACLVerdicts.mu.Lock()
						hookAPIDarwinACLVerdicts.clean = nil
						hookAPIDarwinACLVerdicts.mu.Unlock()
					}
					if _, err := LoadHookAPIToken(dataDir, "claudecode"); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
