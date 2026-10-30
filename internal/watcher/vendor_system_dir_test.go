// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The watcher must not create a vendor system folder such as /etc/codex/skills:
// Codex treats an existing /etc/codex as an administrator policy layer and
// pauses when it cannot read it, which a gateway running as root caused by
// creating the folder (mode 0700) for its skill watch. The folder is watched
// once an administrator creates it, and a skill placed there is admitted.
func TestWatcherDoesNotCreateVendorSystemDir(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	systemRoot := filepath.Join(t.TempDir(), "etc") // stands in for /etc
	previous := vendorSystemRoots
	vendorSystemRoots = []string{systemRoot}
	t.Cleanup(func() { vendorSystemRoots = previous })
	systemSkills := filepath.Join(systemRoot, "codex", "skills")
	cfg.AssetPolicy.Skill.Allowed = append(cfg.AssetPolicy.Skill.Allowed, config.AssetPolicyRule{Name: "late-skill", Reason: "pre-approved"})

	var mu sync.Mutex
	seen := map[string]string{}
	w := New(cfg, []string{skillDir, systemSkills}, nil, store, logger, nil, func(r AdmissionResult) {
		mu.Lock()
		seen[r.Event.Name] = r.Event.Path
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)

	if _, err := os.Lstat(filepath.Join(systemRoot, "codex")); !os.IsNotExist(err) {
		t.Fatalf("watcher created the vendor system folder (err=%v)", err)
	}
	if _, err := os.Lstat(systemRoot); !os.IsNotExist(err) {
		t.Fatalf("watcher created the vendor system root (err=%v)", err)
	}

	// An administrator creates the folder; a skill added later is admitted.
	if err := os.MkdirAll(systemSkills, 0o755); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * w.debounce)
	skill := filepath.Join(systemSkills, "late-skill")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: late-skill\ndescription: lab\n---\nbody\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		_, admitted := seen["late-skill"]
		mu.Unlock()
		if admitted {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-errCh
			t.Fatal("skill under the administrator-created vendor folder was not admitted")
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	<-errCh
}

// ensureAndWatch refuses an absent vendor system folder outright, so no
// caller can create one by accident.
func TestEnsureAndWatchRefusesAbsentVendorSystemDir(t *testing.T) {
	systemRoot := filepath.Join(t.TempDir(), "etc")
	previous := vendorSystemRoots
	vendorSystemRoots = []string{systemRoot}
	t.Cleanup(func() { vendorSystemRoots = previous })

	dir := filepath.Join(systemRoot, "cursor")
	created, err := ensureAndWatch(nil, dir)
	if err != errAbsentVendorSystemDir {
		t.Fatalf("expected errAbsentVendorSystemDir, got created=%v err=%v", created, err)
	}
	if _, statErr := os.Lstat(systemRoot); !os.IsNotExist(statErr) {
		t.Fatalf("vendor system root was created (err=%v)", statErr)
	}
}

func TestUnderVendorSystemRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix path layout")
	}
	previous := vendorSystemRoots
	vendorSystemRoots = gatewayconnector.DefaultVendorSystemRoots()
	t.Cleanup(func() { vendorSystemRoots = previous })

	for _, path := range []string{
		"/etc/codex/skills",
		"/private/etc/codex/skills",
		"/etc/cursor",
		"/etc/github-copilot/policy.d",
		"/Library/Application Support/ClaudeCode/managed-settings.d",
		"/Library/Application Support/opencode",
	} {
		if !underVendorSystemRoot(path) {
			t.Errorf("%s should be under a vendor system root", path)
		}
	}
	for _, path := range []string{
		"/Users/me/.codex/skills",
		"/home/me/.claude/skills",
		"/etcetera/skills",
		"/tmp/Library",
	} {
		if underVendorSystemRoot(path) {
			t.Errorf("%s should not be under a vendor system root", path)
		}
	}
}
