// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// rel-1-0-6 GAP-0178: the enrollment's Claude Code blocker keeps the
// account's own hook script, bytes and mode, and the uninstall's unblock
// puts it back instead of leaving a missing script.
func TestBlockingThePersonalClaudeHookKeepsTheOwnScriptForTheUninstall(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	path := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
	own := []byte("#!/bin/sh\n# defenseclaw-managed-hook v7\necho own >&2\nexit 0\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, own, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := blockPersonalClaudeHook(enterprisehooks.InstallOptions{ConnectorName: "claudecode", UserHome: home}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != enterprisehooks.PersonalClaudeHookBlocker {
		t.Fatalf("the blocker is not in place: %q", got)
	}
	removed, restored, err := enterprisehooks.UnblockPersonalClaudeHook(dataDir)
	if err != nil || !removed || !restored {
		t.Fatalf("unblock = %t, %t, %v; want the own script back", removed, restored, err)
	}
	info, err := os.Stat(path)
	got, _ := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, own) || info.Mode().Perm() != 0o750 {
		t.Fatalf("the own script is not back byte for byte: %q %v", got, err)
	}
}

// Every remove-all job ends with the own install put-back, after its purge;
// an account a pending cleanup keeps gets none.
func TestRemoveAllEndsEveryJobWithTheOwnInstallPutBack(t *testing.T) {
	jobs := map[int]*enterpriseHookWorkerJob{
		1001: newEnterpriseHookRemoveJob(enterpriseHookWorkerAccount{UID: 1001, GID: 1001, User: "sample-a", Home: "/home/sample-a"}),
		1002: newEnterpriseHookRemoveJob(enterpriseHookWorkerAccount{UID: 1002, GID: 1002, User: "sample-b", Home: "/home/sample-b"}),
	}
	jobs[1001].Request.Targets = append(jobs[1001].Request.Targets, enterpriseHookWorkerTarget{Index: 4, Mode: enterpriseHookWorkerModePurge})
	addEnterpriseHookOwnInstallRestores(jobs, map[int]string{1002: enterpriseHookPurgeSkipPending})
	targets := jobs[1001].Request.Targets
	last := targets[len(targets)-1]
	if last.Mode != enterpriseHookWorkerModeRestoreOwnInstall || last.Index <= 4 || last.Options.DataDir != "/home/sample-a/.defenseclaw" {
		t.Fatalf("the job does not end with the put-back: %+v", targets)
	}
	for _, target := range jobs[1002].Request.Targets {
		if target.Mode == enterpriseHookWorkerModeRestoreOwnInstall {
			t.Fatalf("an account a pending cleanup keeps got the put-back: %+v", target)
		}
	}
}
