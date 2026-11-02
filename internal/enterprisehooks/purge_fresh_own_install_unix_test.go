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

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-6 GAP-0484: an account that ran the per-user one-liner but never
// `defenseclaw init` has no config.yaml, .env, audit.db or previous/ in
// ~/.defenseclaw, only the installed program (.venv, installer state,
// receipts, logs) and its launchers in ~/.local/bin. The managed purge took
// that for state DefenseClaw wrote and deleted the install. It is the
// account's own install: the purge keeps the folder and the binaries as they
// are and says so, and still removes the managed Claude Code blocker.
func TestPurgeUserStateKeepsAnOwnInstallThatNeverRanInit(t *testing.T) {
	skipIfRoot(t)
	for _, marker := range []string{".venv", "installer"} {
		t.Run(marker, func(t *testing.T) {
			home := newTestHome(t)
			dataDir := filepath.Join(home, ".defenseclaw")
			binDir := filepath.Join(home, ".local", "bin")
			write := func(path, body string, mode os.FileMode) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			own := map[string]string{
				filepath.Join(dataDir, "receipts", "installer.sha256"): "sample\n",
				filepath.Join(dataDir, "logs", "install.log"):          "sample\n",
				filepath.Join(dataDir, ".uv", "python", "marker"):      "sample\n",
				filepath.Join(binDir, "defenseclaw-gateway"):           "gateway",
				filepath.Join(binDir, "uv"):                            "uv-binary",
			}
			if marker == ".venv" {
				own[filepath.Join(dataDir, ".venv", "bin", "defenseclaw")] = "#!/bin/sh\n"
			} else {
				own[filepath.Join(dataDir, "installer", "binaries.sha256")] = "sample\n"
			}
			for path, body := range own {
				write(path, body, 0o700)
			}
			link := filepath.Join(binDir, "defenseclaw")
			if err := os.Symlink(filepath.Join(dataDir, ".venv", "bin", "defenseclaw"), link); err != nil {
				t.Fatal(err)
			}
			blocker := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
			write(blocker, PersonalClaudeHookBlocker, 0o700)

			summary, err := PurgeUserState(context.Background(), InstallOptions{
				UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Registry: connector.NewDefaultRegistry(),
			})
			if err != nil || !summary.Kept || summary.Data || summary.Binaries || summary.UVCache {
				t.Fatalf("PurgeUserState = %+v, %v; want the own install kept", summary, err)
			}
			for path, body := range own {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != body {
					t.Fatalf("the purge changed %s of the own install: %q, %v", path, got, err)
				}
			}
			if _, err := os.Lstat(link); err != nil {
				t.Fatalf("the purge removed the own install's launcher link: %v", err)
			}
			if _, err := os.Lstat(blocker); !os.IsNotExist(err) {
				t.Fatalf("the managed Claude Code blocker stayed: %v", err)
			}
			if own, err := HoldsPerUserInstall(dataDir); err != nil || !own {
				t.Fatalf("HoldsPerUserInstall = %t, %v; want the own install seen", own, err)
			}
		})
	}
}
