// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func setDarwinProcessParent(t *testing.T, read func(int) (int, error)) {
	t.Helper()
	previous := darwinProcessParent
	darwinProcessParent = read
	t.Cleanup(func() { darwinProcessParent = previous })
}

// A Volta shim counts as a launcher only while the Claude Code build it
// started runs; that child is judged on its own build. A shim without one,
// or a copy merely named volta-shim, stays unverified.
func TestManagedClaudeVoltaShimNeedsItsClaudeChild(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			root := t.TempDir()
			shim := writeClaudeBuildFile(t, filepath.Join(root, "home", "alice", ".volta", "bin", "volta-shim"), "shim")
			shimLink := linkClaudeBuild(t, shim, filepath.Join(root, "home", "alice", ".volta", "bin", "claude"))
			image := filepath.Join(root, "home", "alice", ".volta", "tools", "image", "packages", "@anthropic-ai", "claude-code")
			imageExe, imageBin := claudeNPMNativeBuild(t, image, "2.1.230")
			oldImage := filepath.Join(root, "home", "alice", ".volta", "tools", "image", "packages", "old", "@anthropic-ai", "claude-code")
			oldImageExe, oldImageBin := claudeNPMNativeBuild(t, oldImage, "2.1.130")
			shimPath, childPath, oldChildPath := shim, imageExe, oldImageExe
			if goos == "darwin" {
				shimPath, childPath, oldChildPath = shimLink, imageBin, oldImageBin
			}
			processes := []claudeTestProcess{
				{pid: 7320, ppid: 1, argv: []string{"claude"}, exe: shimPath},
				{pid: 7321, ppid: 7320, argv: []string{imageBin}, exe: childPath},
				{pid: 7322, ppid: 1, argv: []string{"claude"}, exe: shimPath}, // no child
				{pid: 7323, ppid: 1, argv: []string{"claude"}, exe: shimPath},
				{pid: 7324, ppid: 7323, argv: []string{oldImageBin}, exe: oldChildPath},
			}
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
				ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
			h.publishLedger([]byte("ledger\n"))
			h.env.ReportLaunchCoverage = func(context.Context, managed.LaunchCoverageReport) error { return nil }
			runClaudeTestProcesses(t, h, goos, processes)
			parents := map[int]int{}
			for _, p := range processes {
				parents[p.pid] = p.ppid
			}
			setDarwinProcessParent(t, func(pid int) (int, error) {
				if ppid, ok := parents[pid]; ok {
					return ppid, nil
				}
				return 0, fmt.Errorf("no process %d", pid)
			})
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				warning := messagesOf(result.Warnings, codeManagedLaunchUninspected)
				for _, pid := range []string{"7320", "7321", "7323"} {
					if strings.Contains(warning, "(pid "+pid+")") {
						t.Fatalf("%s %s flagged pid %s: %s", goos, action, pid, warning)
					}
				}
				if !strings.Contains(warning, "claudecode (pid 7322)") || !strings.Contains(warning, "claudecode (pid 7324)") ||
					result.CoverageComplete {
					t.Fatalf("%s %s missed a childless shim or an old Volta build: %+v", goos, action, result)
				}
			}
		})
	}
}
