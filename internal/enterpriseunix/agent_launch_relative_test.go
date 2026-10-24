// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestAbsoluteExecPathPrefersTheKernelImageForARelativePath(t *testing.T) {
	image := func(path string, err error) func() (string, error) {
		return func() (string, error) { return path, err }
	}
	for _, tc := range []struct {
		name, exec string
		image      func() (string, error)
		want       string
	}{
		{"absolute kept", "/usr/local/bin/claude", func() (string, error) {
			t.Error("an absolute exec path asked for the image path")
			return "", nil
		}, "/usr/local/bin/claude"},
		{"dot relative", "./claude", image("/Users/alice/.local/share/claude/versions/2.1.230", nil), "/Users/alice/.local/share/claude/versions/2.1.230"},
		{"relative PATH entry", "bin/claude", image("/opt/tools/lib/../bin/claude.exe", nil), "/opt/tools/bin/claude.exe"},
		{"unreadable exec path", "", image("/opt/claude", nil), "/opt/claude"},
		{"image unavailable", "./claude", image("", errors.New("no such process")), "./claude"},
		{"relative image", "./claude", image("claude", nil), "./claude"},
	} {
		if got := absoluteExecPath(tc.exec, tc.image); got != tc.want {
			t.Errorf("%s: absoluteExecPath(%q) = %q, want %q", tc.name, tc.exec, got, tc.want)
		}
	}
}

// A supported Claude Code launched as ./claude (or through a relative PATH
// entry) on macOS has a relative exec path: the kernel's image path
// identifies the build, so healthy verify passes, and an old build or an
// image that cannot be read is still reported.
func TestManagedClaudeRelativeMacOSLaunchUsesTheKernelImage(t *testing.T) {
	root := t.TempDir()
	npmExe, _ := claudeNPMNativeBuild(t, filepath.Join(root, "usr"), "2.1.230")
	native := writeClaudeBuildFile(t, filepath.Join(root, "home", "alice", ".local", "share", "claude", "versions", "2.1.230"), "native")
	cask := writeClaudeBuildFile(t, filepath.Join(root, "opt", "homebrew", "Caskroom", "claude-code", "2.1.230", "claude"), "native")
	oldExe, _ := claudeNPMNativeBuild(t, filepath.Join(root, "home", "alice", ".npm-global"), "2.1.130")
	images := map[int]string{7320: npmExe, 7321: native, 7322: cask, 7323: oldExe}
	healthy := []claudeTestProcess{
		{pid: 7320, ppid: 1, argv: []string{"claude"}, exe: "./claude"},
		{pid: 7321, ppid: 1, argv: []string{"./claude", "--resume"}, exe: "../share/claude/versions/2.1.230"},
		{pid: 7322, ppid: 1, argv: []string{"claude"}, exe: "bin/claude"},
	}
	run := func(processes []claudeTestProcess) (*testHost, *[]managed.LaunchCoverageReport) {
		h := newTestHost(t, "darwin")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
			ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
		h.publishLedger([]byte("ledger\n"))
		audited := &[]managed.LaunchCoverageReport{}
		h.env.ReportLaunchCoverage = func(_ context.Context, report managed.LaunchCoverageReport) error {
			*audited = append(*audited, report)
			return nil
		}
		runClaudeTestProcesses(t, h, "darwin", processes)
		h.env.ProcessImagePath = func(pid int) (string, error) {
			if image, ok := images[pid]; ok {
				return image, nil
			}
			return "", fmt.Errorf("no image for pid %d", pid)
		}
		return h, audited
	}

	h, audited := run(healthy)
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		if warning := messagesOf(result.Warnings, codeManagedLaunchUninspected); warning != "" {
			t.Fatalf("%s flagged a relatively launched supported build: %s", action, warning)
		}
		requireOK(t, result)
		// Security stays incomplete for reasons this test does not cover:
		// the fake sessions predate activation (agent_sessions_restart_required)
		// and a Claude Code hook process can fail open (hook_process_fail_open).
		if !result.CoverageComplete {
			t.Fatalf("%s lowered coverage for a relative launch: %+v", action, result)
		}
	}
	if len(*audited) != 0 {
		t.Fatalf("relative supported launches were audited: %+v", *audited)
	}

	h, audited = run(append(healthy,
		claudeTestProcess{pid: 7323, ppid: 1, argv: []string{"claude"}, exe: "./claude"},
		claudeTestProcess{pid: 7324, ppid: 1, argv: []string{"claude"}, exe: "./claude"}))
	result := h.run(Options{Action: ActionVerify})
	warning := messagesOf(result.Warnings, codeManagedLaunchUninspected)
	if result.CoverageComplete || result.SecurityComplete || !strings.Contains(warning, "claudecode (pid 7323)") ||
		!strings.Contains(warning, "claudecode (pid 7324)") {
		t.Fatalf("an old or unidentified relative launch was missed: %+v", result)
	}
	requireError(t, result, codeManagedLaunchUninspected)
	var reasons []string
	for _, report := range *audited {
		reasons = append(reasons, fmt.Sprintf("%d:%s", report.PID, report.Reason))
	}
	sort.Strings(reasons)
	if want := "7323:claude_version_unverified 7324:launch_arguments_unverified"; strings.Join(reasons, " ") != want {
		t.Fatalf("audit = %v, want %s", reasons, want)
	}
}
