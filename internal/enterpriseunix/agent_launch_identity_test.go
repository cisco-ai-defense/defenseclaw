// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func writeClaudeBuildFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func linkClaudeBuild(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return link
}

// claudeNPMNativeBuild lays out an npm global install of a native Claude Code
// release: bin/claude links to the package's bin/claude.exe (the native
// binary its postinstall placed), as in every release from the contract
// floor on.
func claudeNPMNativeBuild(t *testing.T, prefix, version string) (exe, link string) {
	t.Helper()
	pkg := filepath.Join(prefix, "lib", "node_modules", "@anthropic-ai", "claude-code")
	writeClaudeBuildFile(t, filepath.Join(pkg, "package.json"), fmt.Sprintf(`{"name":"@anthropic-ai/claude-code","version":%q,"bin":{"claude":"bin/claude.exe"}}`, version))
	exe = writeClaudeBuildFile(t, filepath.Join(pkg, "bin", "claude.exe"), "native")
	return exe, linkClaudeBuild(t, exe, filepath.Join(prefix, "bin", "claude"))
}

// claudePlatformBuild lays out the platform package the npm fallback wrapper
// (cli-wrapper.cjs) starts when postinstall did not place bin/claude.exe.
func claudePlatformBuild(t *testing.T, prefix, platform, packageName, version string) string {
	t.Helper()
	pkg := filepath.Join(prefix, "lib", "node_modules", "@anthropic-ai", "claude-code-"+platform)
	writeClaudeBuildFile(t, filepath.Join(pkg, "package.json"), fmt.Sprintf(`{"name":%q,"version":%q}`, packageName, version))
	return writeClaudeBuildFile(t, filepath.Join(pkg, "claude"), "native")
}

func TestManagedClaudeIdentifiesRunningBuildByExecutable(t *testing.T) {
	root := t.TempDir()
	npmExe, npmLink := claudeNPMNativeBuild(t, filepath.Join(root, "usr"), "2.1.230")
	oldNPMExe, _ := claudeNPMNativeBuild(t, filepath.Join(root, "home", "alice", ".npm-global"), "2.1.130")
	platform := claudePlatformBuild(t, filepath.Join(root, "wrap"), "linux-x64", "@anthropic-ai/claude-code-linux-x64", "2.1.230")
	oldPlatform := claudePlatformBuild(t, filepath.Join(root, "wrap-old"), "linux-x64", "@anthropic-ai/claude-code-linux-x64", "2.1.130")
	misnamedPlatform := claudePlatformBuild(t, filepath.Join(root, "wrap-other"), "linux-arm64", "@anthropic-ai/claude-code", "2.1.230")
	versions := filepath.Join(root, "home", "alice", ".local", "share", "claude", "versions")
	native := writeClaudeBuildFile(t, filepath.Join(versions, "2.1.230"), "native")
	nativeLink := linkClaudeBuild(t, native, filepath.Join(root, "home", "alice", ".local", "bin", "claude"))
	nativeOld := writeClaudeBuildFile(t, filepath.Join(versions, "2.0.77"), "native")
	nativeBelowFloor := writeClaudeBuildFile(t, filepath.Join(versions, "2.1.130"), "native")
	cask := writeClaudeBuildFile(t, filepath.Join(root, "opt", "homebrew", "Caskroom", "claude-code", "2.1.230", "claude"), "native")
	caskLink := linkClaudeBuild(t, cask, filepath.Join(root, "opt", "homebrew", "bin", "claude"))
	caskOld := writeClaudeBuildFile(t, filepath.Join(root, "opt", "homebrew", "Caskroom", "claude-code", "2.1.100", "claude"), "native")
	copied := writeClaudeBuildFile(t, filepath.Join(root, "opt", "tools", "claude"), "native")
	renamed := writeClaudeBuildFile(t, filepath.Join(root, "opt", "tools", "renamed-client"), "native")
	oldScript := writeClaudeBuildFile(t, filepath.Join(root, "home", "alice", "tools", "node_modules", "@anthropic-ai", "claude-code", "cli.js"), "// script")
	writeClaudeBuildFile(t, filepath.Join(filepath.Dir(oldScript), "package.json"), `{"name":"@anthropic-ai/claude-code","version":"2.0.77"}`)
	const npmUnverified, versionUnverified, argsUnverified = "claude_npm_launch_unverified", "claude_version_unverified", "launch_arguments_unverified"
	for _, tc := range []struct {
		name string
		argv []string
		exe  string
		want string
	}{
		{"npm native build, interactive title", []string{"claude"}, npmExe, ""},
		{"npm native build, padded title", []string{"claude       "}, npmExe, ""},
		{"npm native build, bin path and flags", []string{filepath.Join(root, "usr", "bin", "claude"), "--resume"}, npmExe, ""},
		{"npm native build through the macOS exec-path link", []string{"claude"}, npmLink, ""},
		{"npm native build below the floor", []string{"claude"}, oldNPMExe, versionUnverified},
		{"npm native build replaced by an upgrade", []string{"claude"}, npmExe + " (deleted)", versionUnverified},
		{"npm fallback wrapper child", []string{platform}, platform, ""},
		{"npm platform package below the floor", []string{oldPlatform}, oldPlatform, versionUnverified},
		{"npm platform package with another package's metadata", []string{misnamedPlatform}, misnamedPlatform, versionUnverified},
		{"native installer build", []string{"claude"}, native, ""},
		{"native installer link", []string{"claude"}, nativeLink, ""},
		{"native installer build replaced by an update", []string{"claude"}, native + " (deleted)", ""},
		{"old native installer build", []string{"claude"}, nativeOld, versionUnverified},
		{"native installer build below the floor", []string{"claude"}, nativeBelowFloor, versionUnverified},
		{"homebrew cask", []string{"claude"}, cask, ""},
		{"homebrew cask link", []string{"claude"}, caskLink, ""},
		{"old homebrew cask", []string{"claude"}, caskOld, versionUnverified},
		{"copied binary", []string{"claude"}, copied, versionUnverified},
		{"renamed binary", []string{"claude"}, renamed, versionUnverified},
		{"argv names a supported build, the kernel runs an old one", []string{native}, nativeOld, versionUnverified},
		{"argv names an old script, the kernel runs a supported build", []string{"node", oldScript}, native, ""},
		{"Node with a hidden script", []string{"claude"}, "/opt/node22/bin/node", npmUnverified},
		{"replaced Node with a hidden script", []string{"claude"}, "/opt/node22/bin/node (deleted)", npmUnverified},
		{"Node with a visible old script", []string{"node", oldScript}, "/opt/node22/bin/node", npmUnverified},
		{"Bun with a hidden script", []string{"claude"}, "/home/alice/.bun/bin/bun", npmUnverified},
		{"unreadable executable", []string{"claude"}, "", argsUnverified},
		{"relative exec path", []string{"claude"}, "claude", argsUnverified},
		{"unreadable executable, visible old script", []string{"node", oldScript}, "", npmUnverified},
	} {
		if got := claudeManagedLaunchCoverage(tc.argv, tc.exe); got != tc.want {
			t.Errorf("%s: argv %q executable %q = %q, want %q", tc.name, tc.argv, tc.exe, got, tc.want)
		}
	}
}

type claudeTestProcess struct {
	pid, ppid int
	argv      []string
	exe       string
}

// runClaudeTestProcesses publishes processes in the host's process table:
// /proc on Linux; ps, kern.procargs2 and the exec path on macOS.
func runClaudeTestProcesses(t *testing.T, h *testHost, goos string, processes []claudeTestProcess) {
	t.Helper()
	if goos == "linux" {
		writeHostFile(t, h, "/proc/stat", fmt.Sprintf("btime %d\n", time.Now().Unix()))
		for _, p := range processes {
			writeHostFile(t, h, fmt.Sprintf("/proc/%d/cmdline", p.pid), strings.Join(p.argv, "\x00")+"\x00")
			writeHostFile(t, h, fmt.Sprintf("/proc/%d/stat", p.pid),
				fmt.Sprintf("%d (claude) S %d %d %s1000 0 0", p.pid, p.ppid, p.pid, strings.Repeat("0 ", 16)))
			if err := os.Symlink(p.exe, h.env.P(fmt.Sprintf("/proc/%d/exe", p.pid))); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	byPID := map[int]claudeTestProcess{}
	var lines []string
	for _, p := range processes {
		byPID[p.pid] = p
		lines = append(lines, fmt.Sprintf("%d %d 00:00:05 %s", p.pid, os.Getuid(), strings.Join(p.argv, " ")))
	}
	h.runner.ps = strings.Join(lines, "\n")
	setDarwinProcessArgv(t, func(pid int) ([]string, error) {
		if p, ok := byPID[pid]; ok {
			return p.argv, nil
		}
		return nil, fmt.Errorf("no process %d", pid)
	})
	h.env.ProcessExecPath = func(pid int) (string, error) {
		if p, ok := byPID[pid]; ok {
			return p.exe, nil
		}
		return "", fmt.Errorf("no process %d", pid)
	}
}

func TestManagedClaudeHealthyInstallsPassVerifyAndOldCopiesAreReported(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			root := t.TempDir()
			npmExe, npmLink := claudeNPMNativeBuild(t, filepath.Join(root, "usr"), "2.1.230")
			native := writeClaudeBuildFile(t, filepath.Join(root, "home", "alice", ".local", "share", "claude", "versions", "2.1.230"), "native")
			nativeLink := linkClaudeBuild(t, native, filepath.Join(root, "home", "alice", ".local", "bin", "claude"))
			cask := writeClaudeBuildFile(t, filepath.Join(root, "opt", "homebrew", "Caskroom", "claude-code", "2.1.230", "claude"), "native")
			platform := claudePlatformBuild(t, filepath.Join(root, "wrap"), goos+"-x64", "@anthropic-ai/claude-code-"+goos+"-x64", "2.1.230")
			oldNPMExe, _ := claudeNPMNativeBuild(t, filepath.Join(root, "home", "alice", ".npm-global"), "2.1.130")
			copied := writeClaudeBuildFile(t, filepath.Join(root, "opt", "tools", "claude"), "native")
			// The kernel path: Linux /proc/<pid>/exe is resolved, the macOS
			// exec path is the link the shell ran.
			npmPath, nativePath := npmExe, native
			if goos == "darwin" {
				npmPath, nativePath = npmLink, nativeLink
			}
			healthy := []claudeTestProcess{
				{pid: 7300, ppid: 1, argv: []string{"claude"}, exe: npmPath},
				{pid: 7301, ppid: 1, argv: []string{"claude", "--resume"}, exe: nativePath},
				{pid: 7302, ppid: 1, argv: []string{"claude       "}, exe: cask},
				{pid: 7303, ppid: 1, argv: []string{platform}, exe: platform},
			}
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
				ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
			h.publishLedger([]byte("ledger\n"))
			var audited []managed.LaunchCoverageReport
			h.env.ReportLaunchCoverage = func(_ context.Context, report managed.LaunchCoverageReport) error {
				audited = append(audited, report)
				return nil
			}
			runClaudeTestProcesses(t, h, goos, healthy)
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				if warning := messagesOf(result.Warnings, codeManagedLaunchUninspected); warning != "" {
					t.Fatalf("%s %s flagged a supported Claude Code build: %s", goos, action, warning)
				}
				requireOK(t, result)
				if !result.CoverageComplete || !result.SecurityComplete {
					t.Fatalf("%s %s lowered health for supported builds: %+v", goos, action, result)
				}
			}
			if len(audited) != 0 {
				t.Fatalf("%s audited supported builds: %+v", goos, audited)
			}

			h2 := newTestHost(t, goos)
			requireOK(t, h2.run(Options{Action: ActionInstall, PayloadDir: h2.payload("1.0.4"),
				ConfigFile: machinePolicyConfig(t, h2, "claudecode")}))
			h2.publishLedger([]byte("ledger\n"))
			audited = nil
			h2.env.ReportLaunchCoverage = func(_ context.Context, report managed.LaunchCoverageReport) error {
				audited = append(audited, report)
				return nil
			}
			runClaudeTestProcesses(t, h2, goos, append(healthy,
				claudeTestProcess{pid: 7304, ppid: 1, argv: []string{"claude"}, exe: oldNPMExe},
				claudeTestProcess{pid: 7305, ppid: 1, argv: []string{"claude"}, exe: copied}))
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h2.run(Options{Action: action})
				warning := messagesOf(result.Warnings, codeManagedLaunchUninspected)
				if result.CoverageComplete || result.SecurityComplete ||
					!strings.Contains(warning, "claudecode (pid 7304)") || !strings.Contains(warning, "claudecode (pid 7305)") {
					t.Fatalf("%s %s missed an old or unidentified Claude Code copy: %+v", goos, action, result)
				}
				for _, pid := range []string{"7300", "7301", "7302", "7303"} {
					if strings.Contains(warning, "(pid "+pid+")") {
						t.Fatalf("%s %s flagged supported pid %s: %s", goos, action, pid, warning)
					}
				}
				if action == ActionVerify {
					requireError(t, result, codeManagedLaunchUninspected)
				}
			}
			var reasons []string
			for _, report := range audited {
				reasons = append(reasons, fmt.Sprintf("%d:%s", report.PID, report.Reason))
			}
			sort.Strings(reasons)
			if want := "7304:claude_version_unverified 7304:claude_version_unverified 7305:claude_version_unverified 7305:claude_version_unverified"; strings.Join(reasons, " ") != want {
				t.Fatalf("%s audit = %v, want %s", goos, reasons, want)
			}
		})
	}
}

// Volta's shim stays resident as "claude" and waits for the build it starts.
func TestManagedClaudeVoltaShimOnLinux(t *testing.T) {
	root := t.TempDir()
	shim := writeClaudeBuildFile(t, filepath.Join(root, "home", "alice", ".volta", "bin", "volta-shim"), "shim")
	image := filepath.Join(root, "home", "alice", ".volta", "tools", "image", "packages", "@anthropic-ai", "claude-code")
	imageExe, imageBin := claudeNPMNativeBuild(t, image, "2.1.230")
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
		ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	h.publishLedger([]byte("ledger\n"))
	h.env.ReportLaunchCoverage = func(context.Context, managed.LaunchCoverageReport) error { return nil }
	runClaudeTestProcesses(t, h, "linux", []claudeTestProcess{
		{pid: 7310, ppid: 1, argv: []string{"claude"}, exe: shim},
		{pid: 7311, ppid: 7310, argv: []string{imageBin}, exe: imageExe},
	})
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		if warning := messagesOf(result.Warnings, codeManagedLaunchUninspected); warning != "" {
			t.Fatalf("%s flagged a Volta-launched supported build: %s", action, warning)
		}
		requireOK(t, result)
	}
}
