// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestManagedLaunchEmptyLinuxProcIsInspectable(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
		ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	h.publishLedger([]byte("ledger\n"))
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		if warning := messagesOf(result.Warnings, "managed_launch_scan_unknown"); warning != "" {
			t.Fatalf("%s treated an empty Linux process table as an unknown scan: %s", action, warning)
		}
		requireOK(t, result)
	}
}

func TestManagedLaunchUnavailableLinuxProcLowersHealth(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
		ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	h.publishLedger([]byte("ledger\n"))
	if err := os.Remove(h.env.P("/proc/stat")); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		if warning := messagesOf(result.Warnings, "managed_launch_scan_unknown"); warning == "" ||
			result.CoverageComplete || result.SecurityComplete {
			t.Fatalf("%s claimed complete coverage without a process scan: %+v", action, result)
		}
		if action == ActionVerify {
			requireError(t, result, "managed_launch_scan_unknown")
		}
	}
}

func TestLinuxDirectoryAgentNormalLaunchUsesNSSHome(t *testing.T) {
	h := newTestHost(t, "linux")
	h.env.ReportLaunchCoverage = func(context.Context, managed.LaunchCoverageReport) error { return nil }
	const uid = 711337
	const home = "/home/alice@example.com"
	h.runner.replies = map[string]fakeReply{
		"getent passwd 711337": {result: CommandResult{Stdout: []byte("alice@example.com:x:711337:711337::" + home + ":/bin/bash\n")}},
	}
	for _, connector := range []string{"opencode", "amp", "devin", "hermes", "antigravity"} {
		t.Run(connector, func(t *testing.T) {
			result := enterprisestatus.New(ActionVerify, managed.ProfileStandalone, "linux", "1.0.4")
			result.CoverageComplete, result.SecurityComplete = true, true
			l := lifecycle{env: h.env, result: result, opts: Options{Action: ActionVerify}}
			agent := connector
			if connector == "antigravity" {
				agent = "agy"
			}
			env := map[string]string{"HOME": home}
			switch connector {
			case "opencode":
				env["OPENCODE_PURE"] = "0"
				env["OPENCODE_CONFIG_DIR"] = home + "/.config/opencode"
			case "hermes":
				env["HERMES_SAFE_MODE"] = "false"
			}
			l.describePluginLaunchSession(context.Background(), agentSession{
				PID: 7133, UID: uid, Agent: agent, Args: []string{agent}, ArgsKnown: true,
				Env: env, EnvKnown: true,
			}, connector)
			if !result.CoverageComplete || !result.SecurityComplete || len(result.Warnings) != 0 || len(result.Errors) != 0 {
				t.Fatalf("normal directory-account launch reported uninspected: %+v", result)
			}
		})
	}
	result := enterprisestatus.New(ActionVerify, managed.ProfileStandalone, "linux", "1.0.4")
	result.CoverageComplete, result.SecurityComplete = true, true
	l := lifecycle{env: h.env, result: result, opts: Options{Action: ActionVerify}}
	l.describePluginLaunchSession(context.Background(), agentSession{PID: 7134, UID: uid, Agent: "opencode",
		Args: []string{"opencode"}, ArgsKnown: true, Env: map[string]string{"HOME": "/tmp/other"}, EnvKnown: true}, "opencode")
	if result.CoverageComplete || result.SecurityComplete || len(result.Errors) != 1 ||
		!strings.Contains(result.Warnings[0].Message, "user config directory was relocated") {
		t.Fatalf("relocated directory-account launch reported healthy: %+v", result)
	}
	delete(h.runner.replies, "getent passwd 711337")
	result = enterprisestatus.New(ActionVerify, managed.ProfileStandalone, "linux", "1.0.4")
	result.CoverageComplete, result.SecurityComplete = true, true
	l.result = result
	l.describePluginLaunchSession(context.Background(), agentSession{PID: 7135, UID: uid, Agent: "opencode",
		Args: []string{"opencode"}, ArgsKnown: true, Env: map[string]string{"HOME": home}, EnvKnown: true}, "opencode")
	if result.CoverageComplete || result.SecurityComplete || len(result.Errors) != 1 ||
		!strings.Contains(result.Warnings[0].Message, "launch environment unverified") {
		t.Fatalf("unresolved directory account reported healthy: %+v", result)
	}
}

func TestDarwinLaunchEnvironmentKeepsOnlyPluginSelectors(t *testing.T) {
	raw := make([]byte, 4)
	binary.LittleEndian.PutUint32(raw, 2)
	raw = append(raw, []byte("/usr/local/bin/opencode\x00\x00opencode\x00--pure\x00OPENCODE_PURE=1\x00OPENCODE_CONFIG_DIR=/tmp/extra\x00KIRO_AGENT_CONFIG_DIR=/tmp/agents\x00API_TOKEN=secret\x00")...)
	env, err := parseProcArgs2Environment(raw)
	if err != nil || env["OPENCODE_PURE"] != "1" || env["KIRO_AGENT_CONFIG_DIR"] != "/tmp/agents" || len(env) != 2 {
		t.Fatalf("plugin selectors = %v, %v", env, err)
	}
	binary.LittleEndian.PutUint32(raw, 1000)
	if _, err := parseProcArgs2Environment(raw); err == nil {
		t.Fatal("accepted truncated process arguments as a known environment")
	}
}

func TestManagedOpenCodePureLaunchLowersStatusAndVerifyOnUnix(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
				ConfigFile: machinePolicyConfig(t, h, "opencode", "hermes")}))
			var audited []managed.LaunchCoverageReport
			h.env.ReportLaunchCoverage = func(_ context.Context, report managed.LaunchCoverageReport) error {
				audited = append(audited, report)
				return nil
			}
			const pid = 7133
			if goos == "linux" {
				writeHostFile(t, h, "/proc/stat", fmt.Sprintf("btime %d\n", time.Now().Unix()))
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/cmdline", pid), "opencode\x00--pure\x00")
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/environ", pid), "HOME=/home/ubuntu\x00")
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/stat", pid),
					fmt.Sprintf("%d (opencode) S 1 %d %s1000 0 0", pid, pid, strings.Repeat("0 ", 16)))
			} else {
				h.runner.ps = fmt.Sprintf("%d %d 00:00:05 opencode --pure", pid, os.Getuid())
				setDarwinProcessArgv(t, func(int) ([]string, error) { return []string{"opencode", "--pure"}, nil })
				previous := darwinProcessEnv
				darwinProcessEnv = func(int) (map[string]string, error) { return map[string]string{}, nil }
				t.Cleanup(func() { darwinProcessEnv = previous })
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				warning := messagesOf(result.Warnings, codeManagedLaunchUninspected)
				if !strings.Contains(warning, "opencode (pid 7133)") || !strings.Contains(warning, "pure mode") ||
					result.CoverageComplete || result.SecurityComplete {
					t.Fatalf("%s %s missed the pure session: coverage=%t security=%t warning=%q", goos, action, result.CoverageComplete, result.SecurityComplete, warning)
				}
				if action == ActionVerify {
					requireError(t, result, codeManagedLaunchUninspected)
				}
			}
			if len(audited) != 2 || audited[0].Connector != "opencode" || audited[0].Reason != "opencode_pure" || audited[0].PID != pid {
				t.Fatalf("launch observations were not audited: %+v", audited)
			}
			if goos == "linux" {
				if err := os.RemoveAll(h.env.P(filepath.Join("/proc", fmt.Sprint(pid)))); err != nil {
					t.Fatal(err)
				}
			} else {
				h.runner.ps = ""
			}
			if warning := messagesOf(h.run(Options{Action: ActionStatus}).Warnings, codeManagedLaunchUninspected); warning != "" {
				t.Fatalf("ended session still reported: %q", warning)
			}
			if goos == "linux" {
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/cmdline", pid), "hermes\x00--safe-mode\x00")
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/environ", pid), "HOME=/home/ubuntu\x00")
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/stat", pid),
					fmt.Sprintf("%d (hermes) S 1 %d %s1000 0 0", pid, pid, strings.Repeat("0 ", 16)))
			} else {
				h.runner.ps = fmt.Sprintf("%d %d 00:00:05 hermes --safe-mode", pid, os.Getuid())
				setDarwinProcessArgv(t, func(int) ([]string, error) { return []string{"hermes", "--safe-mode"}, nil })
			}
			result := h.run(Options{Action: ActionStatus})
			if warning := messagesOf(result.Warnings, codeManagedLaunchUninspected); !strings.Contains(warning, "Hermes safe mode") || result.CoverageComplete || result.SecurityComplete {
				t.Fatalf("%s missed the other connector's bypass: %+v", goos, result)
			}
			if len(audited) != 3 || audited[2].Connector != "hermes" || audited[2].Reason != "hermes_safe_mode" {
				t.Fatalf("other connector's bypass was not audited: %+v", audited)
			}
		})
	}
}

func TestManagedClaudePrivateNPMLaunchIsUnverifiedOnUnix(t *testing.T) {
	home := t.TempDir()
	script := filepath.Join(home, "node_modules", "@anthropic-ai", "claude-code", "cli.js")
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("// fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(script), "package.json"), []byte(`{"name":"@anthropic-ai/claude-code","version":"2.0.77"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := agentCLIOf([]string{"node", script}); got != "claude" {
		t.Fatalf("private npm script classified as %q", got)
	}
	if got := claudeManagedLaunchCoverage([]string{"/home/alice/.local/share/claude/versions/2.0.77"}, ""); got != "claude_version_unverified" {
		t.Fatalf("old native release classified as %q", got)
	}
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
				ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
			var audited []managed.LaunchCoverageReport
			h.env.ReportLaunchCoverage = func(_ context.Context, report managed.LaunchCoverageReport) error {
				audited = append(audited, report)
				return nil
			}
			const pid = 7180
			if goos == "linux" {
				writeHostFile(t, h, "/proc/stat", fmt.Sprintf("btime %d\n", time.Now().Unix()))
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/cmdline", pid), "node\x00"+script+"\x00")
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/stat", pid),
					fmt.Sprintf("%d (node) S 1 %d %s1000 0 0", pid, pid, strings.Repeat("0 ", 16)))
			} else {
				h.runner.ps = fmt.Sprintf("%d %d 00:00:05 node %s", pid, os.Getuid(), script)
				setDarwinProcessArgv(t, func(int) ([]string, error) { return []string{"node", script}, nil })
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				if result.CoverageComplete || result.SecurityComplete ||
					!strings.Contains(messagesOf(result.Warnings, codeManagedLaunchUninspected), "claudecode (pid 7180)") {
					t.Fatalf("%s %s missed private Claude session: %+v", goos, action, result)
				}
			}
			if len(audited) != 2 || audited[0].Connector != "claudecode" || audited[0].Reason != "claude_npm_launch_unverified" {
				t.Fatalf("private Claude launch audit = %+v", audited)
			}
		})
	}
}

func TestManagedClaudeRewrittenInteractiveTitleLowersHealth(t *testing.T) {
	if reason := claudeManagedLaunchCoverage([]string{"claude"}, "/opt/node22/bin/node"); reason != "claude_npm_launch_unverified" {
		t.Fatalf("rewritten Node title = %q", reason)
	}
	if reason := claudeManagedLaunchCoverage([]string{"claude"}, "/opt/node22/bin/node (deleted)"); reason != "claude_npm_launch_unverified" {
		t.Fatalf("rewritten title with deleted Node executable = %q", reason)
	}
	if reason := claudeManagedLaunchCoverage([]string{"claude"}, "/opt/dc-agents/bin/renamed-client"); reason != "launch_arguments_unverified" {
		t.Fatalf("rewritten title with unknown executable = %q", reason)
	}
	if reason := claudeManagedLaunchCoverage([]string{"claude"}, "/home/alice/.local/share/claude/versions/2.1.230"); reason != "" {
		t.Fatalf("supported native executable = %q", reason)
	}
	if reason := claudeManagedLaunchCoverage([]string{"claude"}, "/opt/dc-agents/bin/claude"); reason != "" {
		t.Fatalf("generic native executable = %q", reason)
	}
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
				ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
			h.env.ReportLaunchCoverage = func(context.Context, managed.LaunchCoverageReport) error { return nil }
			const pid = 7182
			if goos == "linux" {
				writeHostFile(t, h, "/proc/stat", fmt.Sprintf("btime %d\n", time.Now().Unix()))
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/cmdline", pid), "claude       \x00")
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/stat", pid),
					fmt.Sprintf("%d (claude) S 1 %d %s1000 0 0", pid, pid, strings.Repeat("0 ", 16)))
				if err := os.Symlink("/opt/node22/bin/node", h.env.P(fmt.Sprintf("/proc/%d/exe", pid))); err != nil {
					t.Fatal(err)
				}
			} else {
				h.runner.ps = fmt.Sprintf("%d %d 00:00:05 claude", pid, os.Getuid())
				setDarwinProcessArgv(t, func(int) ([]string, error) { return []string{"claude       "}, nil })
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				if result.CoverageComplete || result.SecurityComplete ||
					!strings.Contains(messagesOf(result.Warnings, codeManagedLaunchUninspected), "claudecode (pid 7182)") {
					t.Fatalf("%s %s missed rewritten interactive title: %+v", goos, action, result)
				}
				if action == ActionVerify {
					requireError(t, result, codeManagedLaunchUninspected)
				}
			}
		})
	}
}

func TestManagedClaudeSupportedNPMScriptLaunchStaysCovered(t *testing.T) {
	home := t.TempDir()
	packageDir := filepath.Join(home, "lib", "node_modules", "@anthropic-ai", "claude-code")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(packageDir, "cli.js")
	if err := os.WriteFile(script, []byte("// fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{"name":"@anthropic-ai/claude-code","version":"2.1.230"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(home, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(bin, "claude")
	if err := os.Symlink(script, launcher); err != nil {
		t.Fatal(err)
	}
	for _, argv := range [][]string{{"node", script}, {"node", launcher}, {"node", "--no-warnings", launcher}} {
		if reason := claudeManagedLaunchCoverage(argv, ""); reason != "" {
			t.Fatalf("supported npm launch %q reported %q", argv, reason)
		}
	}
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
				ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
			const pid = 7181
			if goos == "linux" {
				writeHostFile(t, h, "/proc/stat", fmt.Sprintf("btime %d\n", time.Now().Unix()))
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/cmdline", pid), "node\x00"+launcher+"\x00")
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/stat", pid),
					fmt.Sprintf("%d (node) S 1 %d %s1000 0 0", pid, pid, strings.Repeat("0 ", 16)))
			} else {
				h.runner.ps = fmt.Sprintf("%d %d 00:00:05 node %s", pid, os.Getuid(), launcher)
				setDarwinProcessArgv(t, func(int) ([]string, error) { return []string{"node", launcher}, nil })
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				if strings.Contains(messagesOf(result.Warnings, codeManagedLaunchUninspected), "claudecode") ||
					strings.Contains(messagesOf(result.Errors, codeManagedLaunchUninspected), "claudecode") {
					t.Fatalf("%s %s flagged supported npm Claude: %+v", goos, action, result)
				}
			}
		})
	}
	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{"name":"other","version":"2.1.230"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if reason := claudeManagedLaunchCoverage([]string{"node", launcher}, ""); reason != "claude_npm_launch_unverified" {
		t.Fatalf("unreadable Claude package metadata reported %q", reason)
	}
	outside := filepath.Join(home, "claimed-package.json")
	if err := os.WriteFile(outside, []byte(`{"name":"@anthropic-ai/claude-code","version":"2.1.230"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(packageDir, "package.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(packageDir, "package.json")); err != nil {
		t.Fatal(err)
	}
	if reason := claudeManagedLaunchCoverage([]string{"node", launcher}, ""); reason != "claude_npm_launch_unverified" {
		t.Fatalf("linked Claude package metadata reported %q", reason)
	}
}

func TestManagedKiroResumePlacementIsUnverifiedOnUnix(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
				ConfigFile: machinePolicyConfig(t, h, "kiro")}))
			var audited []managed.LaunchCoverageReport
			h.env.ReportLaunchCoverage = func(_ context.Context, report managed.LaunchCoverageReport) error {
				audited = append(audited, report)
				return nil
			}
			const pid = 7192
			if goos == "linux" {
				writeHostFile(t, h, "/proc/stat", fmt.Sprintf("btime %d\n", time.Now().Unix()))
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/cmdline", pid), "kiro-cli\x00--resume-id\x00cloud-session-id\x00")
				writeHostFile(t, h, fmt.Sprintf("/proc/%d/stat", pid),
					fmt.Sprintf("%d (kiro-cli) S 1 %d %s1000 0 0", pid, pid, strings.Repeat("0 ", 16)))
			} else {
				h.runner.ps = fmt.Sprintf("%d %d 00:00:05 kiro-cli --resume-id cloud-session-id", pid, os.Getuid())
				setDarwinProcessArgv(t, func(int) ([]string, error) {
					return []string{"kiro-cli", "--resume-id", "cloud-session-id"}, nil
				})
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				warning := messagesOf(result.Warnings, codeManagedLaunchUninspected)
				if result.CoverageComplete || result.SecurityComplete ||
					!strings.Contains(warning, "kiro (pid 7192)") || !strings.Contains(warning, "placement could not be verified") {
					t.Fatalf("%s %s missed Kiro resume: %+v", goos, action, result)
				}
			}
			if len(audited) != 2 || audited[0].Connector != "kiro" ||
				audited[0].Reason != "kiro_resume_placement_unverified" {
				t.Fatalf("Kiro resume coverage audit = %+v", audited)
			}
		})
	}
}
