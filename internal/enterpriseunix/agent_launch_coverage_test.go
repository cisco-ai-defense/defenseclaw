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
