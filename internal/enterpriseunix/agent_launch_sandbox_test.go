// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

func TestLinuxCgroupContainerReadsTheDockerScope(t *testing.T) {
	id := strings.Repeat("ab", 32)
	other := strings.Repeat("cd", 32)
	for _, tc := range []struct{ raw, want string }{
		{"0::/system.slice/docker-" + id + ".scope\n", id},
		{"12:pids:/docker/" + id + "\n0::/docker/" + id + "/init\n", id},
		{"0::/user.slice/user-1000.slice/session-3.scope\n", ""},
		{"0::/system.slice/docker-" + id + ".scope\n1:name=x:/docker/" + other + "\n", ""},
		{"0::/system.slice/docker-" + id[:60] + ".scope\n", ""},
		{"0::/system.slice/notdocker-" + id + ".scope\n", ""},
	} {
		if got := linuxCgroupContainer([]byte(tc.raw)); got != tc.want {
			t.Fatalf("linuxCgroupContainer(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// A Claude Code session that runs inside a sandbox the managed gateway
// registered for the account is covered by the sandbox: verify stays ok
// (GAP-0194). The same process outside a container, in a container of
// another account or sandbox, or in a sandbox whose registration is not live
// is still an uninspected launch.
func TestManagedClaudeInRegisteredSandboxIsNotAnUninspectedLaunch(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
		ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	h.env.ReportLaunchCoverage = func(context.Context, managed.LaunchCoverageReport) error { return nil }
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("the launch check skips root's processes")
	}
	const pid = 7194
	container := strings.Repeat("5e", 32)
	writeHostFile(t, h, "/proc/stat", fmt.Sprintf("btime %d\n", time.Now().Unix()))
	writeHostFile(t, h, fmt.Sprintf("/proc/%d/cmdline", pid), "/usr/local/bin/claude\x00--dangerously-skip-permissions\x00")
	writeHostFile(t, h, fmt.Sprintf("/proc/%d/stat", pid), fmt.Sprintf("%d (claude) S 1 %d %s1000 0 0", pid, pid, strings.Repeat("0 ", 16)))
	if err := os.Symlink("/usr/local/bin/claude", h.env.P(fmt.Sprintf("/proc/%d/exe", pid))); err != nil {
		t.Fatal(err)
	}
	writeHostFile(t, h, "/usr/bin/docker", "#!/bin/sh\n")
	setCgroup := func(raw string) { writeHostFile(t, h, fmt.Sprintf("/proc/%d/cgroup", pid), raw) }
	setLabels := func(labels map[string]string) {
		data, err := json.Marshal(labels)
		if err != nil {
			t.Fatal(err)
		}
		h.runner.replies = map[string]fakeReply{
			"docker container inspect --format {{json .Config.Labels}} " + container: {result: CommandResult{Stdout: data}},
		}
	}
	sandboxLabels := func(sandboxID string, labelUID int) map[string]string {
		return map[string]string{
			openshellLabelManagedBy: openshellManagedBy, openshellLabelSandboxID: sandboxID, openshellLabelSandboxName: "proj-a2c4",
			openshellLabelNamespace: "defenseclaw-managed", "io.defenseclaw.sandbox-image": "1", "io.defenseclaw.uid": fmt.Sprint(labelUID),
		}
	}
	setRegistration := func(state string, seen time.Time) {
		dir := h.env.P(sandboxreg.RegistrationsDir(h.env.Layout.DataDir))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		reg := sandboxreg.Registration{V: sandboxreg.RecordVersion, ID: "reg-" + strings.Repeat("a", sandboxreg.IDRandomChars), UID: uid,
			SandboxID: "sbx-0194", SandboxName: "proj-a2c4", Driver: "docker", State: state, CreatedAt: seen, BoundAt: seen, SeenAt: seen}
		data, err := json.Marshal(map[string]any{"v": 1, "registrations": []sandboxreg.Registration{reg}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d.json", uid)), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	verify := func(name string, wantFlagged bool) {
		t.Helper()
		result := h.run(Options{Action: ActionVerify})
		warning := messagesOf(result.Warnings, codeManagedLaunchUninspected)
		flagged := strings.Contains(warning, fmt.Sprintf("claudecode (pid %d)", pid))
		if flagged != wantFlagged {
			t.Fatalf("%s: flagged=%t, want %t: %+v", name, flagged, wantFlagged, result)
		}
		if wantFlagged {
			requireError(t, result, codeManagedLaunchUninspected)
		} else if messagesOf(result.Errors, codeManagedLaunchUninspected) != "" {
			t.Fatalf("%s: verify failed for a registered sandbox session: %+v", name, result.Errors)
		}
	}

	setCgroup("0::/system.slice/docker-" + container + ".scope\n")
	setLabels(sandboxLabels("sbx-0194", uid))
	setRegistration(sandboxreg.StateLive, time.Now())
	verify("registered live sandbox", false)

	setCgroup("0::/user.slice/user-1000.slice/session-3.scope\n")
	verify("host launch outside any container", true)

	setCgroup("0::/system.slice/docker-" + container + ".scope\n")
	setLabels(sandboxLabels("sbx-other", uid))
	verify("container of an unregistered sandbox", true)

	setLabels(sandboxLabels("sbx-0194", uid+1))
	verify("sandbox image of another account", true)

	labels := sandboxLabels("sbx-0194", uid)
	delete(labels, "io.defenseclaw.sandbox-image")
	setLabels(labels)
	verify("container that does not run a DefenseClaw sandbox image", true)

	setLabels(sandboxLabels("sbx-0194", uid))
	setRegistration(sandboxreg.StateRevoked, time.Now())
	verify("revoked registration", true)

	setRegistration(sandboxreg.StateLive, time.Now().Add(-2*sandboxreg.LiveLease))
	verify("registration whose lease lapsed", true)

	setRegistration(sandboxreg.StateLive, time.Now())
	h.runner.replies = map[string]fakeReply{"docker container inspect --format {{json .Config.Labels}} " + container: {err: fmt.Errorf("docker unavailable")}}
	verify("labels unreadable", true)
}
