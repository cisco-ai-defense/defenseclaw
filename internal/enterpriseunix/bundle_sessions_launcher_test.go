// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// npmCodexProc writes a fake /proc with one npm Codex session (the node
// launcher and its native codex child) started an hour after boot.
func npmCodexProc(t *testing.T, write func(rel, body string), boot int64, extra ...string) {
	t.Helper()
	write("/proc/stat", fmt.Sprintf("cpu 0 0 0 0\nbtime %d\n", boot))
	write("/proc/self/stat", "1 (self) S 0\n")
	proc := func(pid, ppid, comm, cmdline string, ticks int64) {
		write("/proc/"+pid+"/cmdline", cmdline)
		write("/proc/"+pid+"/stat", fmt.Sprintf("%s (%s) S %s %s %s%d 0 0", pid, comm, ppid, pid, strings.Repeat("0 ", 16), ticks))
	}
	proc("3706701", "900", "node", "node\x00/opt/agents/bin/codex\x00", 3600*100)
	proc("3706708", "3706701", "codex", "/opt/agents/lib/node_modules/@openai/codex/vendor/x86_64-unknown-linux-musl/codex/codex\x00", 3600*100+3)
	for i := 0; i+4 < len(extra)+1; i += 4 {
		ticks, _ := strconv.ParseInt(extra[i+3], 10, 64)
		proc(extra[i], extra[i+1], filepath.Base(strings.Split(extra[i+2], "\x00")[0]), extra[i+2], ticks)
	}
}

// GAP-2439 (GitHub #1360): on Linux bundle status counted one npm Codex TUI
// twice, the node launcher and the native codex it starts. The scan now
// reads the parent pid from /proc/<pid>/stat, and the count is one session,
// named by the launcher pid.
func TestBundleSessionsCountAnNpmCodexSessionOnce(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"),
		ConfigFile: writeTempConfig(t, readSampleConfig(t, "linux-standalone.yaml"))}))
	write := func(rel, body string) { t.Helper(); writeHostFile(t, h, rel, body) }
	npmCodexProc(t, write, time.Now().Add(-48*time.Hour).Unix())

	processes, err := h.env.bundleLinuxProcesses(context.Background(), map[string]string{"codex": "codex"})
	if err != nil || len(processes) != 2 {
		t.Fatalf("bundle processes = %+v, %v; want the launcher and its child", processes, err)
	}
	for _, process := range processes {
		if process.PID == 3706708 && process.PPID != 3706701 || process.PID == 3706701 && process.PPID != 900 {
			t.Fatalf("parent pid not read from /proc/<pid>/stat: %+v", processes)
		}
	}
	status := h.env.UnprotectedSessions(context.Background())
	if status.State != "known" || status.Count != 1 || len(status.Entries) != 1 || status.Entries[0].PID != 3706701 || status.Entries[0].Agent != "codex" {
		t.Fatalf("sessions for one npm Codex TUI = %+v, want one codex entry with the launcher pid", status)
	}
}

// The agent_sessions_restart_required scan of status, verify and ensure
// names one pid per session for an agent with a launcher (OpenCode from npm
// here; Codex itself reads its requirements per turn), and keeps the Codex
// background server and another user apart.
func TestAgentSessionsStartedBeforeNameALauncherSessionOnce(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the scan leaves out root sessions; run as a normal user")
	}
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	boot := time.Now().Add(-48 * time.Hour).Unix()
	npmCodexProc(t, write, boot,
		"5001", "900", "node\x00/usr/lib/node_modules/opencode-ai/bin/opencode\x00", "360000",
		"5002", "5001", "/usr/lib/node_modules/opencode-ai/node_modules/opencode-linux-x64/bin/opencode\x00", "360003",
		"5101", "900", "codex\x00app-server\x00--listen\x00stdio://\x00", "360000",
		"5102", "5101", "codex\x00app-server\x00--listen\x00stdio://\x00", "360001")
	env := &Env{Root: root, GOOS: "linux"}
	sessions := env.agentSessionsStartedBefore(context.Background(), time.Now(), -1)
	var pids []int
	for _, session := range sessions {
		pids = append(pids, session.PID)
	}
	got := fmt.Sprint(pids)
	if !strings.Contains(got, "5001") || strings.Contains(got, "5002") {
		t.Fatalf("sessions = %v, want the OpenCode launcher 5001 and not its child 5002", got)
	}
	if !strings.Contains(got, "5101") || !strings.Contains(got, "5102") {
		t.Fatalf("sessions = %v, want both Codex background server processes kept as they were", got)
	}
}

// macOS matches the bundle scan on the process name, which is node for the
// launcher, so only the native codex counts; that stays as it was.
func TestDarwinBundleSessionScanLeavesTheLauncherOut(t *testing.T) {
	h := newTestHost(t, "darwin")
	started := time.Now().Add(-48 * time.Hour).Format("Mon Jan 2 15:04:05 2006")
	ps := strings.Join([]string{"701", "dcm-std1", started, "/opt/homebrew/bin/node"}, " ") + "\n" +
		strings.Join([]string{"702", "dcm-std1", started, "/opt/homebrew/lib/node_modules/@openai/codex/vendor/aarch64-apple-darwin/codex/codex"}, " ") + "\n"
	h.runner.replies = map[string]fakeReply{"ps -axww -o pid=,user=,lstart=,comm=": {result: CommandResult{Stdout: []byte(ps)}}}
	processes, err := h.env.bundleDarwinProcesses(context.Background(), map[string]string{"codex": "codex"})
	if err != nil || len(processes) != 1 || processes[0].PID != 702 {
		t.Fatalf("darwin bundle processes = %+v, %v; want only the native codex 702", processes, err)
	}
}
