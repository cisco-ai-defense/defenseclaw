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

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func TestDarwinBundleSessionScanFromFakeProcessLister(t *testing.T) {
	const command = "ps -axww -o pid=,user=,lstart=,comm="
	runner := &fakeRunner{replies: map[string]fakeReply{
		command: {result: CommandResult{Stdout: []byte("8664 dcw-std1 Tue Oct 13 06:00:00 2026 /usr/local/bin/claude\n")}},
	}}
	env := &Env{Runner: runner}
	processes, err := env.bundleDarwinProcesses(context.Background(), map[string]string{"claude": "claudecode"})
	if err != nil {
		t.Fatal(err)
	}
	changed := time.Date(2026, 10, 13, 7, 0, 0, 0, time.Local)
	status := enterprisestatus.ScanSessions(func() ([]enterprisestatus.SessionProcess, error) { return processes, nil }, map[string]time.Time{"claudecode": changed}, true)
	if status.State != "known" || status.Count != 1 || status.Entries[0].PID != 8664 || status.Entries[0].User != "dcw-std1" {
		t.Fatalf("macOS old Claude session = %+v", status)
	}
}

// TestDarwinBundleSessionScanLauncherNotCounted verifies that on macOS a node
// launcher line in ps output is ignored while the native codex binary is
// counted once.
func TestDarwinBundleSessionScanLauncherNotCounted(t *testing.T) {
	const command = "ps -axww -o pid=,user=,lstart=,comm="
	out := strings.Join([]string{
		"3706701 dcw-std1 Tue Oct 13 06:00:00 2026 /usr/local/bin/node",
		"3706708 dcw-std1 Tue Oct 13 06:00:01 2026 /opt/agents/vendor/aarch64-apple-darwin/codex/codex",
	}, "\n") + "\n"
	runner := &fakeRunner{replies: map[string]fakeReply{
		command: {result: CommandResult{Stdout: []byte(out)}},
	}}
	env := &Env{Runner: runner}
	processes, err := env.bundleDarwinProcesses(context.Background(), map[string]string{"codex": "codex"})
	if err != nil {
		t.Fatal(err)
	}
	changed := time.Date(2026, 10, 13, 7, 0, 0, 0, time.Local)
	status := enterprisestatus.ScanSessions(func() ([]enterprisestatus.SessionProcess, error) { return processes, nil }, map[string]time.Time{"codex": changed}, true)
	if status.State != "known" || status.Count != 1 || len(status.Entries) != 1 || status.Entries[0].PID != 3706708 {
		t.Fatalf("macOS npm Codex session = %+v, want count 1", status)
	}
}

// TestBundleLinuxProcessesReadsParentPID verifies that bundleLinuxProcesses
// parses the parent PID and script-host launcher flag from /proc/<pid>/stat
// and /proc/<pid>/cmdline.
func TestBundleLinuxProcessesReadsParentPID(t *testing.T) {
	h := newTestHost(t, "linux")
	boot := time.Date(2026, 10, 21, 20, 0, 0, 0, time.UTC).Unix()
	writeHostFile(t, h, "/proc/stat", fmt.Sprintf("cpu 0 0 0 0\nbtime %d\n", boot))
	writeProc := func(pid, ppid, cmdline string, ticks int64) {
		writeHostFile(t, h, "/proc/"+pid+"/cmdline", cmdline)
		writeHostFile(t, h, "/proc/"+pid+"/stat", fmt.Sprintf("%s (codex) S %s %s %s%d 0 0", pid, ppid, pid, strings.Repeat("0 ", 16), ticks))
	}
	writeProc("3706701", "1900", "node\x00/opt/agents/bin/codex\x00", 60*100)
	writeProc("3706708", "3706701", "/opt/agents/lib/node_modules/@openai/codex/vendor/x86_64-unknown-linux-musl/codex/codex\x00", 60*100+3)

	processes, err := h.env.bundleLinuxProcesses(context.Background(), map[string]string{"codex": "codex"})
	if err != nil {
		t.Fatal(err)
	}
	byPID := map[int]enterprisestatus.SessionProcess{}
	for _, p := range processes {
		byPID[p.PID] = p
	}
	if byPID[3706701].PPID != 1900 || !byPID[3706701].Launcher || byPID[3706708].PPID != 3706701 || byPID[3706708].Launcher {
		t.Fatalf("processes = %+v, want PPIDs 1900 (launcher) and 3706701 (native child)", processes)
	}
}

// TestBundleSessionsCountNpmCodexOnce verifies end to end that an npm-launched
// Codex session on Linux is counted once under the parent PID and clears to 0
// when restarted.
func TestBundleSessionsCountNpmCodexOnce(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{
		Action:     ActionInstall,
		PayloadDir: h.payload("1.0.0"),
		ConfigFile: writeTempConfig(t, readSampleConfig(t, "linux-standalone.yaml")),
	}))
	applied := time.Now().UTC().Add(-time.Hour)
	state, _ := json.Marshal(enterprisestatus.PolicyStateRecord{AppliedAt: applied.Format(time.RFC3339Nano)})
	writeHostFile(t, h, filepath.Join(h.env.Layout.LifecycleDir, enterprisestatus.PolicyStateFileName), string(state))
	// Ensure managed settings files are not newer than the test's applied time,
	// or set the process start time before both.
	boot := applied.Add(-2 * time.Hour).Unix()
	writeHostFile(t, h, "/proc/stat", fmt.Sprintf("cpu 0 0 0 0\nbtime %d\n", boot))
	writeProc := func(pid, ppid, cmdline string, ticks int64) {
		writeHostFile(t, h, "/proc/"+pid+"/cmdline", cmdline)
		writeHostFile(t, h, "/proc/"+pid+"/stat", fmt.Sprintf("%s (codex) S %s %s %s%d 0 0", pid, ppid, pid, strings.Repeat("0 ", 16), ticks))
	}
	writeProc("3706701", "1900", "node\x00/opt/agents/bin/codex\x00", 60*100)
	writeProc("3706708", "3706701", "/opt/agents/lib/node_modules/@openai/codex/vendor/x86_64-unknown-linux-musl/codex/codex\x00", 60*100+3)

	status := h.env.UnprotectedSessions(context.Background())
	if status.State != "known" || status.Count != 1 || len(status.Entries) != 1 || status.Entries[0].PID != 3706701 {
		t.Fatalf("UnprotectedSessions = %+v, want count 1 with launcher pid 3706701", status)
	}
	// Restarting the session clears the count to 0.
	if err := os.RemoveAll(h.env.P("/proc/3706701")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(h.env.P("/proc/3706708")); err != nil {
		t.Fatal(err)
	}
	after := h.env.UnprotectedSessions(context.Background())
	if after.State != "known" || after.Count != 0 || len(after.Entries) != 0 {
		t.Fatalf("after restart UnprotectedSessions = %+v, want count 0", after)
	}
}

// TestLinuxAgentSessionsCollapsesLauncherPair verifies that linuxAgentSessions
// collapses a script-host launcher and its native child into the parent PID
// while keeping independent native-agent sessions separate.
func TestLinuxAgentSessionsCollapsesLauncherPair(t *testing.T) {
	h := newTestHost(t, "linux")
	boot := time.Date(2026, 10, 21, 20, 0, 0, 0, time.UTC).Unix()
	writeHostFile(t, h, "/proc/stat", fmt.Sprintf("cpu 0 0 0 0\nbtime %d\n", boot))
	writeProc := func(pid, ppid, cmdline string, ticks int64) {
		writeHostFile(t, h, "/proc/"+pid+"/cmdline", cmdline)
		writeHostFile(t, h, "/proc/"+pid+"/stat", fmt.Sprintf("%s (cursor-agent) S %s %s %s%d 0 0", pid, ppid, pid, strings.Repeat("0 ", 16), ticks))
	}
	writeProc("7001", "1000", "node\x00/opt/agents/bin/cursor-agent\x00", 60*100)
	writeProc("7002", "7001", "/opt/agents/vendor/cursor-agent\x00", 60*100+5)

	sessions := h.env.linuxAgentSessions()
	if len(sessions) != 1 || sessions[0].PID != 7001 || sessions[0].Agent != "cursor-agent" {
		t.Fatalf("linuxAgentSessions = %+v, want single parent session pid 7001", sessions)
	}

	writeProc("8001", "1000", "/opt/agents/vendor/cursor-agent\x00", 60*100+10)
	writeProc("8002", "8001", "/opt/agents/vendor/cursor-agent\x00", 60*100+15)
	sessionsWithNativePair := h.env.linuxAgentSessions()
	if len(sessionsWithNativePair) != 3 || sessionsWithNativePair[0].PID != 7001 || sessionsWithNativePair[1].PID != 8001 || sessionsWithNativePair[2].PID != 8002 {
		t.Fatalf("linuxAgentSessions with native parent/child = %+v, want pids 7001, 8001, and 8002", sessionsWithNativePair)
	}
}
