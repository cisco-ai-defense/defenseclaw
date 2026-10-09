//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

type fakeProc struct {
	pid, ppid int
	uid, euid int
	comm      string
	exe, cwd  string
	cmdline   []string
	ns        string
	ticks     uint64
}

// writeProc lays out one /proc/<pid> directory.
func writeProc(t *testing.T, root string, p fakeProc) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(p.pid))
	if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	status := fmt.Sprintf("Name:\t%s\nUmask:\t0022\nUid:\t%d\t%d\t%d\t%d\nGid:\t1\t1\t1\t1\n", p.comm, p.uid, p.euid, p.euid, p.euid)
	stat := fmt.Sprintf("%d (%s) S %d %d %d 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 1 0 %d 1000 100 18446744073709551615\n",
		p.pid, p.comm, p.ppid, p.pid, p.pid, p.ticks)
	cmd := ""
	for _, a := range p.cmdline {
		cmd += a + "\x00"
	}
	for name, content := range map[string]string{"status": status, "stat": stat, "cmdline": cmd} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"exe": p.exe, "cwd": p.cwd, "ns/pid": p.ns} {
		if target == "" {
			continue
		}
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScanProcsReadsEnrolledUsersInFull(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "self", "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("pid:[4026531836]", filepath.Join(root, "self", "ns", "pid")); err != nil {
		t.Fatal(err)
	}
	writeProc(t, root, fakeProc{pid: 4001, ppid: 1, uid: 1001, euid: 1001, comm: "claude (x)", ticks: 777,
		exe: aliceClaudeNew + " (deleted)", cwd: "/home/alice/work", cmdline: []string{aliceClaudeNew, "--flag"}, ns: "pid:[4026531836]"})
	writeProc(t, root, fakeProc{pid: 4002, ppid: 4001, uid: 1001, euid: 1001, comm: "bash", ticks: 778,
		exe: "/usr/bin/bash", cmdline: []string{"bash", "-c", "true"}, ns: "pid:[4026532999]"}) // a container
	writeProc(t, root, fakeProc{pid: 7001, ppid: 1, uid: 1999, euid: 1999, comm: "claude", ticks: 1,
		exe: "/usr/local/bin/claude", cmdline: []string{"claude"}, ns: "pid:[4026531836]"}) // not enrolled, an agent by name
	writeProc(t, root, fakeProc{pid: 7002, ppid: 1, uid: 1999, euid: 1999, comm: "vim", ticks: 2,
		exe: "/usr/bin/vim", cmdline: []string{"vim"}, ns: "pid:[4026531836]"}) // not enrolled, nothing to say
	if err := os.WriteFile(filepath.Join(root, "cpuinfo"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "9999"), 0o755); err != nil { // vanished mid-scan: no status
		t.Fatal(err)
	}
	procs, err := ScanProcs(root, func(uid int) bool { return uid == 1001 })
	if err != nil {
		t.Fatal(err)
	}
	byPID := map[int]Proc{}
	for _, p := range procs {
		byPID[p.PID] = p
	}
	if len(procs) != 3 || byPID[7002].PID != 0 {
		t.Fatalf("procs = %+v", procs)
	}
	claude := byPID[4001]
	if claude.Exe != aliceClaudeNew || claude.Cwd != "/home/alice/work" || claude.StartTicks != 777 || claude.PPID != 1 ||
		claude.Comm != "claude (x)" || len(claude.Cmdline) != 2 || !claude.Host || claude.UID != 1001 {
		t.Fatalf("claude = %+v", claude)
	}
	if byPID[4002].Host {
		t.Fatal("a process in another pid namespace must not be a host process")
	}
	if stranger := byPID[7001]; stranger.Exe != "" || len(stranger.Cmdline) != 0 || stranger.Comm != "claude" {
		t.Fatalf("a user who is not enrolled is read as far as the name: %+v", stranger)
	}
}

func TestScanProcsOfTheRealProc(t *testing.T) {
	procs, err := ScanProcs("/proc", func(uid int) bool { return uid == os.Getuid() })
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range procs {
		if p.PID == os.Getpid() {
			if p.Exe == "" || !p.Host || p.StartTicks == 0 || len(p.Cmdline) == 0 {
				t.Fatalf("own process = %+v", p)
			}
			return
		}
	}
	t.Fatal("the test process was not found in /proc")
}
