// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// clockTicks is USER_HZ, the unit of /proc/<pid>/stat CPU times (100 on
// every Linux the actor images run, gVisor included).
const clockTicks = 100

// procTree is the agent's process tree, from /proc (GAP-0289): the agent,
// every process whose parent is in the tree, and every process of its
// process group. Agents start tools in sessions of their own (Claude Code's
// Bash tool and hooks run under setsid; Codex puts exec-server and MCP
// children in their own groups), so the group alone misses them. A process
// once seen stays in the tree while it lives (its start time tells it from
// a reused PID), so a tool whose parent exits is still counted and stopped.
// gVisor and the microVM kernel both serve /proc/<pid>/stat; a missing io
// file only leaves the I/O out.
type procTree struct {
	proc  string
	root  int
	known map[int]uint64 // pid -> start time
	// rootStart is the agent's start time from the first scan that saw it:
	// a later process that reuses the PID is not the agent (GAP-0303).
	rootStart uint64
}

func newProcTree(root int) *procTree {
	return &procTree{proc: "/proc", root: root, known: map[int]uint64{}}
}

type procStat struct {
	ppid, pgrp int
	start      uint64
	cpu        time.Duration
}

// scan reads every process, rebuilds the tree and returns its live members.
func (t *procTree) scan() map[int]procStat {
	ents, err := os.ReadDir(t.proc)
	if err != nil {
		return nil
	}
	all := map[int]procStat{}
	kids := map[int][]int{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(t.proc, e.Name(), "stat"))
		if err != nil {
			continue
		}
		st, ok := parseProcStat(b)
		if !ok {
			continue
		}
		all[pid] = st
		kids[st.ppid] = append(kids[st.ppid], pid)
	}
	in := map[int]procStat{}
	var queue []int
	add := func(pid int) {
		if _, done := in[pid]; done {
			return
		}
		if st, ok := all[pid]; ok {
			in[pid] = st
			queue = append(queue, pid)
		}
	}
	if st, ok := all[t.root]; ok && (t.rootStart == 0 || st.start == t.rootStart) {
		t.rootStart = st.start
		add(t.root)
	}
	for pid, start := range t.known {
		if st, ok := all[pid]; ok && st.start == start {
			add(pid)
		}
	}
	// The agent's group outlives the agent, but the kernel reuses the PID
	// only once the group is empty: a different process on the agent's PID
	// means the group is someone else's.
	if st, ok := all[t.root]; t.rootStart != 0 && (!ok || st.start == t.rootStart) {
		for pid, st := range all {
			if st.pgrp == t.root {
				add(pid)
			}
		}
	}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		for _, c := range kids[pid] {
			add(c)
		}
	}
	t.known = make(map[int]uint64, len(in))
	for pid, st := range in {
		t.known[pid] = st.start
	}
	return in
}

// usage sums the CPU time and the I/O bytes (rchar + wchar) of the tree.
func (t *procTree) usage() (Usage, bool) {
	in := t.scan()
	if len(in) == 0 {
		return Usage{}, false
	}
	var u Usage
	for pid, st := range in {
		u.CPU += st.cpu
		u.IO += readProcIO(filepath.Join(t.proc, strconv.Itoa(pid), "io"))
	}
	return u, true
}

// signal sends sig to every live process of the tree (a fresh scan, so a
// process started since the last sample is included).
func (t *procTree) signal(sig syscall.Signal) {
	for pid := range t.scan() {
		_ = syscall.Kill(pid, sig)
	}
}

// parseProcStat reads the parent, process group, start time and utime +
// stime of a stat line; the command name in parentheses may hold spaces and
// parentheses.
func parseProcStat(b []byte) (procStat, bool) {
	i := bytes.LastIndexByte(b, ')')
	if i < 0 || i+2 > len(b) {
		return procStat{}, false
	}
	f := strings.Fields(string(b[i+1:]))
	// f[0] state, f[1] ppid, f[2] pgrp, ..., f[11] utime, f[12] stime, ..., f[19] starttime.
	if len(f) < 20 {
		return procStat{}, false
	}
	ppid, err1 := strconv.Atoi(f[1])
	group, err2 := strconv.Atoi(f[2])
	ut, err3 := strconv.ParseUint(f[11], 10, 64)
	st, err4 := strconv.ParseUint(f[12], 10, 64)
	start, err5 := strconv.ParseUint(f[19], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		return procStat{}, false
	}
	return procStat{ppid: ppid, pgrp: group, start: start, cpu: time.Duration(ut+st) * time.Second / clockTicks}, true
}

func readProcIO(path string) uint64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	var n uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok || (k != "rchar" && k != "wchar") {
			continue
		}
		if x, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64); err == nil {
			n += x
		}
	}
	return n
}
