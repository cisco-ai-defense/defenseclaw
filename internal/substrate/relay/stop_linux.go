// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"os"
	"strconv"
	"syscall"
	"time"
)

// stopActorProcesses runs stopAgent (which ends the agent's process group)
// and then ends, by exact PID, every process the agent started: tools in a
// process group or session of their own too (substrate-1 GAP-0358; procTree
// keeps a process it has seen even after its parent exits). As PID 1 of an
// actor it also ends every other process in the actor but itself: a
// daemon that left the agent's tree was re-parented to the relay. It
// returns how many processes it signalled besides the agent's group.
func stopActorProcesses(agentPID int, stopAgent func()) int {
	var tree *procTree
	if agentPID > 0 {
		tree = newProcTree(agentPID)
		tree.scan()
	}
	stopAgent()
	self := os.Getpid()
	seen := map[int]bool{}
	for round := 0; round < 10; round++ {
		var pids []int
		if tree != nil {
			for pid := range tree.scan() {
				pids = append(pids, pid)
			}
		}
		if self == 1 {
			pids = append(pids, otherProcesses(self)...)
		}
		live := 0
		for _, pid := range pids {
			if pid == self || pid <= 1 {
				continue
			}
			if syscall.Kill(pid, syscall.SIGKILL) == nil {
				live++
				seen[pid] = true
			}
		}
		if live == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return len(seen)
}

// otherProcesses lists every process in /proc but self.
func otherProcesses(self int) []int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range ents {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid != self {
			out = append(out, pid)
		}
	}
	return out
}
