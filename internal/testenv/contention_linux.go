// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package testenv

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// schedTimes is the CPU time and the time spent waiting for a CPU of each
// thread of this process, from the kernel's scheduler statistics.
func schedTimes() map[string][2]int64 {
	times := map[string][2]int64{}
	paths, _ := filepath.Glob("/proc/self/task/*/schedstat")
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue // the thread ended
		}
		fields := strings.Fields(string(raw))
		if len(fields) < 2 {
			continue
		}
		ran, errRan := strconv.ParseInt(fields[0], 10, 64)
		waited, errWaited := strconv.ParseInt(fields[1], 10, 64)
		if errRan == nil && errWaited == nil {
			times[path] = [2]int64{ran, waited}
		}
	}
	return times
}

// Contention is the time the host made this process wait for a CPU during a
// test run (GAP-0889): the threads were ready and no CPU was free.
type Contention struct {
	before map[string][2]int64
}

// StartContention starts measuring. A test that bounds a latency adds
// Wait() to the bound, or scales it by Factor(), so a host busy with other
// programs is not read as a slow product. On an idle host both leave the
// bound as it is.
func StartContention() *Contention { return &Contention{before: schedTimes()} }

// sums is the CPU time and the CPU wait of the threads since the start; a
// thread that began during the run counts whole.
func (c *Contention) sums() (ran, waited int64) {
	for path, now := range schedTimes() {
		was := c.before[path]
		ran += now[0] - was[0]
		waited += now[1] - was[1]
	}
	return ran, waited
}

// Wait is the time the threads of this process spent ready and waiting for a
// CPU since StartContention.
func (c *Contention) Wait() time.Duration {
	_, waited := c.sums()
	return time.Duration(max(waited, 0))
}

// Factor is the factor (at least 1) by which the host stretched the CPU time
// the process used since StartContention.
func (c *Contention) Factor() float64 {
	ran, waited := c.sums()
	if ran <= 0 || waited <= 0 {
		return 1
	}
	return 1 + float64(waited)/float64(ran)
}
