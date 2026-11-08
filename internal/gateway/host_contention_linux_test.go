// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// startContention starts measuring how much the host made this process wait
// for a CPU, and returns the function that ends it: the factor (at least 1)
// by which the host stretched the CPU time the process used, from the same
// run (GAP-0859). A test that bounds a latency under load scales its bound
// by it, so a host busy with other programs is not read as a slow product.
func startContention() func() float64 {
	before := schedTimes()
	return func() float64 {
		var ran, waited int64
		for path, now := range schedTimes() {
			was := before[path] // a thread that began during the run counts whole
			ran += now[0] - was[0]
			waited += now[1] - was[1]
		}
		if ran <= 0 || waited <= 0 {
			return 1
		}
		return 1 + float64(waited)/float64(ran)
	}
}
