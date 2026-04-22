// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"runtime"
	"sort"
)

// gcPauseP99Ns returns an approximate P99 of recent GC pause durations from MemStats.
func gcPauseP99Ns(ms *runtime.MemStats) int64 {
	if ms.NumGC == 0 {
		return 0
	}
	const nbuf = 256
	take := int(ms.NumGC)
	if take > nbuf {
		take = nbuf
	}
	pauses := make([]uint64, 0, take)
	for i := 0; i < take; i++ {
		idx := (int(ms.NumGC) - 1 - i + nbuf) % nbuf
		p := ms.PauseNs[idx]
		if p > 0 {
			pauses = append(pauses, p)
		}
	}
	if len(pauses) == 0 {
		return 0
	}
	sort.Slice(pauses, func(i, j int) bool { return pauses[i] < pauses[j] })
	idx := (len(pauses) * 99) / 100
	if idx >= len(pauses) {
		idx = len(pauses) - 1
	}
	return int64(pauses[idx])
}
