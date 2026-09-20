// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"runtime"
	"time"
)

// CollectRuntimeMetrics takes one point-in-time process snapshot. Scheduling,
// collection policy, and metric delivery belong to the observability-v8 runtime;
// keeping this helper side-effect free lets generated builders call it lazily
// only after at least one capacity family is admitted.
func CollectRuntimeMetrics(startedAt time.Time) RuntimeMetrics {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	uptime := float64(0)
	if !startedAt.IsZero() {
		uptime = time.Since(startedAt).Seconds()
		if uptime < 0 {
			uptime = 0
		}
	}
	return RuntimeMetrics{
		Goroutines:     int64(runtime.NumGoroutine()),
		HeapAllocBytes: int64(ms.HeapAlloc),
		HeapObjects:    int64(ms.HeapObjects),
		GCPauseP99Ns:   gcPauseP99Ns(&ms),
		FDsOpen:        countOpenFDs(),
		UptimeSeconds:  uptime,
	}
}
