// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"runtime"
	"time"
)

const capacityTickerInterval = 15 * time.Second

func startCapacityBackground(ctx context.Context, p *Provider) {
	if p == nil || !p.Enabled() || p.metrics == nil {
		return
	}
	go runCapacityLoop(ctx, p)
}

func runCapacityLoop(ctx context.Context, p *Provider) {
	t := time.NewTicker(capacityTickerInterval)
	defer t.Stop()

	var ms runtime.MemStats
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			runtime.ReadMemStats(&ms)
			uptime := time.Since(p.startTime).Seconds()
			fd := countOpenFDs()
			rm := RuntimeMetrics{
				Goroutines:     int64(runtime.NumGoroutine()),
				HeapAllocBytes: int64(ms.HeapAlloc),
				HeapObjects:    int64(ms.HeapObjects),
				GCPauseP99Ns:   gcPauseP99Ns(&ms),
				FDsOpen:        fd,
				UptimeSeconds:  uptime,
			}
			p.RecordRuntimeMetrics(ctx, rm)

			if db := registeredAuditDB.Load(); db != nil {
				sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				sh := collectSQLiteHealth(sctx, db)
				cancel()
				p.RecordSQLiteHealth(ctx, sh)
			}
		}
	}
}
