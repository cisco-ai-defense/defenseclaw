package fleet

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
)

// Metrics holds fleet-level Prometheus metrics.
type Metrics struct {
	DevicesOnline      atomic.Int64
	DevicesOffline     atomic.Int64
	DevicesDegraded    atomic.Int64
	DevicesLockdown    atomic.Int64
	HeartbeatsReceived atomic.Int64
	BlocksTotal        atomic.Int64
	AllowsTotal        atomic.Int64
	VerdictCacheHits   atomic.Int64
	VerdictCacheMisses atomic.Int64
	VerdictCacheSize   atomic.Int64
	AuditChainBreaks   atomic.Int64
	PolicyRollbacks    atomic.Int64
	SpeculativeBlocks  atomic.Int64
	EmergencySeqGaps   atomic.Int64
}

// GlobalMetrics is the singleton metrics instance.
var GlobalMetrics Metrics

// MetricsHandler serves Prometheus-format metrics at /metrics.
func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Device status metrics (labeled gauge family)
	fmt.Fprintln(w, "# HELP defenseclaw_fleet_devices_total Total registered devices")
	fmt.Fprintln(w, "# TYPE defenseclaw_fleet_devices_total gauge")
	fmt.Fprintf(w, "defenseclaw_fleet_devices_total{status=\"online\"} %d\n", GlobalMetrics.DevicesOnline.Load())
	fmt.Fprintf(w, "defenseclaw_fleet_devices_total{status=\"offline\"} %d\n", GlobalMetrics.DevicesOffline.Load())
	fmt.Fprintf(w, "defenseclaw_fleet_devices_total{status=\"degraded\"} %d\n", GlobalMetrics.DevicesDegraded.Load())
	fmt.Fprintf(w, "defenseclaw_fleet_devices_total{status=\"lockdown\"} %d\n", GlobalMetrics.DevicesLockdown.Load())

	fmt.Fprintln(w, "# HELP defenseclaw_fleet_heartbeats_received_total Total heartbeats received")
	fmt.Fprintln(w, "# TYPE defenseclaw_fleet_heartbeats_received_total counter")
	fmt.Fprintf(w, "defenseclaw_fleet_heartbeats_received_total %d\n", GlobalMetrics.HeartbeatsReceived.Load())

	// Simple counter/gauge metrics
	metrics := []struct {
		name  string
		help  string
		mtype string
		value int64
	}{
		{"defenseclaw_fleet_blocks_total", "Total block verdicts", "counter", GlobalMetrics.BlocksTotal.Load()},
		{"defenseclaw_fleet_allows_total", "Total allow verdicts", "counter", GlobalMetrics.AllowsTotal.Load()},
		{"defenseclaw_fleet_verdict_cache_hits_total", "Verdict cache hits", "counter", GlobalMetrics.VerdictCacheHits.Load()},
		{"defenseclaw_fleet_verdict_cache_misses_total", "Verdict cache misses", "counter", GlobalMetrics.VerdictCacheMisses.Load()},
		{"defenseclaw_fleet_verdict_cache_size", "Current cache entries", "gauge", GlobalMetrics.VerdictCacheSize.Load()},
		{"defenseclaw_fleet_audit_chain_breaks_total", "Audit chain integrity failures", "counter", GlobalMetrics.AuditChainBreaks.Load()},
		{"defenseclaw_fleet_policy_rollback_total", "Policy canary rollbacks", "counter", GlobalMetrics.PolicyRollbacks.Load()},
		{"defenseclaw_fleet_speculative_retroactive_blocks_total", "Speculative retroactive blocks", "counter", GlobalMetrics.SpeculativeBlocks.Load()},
		{"defenseclaw_fleet_emergency_seq_gaps_total", "Emergency sequence gaps detected", "counter", GlobalMetrics.EmergencySeqGaps.Load()},
	}

	for _, m := range metrics {
		fmt.Fprintf(w, "# HELP %s %s\n", m.name, m.help)
		fmt.Fprintf(w, "# TYPE %s %s\n", m.name, m.mtype)
		fmt.Fprintf(w, "%s %d\n", m.name, m.value)
	}
}

// WireMetrics connects GlobalMetrics to the FleetManager and verdict Cache
// via their metrics hook interfaces. Call this once at startup after creating
// the manager and cache.
func WireMetrics(mgr *manager.FleetManager, cache *verdict.Cache) {
	mgr.SetMetricsHooks(
		func() { // onDeviceRegistered
			GlobalMetrics.DevicesOnline.Add(1)
		},
		func() { // onDeviceOffline
			GlobalMetrics.DevicesOnline.Add(-1)
			GlobalMetrics.DevicesOffline.Add(1)
		},
		func() { // onHeartbeat
			GlobalMetrics.HeartbeatsReceived.Add(1)
		},
	)

	cache.SetMetricsHooks(
		func() { // onHit
			GlobalMetrics.VerdictCacheHits.Add(1)
		},
		func() { // onMiss
			GlobalMetrics.VerdictCacheMisses.Add(1)
		},
		func() { // onStore
			GlobalMetrics.VerdictCacheSize.Add(1)
		},
	)
}
