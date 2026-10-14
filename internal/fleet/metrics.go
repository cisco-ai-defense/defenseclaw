package fleet

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/mqtt"
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
	AlertsTotal        atomic.Int64
	OTARollbacks       atomic.Int64
}

// GlobalMetrics is the singleton metrics instance.
var GlobalMetrics Metrics

// Reset zeroes all atomic counters.
func (m *Metrics) Reset() {
	m.DevicesOnline.Store(0)
	m.DevicesOffline.Store(0)
	m.DevicesDegraded.Store(0)
	m.DevicesLockdown.Store(0)
	m.HeartbeatsReceived.Store(0)
	m.BlocksTotal.Store(0)
	m.AllowsTotal.Store(0)
	m.VerdictCacheHits.Store(0)
	m.VerdictCacheMisses.Store(0)
	m.VerdictCacheSize.Store(0)
	m.AuditChainBreaks.Store(0)
	m.PolicyRollbacks.Store(0)
	m.SpeculativeBlocks.Store(0)
	m.EmergencySeqGaps.Store(0)
	m.AlertsTotal.Store(0)
	m.OTARollbacks.Store(0)
}

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
		{"defenseclaw_fleet_alerts_total", "Fleet alerts emitted", "counter", GlobalMetrics.AlertsTotal.Load()},
		{"defenseclaw_fleet_ota_rollbacks_total", "OTA canary rollbacks reported by devices", "counter", GlobalMetrics.OTARollbacks.Load()},
	}

	for _, m := range metrics {
		fmt.Fprintf(w, "# HELP %s %s\n", m.name, m.help)
		fmt.Fprintf(w, "# TYPE %s %s\n", m.name, m.mtype)
		fmt.Fprintf(w, "%s %d\n", m.name, m.value)
	}
}

// WireMetrics connects GlobalMetrics to the FleetManager, verdict Cache,
// and MQTT Bridge via their metrics hook interfaces. Call this once at
// startup after creating the manager, cache, and bridge.
func WireMetrics(mgr *manager.FleetManager, cache *verdict.Cache, bridge *mqtt.Bridge) {
	mgr.SetMetricsHooks(
		func() { // onDeviceRegistered — only called for truly new devices
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

	mgr.SetStatusChangeHook(func(oldStatus, newStatus manager.DeviceStatus) {
		// Decrement old status gauge
		switch oldStatus {
		case manager.StatusOnline:
			GlobalMetrics.DevicesOnline.Add(-1)
		case manager.StatusOffline:
			GlobalMetrics.DevicesOffline.Add(-1)
		case manager.StatusDegraded:
			GlobalMetrics.DevicesDegraded.Add(-1)
		case manager.StatusLockdown:
			GlobalMetrics.DevicesLockdown.Add(-1)
		}
		// Increment new status gauge
		switch newStatus {
		case manager.StatusOnline:
			GlobalMetrics.DevicesOnline.Add(1)
		case manager.StatusOffline:
			GlobalMetrics.DevicesOffline.Add(1)
		case manager.StatusDegraded:
			GlobalMetrics.DevicesDegraded.Add(1)
		case manager.StatusLockdown:
			GlobalMetrics.DevicesLockdown.Add(1)
		}
	})

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
		func() { // onEvict
			GlobalMetrics.VerdictCacheSize.Add(-1)
		},
	)

	if bridge != nil {
		bridge.SetOnBlock(func() {
			GlobalMetrics.BlocksTotal.Add(1)
		})
	}

	originalAlertHandler := mgr.GetAlertHandler()
	mgr.SetAlertHandler(func(alert manager.Alert) {
		GlobalMetrics.AlertsTotal.Add(1)
		if alert.Type == manager.AlertCanaryRollback {
			GlobalMetrics.OTARollbacks.Add(1)
			GlobalMetrics.PolicyRollbacks.Add(1)
		}
		if originalAlertHandler != nil {
			originalAlertHandler(alert)
		}
	})
}
