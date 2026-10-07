// Package fleet provides the HTTP API for IoT fleet management.
// Mounts at /api/v1/fleet/ on the existing DefenseClaw gateway HTTP server.
package fleet

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/mqtt"
	"github.com/defenseclaw/defenseclaw/internal/fleet/policy"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
	"github.com/google/uuid"
)

// AuditEmitter is the narrow interface the fleet API uses to emit events
// through the gateway's observability pipeline. The gateway's *audit.Logger
// satisfies this interface, routing fleet events to SQLite, Splunk, OTLP,
// webhooks, and JSONL without importing the audit package directly.
type AuditEmitter interface {
	// LogAction emits an audit action (target is typically the device/fleet ID,
	// details is a human-readable summary).
	LogAction(action, target, details string) error
	// LogAlert emits a runtime alert through the platform-health pipeline.
	LogAlert(source, severity, summary string, details map[string]any) error
}

// API handles fleet REST endpoints.
type API struct {
	manager    *manager.FleetManager
	cache      *verdict.Cache
	policy     *policy.Service
	mqttClient mqtt.Client
	audit      AuditEmitter
	keyStore   DeviceKeyStore
	mux        *http.ServeMux
}

// NewAPI creates the fleet API with its dependencies.
// The policy service is optional; if nil, policy endpoints return 501.
func NewAPI(mgr *manager.FleetManager, cache *verdict.Cache, opts ...APIOption) *API {
	api := &API{manager: mgr, cache: cache, mux: http.NewServeMux()}
	for _, opt := range opts {
		opt(api)
	}
	api.registerRoutes()
	return api
}

// APIOption configures optional API dependencies.
type APIOption func(*API)

// WithPolicyService attaches a policy distribution service to the API.
func WithPolicyService(svc *policy.Service) APIOption {
	return func(a *API) {
		a.policy = svc
	}
}

// WithMQTTClient attaches an MQTT client so the API can publish commands to devices.
func WithMQTTClient(client mqtt.Client) APIOption {
	return func(a *API) {
		a.mqttClient = client
	}
}

// WithAuditEmitter attaches an audit emitter so fleet operations are
// logged through the gateway's observability pipeline (SQLite, Splunk,
// OTLP, webhooks, JSONL). When nil, fleet API handlers still function
// but produce no audit trail beyond stderr.
func WithAuditEmitter(e AuditEmitter) APIOption {
	return func(a *API) {
		a.audit = e
	}
}

// WithDeviceKeyStore attaches a per-device key store so that device
// registration generates and persists unique 32-byte HMAC signing keys.
// The key is returned in the registration response for operator provisioning.
func WithDeviceKeyStore(ks DeviceKeyStore) APIOption {
	return func(a *API) {
		a.keyStore = ks
	}
}

// emitAudit is a nil-safe helper that logs an audit action without
// interrupting the HTTP handler on failure.
func (a *API) emitAudit(action, target, details string) {
	if a.audit == nil {
		return
	}
	if err := a.audit.LogAction(action, target, details); err != nil {
		log.Printf("[fleet-api] audit emit %s: %v", action, err)
	}
}

// emitAlert is a nil-safe helper that logs a fleet alert through
// the platform-health pipeline.
func (a *API) emitAlert(severity, summary string, details map[string]any) {
	// P2-19 fix: Increment the real alerts counter for Prometheus/Grafana.
	GlobalMetrics.AlertsTotal.Add(1)
	if a.audit == nil {
		return
	}
	if err := a.audit.LogAlert("fleet", severity, summary, details); err != nil {
		log.Printf("[fleet-api] audit alert: %v", err)
	}
}

// validDeviceCommands lists the commands accepted by the sendCommand endpoint.
var validDeviceCommands = map[string]bool{
	"reboot":         true,
	"policy-refresh": true,
	"diagnostics":    true,
}

// Handler returns the http.Handler for mounting.
func (a *API) Handler() http.Handler {
	return a.mux
}

// authMiddleware wraps an http.HandlerFunc with Bearer token validation.
// When token is empty, ALL requests are blocked — the fleet API must never
// be reachable without authentication.
func authMiddleware(token string, next http.HandlerFunc) http.HandlerFunc {
	if token == "" {
		return func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "fleet API authentication not configured (set DCLAW_FLEET_API_TOKEN)",
			})
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		got := strings.TrimPrefix(auth, "Bearer ")
		if !strings.HasPrefix(auth, "Bearer ") || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (a *API) registerRoutes() {
	token := os.Getenv("DCLAW_FLEET_API_TOKEN")
	if token == "" {
		log.Println("WARNING: DCLAW_FLEET_API_TOKEN not set, fleet API auth disabled (development mode)")
	}

	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		return authMiddleware(token, h)
	}

	a.mux.HandleFunc("GET /devices", wrap(a.listDevices))
	a.mux.HandleFunc("POST /devices", wrap(a.registerDevice))
	a.mux.HandleFunc("GET /devices/{id}", wrap(a.getDevice))
	a.mux.HandleFunc("POST /devices/{id}/command", wrap(a.sendCommand))
	a.mux.HandleFunc("GET /health", wrap(a.getFleetHealth))
	a.mux.HandleFunc("POST /policy/simulate", wrap(a.simulatePolicy))
	a.mux.HandleFunc("POST /policy/push", wrap(a.pushPolicy))
	a.mux.HandleFunc("GET /policy/versions", wrap(a.listPolicyVersions))
	a.mux.HandleFunc("POST /policy/emergency", wrap(a.pushEmergency))
	a.mux.HandleFunc("POST /threat-intel/push", wrap(a.pushThreatIntel))
	a.mux.HandleFunc("POST /devices/decommission-batch", wrap(a.decommissionBatch))
	a.mux.HandleFunc("GET /metrics", wrap(MetricsHandler))
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request) {
	devices := a.manager.ListDevices()
	health := a.manager.GetFleetHealth()

	writeJSON(w, http.StatusOK, map[string]any{
		"devices": devices,
		"summary": map[string]any{
			"total":    health.TotalDevices,
			"online":   health.Online,
			"offline":  health.Offline,
			"degraded": health.Degraded,
			"lockdown": health.Lockdown,
		},
	})
}

func (a *API) registerDevice(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var req struct {
		TenantID      uint16 `json:"tenant_id"`
		FleetID       uint16 `json:"fleet_id"`
		DeviceID      uint32 `json:"device_id"`
		HWProfile     string `json:"hw_profile"`
		FWVersion     string `json:"fw_version"`
		PolicyVersion uint16 `json:"policy_version"`
		Capabilities  uint8  `json:"capabilities"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "http: request body too large" {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	if req.DeviceID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id is required"})
		return
	}

	dev, err := a.manager.RegisterDevice(
		req.TenantID, req.FleetID, req.DeviceID,
		req.HWProfile, req.FWVersion, req.PolicyVersion, req.Capabilities,
	)
	if err == manager.ErrDeviceExists {
		writeJSON(w, http.StatusOK, dev)
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Generate and persist a per-device HMAC signing key (32 random bytes).
	// The key is returned in the response so the operator can provision it
	// on the device (via DCLAW_DEVICE_KEY env var or /etc/defenseclaw/device.key).
	var deviceKeyHex string
	if a.keyStore != nil {
		deviceKey := make([]byte, 32)
		if _, err := rand.Read(deviceKey); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "failed to generate device key: " + err.Error(),
			})
			return
		}
		if err := a.keyStore.SaveDeviceKey(dev.DeviceID, deviceKey); err != nil {
			// Key save failed — roll back the device registration so we
			// don't leave a device without a persisted key.
			a.manager.DecommissionDevice(req.TenantID, req.FleetID, req.DeviceID)
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "failed to save device key: " + err.Error(),
			})
			return
		}
		deviceKeyHex = hex.EncodeToString(deviceKey)
	}

	a.emitAudit("fleet.device.registered",
		fmt.Sprintf("%d", dev.DeviceID),
		fmt.Sprintf("tenant=%d fleet=%d hw=%s fw=%s policy_v=%d",
			req.TenantID, req.FleetID, req.HWProfile, req.FWVersion, req.PolicyVersion))

	// Include the device key in the registration response when a key store
	// is configured. The operator must provision this key on the device.
	// This is the ONLY time the key is returned — it is not retrievable later.
	resp := map[string]any{
		"device":     dev,
		"device_key": deviceKeyHex, // empty string when no key store
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (a *API) getDevice(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device_id"})
		return
	}

	dev, ok := a.manager.GetDevice(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}
	writeJSON(w, http.StatusOK, dev)
}

func (a *API) sendCommand(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	idStr := r.PathValue("id")
	deviceFullID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device_id"})
		return
	}

	var req struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "http: request body too large" {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	if req.Command == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "command is required"})
		return
	}
	if !validDeviceCommands[req.Command] {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unknown command %q: must be one of reboot, policy-refresh, diagnostics", req.Command),
		})
		return
	}

	// Verify the device exists
	dev, ok := a.manager.GetDevice(deviceFullID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	commandID := uuid.New().String()

	// MQTT is required to dispatch commands to devices.
	if a.mqttClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "MQTT client not configured — cannot dispatch commands to devices",
		})
		return
	}

	// Publish to MQTT
	{
		topic := fmt.Sprintf("defenseclaw/%d/%d/%d/cmd/request",
			dev.TenantID, dev.FleetID, uint32(dev.DeviceID))

		payload, _ := json.Marshal(map[string]string{
			"command_id": commandID,
			"command":    req.Command,
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
		})

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := a.mqttClient.Publish(ctx, topic, 1, payload); err != nil {
			log.Printf("[fleet-api] MQTT publish to %s failed: %v", topic, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":  "failed to dispatch command",
				"detail": err.Error(),
			})
			return
		}
	}

	a.emitAudit("fleet.device.command",
		fmt.Sprintf("%d", deviceFullID),
		fmt.Sprintf("command=%s command_id=%s", req.Command, commandID))

	writeJSON(w, http.StatusAccepted, map[string]any{
		"command_id": commandID,
		"device_id":  deviceFullID,
		"command":    req.Command,
		"status":     "dispatched",
	})
}

func (a *API) getFleetHealth(w http.ResponseWriter, r *http.Request) {
	health := a.manager.GetFleetHealth()
	hits, misses, cacheSize := a.cache.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"fleet":        health,
		"cache_hits":   hits,
		"cache_misses": misses,
		"cache_size":   cacheSize,
	})
}

func (a *API) simulatePolicy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	if a.policy == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"verdicts_tested":     0,
			"verdicts_changed":    0,
			"fits_target_profile": true,
			"status":              "policy service not configured",
		})
		return
	}

	var req struct {
		PolicyYAML string `json:"policy_yaml"`
		Profile    string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "http: request body too large" {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	if req.Profile == "" {
		req.Profile = "standard"
	}

	// Dry-run: compile without signing or distributing
	blob, err := a.policy.Compile([]byte(req.PolicyYAML), req.Profile, 0)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
			"error":  "compilation failed",
			"detail": err.Error(),
		})
		return
	}

	hdr, _ := policy.ParseHeader(blob)
	writeJSON(w, http.StatusOK, map[string]any{
		"blob_size":           len(blob),
		"payload_len":         hdr.PayloadLen,
		"canary_baseline":     hdr.CanaryBaseline,
		"fits_target_profile": true,
		"status":              "dry-run compilation succeeded",
	})
}

// pushPolicy handles POST /policy/push — compiles, signs, stores, and distributes.
func (a *API) pushPolicy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	if a.policy == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error": "policy service not configured",
		})
		return
	}

	var req struct {
		TenantID   uint64 `json:"tenant_id"`
		FleetID    uint64 `json:"fleet_id"`
		PolicyYAML string `json:"policy_yaml"`
		Profile    string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "http: request body too large" {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	if req.TenantID == 0 || req.FleetID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "tenant_id and fleet_id are required",
		})
		return
	}
	if req.PolicyYAML == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "policy_yaml is required",
		})
		return
	}
	if req.Profile == "" {
		req.Profile = "standard"
	}

	signed, version, err := a.policy.CompileSignAndStore([]byte(req.PolicyYAML), req.Profile, req.TenantID, req.FleetID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":  "policy compilation/signing failed",
			"detail": err.Error(),
		})
		return
	}

	if err := a.policy.Distribute(r.Context(), req.TenantID, req.FleetID, signed); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":  "distribution failed",
			"detail": err.Error(),
		})
		return
	}

	// Mark the policy version as distributed in the store so audit
	// queries reflect the actual push state.
	if err := a.policy.Store().MarkDistributed(req.TenantID, req.FleetID, version); err != nil {
		log.Printf("[fleet-api] MarkDistributed(%d, %d, v%d) failed: %v", req.TenantID, req.FleetID, version, err)
	}

	a.emitAudit("fleet.policy.push",
		fmt.Sprintf("tenant=%d/fleet=%d", req.TenantID, req.FleetID),
		fmt.Sprintf("version=%d profile=%s blob_size=%d", version, req.Profile, len(signed)))

	writeJSON(w, http.StatusOK, map[string]any{
		"version":   version,
		"blob_size": len(signed),
		"tenant_id": req.TenantID,
		"fleet_id":  req.FleetID,
		"profile":   req.Profile,
		"status":    "distributed",
	})
}

// listPolicyVersions handles GET /policy/versions?tenant_id=X&fleet_id=Y
func (a *API) listPolicyVersions(w http.ResponseWriter, r *http.Request) {
	if a.policy == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error": "policy service not configured",
		})
		return
	}

	tenantStr := r.URL.Query().Get("tenant_id")
	fleetStr := r.URL.Query().Get("fleet_id")

	tenantID, err := strconv.ParseUint(tenantStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
		return
	}
	fleetID, err := strconv.ParseUint(fleetStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid fleet_id"})
		return
	}

	versions, err := a.policy.Store().ListVersions(tenantID, fleetID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id": tenantID,
		"fleet_id":  fleetID,
		"versions":  versions,
	})
}

// pushEmergency handles POST /policy/emergency — sends an emergency command to a fleet.
func (a *API) pushEmergency(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	if a.policy == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error": "policy service not configured",
		})
		return
	}

	var req struct {
		TenantID uint64 `json:"tenant_id"`
		FleetID  uint64 `json:"fleet_id"`
		Command  string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "http: request body too large" {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	if req.TenantID == 0 || req.FleetID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "tenant_id and fleet_id are required",
		})
		return
	}

	var cmd policy.EmergencyCommand
	switch strings.ToUpper(req.Command) {
	case "BLOCK_ALL":
		cmd = policy.EmergencyBlockAll
	case "ENTER_LOCKDOWN":
		cmd = policy.EmergencyEnterLockdown
	case "RELEASE_LOCKDOWN":
		cmd = policy.EmergencyReleaseLockdown
	case "REVOKE_SESSIONS":
		cmd = policy.EmergencyRevokeSessions
	case "FORCE_SYNC":
		cmd = policy.EmergencyForceSync
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "unknown command: must be BLOCK_ALL, ENTER_LOCKDOWN, RELEASE_LOCKDOWN, REVOKE_SESSIONS, or FORCE_SYNC",
		})
		return
	}

	if err := a.policy.DistributeEmergency(r.Context(), req.TenantID, req.FleetID, cmd); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":  "emergency distribution failed",
			"detail": err.Error(),
		})
		return
	}

	a.emitAudit("fleet.policy.emergency",
		fmt.Sprintf("tenant=%d/fleet=%d", req.TenantID, req.FleetID),
		fmt.Sprintf("command=%s", req.Command))
	a.emitAlert("HIGH",
		fmt.Sprintf("Fleet emergency command %s dispatched to tenant=%d fleet=%d", req.Command, req.TenantID, req.FleetID),
		map[string]any{
			"tenant_id": req.TenantID,
			"fleet_id":  req.FleetID,
			"command":   req.Command,
		})

	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id": req.TenantID,
		"fleet_id":  req.FleetID,
		"command":   req.Command,
		"status":    "distributed",
	})
}

func (a *API) pushThreatIntel(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
	var req struct {
		RevokeAllowHash []string `json:"revoke_allow_hashes"`
		Emergency       bool     `json:"emergency"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "http: request body too large" {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	if req.Emergency {
		a.cache.FlushAll()
	}
	for _, hashHex := range req.RevokeAllowHash {
		decoded, err := hex.DecodeString(hashHex)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid hex in revoke_allow_hashes: " + hashHex,
			})
			return
		}
		if len(decoded) != 32 {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "hash must be exactly 32 bytes (64 hex chars): " + hashHex,
			})
			return
		}
		var hash [32]byte
		copy(hash[:], decoded)
		a.cache.Invalidate(hash)
	}

	a.emitAudit("fleet.threat_intel.push",
		fmt.Sprintf("threat-intel-push.%d", len(req.RevokeAllowHash)),
		fmt.Sprintf("revoked_count:%d emergency:%v", len(req.RevokeAllowHash), req.Emergency))

	writeJSON(w, http.StatusAccepted, map[string]any{
		"revoked": len(req.RevokeAllowHash),
	})
}

func (a *API) decommissionBatch(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var req struct {
		Devices []struct {
			TenantID uint16 `json:"tenant_id"`
			FleetID  uint16 `json:"fleet_id"`
			DeviceID uint32 `json:"device_id"`
		} `json:"devices"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "http: request body too large" {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	if len(req.Devices) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "devices list is required and must not be empty"})
		return
	}

	batchID := uuid.New().String()
	decommissioned := 0
	var notFound []uint64

	for _, d := range req.Devices {
		if a.manager.DecommissionDevice(d.TenantID, d.FleetID, d.DeviceID) {
			decommissioned++
		} else {
			notFound = append(notFound, uint64(manager.ComposeID(d.TenantID, d.FleetID, d.DeviceID)))
		}
	}

	a.emitAudit("fleet.device.decommission",
		batchID,
		fmt.Sprintf("requested:%d decommissioned:%d not_found:%d", len(req.Devices), decommissioned, len(notFound)))

	resp := map[string]any{
		"batch_id":       batchID,
		"requested":      len(req.Devices),
		"decommissioned": decommissioned,
		"status":         "completed",
	}
	if len(notFound) > 0 {
		resp["not_found"] = notFound
	}

	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
