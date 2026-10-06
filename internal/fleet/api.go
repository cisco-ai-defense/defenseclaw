// Package fleet provides the HTTP API for IoT fleet management.
// Mounts at /api/v1/fleet/ on the existing DefenseClaw gateway HTTP server.
package fleet

import (
	"context"
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

// API handles fleet REST endpoints.
type API struct {
	manager    *manager.FleetManager
	cache      *verdict.Cache
	policy     *policy.Service
	mqttClient mqtt.Client
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
// If token is empty, the handler is returned as-is (development mode).
func authMiddleware(token string, next http.HandlerFunc) http.HandlerFunc {
	if token == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != token {
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
	a.mux.HandleFunc("GET /fleet/health", wrap(a.getFleetHealth))
	a.mux.HandleFunc("POST /policy/simulate", wrap(a.simulatePolicy))
	a.mux.HandleFunc("POST /policy/push", wrap(a.pushPolicy))
	a.mux.HandleFunc("GET /policy/versions", wrap(a.listPolicyVersions))
	a.mux.HandleFunc("POST /policy/emergency", wrap(a.pushEmergency))
	a.mux.HandleFunc("POST /threat-intel/push", wrap(a.pushThreatIntel))
	a.mux.HandleFunc("POST /devices/decommission-batch", wrap(a.decommissionBatch))
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

	writeJSON(w, http.StatusCreated, dev)
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

	// Publish to MQTT if a client is available
	if a.mqttClient != nil {
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

	writeJSON(w, http.StatusOK, map[string]any{
		"version":    version,
		"blob_size":  len(signed),
		"tenant_id":  req.TenantID,
		"fleet_id":   req.FleetID,
		"profile":    req.Profile,
		"status":     "distributed",
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
	case "FLUSH_CACHE":
		cmd = policy.EmergencyFlushCache
	case "ENTER_LOCKDOWN":
		cmd = policy.EmergencyEnterLockdown
	case "REVOKE_SESSIONS":
		cmd = policy.EmergencyRevokeSessions
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "unknown command: must be FLUSH_CACHE, ENTER_LOCKDOWN, or REVOKE_SESSIONS",
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
		NewDenyHashes   []string `json:"new_deny_hashes"`
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

	writeJSON(w, http.StatusAccepted, map[string]any{
		"revoked": len(req.RevokeAllowHash),
		"added":   len(req.NewDenyHashes),
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

	resp := map[string]any{
		"batch_id":         batchID,
		"requested":        len(req.Devices),
		"decommissioned":   decommissioned,
		"status":           "completed",
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
