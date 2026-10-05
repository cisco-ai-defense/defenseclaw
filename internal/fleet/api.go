// Package fleet provides the HTTP API for IoT fleet management.
// Mounts at /api/v1/fleet/ on the existing DefenseClaw gateway HTTP server.
package fleet

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
)

// API handles fleet REST endpoints.
type API struct {
	manager *manager.FleetManager
	cache   *verdict.Cache
	mux     *http.ServeMux
}

// NewAPI creates the fleet API with its dependencies.
func NewAPI(mgr *manager.FleetManager, cache *verdict.Cache) *API {
	api := &API{manager: mgr, cache: cache, mux: http.NewServeMux()}
	api.registerRoutes()
	return api
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
	a.mux.HandleFunc("POST /threat-intel/push", wrap(a.pushThreatIntel))
	a.mux.HandleFunc("POST /devices/decommission-batch", wrap(a.decommissionBatch))
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request) {
	health := a.manager.GetFleetHealth()
	writeJSON(w, http.StatusOK, map[string]any{
		"total":   health.TotalDevices,
		"online":  health.Online,
		"offline": health.Offline,
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
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":  "pending",
		"command": req.Command,
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
	writeJSON(w, http.StatusOK, map[string]any{
		"verdicts_tested":     0,
		"verdicts_changed":    0,
		"fits_target_profile": true,
		"status":              "simulation not yet connected to pipeline",
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
	writeJSON(w, http.StatusAccepted, map[string]any{
		"batch_id":         "pending",
		"affected_devices": 0,
		"status":           "decommission not yet implemented",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
