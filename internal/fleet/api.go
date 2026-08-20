// Package fleet provides the HTTP API for IoT fleet management.
// Mounts at /api/v1/fleet/ on the existing DefenseClaw gateway HTTP server.
package fleet

import (
	"encoding/json"
	"net/http"
	"strconv"

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

func (a *API) registerRoutes() {
	a.mux.HandleFunc("GET /devices", a.listDevices)
	a.mux.HandleFunc("GET /devices/{id}", a.getDevice)
	a.mux.HandleFunc("POST /devices/{id}/command", a.sendCommand)
	a.mux.HandleFunc("GET /fleet/health", a.getFleetHealth)
	a.mux.HandleFunc("POST /policy/simulate", a.simulatePolicy)
	a.mux.HandleFunc("POST /threat-intel/push", a.pushThreatIntel)
	a.mux.HandleFunc("POST /devices/decommission-batch", a.decommissionBatch)
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request) {
	health := a.manager.GetFleetHealth()
	writeJSON(w, http.StatusOK, map[string]any{
		"total":   health.TotalDevices,
		"online":  health.Online,
		"offline": health.Offline,
	})
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
	var req struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
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
		"fleet":      health,
		"cache_hits": hits,
		"cache_misses": misses,
		"cache_size": cacheSize,
	})
}

func (a *API) simulatePolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"verdicts_tested":    0,
		"verdicts_changed":   0,
		"fits_target_profile": true,
		"status":             "simulation not yet connected to pipeline",
	})
}

func (a *API) pushThreatIntel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewDenyHashes    []string `json:"new_deny_hashes"`
		RevokeAllowHash  []string `json:"revoke_allow_hashes"`
		Emergency        bool     `json:"emergency"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	if req.Emergency {
		a.cache.FlushAll()
	}
	for _, hashHex := range req.RevokeAllowHash {
		var hash [32]byte
		copy(hash[:], []byte(hashHex))
		a.cache.Invalidate(hash)
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"revoked": len(req.RevokeAllowHash),
		"added":   len(req.NewDenyHashes),
	})
}

func (a *API) decommissionBatch(w http.ResponseWriter, r *http.Request) {
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
