// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/mqtt"
	"github.com/defenseclaw/defenseclaw/internal/fleet/policy"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
	"github.com/google/uuid"
)

const tenantDenied uint16 = 65535

const (
	auditDeviceRegistered   = "fleet.device.registered"
	auditDeviceReregistered = "fleet.device.reregistered"
	auditDeviceCommand      = "fleet.device.command"
	auditPolicyPush         = "fleet.policy.push"
	auditPolicyEmergency    = "fleet.policy.emergency"
	auditThreatIntel        = "fleet.threat_intel.push"
	auditDecommission       = "fleet.device.decommission"
	auditTokenRotated       = "fleet.token.rotated"
	auditKeyRotated         = "fleet.device.key_rotated"
)

// FleetSettings carries fleet configuration values resolved from
// config.yaml by the gateway sidecar. Defined here (not imported from
// internal/config) to avoid circular imports. The sidecar populates
// this from config.FleetConfig and passes it via WithFleetSettings.
type FleetSettings struct {
	APIToken          string // resolved bearer token (empty = reject all)
	TenantTokens      string // "token:tid,token:tid,..." format
	AllowKeyOverHTTP  bool
	TrustProxyHeaders bool
	RequireClientID   bool
}

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

// MQTTBridge is the narrow interface the fleet API uses to notify the MQTT
// bridge about decommissioned and re-registered devices. The bridge's
// MarkDecommissioned and ClearDecommissioned methods satisfy this interface.
type MQTTBridge interface {
	MarkDecommissioned(fullDeviceID uint64)
	// ClearDecommissioned removes a device from the tombstone set so that
	// re-registered devices can resume MQTT communication.
	ClearDecommissioned(fullDeviceID uint64)
}

// API handles fleet REST endpoints.
type API struct {
	manager     *manager.FleetManager
	cache       *verdict.Cache
	policy      *policy.Service
	mqttClient  mqtt.Client
	bridge      MQTTBridge
	audit       AuditEmitter
	keyStore    DeviceKeyStore
	decommStore DecommissionStore
	mux         *http.ServeMux
	settings    FleetSettings

	currentToken atomic.Pointer[string]

	tenantScopesMu sync.RWMutex
	tenantScopes   map[string]uint16

	rotationMu         sync.Mutex
	lastTokenRotation  time.Time
	deviceKeyRotations map[uint64]time.Time
}

// NewAPI creates the fleet API with its dependencies.
// The policy service is optional; if nil, policy endpoints return 501.
// The context controls the lifetime of background goroutines (cleanup ticker).
func NewAPI(ctx context.Context, mgr *manager.FleetManager, cache *verdict.Cache, opts ...APIOption) *API {
	api := &API{
		manager:            mgr,
		cache:              cache,
		mux:                http.NewServeMux(),
		deviceKeyRotations: make(map[uint64]time.Time),
	}
	for _, opt := range opts {
		opt(api)
	}
	api.registerRoutes()

	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				api.rotationMu.Lock()
				now := time.Now()
				for id, ts := range api.deviceKeyRotations {
					if now.Sub(ts) > 2*time.Minute {
						delete(api.deviceKeyRotations, id)
					}
				}
				api.rotationMu.Unlock()
			}
		}
	}()

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

// WithMQTTBridge attaches the MQTT bridge so the API can mark devices as
// decommissioned in the bridge's in-memory set, causing the bridge to reject
// any further MQTT messages from those devices.
func WithMQTTBridge(b MQTTBridge) APIOption {
	return func(a *API) {
		a.bridge = b
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

// WithDecommissionStore attaches a decommission tombstone store so that
// decommissioned device IDs are persisted across gateway restarts.
func WithDecommissionStore(ds DecommissionStore) APIOption {
	return func(a *API) {
		a.decommStore = ds
	}
}

// WithFleetSettings passes config.yaml-resolved fleet settings so the API
// reads tokens, flags, and behavioral toggles from the single source of
// truth instead of environment variables.
func WithFleetSettings(s FleetSettings) APIOption {
	return func(a *API) {
		a.settings = s
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
	GlobalMetrics.AlertsTotal.Add(1)
	if a.audit == nil {
		return
	}
	if err := a.audit.LogAlert("fleet", severity, summary, details); err != nil {
		log.Printf("[fleet-api] audit alert: %v", err)
	}
}

// tenantFromRequest extracts the tenant scope for the authenticated request.
func (a *API) tenantFromRequest(r *http.Request) uint16 {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return tenantDenied
	}
	got := strings.TrimPrefix(auth, "Bearer ")
	if got == "" {
		return tenantDenied
	}

	// Rotated admin token — global access (tenant 0 = admin).
	tp := a.currentToken.Load()
	if tp != nil && *tp != "" && subtle.ConstantTimeCompare([]byte(got), []byte(*tp)) == 1 {
		return 0
	}

	// Check tenant-scoped tokens.
	a.tenantScopesMu.RLock()
	for tok, tid := range a.tenantScopes {
		if tok == "" || tid == 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1 {
			a.tenantScopesMu.RUnlock()
			return tid
		}
	}
	a.tenantScopesMu.RUnlock()

	return tenantDenied
}

// authorizedForDevice checks if the request is authorized for this device's tenant.
func (a *API) authorizedForDevice(r *http.Request, tenantID uint16) bool {
	tid := a.tenantFromRequest(r)
	if tid == tenantDenied {
		return false
	}
	return tid == 0 || tid == tenantID
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
func (a *API) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		got := strings.TrimPrefix(auth, "Bearer ")
		if got == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		authenticated := false
		a.tenantScopesMu.RLock()
		for tok := range a.tenantScopes {
			if tok == "" {
				continue
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1 {
				authenticated = true
				break
			}
		}
		a.tenantScopesMu.RUnlock()

		// Fallback: check the current (possibly rotated) admin token.
		if !authenticated {
			tp := a.currentToken.Load()
			if tp == nil || *tp == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "fleet API authentication not configured (set DCLAW_FLEET_API_TOKEN)",
				})
				return
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(*tp)) == 1 {
				authenticated = true
			}
		}

		if !authenticated {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (a *API) registerRoutes() {
	// Resolve API token from config.yaml (FleetSettings) with env var fallback.
	token := a.settings.APIToken
	if token == "" {
		token = os.Getenv("DCLAW_FLEET_API_TOKEN")
	}
	if token == "" {
		log.Println("WARNING: fleet API token not configured — fleet API will reject all requests (set fleet.api_token_env in config.yaml or DCLAW_FLEET_API_TOKEN)")
	}

	a.currentToken.Store(&token)

	a.tenantScopes = make(map[string]uint16)
	if token != "" {
		a.tenantScopes[token] = 0 // global admin
	}
	tenantTokens := a.settings.TenantTokens
	if tenantTokens == "" {
		tenantTokens = os.Getenv("DCLAW_FLEET_TENANT_TOKENS")
	}
	if tenantTokens != "" {
		for _, entry := range strings.Split(tenantTokens, ",") {
			parts := strings.SplitN(strings.TrimSpace(entry), ":", 2)
			if len(parts) == 2 {
				if tid, err := strconv.ParseUint(parts[1], 10, 16); err == nil {
					a.tenantScopes[parts[0]] = uint16(tid)
				}
			}
		}
	}

	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		return securityHeadersMiddleware(csrfMiddleware(a.authMiddleware(h)))
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
	a.mux.HandleFunc("POST /token/rotate", wrap(a.rotateToken))
	a.mux.HandleFunc("POST /devices/{id}/rotate-key", wrap(a.rotateDeviceKey))
	a.mux.HandleFunc("GET /metrics", wrap(MetricsHandler))
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request) {
	const maxPageSize = 10000

	offset := 0
	limit := maxPageSize

	if offStr := r.URL.Query().Get("offset"); offStr != "" {
		if v, err := strconv.Atoi(offStr); err == nil && v >= 0 {
			offset = v
		}
	}
	if limStr := r.URL.Query().Get("limit"); limStr != "" {
		if v, err := strconv.Atoi(limStr); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > maxPageSize {
		limit = maxPageSize
	}

	tid := a.tenantFromRequest(r)
	allDevices := a.manager.ListDevices()
	health := a.manager.GetFleetHealth()

	filtered := allDevices[:0:0]
	for _, d := range allDevices {
		if tid != 0 && d.TenantID != tid {
			continue
		}
		filtered = append(filtered, d)
	}

	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	paged := filtered[offset:end]

	writeJSON(w, http.StatusOK, map[string]any{
		"devices": paged,
		"total":   total,
		"offset":  offset,
		"limit":   limit,
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
		TenantID        uint16 `json:"tenant_id"`
		FleetID         uint16 `json:"fleet_id"`
		DeviceID        uint32 `json:"device_id"`
		HWProfile       string `json:"hw_profile"`
		FWVersion       string `json:"fw_version"`
		PolicyVersion   uint16 `json:"policy_version"`
		Capabilities    uint8  `json:"capabilities"`
		ForceReregister bool   `json:"force_reregister"`
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

	req.HWProfile = sanitizeString(req.HWProfile, 128)
	req.FWVersion = sanitizeString(req.FWVersion, 128)

	if req.TenantID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant_id must be non-zero"})
		return
	}
	if req.FleetID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "fleet_id must be non-zero"})
		return
	}

	if !a.authorizedForDevice(r, req.TenantID) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "token not authorized for this tenant",
		})
		return
	}

	dev, err := a.manager.RegisterDevice(
		req.TenantID, req.FleetID, req.DeviceID,
		req.HWProfile, req.FWVersion, req.PolicyVersion, req.Capabilities,
	)
	if err == manager.ErrDeviceExists {
		if a.decommStore != nil {
			wasDecomm, decommErr := a.decommStore.IsDecommissioned(dev.DeviceID)
			if decommErr != nil {
				log.Printf("[fleet-api] decommission store check failed for %d: %v", dev.DeviceID, decommErr)
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{
					"error": "decommission store temporarily unavailable",
				})
				return
			}
			if wasDecomm && !req.ForceReregister {
				writeJSON(w, http.StatusConflict, map[string]string{
					"error": "device was decommissioned — set force_reregister=true to re-enable",
				})
				return
			}
		}

		// Clear the decommission tombstone on re-registration so the bridge
		// stops rejecting MQTT traffic from this device.
		if a.bridge != nil {
			a.bridge.ClearDecommissioned(dev.DeviceID)
		}
		if a.decommStore != nil {
			if err := a.decommStore.DeleteDecommissioned(dev.DeviceID); err != nil {
				log.Printf("[fleet-api] failed to delete decommission tombstone for %d: %v", dev.DeviceID, err)
			}
		}

		if r.TLS == nil {
			fwdProto := r.Header.Get("X-Forwarded-Proto")
			allowHTTP := a.settings.AllowKeyOverHTTP || os.Getenv("DCLAW_ALLOW_KEY_OVER_HTTP") == "1"
			if isProductionMode() && !(isTrustedProxy(r, a.settings) && fwdProto == "https") && !allowHTTP {
				http.Error(w, `{"error":"key_delivery_requires_tls"}`, http.StatusForbidden)
				return
			}
			w.Header().Set("X-Security-Warning", "key-delivered-over-plaintext")
		}

		var deviceKeyHex string
		if a.keyStore != nil {
			deviceKey := make([]byte, 32)
			if _, err := rand.Read(deviceKey); err != nil {
				log.Printf("[fleet-api] failed to generate device key on re-registration: %v", err)
				writeJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "failed to generate device key",
				})
				return
			}
			if err := a.keyStore.SaveDeviceKey(dev.DeviceID, deviceKey); err != nil {
				log.Printf("[fleet-api] failed to regenerate key on re-registration for %d: %v", dev.DeviceID, err)
			} else {
				deviceKeyHex = hex.EncodeToString(deviceKey)
			}
		}
		a.emitAudit(auditDeviceReregistered,
			fmt.Sprintf("%d", dev.DeviceID),
			fmt.Sprintf("tenant:%d fleet:%d", req.TenantID, req.FleetID))
		resp := map[string]any{
			"device":     dev,
			"device_key": deviceKeyHex,
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	if err != nil {
		log.Printf("[fleet-api] register device failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "device registration failed"})
		return
	}

	// Clear the decommission tombstone on fresh registration too, in case the
	// device was previously decommissioned and its fleet manager entry was
	// already cleaned up but the bridge tombstone persists.
	if a.bridge != nil {
		a.bridge.ClearDecommissioned(dev.DeviceID)
	}
	if a.decommStore != nil {
		if err := a.decommStore.DeleteDecommissioned(dev.DeviceID); err != nil {
			log.Printf("[fleet-api] failed to delete decommission tombstone for %d: %v", dev.DeviceID, err)
		}
	}

	if r.TLS == nil {
		fwdProto := r.Header.Get("X-Forwarded-Proto")
		allowHTTP := a.settings.AllowKeyOverHTTP || os.Getenv("DCLAW_ALLOW_KEY_OVER_HTTP") == "1"
		if isProductionMode() && !(isTrustedProxy(r, a.settings) && fwdProto == "https") && !allowHTTP {
			http.Error(w, `{"error":"key_delivery_requires_tls"}`, http.StatusForbidden)
			return
		}
		w.Header().Set("X-Security-Warning", "key-delivered-over-plaintext")
	}

	// Generate and persist a per-device HMAC signing key (32 random bytes).
	// The key is returned in the response so the operator can provision it
	// on the device (via DCLAW_DEVICE_KEY env var or /etc/defenseclaw/device.key).
	var deviceKeyHex string
	if a.keyStore != nil {
		deviceKey := make([]byte, 32)
		if _, err := rand.Read(deviceKey); err != nil {
			log.Printf("[fleet-api] failed to generate device key: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "failed to generate device key",
			})
			return
		}
		if err := a.keyStore.SaveDeviceKey(dev.DeviceID, deviceKey); err != nil {
			// Key save failed — roll back the device registration so we
			// don't leave a device without a persisted key.
			a.manager.DecommissionDevice(req.TenantID, req.FleetID, req.DeviceID)
			log.Printf("[fleet-api] failed to save device key for %d: %v", dev.DeviceID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "failed to save device key",
			})
			return
		}
		deviceKeyHex = hex.EncodeToString(deviceKey)
	}

	a.emitAudit(auditDeviceRegistered,
		fmt.Sprintf("%d", dev.DeviceID),
		fmt.Sprintf("tenant=%d fleet=%d hw=%s fw=%s policy_v=%d",
			req.TenantID, req.FleetID, req.HWProfile, req.FWVersion, req.PolicyVersion))

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

	if !a.authorizedForDevice(r, dev.TenantID) {
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

	if !a.authorizedForDevice(r, dev.TenantID) {
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
				"detail": "command delivery failed",
			})
			return
		}
	}

	a.emitAudit(auditDeviceCommand,
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
		log.Printf("[fleet-api] policy simulation compile failed: %v", err)
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
			"error":  "compilation failed",
			"detail": "policy compilation error",
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
		TenantID   uint16 `json:"tenant_id"`
		FleetID    uint16 `json:"fleet_id"`
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

	callerTenant := a.tenantFromRequest(r)
	if callerTenant != 0 && callerTenant != req.TenantID {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "not authorized for this tenant",
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

	signed, version, err := a.policy.CompileSignAndStore([]byte(req.PolicyYAML), req.Profile, uint64(req.TenantID), uint64(req.FleetID))
	if err != nil {
		log.Printf("[fleet-api] policy compile/sign failed for tenant=%d fleet=%d: %v", req.TenantID, req.FleetID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":  "policy compilation/signing failed",
			"detail": "internal policy processing error",
		})
		return
	}

	if err := a.policy.Distribute(r.Context(), uint64(req.TenantID), uint64(req.FleetID), signed); err != nil {
		log.Printf("[fleet-api] policy distribution failed for tenant=%d fleet=%d: %v", req.TenantID, req.FleetID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":  "distribution failed",
			"detail": "policy distribution error",
		})
		return
	}

	// Mark the policy version as distributed in the store so audit
	// queries reflect the actual push state.
	if err := a.policy.Store().MarkDistributed(uint64(req.TenantID), uint64(req.FleetID), version); err != nil {
		log.Printf("[fleet-api] MarkDistributed(%d, %d, v%d) failed: %v", req.TenantID, req.FleetID, version, err)
	}

	a.emitAudit(auditPolicyPush,
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

	tenantID, err := strconv.ParseUint(tenantStr, 10, 16)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
		return
	}
	fleetID, err := strconv.ParseUint(fleetStr, 10, 16)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid fleet_id"})
		return
	}

	callerTenant := a.tenantFromRequest(r)
	if callerTenant != 0 && callerTenant != uint16(tenantID) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "not authorized for this tenant",
		})
		return
	}

	versions, err := a.policy.Store().ListVersions(tenantID, fleetID)
	if err != nil {
		log.Printf("[fleet-api] list policy versions failed for tenant=%d fleet=%d: %v", tenantID, fleetID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list policy versions"})
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
		TenantID uint16 `json:"tenant_id"`
		FleetID  uint16 `json:"fleet_id"`
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

	callerTenant := a.tenantFromRequest(r)
	if callerTenant != 0 && callerTenant != req.TenantID {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "not authorized for this tenant",
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

	if err := a.policy.DistributeEmergency(r.Context(), uint64(req.TenantID), uint64(req.FleetID), cmd); err != nil {
		log.Printf("[fleet-api] emergency distribution failed for tenant=%d fleet=%d cmd=%s: %v", req.TenantID, req.FleetID, req.Command, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":  "emergency distribution failed",
			"detail": "emergency command delivery error",
		})
		return
	}

	a.emitAudit(auditPolicyEmergency,
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

	if a.tenantFromRequest(r) != 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "threat intel push requires admin access",
		})
		return
	}

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

	// Push a REVOKE_SESSIONS emergency command to all affected devices so
	// their local verdict caches are flushed immediately. Without this, edge
	// devices keep serving stale ALLOW verdicts from their on-device cache
	// for up to 24 hours after the cloud cache is invalidated.
	var deviceCacheFlushErr string
	if a.policy != nil && (len(req.RevokeAllowHash) > 0 || req.Emergency) {
		// Known limitation: publishes to tenant=0/fleet=0 which no device
		// subscribes to. The cloud cache is flushed; edge device caches
		// expire via TTL (ALLOW: 24h). Per-tenant/fleet iteration is
		// tracked in the edge-connector roadmap.
		if err := a.policy.DistributeEmergency(r.Context(), 0, 0, policy.EmergencyRevokeSessions); err != nil {
			log.Printf("[fleet-api] threat-intel: failed to push device cache flush: %v", err)
			deviceCacheFlushErr = "device cache flush failed — edge devices may serve stale verdicts"
		} else {
			log.Printf("[fleet-api] threat-intel: REVOKE_SESSIONS published to tenant=0/fleet=0 — edge devices rely on TTL expiry for %d revoked hashes", len(req.RevokeAllowHash))
		}
	}

	a.emitAudit(auditThreatIntel,
		fmt.Sprintf("threat-intel-push.%d", len(req.RevokeAllowHash)),
		fmt.Sprintf("revoked_count:%d emergency:%v", len(req.RevokeAllowHash), req.Emergency))

	resp := map[string]any{
		"revoked": len(req.RevokeAllowHash),
	}
	if deviceCacheFlushErr != "" {
		resp["warning"] = deviceCacheFlushErr
	} else if a.policy != nil && (len(req.RevokeAllowHash) > 0 || req.Emergency) {
		resp["device_cache_flushed"] = false
		resp["warning"] = "emergency broadcast to tenant=0/fleet=0 does not reach devices — devices subscribe to specific tenant/fleet topics"
	}
	writeJSON(w, http.StatusAccepted, resp)
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
	if len(req.Devices) > 1000 {
		http.Error(w, `{"error":"batch size exceeds maximum of 1000"}`, http.StatusBadRequest)
		return
	}

	batchID := uuid.New().String()
	decommissioned := 0
	var notFound []uint64
	var keyDeleteFailed []uint64
	deadline := time.Now().Add(30 * time.Second)

	requestTID := a.tenantFromRequest(r)
	var tenantDenied []uint64

	for _, d := range req.Devices {
		if time.Now().After(deadline) {
			log.Printf("[fleet-api] decommission batch %s: deadline exceeded after %d devices", batchID, decommissioned)
			break
		}
		fullID := manager.ComposeID(d.TenantID, d.FleetID, d.DeviceID)

		if requestTID != 0 && requestTID != d.TenantID {
			tenantDenied = append(tenantDenied, uint64(fullID))
			continue
		}

		if a.manager.DecommissionDevice(d.TenantID, d.FleetID, d.DeviceID) {
			if a.keyStore != nil {
				var keyErr error
				for attempt := 0; attempt < 3; attempt++ {
					if keyErr = a.keyStore.DeleteDeviceKey(fullID); keyErr == nil {
						break
					}
					time.Sleep(50 * time.Millisecond)
				}
				if keyErr != nil {
					log.Printf("WARN: device key deletion failed for %d: %v", fullID, keyErr)
					keyDeleteFailed = append(keyDeleteFailed, fullID)
				}
			}
			// Notify the MQTT bridge so it immediately rejects any further
			// messages (heartbeats, registrations, verdict requests) from
			// this device without waiting for a process restart.
			if a.bridge != nil {
				a.bridge.MarkDecommissioned(fullID)
			}
			if a.decommStore != nil {
				if err := a.decommStore.SaveDecommissioned(fullID); err != nil {
					log.Printf("[fleet-api] failed to persist decommission tombstone for %d: %v", fullID, err)
				}
			}
			decommissioned++
		} else {
			notFound = append(notFound, uint64(fullID))
		}
	}

	a.emitAudit(auditDecommission,
		batchID,
		fmt.Sprintf("requested:%d decommissioned:%d not_found:%d key_delete_failed:%d",
			len(req.Devices), decommissioned, len(notFound), len(keyDeleteFailed)))

	deadlineExceeded := decommissioned+len(notFound)+len(tenantDenied) < len(req.Devices)

	resp := map[string]any{
		"batch_id":       batchID,
		"requested":      len(req.Devices),
		"decommissioned": decommissioned,
	}
	if len(notFound) > 0 {
		resp["not_found"] = notFound
	}
	if len(tenantDenied) > 0 {
		resp["tenant_denied_count"] = len(tenantDenied)
	}

	if len(keyDeleteFailed) > 0 {
		resp["key_delete_failed"] = keyDeleteFailed
		resp["status"] = "partial_failure"
		resp["error"] = "some device keys could not be deleted — those devices may still authenticate"
		writeJSON(w, http.StatusMultiStatus, resp)
		return
	}

	if deadlineExceeded {
		resp["status"] = "partial_timeout"
		resp["processed"] = decommissioned + len(notFound) + len(tenantDenied)
		writeJSON(w, http.StatusMultiStatus, resp)
		return
	}

	resp["status"] = "completed"
	writeJSON(w, http.StatusOK, resp)
}

// rotateToken handles POST /token/rotate — generates a new 32-byte random
// fleet API token, updates DCLAW_FLEET_API_TOKEN in the process environment,
func (a *API) rotateToken(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		fwdProto := r.Header.Get("X-Forwarded-Proto")
		allowHTTP := a.settings.AllowKeyOverHTTP || os.Getenv("DCLAW_ALLOW_KEY_OVER_HTTP") == "1"
		if isProductionMode() && !(isTrustedProxy(r, a.settings) && fwdProto == "https") && !allowHTTP {
			http.Error(w, `{"error":"token_delivery_requires_tls"}`, http.StatusForbidden)
			return
		}
	}

	a.rotationMu.Lock()
	defer a.rotationMu.Unlock()
	if !a.lastTokenRotation.IsZero() && time.Since(a.lastTokenRotation) < time.Minute {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "token rotation rate limited — try again in 1 minute",
		})
		return
	}

	newToken := make([]byte, 32)
	if _, err := rand.Read(newToken); err != nil {
		log.Printf("[fleet-api] failed to generate random token: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to generate random token",
		})
		return
	}

	newTokenHex := hex.EncodeToString(newToken)

	a.tenantScopesMu.Lock()
	for tok, tid := range a.tenantScopes {
		if tid == 0 {
			delete(a.tenantScopes, tok)
		}
	}
	a.tenantScopes[newTokenHex] = 0
	a.tenantScopesMu.Unlock()

	a.currentToken.Store(&newTokenHex)
	a.lastTokenRotation = time.Now()
	log.Printf("INFO: fleet API token rotated (in-memory only, env var DCLAW_FLEET_API_TOKEN not updated)")

	a.emitAudit(auditTokenRotated, "DCLAW_FLEET_API_TOKEN",
		"Fleet API token rotated — old token is now invalid")

	if r.TLS == nil {
		w.Header().Set("X-Security-Warning", "token-delivered-over-plaintext")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":   newTokenHex,
		"status":  "rotated",
		"warning": "This token is shown once and cannot be retrieved later. Store it securely.",
	})
}

// rotateDeviceKey handles POST /devices/{id}/rotate-key — generates a new 32-byte
func (a *API) rotateDeviceKey(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		fwdProto := r.Header.Get("X-Forwarded-Proto")
		allowHTTP := a.settings.AllowKeyOverHTTP || os.Getenv("DCLAW_ALLOW_KEY_OVER_HTTP") == "1"
		if isProductionMode() && !(isTrustedProxy(r, a.settings) && fwdProto == "https") && !allowHTTP {
			http.Error(w, `{"error":"key_delivery_requires_tls"}`, http.StatusForbidden)
			return
		}
	}

	idStr := r.PathValue("id")
	deviceID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device_id"})
		return
	}

	dev, ok := a.manager.GetDevice(deviceID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	if !a.authorizedForDevice(r, dev.TenantID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	a.rotationMu.Lock()
	if lastRot, exists := a.deviceKeyRotations[deviceID]; exists && time.Since(lastRot) < time.Minute {
		a.rotationMu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "device key rotation rate limited — try again in 1 minute",
		})
		return
	}

	if a.keyStore == nil {
		a.rotationMu.Unlock()
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error": "device key store not configured",
		})
		return
	}

	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		a.rotationMu.Unlock()
		log.Printf("[fleet-api] failed to generate device key for %d: %v", deviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to generate device key",
		})
		return
	}

	if err := a.keyStore.SaveDeviceKey(deviceID, newKey); err != nil {
		a.rotationMu.Unlock()
		log.Printf("[fleet-api] failed to save device key for %d: %v", deviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to save device key",
		})
		return
	}

	a.deviceKeyRotations[deviceID] = time.Now()
	a.rotationMu.Unlock()
	newKeyHex := hex.EncodeToString(newKey)

	a.emitAudit(auditKeyRotated,
		fmt.Sprintf("%d", deviceID),
		"Device key rotated — old key is now invalid")

	if r.TLS == nil {
		w.Header().Set("X-Security-Warning", "key-delivered-over-plaintext")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_id":  deviceID,
		"device_key": newKeyHex,
		"status":     "rotated",
		"warning":    "This key is shown once and cannot be retrieved later. Provision it on the device.",
	})
}

// csrfValueValid checks that a CSRF header value is alphanumeric plus
func csrfValueValid(val string) bool {
	if val == "" || len(val) > 64 {
		return false
	}
	for _, c := range val {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func csrfMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			xrw := r.Header.Get("X-Requested-With")
			xdc := r.Header.Get("X-DefenseClaw-Client")
			if xrw == "" && xdc == "" {
				http.Error(w, `{"error":"missing CSRF header"}`, http.StatusForbidden)
				return
			}
			if xdc != "" && !csrfValueValid(xdc) {
				http.Error(w, `{"error":"invalid X-DefenseClaw-Client header value"}`, http.StatusForbidden)
				return
			}
			if xrw != "" && !csrfValueValid(xrw) {
				http.Error(w, `{"error":"invalid X-Requested-With header value"}`, http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

func securityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		next(w, r)
	}
}

// sanitizeString truncates a string to maxLen bytes and strips control
func sanitizeString(s string, maxLen int) string {
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 32 || r == 127 {
			continue // ASCII control
		}
		if unicode.IsControl(r) {
			continue // Unicode control chars (U+0080-U+009F etc.)
		}
		if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' {
			continue // zero-width characters
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isTrustedProxy returns true if the request comes from a trusted proxy.
// Checks config.yaml fleet.trust_proxy_headers first, env var fallback.
func isTrustedProxy(r *http.Request, settings FleetSettings) bool {
	if settings.TrustProxyHeaders || os.Getenv("DCLAW_TRUST_PROXY_HEADERS") == "1" {
		return true
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isProductionMode returns true when DCLAW_PRODUCTION is "true"/"1" or
func isProductionMode() bool {
	v := os.Getenv("DCLAW_PRODUCTION")
	if v == "true" || v == "1" {
		return true
	}
	devMode := strings.ToLower(os.Getenv("DCLAW_DEV_MODE"))
	if devMode == "off" || devMode == "0" || devMode == "false" {
		return true
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
