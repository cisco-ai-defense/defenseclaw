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
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/policy"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
	"github.com/google/uuid"
)

const (
	auditDeviceRegistered   = string(audit.ActionFleetDeviceRegistered)
	auditDeviceReregistered = string(audit.ActionFleetDeviceReregistered)
	auditPolicyPush         = string(audit.ActionFleetPolicyPush)
	auditPolicyEmergency    = string(audit.ActionFleetPolicyEmergency)
	auditThreatIntel        = string(audit.ActionFleetThreatIntel)
	auditDecommission       = string(audit.ActionFleetDeviceDecommission)
	auditDecommissionAllow  = string(audit.ActionFleetDeviceDecommissionAuthorized)
	auditCredentialAllow    = string(audit.ActionFleetDeviceCredentialProvisionAuthorized)
	auditTokenRotated       = string(audit.ActionFleetTokenRotated)
	auditKeyRotated         = string(audit.ActionFleetDeviceKeyRotated)
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
	deviceMutationMu   sync.Mutex // serializes registration/decommission and bridge tombstone updates
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

// requireCredentialAudit refuses credential changes unless the mandatory
// audit event was accepted by the durable observability pipeline.
func (a *API) requireCredentialAudit(action, target, details string) error {
	if a.audit == nil {
		return fmt.Errorf("fleet audit emitter unavailable")
	}
	return a.audit.LogAction(action, target, details)
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
// Returns (tenantID, true) on success. tenantID 0 means admin (global scope).
// Returns (0, false) when authentication fails.
func (a *API) tenantFromRequest(r *http.Request) (uint16, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return 0, false
	}
	got := strings.TrimPrefix(auth, "Bearer ")
	if got == "" {
		return 0, false
	}

	tp := a.currentToken.Load()
	if tp != nil && *tp != "" && subtle.ConstantTimeCompare([]byte(got), []byte(*tp)) == 1 {
		return 0, true
	}

	a.tenantScopesMu.RLock()
	for tok, tid := range a.tenantScopes {
		if tok == "" || tid == 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1 {
			a.tenantScopesMu.RUnlock()
			return tid, true
		}
	}
	a.tenantScopesMu.RUnlock()

	return 0, false
}

// authorizedForDevice checks if the request is authorized for this device's tenant.
func (a *API) authorizedForDevice(r *http.Request, tenantID uint16) bool {
	tid, ok := a.tenantFromRequest(r)
	if !ok {
		return false
	}
	return tid == 0 || tid == tenantID
}

// Handler returns the http.Handler for mounting.
func (a *API) Handler() http.Handler {
	return a.mux
}

// AuthConfigured reports whether the Fleet API has a token that can
// authenticate a request. A nil API (Fleet off) has none.
func (a *API) AuthConfigured() bool {
	if a == nil {
		return false
	}
	if tp := a.currentToken.Load(); tp != nil && *tp != "" {
		return true
	}
	a.tenantScopesMu.RLock()
	defer a.tenantScopesMu.RUnlock()
	for token, tenantID := range a.tenantScopes {
		if token != "" && tenantID != 0 {
			return true
		}
	}
	return false
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
		for tok, tenantID := range a.tenantScopes {
			if tok == "" || tenantID == 0 {
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
			if len(parts) == 2 && parts[0] != "" && parts[0] != token {
				if tid, err := strconv.ParseUint(parts[1], 10, 16); err == nil && tid != 0 {
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
	a.mux.HandleFunc("GET /health", wrap(a.getFleetHealth))
	a.mux.HandleFunc("POST /policy/simulate", wrap(a.simulatePolicy))
	a.mux.HandleFunc("POST /policy/push", wrap(a.pushPolicy))
	a.mux.HandleFunc("GET /policy/versions", wrap(a.listPolicyVersions))
	a.mux.HandleFunc("POST /policy/emergency", wrap(a.pushEmergency))
	a.mux.HandleFunc("POST /threat-intel/push", wrap(a.pushThreatIntel))
	a.mux.HandleFunc("POST /devices/decommission-batch", wrap(a.decommissionBatch))
	a.mux.HandleFunc("POST /token/rotate", wrap(a.rotateToken))
	a.mux.HandleFunc("POST /devices/{id}/rotate-key", wrap(a.rotateDeviceKey))
	a.mux.HandleFunc("GET /metrics", wrap(a.metrics))
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

	tid, ok := a.tenantFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	allDevices := a.manager.ListDevices()
	filtered := allDevices[:0:0]
	summary := map[string]int{"total": 0, "online": 0, "offline": 0, "degraded": 0, "lockdown": 0}
	for _, d := range allDevices {
		if tid != 0 && d.TenantID != tid {
			continue
		}
		filtered = append(filtered, d)
		summary["total"]++
		switch d.Status {
		case manager.StatusOnline:
			summary["online"]++
		case manager.StatusOffline:
			summary["offline"]++
		case manager.StatusDegraded:
			summary["degraded"]++
		case manager.StatusLockdown:
			summary["lockdown"]++
		}
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
		"summary": summary,
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
	a.deviceMutationMu.Lock()
	defer a.deviceMutationMu.Unlock()
	fullID := manager.ComposeID(req.TenantID, req.FleetID, req.DeviceID)
	wasDecommissioned := false
	if a.decommStore != nil {
		var err error
		wasDecommissioned, err = a.decommStore.IsDecommissioned(fullID)
		if err != nil {
			log.Printf("[fleet-api] decommission store check failed for %d: %v", fullID, err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "decommission store temporarily unavailable"})
			return
		}
		if wasDecommissioned && !req.ForceReregister {
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "device was decommissioned — set force_reregister=true to re-enable",
			})
			return
		}
	}
	// Validate the credential delivery channel before RegisterDevice can change
	// in-memory metadata or durable state on either registration path.
	if !credentialDeliveryAllowed(r, a.settings) {
		http.Error(w, `{"error":"key_delivery_requires_tls"}`, http.StatusForbidden)
		return
	}
	if a.keyStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "device credential store unavailable"})
		return
	}
	if r.TLS == nil {
		w.Header().Set("X-Security-Warning", "key-delivered-over-plaintext")
	}

	// Production Fleet shares one SQLiteStore for manager, credentials, and
	// tombstones. Reject split stores: rollback could otherwise leave a device
	// unable to authenticate after changing its key.
	deviceStore, hasDeviceStore := a.keyStore.(manager.DeviceStore)
	_, hasAtomicStore := a.keyStore.(manager.DeviceRegistrationStore)
	tombstoneStore, hasTombstoneStore := a.keyStore.(DecommissionStore)
	if !hasDeviceStore || !hasAtomicStore || !a.manager.StoreIs(deviceStore) ||
		(a.decommStore != nil && (!hasTombstoneStore || a.decommStore != tombstoneStore)) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "atomic registration store unavailable"})
		return
	}
	deviceKey := make([]byte, 32)
	if _, err := rand.Read(deviceKey); err != nil {
		log.Printf("[fleet-api] failed to generate device key: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate device key"})
		return
	}
	if err := a.requireCredentialAudit(auditCredentialAllow, fmt.Sprintf("%d", fullID),
		fmt.Sprintf("tenant=%d fleet=%d force_reregister=%t", req.TenantID, req.FleetID, req.ForceReregister)); err != nil {
		log.Printf("[fleet-api] device registration refused because audit failed for %d: %v", fullID, err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "credential audit unavailable"})
		return
	}
	dev, reregistered, err := a.manager.RegisterDeviceWithCredential(
		req.TenantID, req.FleetID, req.DeviceID,
		req.HWProfile, req.FWVersion, req.PolicyVersion, req.Capabilities,
		deviceKey, req.ForceReregister,
	)
	if err != nil {
		if errors.Is(err, ErrDeviceDecommissioned) {
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "device was decommissioned — set force_reregister=true to re-enable",
			})
			return
		}
		log.Printf("[fleet-api] atomic device registration failed for %d: %v", fullID, err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "device registration store temporarily unavailable"})
		return
	}

	if a.bridge != nil {
		a.bridge.ClearDecommissioned(dev.DeviceID)
	}
	if reregistered {
		a.emitAudit(auditDeviceReregistered, fmt.Sprintf("%d", dev.DeviceID),
			fmt.Sprintf("tenant:%d fleet:%d", req.TenantID, req.FleetID))
		writeJSON(w, http.StatusOK, map[string]any{"device": dev, "device_key": hex.EncodeToString(deviceKey)})
		return
	}
	a.emitAudit(auditDeviceRegistered, fmt.Sprintf("%d", dev.DeviceID),
		fmt.Sprintf("tenant=%d fleet=%d hw=%s fw=%s policy_v=%d",
			req.TenantID, req.FleetID, req.HWProfile, req.FWVersion, req.PolicyVersion))
	writeJSON(w, http.StatusCreated, map[string]any{"device": dev, "device_key": hex.EncodeToString(deviceKey)})
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

func (a *API) getFleetHealth(w http.ResponseWriter, r *http.Request) {
	tid, ok := a.tenantFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if tid == 0 {
		health := a.manager.GetFleetHealth()
		hits, misses, cacheSize := a.cache.Stats()
		writeJSON(w, http.StatusOK, map[string]any{
			"fleet": health, "cache_hits": hits, "cache_misses": misses, "cache_size": cacheSize,
		})
		return
	}
	health := manager.FleetHealth{PolicyVersions: make(map[uint16]int)}
	for _, dev := range a.manager.ListDevices() {
		if dev.TenantID != tid {
			continue
		}
		health.TotalDevices++
		health.PolicyVersions[dev.PolicyVersion]++
		switch dev.Status {
		case manager.StatusOnline:
			health.Online++
		case manager.StatusOffline:
			health.Offline++
		case manager.StatusDegraded:
			health.Degraded++
		case manager.StatusLockdown:
			health.Lockdown++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"fleet": health})
}

func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	if tid, ok := a.tenantFromRequest(r); !ok || tid != 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "fleet metrics require admin credentials"})
		return
	}
	MetricsHandler(w, r)
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

	callerTenant, ok := a.tenantFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
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
		if errors.Is(err, policy.ErrPolicyVersionExhausted) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "policy version exhausted at 65534; provision a new device policy lineage"})
			return
		}
		if errors.Is(err, policy.ErrPolicyTooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "policy exceeds maximum size of 64KB"})
			return
		}
		if errors.Is(err, policy.ErrMalformedPolicy) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "malformed policy"})
			return
		}
		if errors.Is(err, policy.ErrInvalidPolicy) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid policy or profile"})
			return
		}
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

	callerTenant, ok := a.tenantFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
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
	if versions == nil {
		versions = []policy.PolicyRecord{}
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

	callerTenant, ok := a.tenantFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
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

	if tid, ok := a.tenantFromRequest(r); !ok || tid != 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "threat intel push requires admin access",
		})
		return
	}

	var req struct {
		RevokeAllowHash []string `json:"revoke_allow_hashes"`
		Emergency       bool     `json:"emergency"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "http: request body too large" {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	var hashes [][32]byte
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
		hashes = append(hashes, hash)
	}
	// Validate the full request before changing any gateway cache entry.
	if req.Emergency {
		a.cache.FlushAll()
	}
	for _, hash := range hashes {
		a.cache.Invalidate(hash)
	}

	// Device subscriptions are scoped to their tenant/fleet. Publish one
	// REVOKE_SESSIONS for each registered pair, including offline devices that
	// may reconnect later. Broker publication still does not prove receipt.
	type fleetTarget struct{ tenant, fleet uint16 }
	var targets []fleetTarget
	var failed []string
	published := 0
	if len(hashes) > 0 || req.Emergency {
		seen := make(map[fleetTarget]struct{})
		for _, dev := range a.manager.ListDevices() {
			if dev.TenantID == 0 || dev.FleetID == 0 {
				continue
			}
			pair := fleetTarget{dev.TenantID, dev.FleetID}
			if _, ok := seen[pair]; !ok {
				seen[pair] = struct{}{}
				targets = append(targets, pair)
			}
		}
		sort.Slice(targets, func(i, j int) bool {
			if targets[i].tenant != targets[j].tenant {
				return targets[i].tenant < targets[j].tenant
			}
			return targets[i].fleet < targets[j].fleet
		})
		for _, pair := range targets {
			if a.policy == nil {
				failed = append(failed, fmt.Sprintf("%d/%d", pair.tenant, pair.fleet))
				continue
			}
			if err := a.policy.DistributeEmergency(r.Context(), uint64(pair.tenant), uint64(pair.fleet), policy.EmergencyRevokeSessions); err != nil {
				log.Printf("[fleet-api] threat-intel: device cache flush publish failed for %d/%d: %v", pair.tenant, pair.fleet, err)
				failed = append(failed, fmt.Sprintf("%d/%d", pair.tenant, pair.fleet))
				continue
			}
			published++
		}
	}

	a.emitAudit(auditThreatIntel,
		fmt.Sprintf("threat-intel-push.%d", len(req.RevokeAllowHash)),
		fmt.Sprintf("revoked_count:%d emergency:%v", len(req.RevokeAllowHash), req.Emergency))

	resp := map[string]any{"revoked": len(hashes)}
	if len(hashes) > 0 || req.Emergency {
		resp["device_cache_flush_published"] = published
		resp["device_cache_flush_target_fleets"] = len(targets)
		resp["device_cache_flushed"] = false
		resp["warning"] = "MQTT publication does not confirm device receipt; offline devices may keep cached verdicts until reconnect or TTL expiry"
	}
	if len(failed) > 0 {
		resp["device_cache_flush_failed"] = failed
		writeJSON(w, http.StatusMultiStatus, resp)
		return
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
	a.deviceMutationMu.Lock()
	defer a.deviceMutationMu.Unlock()

	batchID := uuid.New().String()
	decommissioned := 0
	var notFound []uint64
	var persistenceFailed []uint64
	var auditFailed []uint64
	deadline := time.Now().Add(30 * time.Second)

	requestTID, ok := a.tenantFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var tenantDenied []uint64
	sqliteKeys, keysAreSQLite := a.keyStore.(*SQLiteStore)
	sqliteTombstones, tombstonesAreSQLite := a.decommStore.(*SQLiteStore)
	useAtomicStore := keysAreSQLite && tombstonesAreSQLite &&
		sqliteKeys == sqliteTombstones && a.manager.StoreIs(sqliteKeys)

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
		if _, exists := a.manager.GetDevice(fullID); !exists {
			notFound = append(notFound, fullID)
			continue
		}
		if err := a.requireCredentialAudit(auditDecommissionAllow, fmt.Sprintf("%d", fullID),
			fmt.Sprintf("batch=%s tenant=%d fleet=%d", batchID, d.TenantID, d.FleetID)); err != nil {
			log.Printf("[fleet-api] device decommission refused because audit failed for %d: %v", fullID, err)
			auditFailed = append(auditFailed, fullID)
			continue
		}
		if useAtomicStore {
			removed, err := a.manager.DecommissionDeviceAtomically(d.TenantID, d.FleetID, d.DeviceID)
			if err != nil {
				log.Printf("[fleet-api] atomic decommission failed for %d: %v", fullID, err)
				persistenceFailed = append(persistenceFailed, fullID)
				continue
			}
			if !removed {
				notFound = append(notFound, fullID)
				continue
			}
			if a.bridge != nil {
				a.bridge.MarkDecommissioned(fullID)
			}
			decommissioned++
			continue
		}

		// Durable device, key, and tombstone state must share an atomic
		// store. A split-store rollback can fail after key deletion, so only
		// an entirely in-memory test instance may use the simple path.
		if a.keyStore != nil || a.decommStore != nil || !a.manager.StoreIs(nil) {
			persistenceFailed = append(persistenceFailed, fullID)
			continue
		}
		removed, err := a.manager.DecommissionDeviceChecked(d.TenantID, d.FleetID, d.DeviceID)
		if err != nil {
			log.Printf("[fleet-api] device persistence delete failed for %d: %v", fullID, err)
			persistenceFailed = append(persistenceFailed, fullID)
			continue
		}
		if removed {
			if a.bridge != nil {
				a.bridge.MarkDecommissioned(fullID)
			}
			decommissioned++
		} else {
			notFound = append(notFound, uint64(fullID))
		}
	}

	a.emitAudit(auditDecommission,
		batchID,
		fmt.Sprintf("requested:%d decommissioned:%d not_found:%d persistence_failed:%d audit_failed:%d",
			len(req.Devices), decommissioned, len(notFound), len(persistenceFailed), len(auditFailed)))

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

	if len(persistenceFailed) > 0 {
		resp["persistence_failed"] = persistenceFailed
	}
	if len(auditFailed) > 0 {
		resp["audit_failed"] = auditFailed
	}
	if len(persistenceFailed)+len(auditFailed)+len(tenantDenied) > 0 {
		resp["status"] = "partial_failure"
		resp["error"] = "some devices were not decommissioned"
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
	tid, ok := a.tenantFromRequest(r)
	if !ok || tid != 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token rotation requires admin credentials"})
		return
	}
	if r.TLS == nil {
		if !credentialDeliveryAllowed(r, a.settings) {
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
	if err := a.requireCredentialAudit(auditTokenRotated, "DCLAW_FLEET_API_TOKEN",
		"Fleet API token rotation authorized — old token will be invalidated"); err != nil {
		log.Printf("[fleet-api] token rotation refused because audit failed: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "credential audit unavailable"})
		return
	}

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
	callerTID, ok := a.tenantFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "device key rotation requires valid credentials"})
		return
	}
	_ = callerTID
	if r.TLS == nil {
		if !credentialDeliveryAllowed(r, a.settings) {
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
	if err := a.requireCredentialAudit(auditKeyRotated,
		fmt.Sprintf("%d", deviceID),
		"Device key rotation authorized — old key will be invalidated"); err != nil {
		a.rotationMu.Unlock()
		log.Printf("[fleet-api] device key rotation refused because audit failed: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "credential audit unavailable"})
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
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !alnum && c != '-' {
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
// Only a configured local reverse proxy may attest to the outer TLS hop.
func isTrustedProxy(r *http.Request, settings FleetSettings) bool {
	if !settings.TrustProxyHeaders {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// credentialDeliveryAllowed requires a private transport unless the gateway's
// resolved Fleet settings explicitly permit plaintext credential delivery.
func credentialDeliveryAllowed(r *http.Request, settings FleetSettings) bool {
	return r.TLS != nil || settings.AllowKeyOverHTTP ||
		(isTrustedProxy(r, settings) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
