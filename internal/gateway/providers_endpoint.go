// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/defenseclaw/defenseclaw/internal/configs"
)

// providersListResponse is the wire shape returned by GET
// /v1/config/providers. It intentionally mirrors
// configs.ProvidersConfig so the TS interceptor can use the same
// shape as the embedded providers.json it ships with.
type providersListResponse struct {
	Providers   []configs.Provider `json:"providers"`
	OllamaPorts []int              `json:"ollama_ports"`
	// OverlayPath is the resolved filesystem location of the
	// operator overlay (custom-providers.json) that was (or
	// would be) merged. Reported so operators can see where to
	// add a new provider without reading source.
	OverlayPath string `json:"overlay_path,omitempty"`
	// OverlayApplied is true when OverlayPath exists on disk and
	// was parsed successfully. False when the file is missing or
	// when a parse error was encountered (see stderr).
	OverlayApplied bool `json:"overlay_applied"`
}

// registerProviderRoutes installs provider management on the sidecar mux. Kept
// separate from Run so route/auth behavior can be tested without opening any
// listener (especially the guardrail proxy listener).
func (a *APIServer) registerProviderRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/config/providers", a.handleListProviders)
	mux.HandleFunc("/v1/config/providers/reload", a.handleReloadProviders)
}

// handleListProviders exposes the merged provider registry over HTTP.
// Used by the TypeScript fetch-interceptor at bootstrap so custom
// providers (added via `defenseclaw setup provider add` or by hand-
// editing ~/.defenseclaw/custom-providers.json) are honored without
// rebuilding the TS bundle.
//
// Proxy compatibility wrapper. Provider metadata is configuration state, so
// both the legacy proxy route and the sidecar management route require the
// configured gateway token.
func (p *GuardrailProxy) handleListProviders(w http.ResponseWriter, r *http.Request) {
	if !p.authenticateRequest(w, r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	serveListProviders(w, r)
}

// handleListProviders exposes the same registry through the authenticated
// sidecar management API. Authentication is enforced by APIServer.tokenAuth.
func (a *APIServer) handleListProviders(w http.ResponseWriter, r *http.Request) {
	serveListProviders(w, r)
}

func serveListProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reg, _, ports := providerRegistrySnapshot()
	resp := providersListResponse{
		OllamaPorts:    ports,
		OverlayPath:    configs.CustomProvidersPath(),
		OverlayApplied: overlayExists(configs.CustomProvidersPath()),
	}
	if reg != nil {
		resp.Providers = reg.Providers
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// handleReloadProviders re-reads providers.json + the overlay and
// swaps the active registry. Authenticated (same X-DC-Auth flow as
// every mutating endpoint) so a non-cooperating local process can't
// roll the provider list out from under running requests.
//
// On success emits an EventGatewayLifecycle event ("provider-reload")
// so operators can see in gateway.jsonl exactly when an overlay took
// effect.
func (p *GuardrailProxy) handleReloadProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !p.authenticateRequest(w, r) {
		// authenticateRequest only emits the auth-failure audit
		// event; it does not write a status. The 401 surface is
		// our responsibility.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// follow-up: promote peeked agent identity now that auth
	// succeeded so emitLifecycleReload below stamps a stable
	// agent_instance_id on its lifecycle event.
	r = r.WithContext(PromoteSessionIfAuthenticated(r.Context()))
	serveReloadProviders(w, r)
}

// handleReloadProviders exposes provider reload through the authenticated
// sidecar management API. It intentionally does not depend on a
// GuardrailProxy, so hook-only deployments keep the proxy listener disabled.
func (a *APIServer) handleReloadProviders(w http.ResponseWriter, r *http.Request) {
	serveReloadProviders(w, r)
}

func serveReloadProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := ReloadProviderRegistry(); err != nil {
		// Log full error server-side for operators; return a
		// generic message to the caller so a malformed overlay
		// (or any loader path) cannot leak filesystem details
		// to an authenticated-but-untrusted local client.
		fmt.Fprintf(os.Stderr, "[defenseclaw] provider reload failed: %v\n", err)
		http.Error(w, "reload failed", http.StatusInternalServerError)
		return
	}
	reg, _, _ := providerRegistrySnapshot()
	providerCount := 0
	if reg != nil {
		providerCount = len(reg.Providers)
	}
	ctx := r.Context()
	emitProvidersReloadLifecycle(ctx, providerCount)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":          "ok",
		"provider_count":  providerCount,
		"overlay_path":    configs.CustomProvidersPath(),
		"overlay_applied": overlayExists(configs.CustomProvidersPath()),
	})
}

// overlayExists is a tiny helper isolated for testability.
func overlayExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// emitLifecycleReload writes a gateway lifecycle event so the TUI
// and any downstream sink can surface "operator reloaded providers"
// as its own audit trail row. Delegates to emitLifecycle so the
// caller-meaningful "reload" transition gets normalized to the
// schema-valid "completed" while the original intent survives on
// details.transition_raw.
func emitProvidersReloadLifecycle(ctx context.Context, providerCount int) {
	emitLifecycle(ctx, "providers", "reload", map[string]string{
		"provider_count": strconv.Itoa(providerCount),
		"overlay_path":   configs.CustomProvidersPath(),
	})
}
