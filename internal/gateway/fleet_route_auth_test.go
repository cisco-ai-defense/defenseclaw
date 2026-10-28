// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fleet"
	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
)

func fleetRouteAuthTestAPI(t *testing.T, token string) *fleet.API {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cache := verdict.NewCache(8, func(_, _ uint16, _ [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})
	return fleet.NewAPI(ctx, manager.New(nil), cache, fleet.WithFleetSettings(fleet.FleetSettings{APIToken: token}))
}

func serveFleetRoute(api *APIServer, called *bool, bearer string) int {
	handler := api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/health", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr.Code
}

// TestTokenAuth_FleetRouteExemptionNeedsWiredFleet pins DAMAGE-678 B3: the
// gateway token check is skipped for /api/v1/fleet/ only when Fleet is wired
// with a token, decided per request, never from the environment at startup.
func TestTokenAuth_FleetRouteExemptionNeedsWiredFleet(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", "fleet-token-in-env")

	t.Run("Fleet off keeps the gateway token check", func(t *testing.T) {
		api, called := tokenAuthTestServer(t, "gateway-token")
		if code := serveFleetRoute(api, called, "fleet-token-in-env"); code != http.StatusUnauthorized || *called {
			t.Fatalf("Fleet off: status %d, next called %t; want 401 and no call", code, *called)
		}
	})

	t.Run("Fleet wired with a token uses Fleet auth", func(t *testing.T) {
		api, called := tokenAuthTestServer(t, "gateway-token")
		api.SetFleetAPI(fleetRouteAuthTestAPI(t, "fleet-token"))
		if code := serveFleetRoute(api, called, "fleet-token"); code != http.StatusOK || !*called {
			t.Fatalf("Fleet on: status %d, next called %t; want the Fleet handler", code, *called)
		}
	})
}

func TestFleetAPIAuthConfigured(t *testing.T) {
	var none *fleet.API
	if none.AuthConfigured() {
		t.Fatal("a nil Fleet API reports configured auth")
	}
	t.Setenv("DCLAW_FLEET_API_TOKEN", "")
	t.Setenv("DCLAW_FLEET_TENANT_TOKENS", "")
	if fleetRouteAuthTestAPI(t, "").AuthConfigured() {
		t.Fatal("a Fleet API with no token reports configured auth")
	}
	if !fleetRouteAuthTestAPI(t, "fleet-token").AuthConfigured() {
		t.Fatal("a Fleet API with a token reports no auth")
	}
}

// GAP-0569: a body-less fleet POST without Content-Type gets 415 from the
// gateway, as the fleet API page says.
func TestFleetPostWithoutContentTypeIsDocumented415(t *testing.T) {
	api, _ := tokenAuthTestServer(t, "gateway-token")
	api.SetFleetAPI(fleetRouteAuthTestAPI(t, "fleet-token"))
	handler := api.tokenAuth(api.apiCSRFProtect(http.StripPrefix("/api/v1/fleet", api.fleetAPI.Handler())))
	const want = `{"error":"Content-Type must be application/json"}`
	for _, path := range []string{"/api/v1/fleet/token/rotate", "/api/v1/fleet/devices/1/rotate-key"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer fleet-token")
		req.Header.Set("X-DefenseClaw-Client", "true")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnsupportedMediaType || strings.TrimSpace(rr.Body.String()) != want {
			t.Fatalf("POST %s: status=%d body=%q", path, rr.Code, rr.Body.String())
		}
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs-site", "content", "docs", "edge-connector", "api-reference.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	_, table, _ := strings.Cut(string(raw), "## Common status codes")
	if !strings.Contains(table, "| `415` |") || !strings.Contains(string(raw), "`415` with `"+want+"`") {
		t.Fatal("api-reference.mdx does not document the 415 the gateway returns")
	}
}
