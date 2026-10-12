// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// TestStandaloneHealthShowsThePolicyBlockOnlyToAnAdministrator pins
// GAP-0481: an ordinary account's unauthenticated /health on a standalone
// host carried the host-wide effective digest and config generation. Only
// the hook socket's root or service-account peer (the Linux and macOS
// lifecycle) and a caller with the gateway token (the Windows lifecycle)
// read it there; a per-user gateway keeps it for every caller.
//
// GAP-0666: the same caller also read provenance.content_hash, the SHA-256
// of the administrator's config file, and the config reload details; it now
// reads liveness and the binary version only.
func TestStandaloneHealthShowsThePolicyBlockOnlyToAnAdministrator(t *testing.T) {
	prev := liveGeneration.Load()
	t.Cleanup(func() { liveGeneration.Store(prev) })
	version.SetContentHash([]byte("dccert-block-marker admin config"))
	t.Cleanup(func() { version.SetContentHash(nil) })
	standalone := &config.Config{DeploymentMode: "managed_enterprise"}
	standalone.Enterprise.Profile = managed.ProfileStandalone
	standalone.Gateway.Token = "gw-token"
	perUser := &config.Config{}
	perUser.Gateway.Token = "gw-token"
	ordinaryUID := 94404078
	if ordinaryUID == os.Geteuid() {
		ordinaryUID++
	}
	viaSocket := func(uid int) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			return r.WithContext(context.WithValue(r.Context(), managedHookPeerContextKey{}, managedHookPeer{UID: uid}))
		}
	}
	withHeader := func(key, value string) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request { r.Header.Set(key, value); return r }
	}
	for _, test := range []struct {
		name    string
		cfg     *config.Config
		request func(*http.Request) *http.Request
		want    bool
	}{
		{"standalone, no credential", standalone, nil, false},
		{"standalone, wrong token", standalone, withHeader("X-DefenseClaw-Token", "other"), false},
		{"standalone, ordinary hook-socket peer", standalone, viaSocket(ordinaryUID), false},
		{"standalone, gateway token", standalone, withHeader("X-DefenseClaw-Token", "gw-token"), true},
		{"standalone, bearer gateway token", standalone, withHeader("Authorization", "Bearer gw-token"), true},
		{"standalone, root hook-socket peer", standalone, viaSocket(0), true},
		{"standalone, service-account hook-socket peer", standalone, viaSocket(os.Geteuid()), true},
		{"per-user, no credential", perUser, nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			liveGeneration.Store(&Generation{Config: test.cfg, Digest: "sha256:host", N: 7, ConfigGen: 83})
			request := httptest.NewRequest(http.MethodGet, "/health", nil)
			if test.request != nil {
				request = test.request(request)
			}
			response := httptest.NewRecorder()
			health := NewSidecarHealth()
			health.SetConfig(StateError, "yaml: line 12: dccert-block-marker", map[string]interface{}{
				"path": "/etc/defenseclaw/config.yaml", "generation": 4, "changed": []string{"guardrail"},
			})
			(&APIServer{health: health, scannerCfg: test.cfg}).handleHealth(response, request)
			var body struct {
				Policy     json.RawMessage        `json:"policy"`
				Provenance map[string]interface{} `json:"provenance"`
				Config     SubsystemHealth        `json:"config"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if got := body.Policy != nil; got != test.want {
				t.Fatalf("policy block published = %v, want %v: %s", got, test.want, response.Body.String())
			}
			_, hash := body.Provenance["content_hash"]
			_, generation := body.Provenance["generation"]
			if hash != test.want || generation != test.want || body.Provenance["binary_version"] == nil {
				t.Fatalf("provenance = %v, want the config fingerprint only for an administrator (%v)", body.Provenance, test.want)
			}
			if got := body.Config.Details != nil; got != test.want || body.Config.State != StateError ||
				test.want != (body.Config.LastError == "yaml: line 12: dccert-block-marker") {
				t.Fatalf("config health = %+v, want state and the details only for an administrator (%v)", body.Config, test.want)
			}
		})
	}
}
