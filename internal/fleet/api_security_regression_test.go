// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
	"github.com/defenseclaw/defenseclaw/internal/fleet/policy"
	"github.com/defenseclaw/defenseclaw/internal/fleet/verdict"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

type failingCredentialAudit struct{ calls int }

type passingCredentialAudit struct{ actions []string }

func (a *passingCredentialAudit) LogAction(action, _, _ string) error {
	a.actions = append(a.actions, action)
	return nil
}
func (*passingCredentialAudit) LogAlert(_, _, _ string, _ map[string]any) error { return nil }

type failSelectedEmergencyPublish struct{ *apiMockMQTTClient }

func (f *failSelectedEmergencyPublish) Publish(ctx context.Context, topic string, qos byte, payload []byte) error {
	if strings.Contains(topic, "/2/1/ota/emergency") {
		return errors.New("injected broker publish failure")
	}
	return f.apiMockMQTTClient.Publish(ctx, topic, qos, payload)
}

func (a *failingCredentialAudit) LogAction(_, _, _ string) error {
	a.calls++
	return errors.New("injected mandatory audit failure")
}
func (*failingCredentialAudit) LogAlert(_, _, _ string, _ map[string]any) error { return nil }

func securityTestCache() *verdict.Cache {
	return verdict.NewCache(10, func(_, _ uint16, _ [32]byte) (verdict.Action, uint8) {
		return verdict.ActionAllow, 0
	})
}

func securitySQLiteDir(t *testing.T) string {
	t.Helper()
	// A native Windows elevated token can make TempDir Administrators-owned.
	// A newly created child gets the current user's private DACL and owner.
	dir := filepath.Join(t.TempDir(), "fleet-state")
	if err := safefile.ProtectDirectory(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func securityTestRequest(api *API, method, path, token, body string, tlsEnabled bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if method == http.MethodPost {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.Header.Set("Content-Type", "application/json")
	}
	if tlsEnabled {
		req.TLS = &tls.ConnectionState{}
	}
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, req)
	return recorder
}

func TestFleetRegistrationThroughLocalTLSProxy(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", testFleetToken)
	for _, tc := range []struct {
		name       string
		trustProxy bool
		wantStatus int
	}{
		{"default refuses forwarded TLS", false, http.StatusForbidden},
		{"documented proxy setting delivers key", true, http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store := NewMemoryStore()
			mgr := manager.New(nil)
			mgr.SetStore(store)
			api := NewAPI(ctx, mgr, securityTestCache(), WithDeviceKeyStore(store),
				WithAuditEmitter(&passingCredentialAudit{}),
				WithFleetSettings(FleetSettings{APIToken: testFleetToken, TrustProxyHeaders: tc.trustProxy}))
			backend := httptest.NewServer(api.Handler())
			defer backend.Close()
			backendURL, err := url.Parse(backend.URL)
			if err != nil {
				t.Fatal(err)
			}
			proxy := &httputil.ReverseProxy{Rewrite: func(req *httputil.ProxyRequest) {
				req.SetURL(backendURL)
				req.Out.URL.Path = strings.TrimPrefix(req.In.URL.Path, "/api/v1/fleet")
				req.Out.Header.Set("X-Forwarded-Proto", "https")
			}}
			tlsProxy := httptest.NewTLSServer(proxy)
			defer tlsProxy.Close()

			body := strings.NewReader(`{"tenant_id":1,"fleet_id":1,"device_id":42}`)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost,
				tlsProxy.URL+"/api/v1/fleet/devices", body)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+testFleetToken)
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
			response, err := tlsProxy.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var got map[string]any
			if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.wantStatus {
				t.Fatalf("status=%d want=%d response=%v", response.StatusCode, tc.wantStatus, got)
			}
			if tc.trustProxy {
				if key, ok := got["device_key"].(string); !ok || len(key) != 64 {
					t.Fatalf("registration did not deliver a device key: %v", got)
				}
			} else if _, ok := mgr.GetDevice(manager.ComposeID(1, 1, 42)); ok {
				t.Fatal("TLS proxy was trusted without fleet.trust_proxy_headers")
			}
		})
	}
}

func TestFleetZeroTenantTokenCannotActAsAdmin(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", "admin-review")
	t.Setenv("DCLAW_FLEET_TENANT_TOKENS", "tenant1:1,tenantzero:0,tenantmax:65535")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := manager.New(nil)
	for _, tenant := range []uint16{1, 2, 65535} {
		if _, err := mgr.RegisterDevice(tenant, 1, 42, "sbc", "1", 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	store := policy.NewMemoryPolicyStore()
	if err := store.SavePolicy(2, 1, 7, []byte("foreign"), []byte("sig"), "standard"); err != nil {
		t.Fatal(err)
	}
	signer, err := policy.NewHMACSigner(bytes.Repeat([]byte{0xA7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	api := NewAPI(ctx, mgr, securityTestCache(), WithPolicyService(policy.NewService(store, signer, nil, nil)), WithAuditEmitter(&passingCredentialAudit{}))
	id2 := manager.ComposeID(2, 1, 42)
	idMax := manager.ComposeID(65535, 1, 42)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/devices", ""},
		{http.MethodGet, "/policy/versions?tenant_id=2&fleet_id=1", ""},
		{http.MethodPost, "/devices/decommission-batch", `{"devices":[{"tenant_id":2,"fleet_id":1,"device_id":42}]}`},
	} {
		got := securityTestRequest(api, tc.method, tc.path, "tenantzero", tc.body, true)
		if got.Code != http.StatusUnauthorized {
			t.Fatalf("tenant-zero %s %s status=%d body=%s", tc.method, tc.path, got.Code, got.Body.String())
		}
	}
	if _, exists := mgr.GetDevice(id2); !exists {
		t.Fatal("tenant-zero request decommissioned another tenant")
	}
	if got := securityTestRequest(api, http.MethodGet, fmt.Sprintf("/devices/%d", idMax), "tenantmax", "", true); got.Code != http.StatusOK {
		t.Fatalf("tenant 65535 own device status=%d", got.Code)
	}
	if got := securityTestRequest(api, http.MethodGet, "/devices", "admin-review", "", true); got.Code != http.StatusOK {
		t.Fatalf("admin device list status=%d", got.Code)
	}
	var scoped struct {
		Total   int            `json:"total"`
		Summary map[string]int `json:"summary"`
	}
	response := securityTestRequest(api, http.MethodGet, "/devices", "tenant1", "", true)
	if err := json.Unmarshal(response.Body.Bytes(), &scoped); err != nil {
		t.Fatal(err)
	}
	if scoped.Total != 1 || scoped.Summary["total"] != 1 || scoped.Summary["online"] != 1 {
		t.Fatalf("tenant scope leaked global summary: %+v", scoped)
	}
	health := securityTestRequest(api, http.MethodGet, "/health", "tenant1", "", true)
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"total_devices":1`) ||
		strings.Contains(health.Body.String(), `"cache_hits"`) {
		t.Fatalf("tenant health leaked global fleet/cache metrics: status=%d body=%s", health.Code, health.Body.String())
	}
	if got := securityTestRequest(api, http.MethodGet, "/metrics", "tenant1", "", true); got.Code != http.StatusForbidden {
		t.Fatalf("tenant global Prometheus metrics status=%d body=%s", got.Code, got.Body.String())
	}
	if got := securityTestRequest(api, http.MethodGet, "/metrics", "admin-review", "", true); got.Code != http.StatusOK {
		t.Fatalf("admin Prometheus metrics status=%d", got.Code)
	}
	mixed := `{"devices":[{"tenant_id":1,"fleet_id":1,"device_id":42},{"tenant_id":2,"fleet_id":1,"device_id":42}]}`
	if got := securityTestRequest(api, http.MethodPost, "/devices/decommission-batch", "tenant1", mixed, true); got.Code != http.StatusMultiStatus ||
		!strings.Contains(got.Body.String(), `"decommissioned":1`) || !strings.Contains(got.Body.String(), `"tenant_denied_count":1`) {
		t.Fatalf("mixed tenant batch hid skipped device: status=%d body=%s", got.Code, got.Body.String())
	}
	if _, exists := mgr.GetDevice(id2); !exists {
		t.Fatal("tenant 1 mixed batch decommissioned tenant 2")
	}
}

func TestFleetRegistrationRejectsPlaintextBeforeMutation(t *testing.T) {
	t.Setenv("DCLAW_DEV_MODE", "on")
	t.Setenv("DCLAW_ALLOW_KEY_OVER_HTTP", "1")
	t.Setenv("DCLAW_FLEET_API_TOKEN", "admin-review")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStore()
	mgr := manager.New(nil)
	mgr.SetStore(store)
	api := NewAPI(ctx, mgr, securityTestCache(), WithDeviceKeyStore(store), WithAuditEmitter(&passingCredentialAudit{}))
	path := "/devices"
	body := `{"tenant_id":1,"fleet_id":1,"device_id":42,"fw_version":"v2"}`
	if got := securityTestRequest(api, http.MethodPost, path, "admin-review", body, false); got.Code != http.StatusForbidden {
		t.Fatalf("raw development/HTTP opt-outs allowed plaintext registration: status=%d body=%s", got.Code, got.Body.String())
	}
	fullID := manager.ComposeID(1, 1, 42)
	if _, ok := mgr.GetDevice(fullID); ok {
		t.Fatal("plaintext request persisted a device")
	}
	if got := securityTestRequest(api, http.MethodPost, path, "admin-review", body, true); got.Code != http.StatusCreated {
		t.Fatalf("TLS registration status=%d body=%s", got.Code, got.Body.String())
	}
	old, ok := mgr.GetDevice(fullID)
	if !ok {
		t.Fatal("TLS registration missing device")
	}
	oldKey, err := store.LoadDeviceKey(fullID)
	if err != nil || len(oldKey) != 32 {
		t.Fatalf("TLS registration missing device key: %v", err)
	}
	retry := `{"tenant_id":1,"fleet_id":1,"device_id":42,"fw_version":"v3"}`
	if got := securityTestRequest(api, http.MethodPost, path, "admin-review", retry, false); got.Code != http.StatusForbidden {
		t.Fatalf("plaintext re-registration status=%d body=%s", got.Code, got.Body.String())
	}
	current, ok := mgr.GetDevice(fullID)
	if !ok || current.FWVersion != old.FWVersion {
		t.Fatalf("plaintext re-registration changed device metadata: %+v", current)
	}
	key, err := store.LoadDeviceKey(fullID)
	if err != nil || !bytes.Equal(key, oldKey) {
		t.Fatalf("plaintext re-registration changed device key: %v", err)
	}
}

func TestFleetRegistrationRequiresCredentialStore(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", "admin-review")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := manager.New(nil)
	api := NewAPI(ctx, mgr, securityTestCache(), WithAuditEmitter(&passingCredentialAudit{}))
	got := securityTestRequest(api, http.MethodPost, "/devices", "admin-review",
		`{"tenant_id":1,"fleet_id":1,"device_id":42}`, true)
	if got.Code != http.StatusServiceUnavailable || !strings.Contains(got.Body.String(), "credential store unavailable") {
		t.Fatalf("registration without credential persistence status=%d body=%s", got.Code, got.Body.String())
	}
	if _, present := mgr.GetDevice(manager.ComposeID(1, 1, 42)); present {
		t.Fatal("registered device without a durable credential store")
	}
}

func TestFleetRegistrationRollsBackCredentialAndMetadataFaults(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", "admin-review")
	for _, tc := range []struct {
		name, trigger string
		initial       bool
		tombstone     bool
	}{
		{
			name:    "new-device-key-insert",
			trigger: "CREATE TRIGGER registration_fault BEFORE INSERT ON device_keys BEGIN SELECT RAISE(FAIL, 'injected key insert failure'); END",
		},
		{
			name:    "existing-device-key-update",
			trigger: "CREATE TRIGGER registration_fault BEFORE UPDATE ON device_keys BEGIN SELECT RAISE(FAIL, 'injected key update failure'); END",
			initial: true,
		},
		{
			name:      "forced-reregistration-tombstone-delete",
			trigger:   "CREATE TRIGGER registration_fault BEFORE DELETE ON decommissioned_devices BEGIN SELECT RAISE(FAIL, 'injected tombstone delete failure'); END",
			initial:   true,
			tombstone: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(securitySQLiteDir(t), "fleet.db")
			store, err := NewSQLiteStore(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			mgr := manager.New(nil)
			mgr.SetStore(store)
			audit := &passingCredentialAudit{}
			api := NewAPI(ctx, mgr, securityTestCache(), WithDeviceKeyStore(store), WithDecommissionStore(store), WithAuditEmitter(audit))
			fullID := manager.ComposeID(1, 1, 42)
			var oldKey []byte
			if tc.initial {
				got := securityTestRequest(api, http.MethodPost, "/devices", "admin-review",
					`{"tenant_id":1,"fleet_id":1,"device_id":42,"fw_version":"old"}`, true)
				if got.Code != http.StatusCreated {
					t.Fatalf("initial registration status=%d body=%s", got.Code, got.Body.String())
				}
				oldKey, err = store.LoadDeviceKey(fullID)
				if err != nil || len(oldKey) != 32 {
					t.Fatalf("initial device key missing: %v", err)
				}
			}
			if tc.tombstone {
				if err := store.SaveDecommissioned(fullID); err != nil {
					t.Fatal(err)
				}
				// Simulate a tombstone appearing after the API's preliminary
				// check. The store must reject it inside the registration
				// transaction unless force_reregister was requested.
				_, _, err := mgr.RegisterDeviceWithCredential(1, 1, 42,
					"changed", "changed", 1, 0, bytes.Repeat([]byte{0xA7}, 32), false)
				if !errors.Is(err, ErrDeviceDecommissioned) {
					t.Fatalf("transaction missed a new tombstone: %v", err)
				}
			}
			if _, err := store.db.Exec(tc.trigger); err != nil {
				t.Fatal(err)
			}
			body := `{"tenant_id":1,"fleet_id":1,"device_id":42,"fw_version":"new","force_reregister":true}`
			previousActions := len(audit.actions)
			got := securityTestRequest(api, http.MethodPost, "/devices", "admin-review", body, true)
			if got.Code != http.StatusServiceUnavailable || strings.Contains(got.Body.String(), "device_key") {
				t.Fatalf("fault status=%d body=%s", got.Code, got.Body.String())
			}
			if len(audit.actions) != previousActions+1 || audit.actions[previousActions] != auditCredentialAllow {
				t.Fatalf("transaction fault logged a success instead of only authorization: %v", audit.actions[previousActions:])
			}
			assertRegistrationState := func(label string, mgr *manager.FleetManager, store *SQLiteStore) {
				t.Helper()
				dev, inMemory := mgr.GetDevice(fullID)
				if inMemory != tc.initial {
					t.Fatalf("%s memory presence=%t want=%t", label, inMemory, tc.initial)
				}
				persisted, err := store.LoadDevice(1, 1, 42)
				if err != nil || (persisted != nil) != tc.initial {
					t.Fatalf("%s persistent device=%v err=%v", label, persisted, err)
				}
				if tc.initial && (dev.FWVersion != "old" || persisted.FWVersion != "old") {
					t.Fatalf("%s changed metadata: memory=%q persisted=%q", label, dev.FWVersion, persisted.FWVersion)
				}
				key, err := store.LoadDeviceKey(fullID)
				if err != nil || !bytes.Equal(key, oldKey) {
					t.Fatalf("%s invalidated old key: %x err=%v", label, key, err)
				}
				hasTombstone, err := store.IsDecommissioned(fullID)
				if err != nil || hasTombstone != tc.tombstone {
					t.Fatalf("%s tombstone=%t want=%t err=%v", label, hasTombstone, tc.tombstone, err)
				}
			}
			assertRegistrationState("after fault", mgr, store)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = NewSQLiteStore(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			mgr = manager.New(nil)
			mgr.SetStore(store)
			if _, err := mgr.LoadFromStore(); err != nil {
				t.Fatal(err)
			}
			assertRegistrationState("after restart", mgr, store)
			if _, err := store.db.Exec("DROP TRIGGER registration_fault"); err != nil {
				t.Fatal(err)
			}
			api = NewAPI(ctx, mgr, securityTestCache(), WithDeviceKeyStore(store), WithDecommissionStore(store), WithAuditEmitter(audit))
			got = securityTestRequest(api, http.MethodPost, "/devices", "admin-review", body, true)
			want := http.StatusCreated
			if tc.initial {
				want = http.StatusOK
			}
			if got.Code != want {
				t.Fatalf("retry status=%d want=%d body=%s", got.Code, want, got.Body.String())
			}
			newKey, err := store.LoadDeviceKey(fullID)
			if err != nil || len(newKey) != 32 || bytes.Equal(newKey, oldKey) {
				t.Fatalf("retry did not provision a new key: %x err=%v", newKey, err)
			}
			if tombstone, err := store.IsDecommissioned(fullID); err != nil || tombstone {
				t.Fatalf("retry did not clear tombstone: %t %v", tombstone, err)
			}
		})
	}
}

func TestFleetCredentialAuditFailureBlocksRegistrationAndDecommission(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", "admin-review")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store, err := NewSQLiteStore(filepath.Join(securitySQLiteDir(t), "fleet.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	mgr := manager.New(nil)
	mgr.SetStore(store)
	fullID := manager.ComposeID(1, 1, 42)
	failedAudit := &failingCredentialAudit{}
	api := NewAPI(ctx, mgr, securityTestCache(), WithDeviceKeyStore(store), WithDecommissionStore(store), WithAuditEmitter(failedAudit))
	oldBody := `{"tenant_id":1,"fleet_id":1,"device_id":42,"fw_version":"old"}`
	if got := securityTestRequest(api, http.MethodPost, "/devices", "admin-review", oldBody, true); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("first credential issue despite audit failure: status=%d body=%s", got.Code, got.Body.String())
	}
	if _, present := mgr.GetDevice(fullID); present {
		t.Fatal("audit failure registered device in memory")
	}
	if saved, err := store.LoadDevice(1, 1, 42); err != nil || saved != nil {
		t.Fatalf("audit failure registered persistent device=%v err=%v", saved, err)
	}
	if key, err := store.LoadDeviceKey(fullID); err != nil || key != nil {
		t.Fatalf("audit failure issued a key=%v err=%v", key, err)
	}
	goodAudit := &passingCredentialAudit{}
	goodAPI := NewAPI(ctx, mgr, securityTestCache(), WithDeviceKeyStore(store), WithDecommissionStore(store), WithAuditEmitter(goodAudit))
	if got := securityTestRequest(goodAPI, http.MethodPost, "/devices", "admin-review", oldBody, true); got.Code != http.StatusCreated {
		t.Fatalf("audited registration status=%d body=%s", got.Code, got.Body.String())
	}
	if len(goodAudit.actions) != 2 || goodAudit.actions[0] != auditCredentialAllow || goodAudit.actions[1] != auditDeviceRegistered {
		t.Fatalf("registration audit order=%v", goodAudit.actions)
	}
	oldKey, err := store.LoadDeviceKey(fullID)
	if err != nil || len(oldKey) != 32 {
		t.Fatalf("registered key missing: %v", err)
	}
	newBody := `{"tenant_id":1,"fleet_id":1,"device_id":42,"fw_version":"new"}`
	if got := securityTestRequest(api, http.MethodPost, "/devices", "admin-review", newBody, true); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("re-registration bypassed audit: status=%d body=%s", got.Code, got.Body.String())
	}
	if dev, present := mgr.GetDevice(fullID); !present || dev.FWVersion != "old" {
		t.Fatalf("audit failure changed device metadata=%+v present=%t", dev, present)
	}
	if key, err := store.LoadDeviceKey(fullID); err != nil || !bytes.Equal(key, oldKey) {
		t.Fatalf("audit failure invalidated old key=%x err=%v", key, err)
	}
	decommission := `{"devices":[{"tenant_id":1,"fleet_id":1,"device_id":42}]}`
	got := securityTestRequest(api, http.MethodPost, "/devices/decommission-batch", "admin-review", decommission, true)
	if got.Code != http.StatusMultiStatus || !strings.Contains(got.Body.String(), `"audit_failed"`) {
		t.Fatalf("decommission bypassed audit: status=%d body=%s", got.Code, got.Body.String())
	}
	if _, present := mgr.GetDevice(fullID); !present {
		t.Fatal("audit failure decommissioned device")
	}
	if key, err := store.LoadDeviceKey(fullID); err != nil || !bytes.Equal(key, oldKey) {
		t.Fatalf("audit failure deleted old key=%x err=%v", key, err)
	}
	if tombstone, err := store.IsDecommissioned(fullID); err != nil || tombstone {
		t.Fatalf("audit failure wrote tombstone=%t err=%v", tombstone, err)
	}
}

func TestFleetDecommissionRejectsSplitStoresBeforeDeletingKey(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", "admin-review")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := securitySQLiteDir(t)
	deviceStore, err := NewSQLiteStore(filepath.Join(root, "devices.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer deviceStore.Close()
	keyStore, err := NewSQLiteStore(filepath.Join(root, "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer keyStore.Close()
	mgr := manager.New(nil)
	mgr.SetStore(deviceStore)
	dev, err := mgr.RegisterDevice(1, 1, 42, "sbc", "old", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := bytes.Repeat([]byte{0xA7}, 32)
	if err := keyStore.SaveDeviceKey(dev.DeviceID, oldKey); err != nil {
		t.Fatal(err)
	}
	api := NewAPI(ctx, mgr, securityTestCache(), WithDeviceKeyStore(keyStore),
		WithDecommissionStore(deviceStore), WithAuditEmitter(&passingCredentialAudit{}))
	body := `{"devices":[{"tenant_id":1,"fleet_id":1,"device_id":42}]}`
	got := securityTestRequest(api, http.MethodPost, "/devices/decommission-batch", "admin-review", body, true)
	if got.Code != http.StatusMultiStatus || !strings.Contains(got.Body.String(), `"persistence_failed"`) {
		t.Fatalf("split-store decommission status=%d body=%s", got.Code, got.Body.String())
	}
	if _, present := mgr.GetDevice(dev.DeviceID); !present {
		t.Fatal("split-store request removed in-memory device")
	}
	if persisted, err := deviceStore.LoadDevice(1, 1, 42); err != nil || persisted == nil {
		t.Fatalf("split-store request removed persistent device=%v err=%v", persisted, err)
	}
	if key, err := keyStore.LoadDeviceKey(dev.DeviceID); err != nil || !bytes.Equal(key, oldKey) {
		t.Fatalf("split-store request removed signing key=%x err=%v", key, err)
	}
}

func TestFleetPushPolicyDistinguishesInvalidInputFromCompilerFailure(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", "admin-review")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signer, err := policy.NewHMACSigner(bytes.Repeat([]byte{0xA7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc := policy.NewService(policy.NewMemoryPolicyStore(), signer, nil, &policy.Config{
		CompilerPath: "/usr/local/lib/defenseclaw/nonexistent-review-compiler.py",
	})
	api := NewAPI(ctx, manager.New(nil), securityTestCache(), WithPolicyService(svc))
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"invalid-profile", `{"tenant_id":1,"fleet_id":1,"policy_yaml":"rules: []","profile":"invalid"}`, http.StatusBadRequest},
		{"too-large-policy", fmt.Sprintf(`{"tenant_id":1,"fleet_id":1,"policy_yaml":%q,"profile":"standard"}`, strings.Repeat("a", 65537)), http.StatusRequestEntityTooLarge},
		{"compiler-missing", `{"tenant_id":1,"fleet_id":1,"policy_yaml":"rules: []","profile":"standard"}`, http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := securityTestRequest(api, http.MethodPost, "/policy/push", "admin-review", tc.body, true)
			if got.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", got.Code, tc.want, got.Body.String())
			}
		})
	}
}

func TestFleetThreatIntelPublishesEachDeviceFleetAndValidatesBeforeMutation(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", "admin-review")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := manager.New(nil)
	for _, key := range [][3]uint32{{1, 1, 42}, {1, 1, 43}, {1, 2, 44}, {2, 1, 45}} {
		if _, err := mgr.RegisterDevice(uint16(key[0]), uint16(key[1]), key[2], "sbc", "1", 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	cache := securityTestCache()
	var hash [32]byte
	hash[0] = 0xA7
	cache.Store(1, 1, hash, verdict.ActionAllow, 0)
	client := &apiMockMQTTClient{}
	signer, err := policy.NewHMACSigner(bytes.Repeat([]byte{0xA7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc := policy.NewService(policy.NewMemoryPolicyStore(), signer, client, &policy.Config{
		EmergencyKeyHex: strings.Repeat("ab", 32),
	})
	api := NewAPI(ctx, mgr, cache, WithPolicyService(svc))
	bad := fmt.Sprintf(`{"revoke_allow_hashes":[%q,"invalid"]}`, hex.EncodeToString(hash[:]))
	if got := securityTestRequest(api, http.MethodPost, "/threat-intel/push", "admin-review", bad, true); got.Code != http.StatusBadRequest {
		t.Fatalf("bad revocation status=%d body=%s", got.Code, got.Body.String())
	}
	if _, exists := cache.Lookup(1, 1, hash); !exists {
		t.Fatal("invalid request partially mutated cache")
	}
	if len(client.published) != 0 {
		t.Fatal("invalid request published emergency command")
	}
	valid := fmt.Sprintf(`{"revoke_allow_hashes":[%q]}`, hex.EncodeToString(hash[:]))
	got := securityTestRequest(api, http.MethodPost, "/threat-intel/push", "admin-review", valid, true)
	if got.Code != http.StatusAccepted || !strings.Contains(got.Body.String(), `"device_cache_flush_published":3`) {
		t.Fatalf("valid revocation status=%d body=%s", got.Code, got.Body.String())
	}
	if _, exists := cache.Lookup(1, 1, hash); exists {
		t.Fatal("valid request did not revoke gateway verdict")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	want := []string{
		"defenseclaw/1/1/ota/emergency",
		"defenseclaw/1/2/ota/emergency",
		"defenseclaw/2/1/ota/emergency",
	}
	if len(client.published) != len(want) {
		t.Fatalf("published=%d want=%d", len(client.published), len(want))
	}
	for i, target := range want {
		if client.published[i].Topic != target || len(client.published[i].Payload) != policy.EmergencyMsgSize {
			t.Fatalf("publish[%d]=%s length=%d, want %s length=%d", i, client.published[i].Topic, len(client.published[i].Payload), target, policy.EmergencyMsgSize)
		}
	}
}

func TestFleetThreatIntelReportsPartialBrokerPublish(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", "admin-review")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := manager.New(nil)
	for _, tenant := range []uint16{1, 2} {
		if _, err := mgr.RegisterDevice(tenant, 1, 42, "sbc", "1", 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	client := &failSelectedEmergencyPublish{apiMockMQTTClient: &apiMockMQTTClient{}}
	signer, err := policy.NewHMACSigner(bytes.Repeat([]byte{0xA7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc := policy.NewService(policy.NewMemoryPolicyStore(), signer, client, &policy.Config{
		EmergencyKeyHex: strings.Repeat("ab", 32),
	})
	api := NewAPI(ctx, mgr, securityTestCache(), WithPolicyService(svc))
	got := securityTestRequest(api, http.MethodPost, "/threat-intel/push", "admin-review", `{"emergency":true}`, true)
	if got.Code != http.StatusMultiStatus || !strings.Contains(got.Body.String(), `"device_cache_flush_published":1`) ||
		!strings.Contains(got.Body.String(), `"device_cache_flush_failed":["2/1"]`) ||
		!strings.Contains(got.Body.String(), `"device_cache_flushed":false`) {
		t.Fatalf("partial broker publish status=%d body=%s", got.Code, got.Body.String())
	}
	if len(client.published) != 1 || client.published[0].Topic != "defenseclaw/1/1/ota/emergency" {
		t.Fatalf("published topics=%+v", client.published)
	}
}

func TestFleetCredentialRotationsRequireAuditBeforeMutation(t *testing.T) {
	t.Setenv("DCLAW_PRODUCTION", "1")
	t.Setenv("DCLAW_FLEET_API_TOKEN", "admin-review")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStore()
	mgr := manager.New(nil)
	mgr.SetStore(store)
	dev, err := mgr.RegisterDevice(1, 1, 42, "sbc", "1", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := bytes.Repeat([]byte{0xA7}, 32)
	if err := store.SaveDeviceKey(dev.DeviceID, oldKey); err != nil {
		t.Fatal(err)
	}
	audit := &failingCredentialAudit{}
	api := NewAPI(ctx, mgr, securityTestCache(), WithDeviceKeyStore(store), WithAuditEmitter(audit))
	path := fmt.Sprintf("/devices/%d/rotate-key", dev.DeviceID)
	if got := securityTestRequest(api, http.MethodPost, path, "admin-review", "{}", true); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("key rotation during audit failure status=%d body=%s", got.Code, got.Body.String())
	}
	key, err := store.LoadDeviceKey(dev.DeviceID)
	if err != nil || !bytes.Equal(key, oldKey) {
		t.Fatalf("device key changed after audit failure: err=%v", err)
	}
	if _, exists := api.deviceKeyRotations[dev.DeviceID]; exists {
		t.Fatal("audit failure consumed device rotation window")
	}
	if got := securityTestRequest(api, http.MethodPost, "/token/rotate", "admin-review", "{}", true); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("token rotation during audit failure status=%d body=%s", got.Code, got.Body.String())
	}
	if token := api.currentToken.Load(); token == nil || *token != "admin-review" {
		t.Fatal("admin token changed after audit failure")
	}
	if !api.lastTokenRotation.IsZero() {
		t.Fatal("audit failure consumed token rotation window")
	}
	if audit.calls != 2 {
		t.Fatalf("audit calls=%d, want 2", audit.calls)
	}
}

func TestFleetDecommissionSQLiteRollsBackOnFault(t *testing.T) {
	for _, tc := range []struct{ name, trigger string }{
		{"device-delete", `CREATE TRIGGER block_device_delete BEFORE DELETE ON devices BEGIN SELECT RAISE(FAIL,'injected device delete'); END`},
		{"tombstone-write", `CREATE TRIGGER block_tombstone BEFORE INSERT ON decommissioned_devices BEGIN SELECT RAISE(FAIL,'injected tombstone'); END`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DCLAW_FLEET_API_TOKEN", "admin-review")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store, err := NewSQLiteStore(filepath.Join(securitySQLiteDir(t), "devices.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			mgr := manager.New(nil)
			mgr.SetStore(store)
			dev, err := mgr.RegisterDevice(1, 1, 42, "sbc", "1", 1, 0)
			if err != nil {
				t.Fatal(err)
			}
			oldKey := bytes.Repeat([]byte{0xA7}, 32)
			if err := store.SaveDeviceKey(dev.DeviceID, oldKey); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(tc.trigger); err != nil {
				t.Fatal(err)
			}
			api := NewAPI(ctx, mgr, securityTestCache(), WithDeviceKeyStore(store), WithDecommissionStore(store), WithAuditEmitter(&passingCredentialAudit{}))
			body := `{"devices":[{"tenant_id":1,"fleet_id":1,"device_id":42}]}`
			got := securityTestRequest(api, http.MethodPost, "/devices/decommission-batch", "admin-review", body, true)
			if got.Code != http.StatusMultiStatus || !strings.Contains(got.Body.String(), `"persistence_failed"`) {
				t.Fatalf("fault status=%d body=%s", got.Code, got.Body.String())
			}
			if _, exists := mgr.GetDevice(dev.DeviceID); !exists {
				t.Fatal("fault removed device in memory")
			}
			if saved, err := store.LoadDevice(1, 1, 42); err != nil || saved == nil {
				t.Fatalf("fault removed durable device: %v", err)
			}
			if key, err := store.LoadDeviceKey(dev.DeviceID); err != nil || !bytes.Equal(key, oldKey) {
				t.Fatalf("fault removed durable key: %v", err)
			}
			if tombstone, err := store.IsDecommissioned(dev.DeviceID); err != nil || tombstone {
				t.Fatalf("fault left tombstone=%t err=%v", tombstone, err)
			}
			if _, err := store.db.Exec("DROP TRIGGER " + strings.Fields(tc.trigger)[2]); err != nil {
				t.Fatal(err)
			}
			got = securityTestRequest(api, http.MethodPost, "/devices/decommission-batch", "admin-review", body, true)
			if got.Code != http.StatusOK {
				t.Fatalf("retry status=%d body=%s", got.Code, got.Body.String())
			}
			if _, exists := mgr.GetDevice(dev.DeviceID); exists {
				t.Fatal("retry left device in memory")
			}
			if saved, err := store.LoadDevice(1, 1, 42); err != nil || saved != nil {
				t.Fatalf("retry left durable device=%v err=%v", saved, err)
			}
			if key, err := store.LoadDeviceKey(dev.DeviceID); err != nil || key != nil {
				t.Fatalf("retry left key=%v err=%v", key, err)
			}
			if tombstone, err := store.IsDecommissioned(dev.DeviceID); err != nil || !tombstone {
				t.Fatalf("retry tombstone=%t err=%v", tombstone, err)
			}
		})
	}
}

func TestFleetSQLiteReopenRestrictsExistingJournals(t *testing.T) {
	for _, kind := range []string{"fleet", "policy"} {
		t.Run(kind, func(t *testing.T) {
			dir := securitySQLiteDir(t)
			if err := widenSQLiteParentAccess(dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, kind+".db")
			if kind == "fleet" {
				first, err := NewSQLiteStore(path)
				if err != nil {
					t.Fatal(err)
				}
				defer first.Close()
				if err := first.SaveDeviceKey(42, bytes.Repeat([]byte{0xA7}, 32)); err != nil {
					t.Fatal(err)
				}
			} else {
				first, err := policy.NewSQLitePolicyStore(path)
				if err != nil {
					t.Fatal(err)
				}
				defer first.Close()
				if err := first.SavePolicy(1, 1, 1, []byte("policy"), []byte("signature"), "standard"); err != nil {
					t.Fatal(err)
				}
			}
			if err := assertSQLiteParentPrivate(dir); err != nil {
				t.Fatal(err)
			}
			for _, suffix := range []string{"", "-wal", "-shm"} {
				if err := assertSQLiteFilePrivate(path + suffix); err != nil {
					t.Fatalf("new %s%s: %v", kind, suffix, err)
				}
				if err := widenSQLiteFileAccess(path + suffix); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "fleet" {
				reopened, err := NewSQLiteStore(path)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
			} else {
				reopened, err := policy.NewSQLitePolicyStore(path)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
			}
			for _, suffix := range []string{"", "-wal", "-shm"} {
				if err := assertSQLiteFilePrivate(path + suffix); err != nil {
					t.Fatalf("%s%s: %v", kind, suffix, err)
				}
			}
		})
	}
}

func TestFleetSignedBootCounterRejectsReplayAcrossRestartAndStoreFault(t *testing.T) {
	path := filepath.Join(securitySQLiteDir(t), "fleet.db")
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	mgr := manager.New(nil)
	mgr.SetStore(store)
	dev, err := mgr.RegisterDevice(1, 1, 42, "sbc", "1", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	process := func(counter, uptime, denied uint32) bool {
		return mgr.ProcessHeartbeat(1, 1, 42, &manager.Heartbeat{
			DeviceID: 42, BootCounter: counter, UptimeSec: uptime, DeniedCount: denied,
		})
	}
	if !process(1, 100, 2) {
		t.Fatal("initial signed boot heartbeat rejected")
	}
	if process(1, 50, 999) {
		t.Fatal("delayed signed lower-uptime heartbeat accepted as reboot")
	}
	if !process(2, 5, 1) {
		t.Fatal("genuine higher-counter reboot rejected")
	}
	if process(1, 101, 999) || process(2, 5, 999) {
		t.Fatal("old boot or duplicate signed heartbeat accepted")
	}
	if got, ok := mgr.GetDevice(dev.DeviceID); !ok || got.BootCounter != 2 || got.BootEpoch != 1 || got.DeniedTotal != 3 {
		t.Fatalf("post-reboot state=%+v exists=%t", got, ok)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	mgr = manager.New(nil)
	mgr.SetStore(store)
	if loaded, err := mgr.LoadFromStore(); err != nil || loaded != 1 {
		t.Fatalf("restart loaded=%d err=%v", loaded, err)
	}
	if process(1, 102, 999) || process(2, 4, 999) {
		t.Fatal("replay accepted after gateway restart")
	}
	if _, err := store.db.Exec(`CREATE TRIGGER block_heartbeat_update BEFORE UPDATE ON devices BEGIN SELECT RAISE(FAIL,'injected persistence failure'); END`); err != nil {
		t.Fatal(err)
	}
	if process(2, 6, 4) {
		t.Fatal("heartbeat reported accepted when anti-replay state could not persist")
	}
	if got, _ := mgr.GetDevice(dev.DeviceID); got.LastUptime != 5 || got.DeniedTotal != 3 {
		t.Fatalf("persistence failure changed memory state: %+v", got)
	}
	if _, err := store.db.Exec("DROP TRIGGER block_heartbeat_update"); err != nil {
		t.Fatal(err)
	}
	if !process(2, 6, 4) {
		t.Fatal("heartbeat retry after store recovery rejected")
	}
	if got, _ := mgr.GetDevice(dev.DeviceID); got.LastUptime != 6 || got.DeniedTotal != 6 {
		t.Fatalf("retry produced wrong state: %+v", got)
	}
}

func TestFleetSQLiteAddsBootCounterToExistingDeviceDatabase(t *testing.T) {
	path := filepath.Join(securitySQLiteDir(t), "fleet.db")
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	mgr := manager.New(nil)
	mgr.SetStore(store)
	if _, err := mgr.RegisterDevice(1, 1, 42, "sbc", "1", 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec("ALTER TABLE devices DROP COLUMN boot_counter"); err != nil {
		legacy.Close()
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("upgrade old database missing boot_counter: %v", err)
	}
	defer upgraded.Close()
	loaded, err := upgraded.LoadDevice(1, 1, 42)
	if err != nil || loaded == nil || loaded.BootCounter != 0 {
		t.Fatalf("migrated device=%+v err=%v", loaded, err)
	}
	loaded.BootCounter = 1
	if err := upgraded.SaveDevice(loaded); err != nil {
		t.Fatal(err)
	}
	reloaded, err := upgraded.LoadDevice(1, 1, 42)
	if err != nil || reloaded == nil || reloaded.BootCounter != 1 {
		t.Fatalf("reloaded boot counter=%+v err=%v", reloaded, err)
	}
}

// GAP-0569: the fleet API's own JSON error bodies (credential delivery over
// plain HTTP, a missing CSRF header) are sent as application/json, as the API
// reference says, not text/plain.
func TestFleetJSONErrorsAreApplicationJSON(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", "admin-review")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	api := NewAPI(ctx, manager.New(nil), securityTestCache(), WithAuditEmitter(&passingCredentialAudit{}))
	plain := securityTestRequest(api, http.MethodPost, "/token/rotate", "admin-review", "{}", false)
	req := httptest.NewRequest(http.MethodPost, "/token/rotate", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer admin-review")
	req.Header.Set("Content-Type", "application/json")
	noCSRF := httptest.NewRecorder()
	api.Handler().ServeHTTP(noCSRF, req)
	for name, got := range map[string]*httptest.ResponseRecorder{"plain HTTP rotate": plain, "missing CSRF header": noCSRF} {
		var body map[string]string
		if got.Code != http.StatusForbidden || got.Header().Get("Content-Type") != "application/json" ||
			json.Unmarshal(got.Body.Bytes(), &body) != nil || body["error"] == "" {
			t.Fatalf("%s: status %d, Content-Type %q, body %q", name, got.Code, got.Header().Get("Content-Type"), got.Body.String())
		}
	}
}
