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

package fleet

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
)

// hardeningAPI builds an API over a SQLite store at dbPath (a fresh one when
// dbPath is empty) so tests can simulate a gateway restart on the same state.
func hardeningAPI(t *testing.T, settings FleetSettings, dbPath string) (*API, *SQLiteStore, *manager.FleetManager, string) {
	t.Helper()
	t.Setenv("DCLAW_FLEET_API_TOKEN", "")
	t.Setenv("DCLAW_FLEET_TENANT_TOKENS", "")
	if dbPath == "" {
		dbPath = filepath.Join(securitySQLiteDir(t), "devices.db")
	}
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	mgr := manager.New(nil)
	mgr.SetStore(store)
	if _, err := mgr.LoadFromStore(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	api := NewAPI(ctx, mgr, securityTestCache(), WithDeviceKeyStore(store), WithDecommissionStore(store),
		WithAuditEmitter(&passingCredentialAudit{}), WithFleetSettings(settings))
	return api, store, mgr, dbPath
}

func registerDeviceVia(t *testing.T, api *API, token string, tenant, fleetID uint16, dev uint32, extra string, tlsOn bool) (int, string) {
	t.Helper()
	body := fmt.Sprintf(`{"tenant_id":%d,"fleet_id":%d,"device_id":%d%s}`, tenant, fleetID, dev, extra)
	rec := securityTestRequest(api, http.MethodPost, "/devices", token, body, tlsOn)
	var out struct {
		DeviceKey string `json:"device_key"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out.DeviceKey
}

func healthCode(api *API, token string) int {
	return securityTestRequest(api, http.MethodGet, "/health", token, "", true).Code
}

// A rotated admin token survives a gateway restart: the rotated-out token is
// not revived and the rotated token keeps working.
func TestAdminTokenRotationSurvivesRestart(t *testing.T) {
	settings := FleetSettings{APIToken: "original-admin-token"}
	api, _, _, dbPath := hardeningAPI(t, settings, "")
	rec := securityTestRequest(api, http.MethodPost, "/token/rotate", "original-admin-token", "{}", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	var out struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if healthCode(api, "original-admin-token") != http.StatusUnauthorized || healthCode(api, out.Token) != http.StatusOK {
		t.Fatal("in-process rotation did not take effect")
	}

	restarted, _, _, _ := hardeningAPI(t, settings, dbPath)
	if c := healthCode(restarted, "original-admin-token"); c != http.StatusUnauthorized {
		t.Fatalf("rotated-out token valid again after restart: %d", c)
	}
	if c := healthCode(restarted, out.Token); c != http.StatusOK {
		t.Fatalf("rotated token rejected after restart: %d", c)
	}

	// Saving the rotated token in the secret source keeps it working.
	saved, _, _, _ := hardeningAPI(t, FleetSettings{APIToken: out.Token}, dbPath)
	if healthCode(saved, out.Token) != http.StatusOK || healthCode(saved, "original-admin-token") != http.StatusUnauthorized {
		t.Fatal("configuring the rotated token changed which token is accepted")
	}

	// An operator who configures a brand-new secret replaces the rotation.
	fresh, _, _, _ := hardeningAPI(t, FleetSettings{APIToken: "operator-new-secret"}, dbPath)
	if healthCode(fresh, "operator-new-secret") != http.StatusOK {
		t.Fatal("newly configured admin token rejected")
	}
	if healthCode(fresh, out.Token) != http.StatusUnauthorized || healthCode(fresh, "original-admin-token") != http.StatusUnauthorized {
		t.Fatal("superseded tokens still accepted after configuring a new secret")
	}
}

// Rotation is refused when it cannot be persisted.
func TestAdminTokenRotationRequiresDurableStore(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	api := NewAPI(ctx, manager.New(nil), securityTestCache(), WithAuditEmitter(&passingCredentialAudit{}),
		WithFleetSettings(FleetSettings{APIToken: "admin"}))
	rec := securityTestRequest(api, http.MethodPost, "/token/rotate", "admin", "{}", true)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("rotation without durable store: %d %s", rec.Code, rec.Body.String())
	}
	if healthCode(api, "admin") != http.StatusOK {
		t.Fatal("refused rotation changed the admin token")
	}
}

// allow_key_over_http is ignored on managed or production hosts: device keys
// and the admin token are never returned over plaintext HTTP there.
func TestAllowKeyOverHTTPIgnoredOutsideDevMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
	}{
		{"managed", map[string]string{"DEFENSECLAW_DEPLOYMENT_MODE": "managed_enterprise", "DCLAW_DEV_MODE": "ON"}},
		{"production flag", map[string]string{"DCLAW_PRODUCTION": "1", "DCLAW_DEV_MODE": "ON"}},
		{"default", map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			t.Setenv("DCLAW_PRODUCTION", "")
			t.Setenv("DCLAW_DEV_MODE", "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			api, store, _, _ := hardeningAPI(t, FleetSettings{APIToken: "admin", AllowKeyOverHTTP: true}, "")
			c, key := registerDeviceVia(t, api, "admin", 1, 1, 12, "", false)
			if c != http.StatusForbidden || key != "" {
				t.Fatalf("plaintext device key delivery: %d", c)
			}
			if k, _ := store.LoadDeviceKey(manager.ComposeID(1, 1, 12)); k != nil {
				t.Fatal("refused registration stored a key")
			}
			if rec := securityTestRequest(api, http.MethodPost, "/token/rotate", "admin", "{}", false); rec.Code != http.StatusForbidden {
				t.Fatalf("plaintext token delivery: %d", rec.Code)
			}
			if c, _ := registerDeviceVia(t, api, "admin", 1, 1, 12, "", true); c != http.StatusCreated {
				t.Fatalf("TLS registration: %d", c)
			}
		})
	}
	t.Run("explicit dev mode", func(t *testing.T) {
		t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
		t.Setenv("DCLAW_PRODUCTION", "")
		t.Setenv("DCLAW_DEV_MODE", "ON")
		api, _, _, _ := hardeningAPI(t, FleetSettings{APIToken: "admin", AllowKeyOverHTTP: true}, "")
		if c, key := registerDeviceVia(t, api, "admin", 1, 1, 13, "", false); c != http.StatusCreated || key == "" {
			t.Fatalf("dev-mode plaintext delivery: %d", c)
		}
	})
}

// POST /devices for a live device does not silently issue a new key: it needs
// force_reregister and shares rotate-key's per-device rate limit.
func TestRegisterLiveDeviceRequiresForceAndIsRateLimited(t *testing.T) {
	api, store, _, _ := hardeningAPI(t, FleetSettings{APIToken: "admin"}, "")
	id := manager.ComposeID(1, 1, 9)
	c, k1 := registerDeviceVia(t, api, "admin", 1, 1, 9, "", true)
	if c != http.StatusCreated || k1 == "" {
		t.Fatalf("initial registration: %d", c)
	}
	if c, k := registerDeviceVia(t, api, "admin", 1, 1, 9, "", true); c != http.StatusConflict || k != "" {
		t.Fatalf("re-registration without force_reregister: %d key=%q", c, k)
	}
	stored, _ := store.LoadDeviceKey(id)
	if fmt.Sprintf("%x", stored) != k1 {
		t.Fatal("refused re-registration replaced the key")
	}
	c, k2 := registerDeviceVia(t, api, "admin", 1, 1, 9, `,"force_reregister":true`, true)
	if c != http.StatusOK || k2 == "" || k2 == k1 {
		t.Fatalf("forced re-registration: %d", c)
	}
	if c, _ := registerDeviceVia(t, api, "admin", 1, 1, 9, `,"force_reregister":true`, true); c != http.StatusTooManyRequests {
		t.Fatalf("second forced re-registration within a minute: %d", c)
	}
	rot := securityTestRequest(api, http.MethodPost, fmt.Sprintf("/devices/%d/rotate-key", id), "admin", "{}", true)
	if rot.Code != http.StatusTooManyRequests {
		t.Fatalf("rotate-key right after forced re-registration: %d", rot.Code)
	}
}

// decommissionOnKeyRotationAudit decommissions the device at the moment the
// rotation is authorized, i.e. between the handler's existence check and the
// key write.
type decommissionOnKeyRotationAudit struct {
	passingCredentialAudit
	mgr *manager.FleetManager
}

func (a *decommissionOnKeyRotationAudit) LogAction(action, target, details string) error {
	if action == auditKeyRotated {
		if _, err := a.mgr.DecommissionDeviceAtomically(1, 1, 11); err != nil {
			return err
		}
	}
	return a.passingCredentialAudit.LogAction(action, target, details)
}

// A key rotation that races a decommission must not leave a key row for the
// removed device or report success.
func TestRotateKeyCannotRecreateKeyForDecommissionedDevice(t *testing.T) {
	api, store, mgr, _ := hardeningAPI(t, FleetSettings{APIToken: "admin"}, "")
	if c, _ := registerDeviceVia(t, api, "admin", 1, 1, 11, "", true); c != http.StatusCreated {
		t.Fatalf("register: %d", c)
	}
	id := manager.ComposeID(1, 1, 11)
	api.audit = &decommissionOnKeyRotationAudit{mgr: mgr}
	rec := securityTestRequest(api, http.MethodPost, fmt.Sprintf("/devices/%d/rotate-key", id), "admin", "{}", true)
	if rec.Code == http.StatusOK {
		t.Fatalf("rotation reported success for a decommissioned device: %s", rec.Body.String())
	}
	if key, err := store.LoadDeviceKey(id); err != nil || key != nil {
		t.Fatalf("key row exists for decommissioned device: %v err=%v", key != nil, err)
	}
	if tomb, _ := store.IsDecommissioned(id); !tomb {
		t.Fatal("tombstone missing")
	}
}

// The store transaction itself refuses to write a key for a missing or
// tombstoned device.
func TestSQLiteRotateDeviceKeyRequiresLiveDevice(t *testing.T) {
	_, store, mgr, _ := hardeningAPI(t, FleetSettings{APIToken: "admin"}, "")
	dev := &manager.Device{DeviceID: manager.ComposeID(1, 1, 5), TenantID: 1, FleetID: 1}
	key := make([]byte, 32)
	key[0] = 1
	if err := store.RotateDeviceKey(dev, key); err == nil {
		t.Fatal("rotated key for a device with no row")
	}
	if _, err := mgr.RegisterDevice(1, 1, 5, "sbc", "1", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDecommissioned(dev.DeviceID); err != nil {
		t.Fatal(err)
	}
	if err := store.RotateDeviceKey(dev, key); err == nil {
		t.Fatal("rotated key for a tombstoned device")
	}
	if k, _ := store.LoadDeviceKey(dev.DeviceID); k != nil {
		t.Fatal("refused rotation wrote a key")
	}
}

// A re-provisioned device (new key, reset flash so its boot counter restarts)
// is not dropped as a replay after forced re-registration or key rotation,
// including after a gateway restart.
func TestNewDeviceKeyStartsNewHeartbeatLineage(t *testing.T) {
	api, _, mgr, dbPath := hardeningAPI(t, FleetSettings{APIToken: "admin"}, "")
	if c, _ := registerDeviceVia(t, api, "admin", 1, 1, 21, "", true); c != http.StatusCreated {
		t.Fatalf("register: %d", c)
	}
	id := manager.ComposeID(1, 1, 21)
	hb := func(m *manager.FleetManager, boot, uptime uint32) bool {
		return m.ProcessHeartbeat(1, 1, 21, &manager.Heartbeat{DeviceID: 21, BootCounter: boot, UptimeSec: uptime})
	}
	if !hb(mgr, 5, 7200) {
		t.Fatal("setup heartbeat rejected")
	}
	if hb(mgr, 1, 10) {
		t.Fatal("old-lineage replay accepted before re-provisioning")
	}

	if c, _ := registerDeviceVia(t, api, "admin", 1, 1, 21, `,"force_reregister":true`, true); c != http.StatusOK {
		t.Fatalf("forced re-registration: %d", c)
	}
	restarted, _, mgr2, _ := hardeningAPI(t, FleetSettings{APIToken: "admin"}, dbPath)
	if d, _ := mgr2.GetDevice(id); d.BootCounter != 0 || d.LastUptime != 0 {
		t.Fatalf("lineage not reset durably: boot=%d uptime=%d", d.BootCounter, d.LastUptime)
	}
	if !hb(mgr2, 1, 10) {
		t.Fatal("re-provisioned device dropped as a replay after forced re-registration")
	}
	if !hb(mgr2, 3, 50) {
		t.Fatal("heartbeat rejected")
	}

	restarted.rotationMu.Lock()
	restarted.deviceKeyRotations = map[uint64]time.Time{}
	restarted.rotationMu.Unlock()
	rec := securityTestRequest(restarted, http.MethodPost, fmt.Sprintf("/devices/%d/rotate-key", id), "admin", "{}", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate-key: %d %s", rec.Code, rec.Body.String())
	}
	if !hb(mgr2, 1, 5) {
		t.Fatal("device dropped as a replay after key rotation")
	}
}

// emergency_lockdown persists in SQLite, including on a database created
// before the column existed.
func TestEmergencyLockdownPersistsAndMigrates(t *testing.T) {
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
	if _, err := legacy.Exec("ALTER TABLE devices DROP COLUMN emergency_lockdown"); err != nil {
		legacy.Close()
		t.Fatal(err)
	}
	legacy.Close()

	upgraded, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("migrate database without emergency_lockdown: %v", err)
	}
	defer upgraded.Close()
	mgr = manager.New(nil)
	mgr.SetStore(upgraded)
	if _, err := mgr.LoadFromStore(); err != nil {
		t.Fatal(err)
	}
	if !mgr.ProcessHeartbeat(1, 1, 42, &manager.Heartbeat{DeviceID: 42, BootCounter: 1, UptimeSec: 5,
		Flags: manager.HeartbeatFlagEmergencyLockdown}) {
		t.Fatal("heartbeat rejected")
	}
	loaded, err := upgraded.LoadDevice(1, 1, 42)
	if err != nil || loaded == nil || !loaded.EmergencyLockdown || loaded.Status != manager.StatusLockdown {
		t.Fatalf("persisted device=%+v err=%v", loaded, err)
	}
	rec := httptest.NewRecorder()
	json.NewEncoder(rec).Encode(loaded)
	if !strings.Contains(rec.Body.String(), `"emergency_lockdown":true`) {
		t.Fatalf("device JSON lacks emergency_lockdown: %s", rec.Body.String())
	}
}
