// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// abs makes a slash path absolute on the running OS (a drive on Windows).
func abs(p string) string {
	if runtime.GOOS == "windows" {
		return `C:` + filepath.FromSlash(p)
	}
	return p
}

func TestValidateRoutingBudgetStore(t *testing.T) {
	ok := &RoutingBudgetStoreConfig{URL: "https://budgets.example.test:8443", SyncInterval: "30s", TimeoutMs: 2000}
	if err := ValidateRoutingBudgetStore(ok, true); err != nil {
		t.Fatalf("device config: %v", err)
	}
	server := &RoutingBudgetStoreConfig{Server: &RoutingBudgetStoreServerConfig{Listen: ":8443", TLSCertFile: abs("/etc/s/cert.pem"),
		TLSKeyFile: abs("/etc/s/key.pem"), DBPath: abs("/var/lib/s/store.db")}}
	if err := ValidateRoutingBudgetStore(server, false); err != nil {
		t.Fatalf("store host config: %v", err)
	}
	for _, tc := range []struct {
		name   string
		store  *RoutingBudgetStoreConfig
		device bool
		want   string
	}{
		{"plaintext", &RoutingBudgetStoreConfig{URL: "http://budgets:8443"}, true, "HTTPS only"},
		{"path", &RoutingBudgetStoreConfig{URL: "https://budgets/v1"}, true, "HTTPS only"},
		{"userinfo", &RoutingBudgetStoreConfig{URL: "https://u:p@budgets"}, true, "HTTPS only"},
		{"no url on a device", &RoutingBudgetStoreConfig{}, true, "HTTPS only"},
		{"credential", &RoutingBudgetStoreConfig{URL: "https://b", Credential: "../x"}, true, "credential"},
		{"sync too fast", &RoutingBudgetStoreConfig{URL: "https://b", SyncInterval: "1s"}, true, "10s to 10m"},
		{"timeout", &RoutingBudgetStoreConfig{URL: "https://b", TimeoutMs: 50}, true, "100 to 10000"},
		{"relative ca", &RoutingBudgetStoreConfig{URL: "https://b", CAFile: "ca.pem"}, true, "absolute"},
		{"server in a device config", &RoutingBudgetStoreConfig{URL: "https://b", Server: server.Server}, true, "store host"},
		{"server without TLS", &RoutingBudgetStoreConfig{Server: &RoutingBudgetStoreServerConfig{Listen: ":8443", DBPath: abs("/d")}}, false, "HTTPS only"},
		{"server listen", &RoutingBudgetStoreConfig{Server: &RoutingBudgetStoreServerConfig{Listen: "8443", TLSCertFile: abs("/c"), TLSKeyFile: abs("/k"), DBPath: abs("/d")}}, false, "host:port"},
		{"server cap", &RoutingBudgetStoreConfig{Server: &RoutingBudgetStoreServerConfig{Listen: ":8443", TLSCertFile: abs("/c"), TLSKeyFile: abs("/k"), DBPath: abs("/d"), DeviceDailyCapUSD: -1}}, false, "device_daily_cap_usd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRoutingBudgetStore(tc.store, tc.device)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	if ok.EffectiveCredential() != RoutingBudgetStoreDefaultCredential || ok.EffectiveSyncInterval().String() != "30s" {
		t.Fatal("defaults")
	}
}

func TestBudgetStoreNeedsAManagedDevice(t *testing.T) {
	c := &Config{}
	c.Routing.Admin = &RoutingAdminConfig{BudgetStore: &RoutingBudgetStoreConfig{URL: "https://budgets:8443"}}
	if err := c.validateRoutingAdminRules(); err == nil || !strings.Contains(err.Error(), "standalone managed device") {
		t.Fatalf("OSS: %v", err)
	}
}
