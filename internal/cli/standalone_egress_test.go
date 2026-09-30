// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestStandaloneGatewayAppliesTheEnterpriseProxyToItsEnvironment(t *testing.T) {
	network := config.EnterpriseNetworkConfig{HTTPSProxy: "http://proxy.corp:3128", NoProxy: "internal.corp"}
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want map[string]string
	}{
		{
			name: "standalone with a proxy",
			cfg: &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, Enterprise: config.EnterpriseConfig{
				Profile: managed.ProfileStandalone, Network: network,
			}},
			want: map[string]string{
				"HTTPS_PROXY": "http://proxy.corp:3128", "https_proxy": "http://proxy.corp:3128",
				"NO_PROXY": "internal.corp", "no_proxy": "internal.corp",
			},
		},
		{
			name: "standalone without a proxy",
			cfg: &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, Enterprise: config.EnterpriseConfig{
				Profile: managed.ProfileStandalone,
			}},
			want: map[string]string{},
		},
		{
			name: "secure client shape",
			cfg:  &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise},
			want: map[string]string{},
		},
		{
			name: "unmanaged",
			cfg:  &config.Config{Enterprise: config.EnterpriseConfig{Network: network}},
			want: map[string]string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := map[string]string{}
			if err := applyStandaloneEgressEnvironment(tc.cfg, func(key, value string) error {
				got[key] = value
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("environment = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStandaloneGatewayRefusesAnInvalidEnterpriseProxy(t *testing.T) {
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, Enterprise: config.EnterpriseConfig{
		Profile: managed.ProfileStandalone, Network: config.EnterpriseNetworkConfig{HTTPSProxy: "http://user:secret@proxy.corp:3128"},
	}}
	called := false
	if err := applyStandaloneEgressEnvironment(cfg, func(string, string) error { called = true; return nil }); err == nil || called {
		t.Fatalf("an invalid proxy must fail before any variable is set: err=%v set=%v", err, called)
	}
}
