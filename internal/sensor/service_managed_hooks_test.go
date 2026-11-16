// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
)

// A brokered Plane C labels hook_seen only on a managed host. The Cowork VM
// brokers through a root helper without managed hooks, so no tool call there
// is reported as unseen by machine policy.
func TestHookRingOnlyForManagedBrokeredHosts(t *testing.T) {
	for _, managed := range []bool{false, true} {
		service, err := New(Options{
			Config:       config.AIRuntimeConfig{Enabled: true, EnableHostPlane: true},
			Providers:    testCatalog(),
			Platform:     allPlanesAvailable(),
			Resolver:     StaticResolver{Names: map[string]string{}},
			Acquirer:     brokeredAcquirer{Acquirer: acquire.NewLocal()},
			ManagedHooks: managed,
		})
		if err != nil {
			t.Fatalf("New(): %v", err)
		}
		if service.hostPlane == nil {
			t.Fatal("no host plane")
		}
		if got := service.hostPlane.hooks != nil; got != managed {
			t.Fatalf("ManagedHooks=%v: hook ring on = %v", managed, got)
		}
	}
}
