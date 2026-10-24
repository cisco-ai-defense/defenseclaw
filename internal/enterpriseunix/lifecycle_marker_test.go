// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"strings"
	"testing"
)

// GAP-1074: the managed hooks of a Linux or macOS computer could not tell a
// lifecycle restart from an outage (the lifecycle lock is in the root-only
// lifecycle directory), so under an administrator's open they let calls run
// while an upgrade, a failed upgrade's rollback or a configuration change
// stopped or restarted the gateway. Every run that may change the
// deployment now holds the lifecycle run marker from before it touches a
// service until it ends; a run that cannot publish it changes nothing.
func TestLifecycleRunHoldsTheHookMarkerWhileItStopsOrRestartsTheGateway(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			marker := h.env.P(h.env.Layout.LifecycleMarkerPath)
			if h.env.Layout.LifecycleMarkerPath == "" {
				t.Fatal("the layout has no lifecycle marker")
			}
			var gatewayCalls, unmarked []string
			h.services.observe = func(call string) {
				if !strings.HasSuffix(call, " "+unitGateway) && !strings.HasSuffix(call, " "+labelGateway) {
					return
				}
				gatewayCalls = append(gatewayCalls, call)
				if _, err := os.Lstat(marker); err != nil {
					unmarked = append(unmarked, call)
				}
			}
			check := func(step string) {
				t.Helper()
				if len(gatewayCalls) == 0 {
					t.Fatalf("%s touched no gateway unit", step)
				}
				if len(unmarked) > 0 {
					t.Fatalf("%s: %v ran without the lifecycle marker", step, unmarked)
				}
				if _, err := os.Lstat(marker); !os.IsNotExist(err) {
					t.Fatalf("%s left the lifecycle marker (%v)", step, err)
				}
				gatewayCalls, unmarked = nil, nil
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			check("install")
			requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1"), ProductVersion: "1.0.1"}))
			check("upgrade")
			h.healthy = false
			requireError(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")}), codeActivate)
			check("failed upgrade and its rollback")
			h.healthy = true

			// A marker that cannot be published stops the run before it
			// changes anything.
			if err := os.Symlink(h.env.P("/nonexistent"), marker); err != nil {
				t.Fatal(err)
			}
			r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.2"), ProductVersion: "1.0.2"})
			requireError(t, r, codeState)
			if len(gatewayCalls) != 0 {
				t.Fatalf("a run without its marker touched the gateway: %v", gatewayCalls)
			}
			if r.InstalledVersion == "1.0.2" {
				t.Fatal("a run without its marker upgraded the deployment")
			}
			// Status and verify read only, and hold no marker.
			if err := os.Remove(marker); err != nil {
				t.Fatal(err)
			}
			h.run(Options{Action: ActionStatus})
			if _, err := os.Lstat(marker); !os.IsNotExist(err) {
				t.Fatalf("status left a lifecycle marker (%v)", err)
			}
		})
	}
}
