// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0238 (#1279 L3): a hot change whose run was killed (TERM or SIGKILL
// during apply) is rolled back by the next run with the gateway and the
// sensor helper left running: the gateway reloads the restored config.yaml
// itself, so the retry can apply the change hot to the same gateway. An
// intent that is not hot (or written before the field) still rolls back
// with a restart.
func TestAnInterruptedHotChangeIsRolledBackWithTheGatewayRunning(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, hot := range []bool{true, false} {
			name := goos + "/restart"
			if hot {
				name = goos + "/hot"
			}
			t.Run(name, func(t *testing.T) {
				h := newTestHost(t, goos)
				requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
				gateway, helper := unitOf(goos, "gateway"), unitOf(goos, "sensor_helper")
				configPath := h.env.Layout.ConfigPath
				applied := h.read(configPath)
				snap, err := h.env.takeSnapshot("killed", []string{configPath}, nil)
				if err != nil {
					t.Fatal(err)
				}
				var active []string
				for _, unit := range h.env.Services.Units() {
					if h.services.isActive(unit.Name) {
						active = append(active, unit.Name)
					}
				}
				if err := h.env.savePending(&Pending{Action: ActionEnsure, SnapshotDir: snap.Dir, Phase: "apply", PreviouslyActive: active, Hot: hot}); err != nil {
					t.Fatal(err)
				}
				// The killed run had written its config.yaml.
				if err := os.WriteFile(h.env.P(configPath), []byte(applied+"# the killed run's push\n"), 0o640); err != nil {
					t.Fatal(err)
				}
				from := len(h.services.calls)
				r := &enterprisestatus.Result{}
				l := &lifecycle{env: h.env, opts: Options{Action: ActionEnsure}, result: r}
				if !l.recoverInterrupted(context.Background()) {
					t.Fatalf("recovery failed: %+v", r.Errors)
				}
				if !hasWarning(r, codeRecovered) {
					t.Fatalf("expected the recovery warning: %+v", r.Warnings)
				}
				if pending, _ := h.env.loadPending(); pending != nil {
					t.Fatalf("the intent is still pending: %+v", pending)
				}
				if got := h.read(configPath); got != applied {
					t.Fatalf("config.yaml not restored: %q", got)
				}
				touched := map[string]bool{}
				for _, call := range h.services.calls[from:] {
					for _, unit := range []string{gateway, helper} {
						if unit != "" && strings.HasSuffix(call, " "+unit) && !strings.HasPrefix(call, "enable ") {
							touched[unit] = true
						}
					}
				}
				if hot && touched[gateway] {
					t.Fatalf("the hot rollback touched the gateway: %q", h.services.calls[from:])
				}
				if !hot && !touched[gateway] {
					t.Fatalf("a rollback that is not hot did not restart the gateway: %q", h.services.calls[from:])
				}
				if !h.services.isActive(gateway) {
					t.Fatal("the gateway is not running after the recovery")
				}
			})
		}
	}
}
