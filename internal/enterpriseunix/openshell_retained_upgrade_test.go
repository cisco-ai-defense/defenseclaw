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
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// G05 retained an authentic OpenShell 0.1.3 MicroVM named t7y-cem1-legacy.
// The native SDK reported Error, MainProcessFailed, exit 137. Both old
// account services were down after package upgrade, before the first ensure.
// The published 1.0.2 manager record had driver, phase and phase_reason,
// but no session_release field.
func TestGAP0783Retained013MicroVMBlocksSwitch(t *testing.T) {
	const name = "t7y-cem1-legacy"
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newOSHost(t, goos)
			old := map[string]any{"install": "prerequisite", "driver": "vm", "version": "0.1.3"}
			requireOK(t, h.ensure(sandboxConfig(t, goos, true, old)))
			ops := &commandUserOps{env: h.env}
			readStatus := func() (SandboxStatus, error) {
				original := h.env.Runner
				h.env.Runner = &scriptRunner{answer: func(string) (CommandResult, error) { return CommandResult{}, nil }}
				defer func() { h.env.Runner = original }()
				return ops.Status(context.Background(), h.alice)
			}
			record := filepath.Join(h.alice.Home, h.env.daemonStateRel(), "sandboxes", "manager", name+".json")
			setRecord := func(driver, phase, reason string) {
				t.Helper()
				writeHostFile(t, h.testHost, record, fmt.Sprintf(`{"version":1,"name":%q,"driver":%q,"phase":%q,"phase_reason":%q}`, name, driver, phase, reason))
			}
			setRecord("vm", "error", "MainProcessFailed")
			status, err := readStatus()
			if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "MainProcessFailed") ||
				!strings.Contains(err.Error(), "defenseclaw sandbox delete "+name) {
				t.Fatalf("retained failed guest read as idle: status=%+v err=%v", status, err)
			}
			h.ops.statusErr[h.alice.UID] = err
			setup := map[string]any{"install": "setup", "driver": "vm", "version": openshell.InstallerVersion}
			r := h.ensure(sandboxConfig(t, goos, true, setup))
			requireOK(t, r)
			if containsLine(r.Changes, "switched the sandbox setup of alice") || len(h.ops.stopped()) != 0 ||
				!strings.Contains(messagesOf(r.Warnings, codeSandboxPending), name) ||
				!strings.Contains(messagesOf(r.Warnings, codeSandboxPending), "defenseclaw sandbox delete "+name) {
				t.Fatalf("failed guest did not keep the old account setup pending with its next step: changes=%v stops=%v warnings=%+v", r.Changes, h.ops.stopped(), r.Warnings)
			}
			pending := h.env.loadOpenShellState().Pending[fmt.Sprint(h.alice.UID)]
			if pending.Kind != "switch" || pending.From == nil || pending.From.Install != "prerequisite" {
				t.Fatalf("the refused switch lost the account's prior setup: %+v", pending)
			}
			for _, tc := range []struct {
				driver, phase, reason, next string
				blocked                     bool
			}{
				{"vm", "ready", "", "defenseclaw sandbox stop " + name, true},
				{"vm", "completed", "", "defenseclaw sandbox delete " + name, true},
				{"vm", "error", "ProcessExited", "", false},
				{"docker", "error", "MainProcessFailed", "", false},
				{"vm", "stopped", "", "", false},
			} {
				setRecord(tc.driver, tc.phase, tc.reason)
				_, err := readStatus()
				if (err != nil) != tc.blocked || (tc.blocked && !strings.Contains(err.Error(), tc.next)) {
					t.Errorf("driver %s phase %s reason %s: blocked=%v, err=%v", tc.driver, tc.phase, tc.reason, tc.blocked, err)
				}
			}
			setRecord("vm", "stopped", "")
			if _, err := readStatus(); err != nil {
				t.Fatalf("a stopped guest still blocks the switch: %v", err)
			}
			h.ops.statusErr[h.alice.UID] = nil
			r = h.ensure(sandboxConfig(t, goos, true, setup))
			requireOK(t, r)
			if !containsLine(r.Changes, "switched the sandbox setup of alice") {
				t.Fatalf("the switch stayed pending after disposition: changes=%v warnings=%+v", r.Changes, r.Warnings)
			}
		})
	}
}
