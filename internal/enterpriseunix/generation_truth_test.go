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
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// GAP-0943, GAP-1032: on a managed host without bundle trust anchors, a
// config update that restarted or started the gateway reports success only
// when the gateway runs the generation the lifecycle recorded. A rejected
// reload, a stale generation or another policy fails the update with the
// gateway's cause, and status and verify read the same generation check the
// hot apply settles on: they never certify a generation the gateway does not
// run.
func TestCommittedChangeReportsOnlyTheGenerationTheGatewayRuns(t *testing.T) {
	const digest = "sha256:" + "cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34"
	const other = "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000"
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			gatewayUnit := unitGateway
			if goos == "darwin" {
				gatewayUnit = labelGateway
			}
			h.env.Runner = &policyDigestRunner{fakeRunner: h.runner, digest: digest}
			// mode is what the gateway reports for the installed generation;
			// stale is the generation it keeps running when it does not take it.
			mode, stale := "accept", uint64(0)
			const cause = "config reload refused: this managed computer requires a lifecycle-recorded generation"
			h.env.HealthGet = func(context.Context) (int, []byte, error) {
				if !h.healthy || !h.services.isActive(gatewayUnit) {
					return 0, nil, errors.New("connection refused")
				}
				installed, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
				if err != nil {
					return 0, nil, err
				}
				generation, reported, reloadError := installed.Generation, digest, ""
				switch mode {
				case "reject":
					generation, reloadError = stale, cause
				case "stale":
					generation = stale
				case "missing generation":
					generation = 0
				case "other policy":
					reported = other
				}
				return 200, []byte(fmt.Sprintf(`{"api":{"state":"running"},"policy":{"effective_digest":%q,"config_generation":%d,"last_reload_error":%q},"inspection":{"local":"active","ai_defense":"disabled"}}`,
					reported, generation, reloadError)), nil
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			installedGeneration := func() uint64 {
				t.Helper()
				state, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
				if err != nil {
					t.Fatal(err)
				}
				return state.Generation
			}

			for i, tc := range []struct {
				mode, code, want string
				// repair restarts the running gateway; otherwise ensure --config
				// starts a gateway that was not running.
				repair bool
			}{
				{mode: "reject", code: codePolicyReloadRejected, want: cause},
				{mode: "stale", code: codePolicyNotApplied, want: "not lifecycle generation"},
				{mode: "missing generation", code: codePolicyNotApplied, want: "config generation 0"},
				{mode: "other policy", code: codePolicyNotApplied, want: shortDigest(other)},
				{mode: "reject", code: codePolicyReloadRejected, want: cause, repair: true},
				{mode: "stale", code: codePolicyNotApplied, want: "not lifecycle generation", repair: true},
				{mode: "missing generation", code: codePolicyNotApplied, want: "config generation 0", repair: true},
			} {
				name := tc.mode + " after ensure --config"
				if tc.repair {
					name = tc.mode + " after repair"
				}
				t.Run(name, func(t *testing.T) {
					mode, stale = tc.mode, installedGeneration()
					if tc.repair {
						// Repair records no new generation: the gateway
						// comes back on the one before the installed one.
						stale--
					}
					var r = h.run(Options{Action: ActionRepair})
					if !tc.repair {
						h.services.mu.Lock()
						h.services.active[gatewayUnit] = false
						h.services.mu.Unlock()
						r = h.run(Options{Action: ActionEnsure, ConfigFile: writeTempConfig(t, []byte(fmt.Sprintf("# update %d\n%s", i, h.read(h.env.Layout.ConfigPath))))})
						if installedGeneration() <= stale {
							t.Fatalf("ensure --config recorded no new generation (still %d)", stale)
						}
					}
					if r.OK || r.ExitCode == 0 || !strings.Contains(messagesOf(r.Errors, tc.code), tc.want) {
						t.Fatalf("%s reported success or hid the cause: exit=%d errors=%+v warnings=%+v", name, r.ExitCode, r.Errors, r.Warnings)
					}
					if r.SecurityComplete || r.Policy == nil || r.Policy.Applied {
						t.Fatalf("%s certified the policy: complete=%v policy=%+v", name, r.SecurityComplete, r.Policy)
					}
					status := h.run(Options{Action: ActionStatus})
					if status.SecurityComplete || status.Policy == nil || status.Policy.Applied ||
						!strings.Contains(messagesOf(status.Warnings, tc.code), tc.want) {
						t.Fatalf("status after %s: complete=%v policy=%+v warnings=%+v", name, status.SecurityComplete, status.Policy, status.Warnings)
					}
					verify := h.run(Options{Action: ActionVerify})
					if verify.OK || verify.SecurityComplete || verify.Policy == nil || verify.Policy.Applied ||
						!strings.Contains(messagesOf(verify.Errors, tc.code), tc.want) {
						t.Fatalf("verify after %s: exit=%d complete=%v policy=%+v errors=%+v", name, verify.ExitCode, verify.SecurityComplete, verify.Policy, verify.Errors)
					}

					// Once the gateway runs the recorded generation, the same
					// commands report it applied.
					mode = "accept"
					if r := h.run(Options{Action: ActionStatus}); r.Policy == nil || !r.Policy.Applied || hasWarning(r, codePolicyNotApplied) || hasWarning(r, codePolicyReloadRejected) {
						t.Fatalf("status after the gateway took the generation: policy=%+v warnings=%+v", r.Policy, r.Warnings)
					}
					if r := h.run(Options{Action: ActionVerify}); len(messagesOf(r.Errors, codePolicyNotApplied)+messagesOf(r.Errors, codePolicyReloadRejected)) > 0 || r.Policy == nil || !r.Policy.Applied {
						t.Fatalf("verify after the gateway took the generation: policy=%+v errors=%+v", r.Policy, r.Errors)
					}
				})
			}
			mode = "accept"
			requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: writeTempConfig(t, []byte("# accepted\n"+h.read(h.env.Layout.ConfigPath)))}))
		})
	}
}

// A missing or unreadable config generation record cannot confirm the
// gateway's reported policy, even if its digest still matches the config.
func TestStatusAndVerifyRequireReadableInstalledGeneration(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, goos := range []string{"linux", "darwin"} {
		for _, damage := range []string{"missing", "corrupt"} {
			t.Run(goos+"/"+damage, func(t *testing.T) {
				h := newTestHost(t, goos)
				h.env.Runner = &policyDigestRunner{fakeRunner: h.runner, digest: digest}
				reported, reloadError := digest, ""
				servePolicyHealth(h, &reported, &reloadError)
				requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
				path := configwrite.GenerationPath(h.env.P(h.env.Layout.ConfigPath))
				var err error
				if damage == "missing" {
					err = os.Remove(path)
				} else {
					err = os.WriteFile(path, []byte("{corrupt"), 0o640)
				}
				if err != nil {
					t.Fatal(err)
				}
				status := h.run(Options{Action: ActionStatus})
				if status.Policy == nil || status.Policy.Applied || status.SecurityComplete ||
					!strings.Contains(messagesOf(status.Warnings, codePolicyNotApplied), "cannot read lifecycle generation record") {
					t.Fatalf("status certified %s generation record: complete=%v policy=%+v warnings=%+v", damage, status.SecurityComplete, status.Policy, status.Warnings)
				}
				verify := h.run(Options{Action: ActionVerify})
				if verify.OK || verify.Policy == nil || verify.Policy.Applied || verify.SecurityComplete ||
					!strings.Contains(messagesOf(verify.Errors, codePolicyNotApplied), "cannot read lifecycle generation record") {
					t.Fatalf("verify certified %s generation record: exit=%d complete=%v policy=%+v errors=%+v", damage, verify.ExitCode, verify.SecurityComplete, verify.Policy, verify.Errors)
				}
			})
		}
	}
}
