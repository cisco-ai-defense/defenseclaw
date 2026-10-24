// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// undoProofGateway is a gateway that runs the config it last loaded: nil
// while it is down. Its file watcher picks up the candidate config as soon
// as it is written and misses the restore write, so after an undo only a
// reload request, a restart or a start puts it back on the restored config.
// A stuck gateway does neither: it keeps the candidate, or stays down.
type undoProofGateway struct {
	host           *hotConfigHost
	loaded         []byte
	stuck          bool
	restartFails   bool // the apply's restart fails and leaves the gateway down
	restarts       int
	reloads        int
	recovers       int
	loadsOfRestore int
}

func (g *undoProofGateway) load() bool {
	if g.stuck {
		return false
	}
	installed, err := os.ReadFile(g.host.configPath)
	if err != nil {
		return false
	}
	g.loaded = installed
	if string(installed) != g.host.next {
		g.loadsOfRestore++
	}
	return true
}

// Review loop round 4: a failed hot apply undoes the change on the gateway
// and proves it on every path, not only after the adoption check passed.
// The gateway can run the candidate config while the adoption check fails:
// the watcher loaded it before the post-write validation failed, or the
// gateway reports the candidate's digest with a generation or a bundle
// identity the check does not accept, or its restart on the candidate
// failed. In each case the undo puts the gateway back on the restored
// config (a reload request, or a restart for a gateway whose restart was
// attempted) and proves it by the policy digest, or stops the gateway when
// it cannot. A gateway that still runs the restored policy with a reload
// error of its live generation is proven too: the error does not change
// which policy decides the hooks. Before, an undo without a passed adoption
// check asked nothing of the gateway, so the candidate policy stayed live
// and the run reported a clean undo.
func TestWindowsEnterpriseHotConfigEveryUndoIsProven(t *testing.T) {
	const policyPrevious = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_fail_mode: open\n"
	const policyNext = "config_version: 9\nguardrail:\n  block_at: LOW\n  hook_fail_mode: open\n"
	const startPrevious = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 500\n"
	const startNext = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 600\n"
	const bundleID = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T8"
	failedVerify := installedStatus("Verify")
	failedVerify["ok"], failedVerify["gateway_ready"] = false, false
	type failure struct {
		name             string
		previous, next   string
		bundle           bool
		validationFails  bool
		writeFails       bool
		writerRestored   bool
		generationLags   bool
		otherBundle      bool
		restartFails     bool
		verifyFails      bool
		reloadError      string
		code             string // the bundle error of the failed apply
		restartsTheUndo  bool
		onlyWhenFollowed bool
	}
	failures := []failure{
		{name: "initial write failed after publishing the candidate",
			previous: policyPrevious, next: policyNext, writeFails: true},
		{name: "initial bundle write failed after publishing the candidate",
			previous: policyPrevious, next: policyNext, bundle: true, writeFails: true, code: "bundle_config_write_failed"},
		{name: "initial writer restored bytes after the watcher loaded the candidate",
			previous: policyPrevious, next: policyNext, writeFails: true, writerRestored: true},
		{name: "post-write validation failed after the watcher loaded the candidate",
			previous: policyPrevious, next: policyNext, validationFails: true},
		{name: "adoption failed on the generation with the candidate digest live",
			previous: policyPrevious, next: policyNext, generationLags: true},
		{name: "bundle adoption failed on the generation with the candidate digest live",
			previous: policyPrevious, next: policyNext, bundle: true, generationLags: true, code: "bundle_policy_not_adopted"},
		{name: "bundle adoption failed on the bundle identity with the candidate digest live",
			previous: policyPrevious, next: policyNext, bundle: true, otherBundle: true, code: "bundle_policy_not_adopted"},
		{name: "bundle gateway restart failed",
			previous: startPrevious, next: startNext, bundle: true, restartFails: true, code: "bundle_gateway_restart_failed", restartsTheUndo: true},
		{name: "post-verify failed while the live generation reports a reload error",
			previous: policyPrevious, next: policyNext, verifyFails: true, reloadError: "opa: rego compile failed", onlyWhenFollowed: true},
	}
	for _, tc := range failures {
		for _, stuck := range []bool{false, true} {
			if stuck && tc.onlyWhenFollowed {
				continue
			}
			name := tc.name + "/gateway follows the undo"
			if stuck {
				name = tc.name + "/gateway does not follow the undo"
			}
			t.Run(name, func(t *testing.T) {
				host, opts := newHotConfigHost(t, tc.previous, tc.next)
				recorded := `{"generation":3,"config_sha256":"` + configwrite.SHA256Hex([]byte(tc.previous)) + `"}`
				if err := os.WriteFile(configwrite.GenerationPath(host.configPath), []byte(recorded), 0o600); err != nil {
					t.Fatal(err)
				}
				gw := &undoProofGateway{host: host, loaded: []byte(tc.previous), stuck: stuck, restartFails: tc.restartFails}
				if tc.bundle {
					// A staged bundle needs its signer and policy principal before
					// this test can exercise the config publication and undo.
					opts.bundle = &windowsBundleRun{prepared: &enterprisebundle.Prepared{Receipt: &enterprisebundle.Receipt{
						BundleID: bundleID, Version: 2, Principal: "control-plane:acme/alice", SignerKeyID: "k1",
					}}}
				}
				write := windowsEnterpriseHotConfigWrite
				windowsEnterpriseHotConfigWrite = func(ctx context.Context, path string, raw []byte, opt configwrite.Options) error {
					if err := write(ctx, path, raw, opt); err != nil {
						return err
					}
					if string(raw) == tc.next && !tc.restartFails {
						// The watcher loads the candidate at once.
						gw.loaded = append([]byte(nil), raw...)
					}
					if tc.writeFails && string(raw) == tc.next {
						if tc.writerRestored {
							if err := os.WriteFile(path, []byte(tc.previous), 0o600); err != nil {
								return err
							}
						}
						return configwrite.AfterPublication(errors.New("generation write and writer restore failed after config publication"))
					}
					return nil
				}
				if tc.validationFails {
					windowsEnterpriseHotConfigValidate = func(string, string, string, bool) (windowsServiceConfigValidation, error) {
						return windowsServiceConfigValidation{}, errors.New("the gateway service cannot load the config")
					}
				}
				windowsEnterpriseHotBundleReload = func(context.Context, managed.StandaloneLayout) error {
					gw.reloads++
					gw.load()
					return nil
				}
				windowsEnterpriseHotConfigRestart = func() (bool, error) {
					gw.restarts++
					if gw.restartFails && gw.restarts == 1 {
						gw.loaded = nil
						return false, errors.New("the gateway did not start")
					}
					if gw.loaded == nil && gw.stuck {
						return false, nil
					}
					if !gw.load() {
						return false, errors.New("the gateway did not restart")
					}
					return true, nil
				}
				windowsEnterpriseHotConfigRecover = func() (bool, error) {
					gw.recovers++
					if gw.loaded != nil {
						return false, nil
					}
					if !gw.load() {
						return false, errors.New("the gateway did not start")
					}
					return true, nil
				}
				var replies []map[string]any
				if tc.verifyFails {
					replies = append(replies, failedVerify)
				}
				stub := &ensureStub{t: t, replies: replies}
				// The installer stub replaces the policy digest seam too: install it first.
				stub.install(t)
				windowsEnterprisePolicyDigest = func(context.Context) ([]byte, error) {
					installed, err := os.ReadFile(host.configPath)
					if err != nil {
						return nil, err
					}
					reported := ""
					if gw.loaded != nil {
						reported = "sha256:" + configwrite.SHA256Hex(gw.loaded)
					}
					generation := len(host.writes) + 10
					gatewayGeneration := generation
					if tc.generationLags {
						gatewayGeneration--
					}
					// The reload error belongs to the live generation of the
					// restored config, not to the candidate the gateway adopts.
					reloadError := ""
					if tc.reloadError != "" && bytes.Equal(gw.loaded, []byte(tc.previous)) {
						reloadError = tc.reloadError
					}
					reportedBundle := bundleID
					if tc.otherBundle {
						reportedBundle = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T9"
					}
					return []byte(`{"effective_digest":"sha256:` + configwrite.SHA256Hex(installed) +
						`","config_generation":` + strconv.Itoa(generation) +
						`,"config_generation_recorded":true,"gateway_reported_digest":"` + reported +
						`","gateway_reported_config_generation":` + strconv.Itoa(gatewayGeneration) +
						`,"gateway_reported_bundle_id":"` + reportedBundle +
						`","gateway_reported_bundle_version":2,"gateway_last_reload_error":"` + reloadError + `"}`), nil
				}
				result := newWindowsEnterpriseStandaloneResult("ensure", opts)
				applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
					&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
				message := fmt.Sprint(result.Errors)
				if applied {
					t.Fatalf("the failed apply reported applied; errors %s", message)
				}
				if got, _ := os.ReadFile(host.configPath); string(got) != tc.previous {
					t.Fatalf("config.yaml = %q, want the previous config back", got)
				}
				if tc.code != "" && !windowsBundleHasCode(result.Errors, tc.code) {
					t.Fatalf("errors %s, want %s", message, tc.code)
				}
				// The undo went to the gateway after the restore: a restart (or
				// a start) for one whose restart was attempted, else a reload.
				if tc.restartsTheUndo {
					if gw.restarts < 2 {
						t.Fatalf("restarts = %d, want the failed restart and one on the restored config", gw.restarts)
					}
				} else if gw.reloads == 0 || gw.restarts != 0 {
					t.Fatalf("reloads = %d, restarts = %d: want a reload request on the restored config", gw.reloads, gw.restarts)
				}
				if !stuck {
					if !bytes.Equal(gw.loaded, []byte(tc.previous)) || gw.loadsOfRestore == 0 {
						t.Fatalf("the gateway runs %q, want the restored config", gw.loaded)
					}
					if host.stops != 0 || host.closes != 0 || opts.hotConfigRestoreFailed || windowsBundleHasCode(result.Errors, "config_restore_failed") {
						t.Fatalf("a proven undo: stops=%d restoreFailed=%t errors %s", host.stops, opts.hotConfigRestoreFailed, message)
					}
					if tc.restartsTheUndo && !opts.bundle.gatewayRestarted {
						t.Fatal("the bundle receipt does not record the restart of the undo")
					}
					return
				}
				if host.stops != 1 || host.closes != 1 || !host.closureHeld || !opts.hotConfigRestoreFailed || !windowsBundleHasCode(result.Errors, "config_restore_failed") {
					t.Fatalf("an unproven undo: stops=%d closes=%d held=%t restoreFailed=%t errors %s", host.stops, host.closes, host.closureHeld, opts.hotConfigRestoreFailed, message)
				}
				for _, want := range []string{"did not report the restored config's policy", "holds the previous config", "gateway service was stopped"} {
					if !strings.Contains(message, want) {
						t.Fatalf("errors %s do not say %q", message, want)
					}
				}
			})
		}
	}
}

func TestWindowsEnterpriseHotConfigDoesNotStopWithUnclosedHooks(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_fail_mode: open\n"
	const next = "config_version: 9\nguardrail:\n  block_at: LOW\n  hook_fail_mode: open\n"
	host, opts := newHotConfigHost(t, previous, next)
	windowsEnterpriseHotConfigCloseHooks = func(managed.StandaloneLayout) error {
		return errors.New("managed hook closure could not be published")
	}
	stub := &ensureStub{t: t}
	stub.install(t)
	windowsEnterprisePolicyDigest = func(context.Context) ([]byte, error) {
		return nil, errors.New("policy digest readback unavailable")
	}
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	applied, _ := windowsEnterpriseHotConfigApply(context.Background(), &cobra.Command{}, opts, "installer.ps1",
		&windowsEnterpriseInstallerReport{OK: true, Installed: true, GatewayReady: true}, result)
	if applied || host.stops != 0 || !opts.hotConfigRestoreFailed || !windowsBundleHasCode(result.Errors, "config_restore_failed") {
		t.Fatalf("applied=%t stops=%d restoreFailed=%t errors=%+v", applied, host.stops, opts.hotConfigRestoreFailed, result.Errors)
	}
	if message := fmt.Sprint(result.Errors); !strings.Contains(message, "gateway service was left running because its hooks could not be durably forced closed") {
		t.Fatalf("closure failure was not reported: %s", message)
	}
}
