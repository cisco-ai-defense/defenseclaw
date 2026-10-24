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
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func TestHotBundleUsesVerifiedDigestWithoutRebuildingPolicy(t *testing.T) {
	want := "sha256:" + strings.Repeat("a", 64)
	h := newTestHost(t, "linux")
	path := h.env.P(h.env.Layout.ConfigPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	configBytes := []byte("config_version: 8\n")
	if err := os.WriteFile(path, configBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	l := &lifecycle{env: h.env, bundle: &bundleRun{configSHA: sha256Bytes(configBytes), receipt: &enterprisebundle.Receipt{
		ExpectedDigest: want, DigestComparable: true,
	}}}
	if got, ok := l.bundlePolicyWant(t.Context(), l.bundle.receipt); !ok || got != want {
		t.Fatalf("verified bundle digest = %q, %v; want %q", got, ok, want)
	}
	fallback := "sha256:" + strings.Repeat("b", 64)
	h.env.Runner = &policyDigestRunner{fakeRunner: h.runner, digest: fallback}
	if err := os.WriteFile(path, []byte("config_version: 8\nmode: action\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := l.bundlePolicyWant(t.Context(), l.bundle.receipt); !ok || got != fallback {
		t.Fatalf("changed installed config digest = %q, %v; want fallback %q", got, ok, fallback)
	}
}

// TestEnsureAppliesAHotConfigChangeInTheRunningGateway covers GAP-0120: a
// config change the gateway reloads in place keeps it running (so its policy
// generation advances), a restart-required key still restarts it, and a
// gateway that does not apply the change is restarted after all.
func TestEnsureAppliesAHotConfigChangeInTheRunningGateway(t *testing.T) {
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	h := newTestHost(t, "linux")
	runner := &policyDigestRunner{fakeRunner: h.runner, digest: digest("a")}
	h.env.Runner = runner
	// The gateway reloads config.yaml itself: it reports the new policy once
	// the file holds the new mode, unless it is told to ignore the change.
	// A restart loads the installed config whole.
	reloads, restarted := true, false
	h.services.afterRestart = func(u Unit) { restarted = restarted || u.Name == unitGateway }
	h.services.afterStart = h.services.afterRestart
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		if !h.healthy || !h.services.isActive(unitGateway) {
			return 0, nil, errors.New("connection refused")
		}
		if !reloads && restarted {
			return 200, []byte(fmt.Sprintf(`{"api":{"state":"running"},"policy":{"effective_digest":%q,"config_generation":%d},"inspection":{"local":"active","ai_defense":"disabled"}}`,
				runner.digest, installedGenerationOf(h))), nil
		}
		reported := digest("a")
		if reloads && strings.Contains(h.read(h.env.Layout.ConfigPath), "mode: action") {
			reported = digest("b")
		}
		if reloads && strings.Contains(h.read(h.env.Layout.ConfigPath), "rule_pack: strict") {
			reported = digest("c")
		}
		state, _ := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
		return 200, []byte(fmt.Sprintf(`{"api":{"state":"running"},"policy":{"effective_digest":%q,"config_generation":%d},"inspection":{"local":"active","ai_defense":"disabled"}}`,
			reported, state.Generation)), nil
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))

	ensure := func(config string) (*enterprisestatus.Result, bool) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
		from := len(h.services.calls)
		r := h.run(Options{Action: ActionEnsure, ConfigFile: path})
		requireOK(t, r)
		for _, call := range h.services.calls[from:] {
			if strings.HasSuffix(call, " "+unitGateway) && !strings.HasPrefix(call, "enable ") {
				return r, true
			}
		}
		return r, false
	}
	hot := strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: action", 1)
	runner.digest = digest("b")
	from := len(h.services.calls)
	r, touched := ensure(hot)
	if touched || !strings.Contains(strings.Join(r.Changes, "\n"), "it was not restarted") || r.Policy == nil || !r.Policy.Applied {
		t.Fatalf("hot change: gateway touched = %v, changes = %q, policy = %+v", touched, r.Changes, r.Policy)
	}
	// GAP-1418: the sensor helper stays up with the gateway; stopping it
	// ended the running gateway's kernel event stream.
	for _, call := range h.services.calls[from:] {
		if call == "stop "+unitSensorHelper || call == "start "+unitSensorHelper || call == "restart "+unitSensorHelper {
			t.Fatalf("hot change touched the sensor helper: %q", call)
		}
	}
	// GAP-0545: a change in bytes only keeps the gateway and its policy.
	if r, touched := ensure("# edited by configuration management\n" + strings.ReplaceAll(hot, "\n", "\r\n")); touched || !strings.Contains(strings.Join(r.Changes, "\n"), "it was not restarted") {
		t.Fatalf("a comment and CRLF restarted the gateway: changes = %q", r.Changes)
	}
	// GAP-0550: switching the rule pack is applied in the running gateway.
	runner.digest = digest("c")
	if r, touched := ensure(strings.Replace(hot, "rule_pack: default", "rule_pack: strict", 1)); touched || !strings.Contains(strings.Join(r.Changes, "\n"), "it was not restarted") {
		t.Fatalf("a rule pack switch restarted the gateway: changes = %q", r.Changes)
	}
	runner.digest = digest("b")
	if _, touched := ensure(strings.Replace(hot, "mode: action\n", "mode: action\n  hook_self_heal: false\n", 1)); !touched {
		t.Fatal("a restart-required key (guardrail.hook_self_heal) left the gateway running")
	}
	reloads, restarted = false, false
	if _, touched := ensure(strings.Replace(hot, "mode: action\n", "mode: action\n  block_at: HIGH\n", 1)); !touched {
		t.Fatal("a gateway that did not apply the change was not restarted")
	}
}

func installedGenerationOf(h *testHost) uint64 {
	state, _ := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
	return state.Generation
}

func TestNoAnchorHotEnsureRequiresGatewayGenerationAndCleanReload(t *testing.T) {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	h := newTestHost(t, "linux")
	h.env.Runner = &policyDigestRunner{fakeRunner: h.runner, digest: digest}
	staleGeneration, restartFrom := ^uint64(0), -1
	reloadError := ""
	persist := false
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		if !h.healthy || !h.services.isActive(unitGateway) {
			return 0, nil, errors.New("connection refused")
		}
		state, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
		if err != nil {
			return 0, nil, err
		}
		generation, lastError := state.Generation, ""
		restarted := false
		if restartFrom >= 0 {
			for _, call := range h.services.calls[restartFrom:] {
				if call == "restart "+unitGateway {
					restarted = true
				}
			}
		}
		if state.Generation > staleGeneration && (persist || !restarted) {
			generation, lastError = staleGeneration, reloadError
		}
		return 200, []byte(fmt.Sprintf(`{"api":{"state":"running"},"policy":{"effective_digest":%q,"config_generation":%d,"last_reload_error":%q},"inspection":{"local":"active","ai_defense":"disabled"}}`,
			digest, generation, lastError)), nil
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	for _, tc := range []struct {
		name, reloadError string
	}{
		{"rejected reload with unchanged digest", "managed generation was refused"},
		{"stale generation without reload error", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
			if err != nil {
				t.Fatal(err)
			}
			staleGeneration, reloadError = state.Generation, tc.reloadError
			configFile := writeTempConfig(t, []byte("# "+tc.name+"\n"+h.read(h.env.Layout.ConfigPath)))
			restartFrom = len(h.services.calls)
			r := h.run(Options{Action: ActionEnsure, ConfigFile: configFile})
			requireOK(t, r)
			if r.Policy == nil || !r.Policy.Applied {
				t.Fatalf("ensure did not report the restarted gateway's policy: policy=%+v warnings=%+v", r.Policy, r.Warnings)
			}
			restarted := false
			for _, call := range h.services.calls[restartFrom:] {
				restarted = restarted || call == "restart "+unitGateway
			}
			if !restarted {
				t.Fatalf("ensure returned without restarting the gateway for stale generation %d: changes=%q", staleGeneration, r.Changes)
			}
		})
	}
	state, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	staleGeneration, reloadError, persist = state.Generation, "managed generation refused after restart", true
	restartFrom = len(h.services.calls)
	refused := h.run(Options{Action: ActionEnsure, ConfigFile: writeTempConfig(t, []byte("# rejected after restart\n"+h.read(h.env.Layout.ConfigPath)))})
	if refused.OK || !strings.Contains(fmt.Sprint(refused.Errors), reloadError) {
		t.Fatalf("persistent rejection did not fail with its cause: exit=%d errors=%+v warnings=%+v", refused.ExitCode, refused.Errors, refused.Warnings)
	}
}

// GAP-0941: configuration management that installs the same config.yaml
// again with another group (install -o root -g root -m 0640) gets a no-op:
// the managed owner comes back, and the gateway is neither stopped nor
// restarted.
func TestEnsureOfAnUnchangedConfigWithAnotherOwnerIsANoop(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	config := h.env.P(h.env.Layout.ConfigPath)
	_, serviceGID, err := h.env.OwnerOf(config)
	if err != nil || serviceGID == 0 {
		t.Fatalf("installed config group = %d, %v", serviceGID, err)
	}
	if err := h.env.Lchown(config, 0, 0); err != nil {
		t.Fatal(err)
	}
	from := len(h.services.calls)
	r := h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	for _, call := range h.services.calls[from:] {
		if strings.HasSuffix(call, " "+unitGateway) && !strings.HasPrefix(call, "enable ") {
			t.Fatalf("the gateway was touched (%s); changes = %q", call, r.Changes)
		}
	}
	if !r.Noop || !hasWarning(r, codeConfigMetadataRestored) {
		t.Fatalf("noop = %v, warnings = %+v, changes = %q", r.Noop, r.Warnings, r.Changes)
	}
	if _, gid, _ := h.env.OwnerOf(config); gid != serviceGID {
		t.Fatalf("config group = %d, want the service group %d", gid, serviceGID)
	}
}

// GAP-1030: the same config.yaml installed again while the apply run that
// the previous install started is checking (right after it restored the
// owner) is still a no-op; the gateway is not restarted.
func TestEnsureStaysANoopWhenTheSameConfigIsInstalledAgainDuringTheCheck(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	config := h.env.P(h.env.Layout.ConfigPath)
	_, serviceGID, _ := h.env.OwnerOf(config)
	lchown := h.env.Lchown
	if err := lchown(config, 0, 0); err != nil {
		t.Fatal(err)
	}
	installedAgain := false
	h.env.Lchown = func(path string, uid, gid int) error {
		if err := lchown(path, uid, gid); err != nil || path != config || installedAgain {
			return err
		}
		installedAgain = true
		return lchown(path, 0, 0) // install -o root -g root -m 0640 of the same bytes
	}
	from := len(h.services.calls)
	r := h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	for _, call := range h.services.calls[from:] {
		if strings.HasSuffix(call, " "+unitGateway) && !strings.HasPrefix(call, "enable ") {
			t.Fatalf("the gateway was touched (%s); changes = %q", call, r.Changes)
		}
	}
	if !installedAgain || !r.Noop {
		t.Fatalf("installed again = %v, noop = %v, changes = %q", installedAgain, r.Noop, r.Changes)
	}
	if _, gid, _ := h.env.OwnerOf(config); gid != serviceGID {
		t.Fatalf("config group = %d, want the service group %d", gid, serviceGID)
	}
}

// GAP-0738 (#1104): a second config push that lands while the apply of the
// first one waits for the running gateway's policy keeps the gateway
// running. The first run waited out the hot-apply timeout and restarted the
// gateway; its follow-up transaction now applies the second push hot.
func TestAConfigPushedDuringAHotApplyKeepsTheGatewayRunning(t *testing.T) {
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			runner := &policyDigestRunner{fakeRunner: h.runner, digest: digest("a")}
			h.env.Runner = runner
			gateway := unitOf(goos, "gateway")
			first := strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: action", 1)
			second := first + "# second push\n"
			calls, pushAt := 0, -1
			h.env.HealthGet = func(context.Context) (int, []byte, error) {
				if !h.healthy || !h.services.isActive(gateway) {
					return 0, nil, errors.New("connection refused")
				}
				calls++
				if calls == pushAt {
					// The administrator pushes again before the gateway has
					// applied the first push; the gateway follows the file.
					if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), []byte(second), 0o640); err != nil {
						t.Error(err)
					}
					runner.digest = digest("c")
				}
				config := h.read(h.env.Layout.ConfigPath)
				reported := digest("a")
				switch {
				case strings.Contains(config, "# second push"):
					reported = digest("c")
				case strings.Contains(config, "mode: action"):
					reported = digest("b")
				}
				state, _ := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
				return 200, []byte(fmt.Sprintf(`{"api":{"state":"running"},"policy":{"effective_digest":%q,"config_generation":%d},"inspection":{"local":"active","ai_defense":"disabled"}}`,
					reported, state.Generation)), nil
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), []byte(first), 0o640); err != nil {
				t.Fatal(err)
			}
			runner.digest = digest("b")
			// Call 1 is the hot-apply check; call 2 is the first look of
			// the settle wait, after this run computed the policy it waits for.
			calls, pushAt = 0, 2
			from := len(h.services.calls)
			r := h.run(Options{Action: ActionEnsure})
			requireOK(t, r)
			if calls < pushAt {
				t.Fatalf("health asked %d times; the second push never landed", calls)
			}
			for _, call := range h.services.calls[from:] {
				if strings.HasSuffix(call, " "+gateway) && !strings.HasPrefix(call, "enable ") {
					t.Fatalf("the gateway was touched (%s); changes = %q", call, r.Changes)
				}
			}
			record, _ := h.env.loadDeployment()
			if record == nil || record.ConfigSHA256 != sha256Bytes([]byte(second)) || !hasWarning(r, "input_changed") {
				t.Fatalf("the second push is not applied: warnings = %+v, changes = %q", r.Warnings, r.Changes)
			}
		})
	}
}
