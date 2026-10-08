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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

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
	reloads := true
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		if !h.healthy || !h.services.isActive(unitGateway) {
			return 0, nil, errors.New("connection refused")
		}
		reported := digest("a")
		if reloads && strings.Contains(h.read(h.env.Layout.ConfigPath), "mode: action") {
			reported = digest("b")
		}
		if reloads && strings.Contains(h.read(h.env.Layout.ConfigPath), "rule_pack: strict") {
			reported = digest("c")
		}
		return 200, []byte(`{"api":{"state":"running"},"policy":{"effective_digest":"` + reported + `"},"inspection":{"local":"active","ai_defense":"disabled"}}`), nil
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
	r, touched := ensure(hot)
	if touched || !strings.Contains(strings.Join(r.Changes, "\n"), "it was not restarted") || r.Policy == nil || !r.Policy.Applied {
		t.Fatalf("hot change: gateway touched = %v, changes = %q, policy = %+v", touched, r.Changes, r.Policy)
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
	reloads = false
	if _, touched := ensure(strings.Replace(hot, "mode: action\n", "mode: action\n  block_at: HIGH\n", 1)); !touched {
		t.Fatal("a gateway that did not apply the change was not restarted")
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
