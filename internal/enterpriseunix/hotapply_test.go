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
	if _, touched := ensure(strings.Replace(hot, "mode: action\n", "mode: action\n  hook_self_heal: false\n", 1)); !touched {
		t.Fatal("a restart-required key (guardrail.hook_self_heal) left the gateway running")
	}
	reloads = false
	if _, touched := ensure(strings.Replace(hot, "mode: action\n", "mode: action\n  block_at: HIGH\n", 1)); !touched {
		t.Fatal("a gateway that did not apply the change was not restarted")
	}
}
