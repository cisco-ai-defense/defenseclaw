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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// A run that fails before any service starts on its config leaves the
// generation record as it found it; one that fails after the services started
// keeps the counter moving forward (a generation number never names two
// configs once the gateway can have reported it).
func TestRolledBackEnsureGenerationOnlyMovesOnceTheGatewayCouldReadIt(t *testing.T) {
	generation := func(h *testHost) uint64 {
		t.Helper()
		state, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
		if err != nil {
			t.Fatal(err)
		}
		return state.Generation
	}
	setup := func() (*testHost, uint64, string) {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		return h, generation(h), h.read(h.env.Layout.ConfigPath)
	}
	changed := func(h *testHost) Options {
		return Options{Action: ActionEnsure, ConfigFile: writeTempConfig(t, previousDefaultConfig(h.env.Layout))}
	}

	h, before, installed := setup()
	h.services.failReloadOnce = true
	requireError(t, h.run(changed(h)), codeApply)
	if got := generation(h); got != before || h.read(h.env.Layout.ConfigPath) != installed {
		t.Fatalf("generation %d -> %d after a run that failed before the services started; want it unchanged", before, got)
	}
	requireOK(t, h.run(changed(h)))
	if got := generation(h); got != before+1 {
		t.Fatalf("the next successful run recorded generation %d, want %d", got, before+1)
	}

	h, before, _ = setup()
	h.healthy = false
	requireError(t, h.run(changed(h)), codeActivate)
	if got := generation(h); got != before+2 {
		t.Fatalf("generation %d -> %d after a run that failed once the services started; want %d", before, got, before+2)
	}
}
