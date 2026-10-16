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
	"os"
	"path/filepath"
	"testing"
)

// GAP-1411: after a failed --config run rolled back, the config.yaml written
// during the run is put back unless config.yaml changed since the rollback
// restored it (GAP-1379), which was told by the digest alone: an
// administrator who pushed the last applied config again after the restart
// (the same bytes) had it overwritten by the older edit. A later write of
// the same bytes stays.
func TestSameContentPushAfterARollbackIsNotOverwritten(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	applied := h.read(h.env.Layout.ConfigPath)
	early := []byte(applied + "# early push\n")
	configPath := h.env.P(h.env.Layout.ConfigPath)
	replace := func(data []byte) {
		tmp := configPath + ".push"
		if err := os.WriteFile(tmp, data, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, configPath); err != nil {
			t.Fatal(err)
		}
	}
	hooked := &hookedServices{fakeServices: h.services}
	pushed := false
	hooked.onStop = func(unit string) {
		if unit == unitEnumerator && !pushed {
			pushed = true
			replace(early)
		}
	}
	sawOwn, done := false, false
	hooked.onStart = func(unit string) {
		if unit != unitGateway || done {
			return
		}
		if h.read(h.env.Layout.ConfigPath) != applied {
			sawOwn = true
		} else if sawOwn {
			done = true
			replace([]byte(applied)) // the administrator pushes the applied config again
		}
	}
	h.env.Services = hooked
	h.healthy = false
	configFile := filepath.Join(t.TempDir(), "pushed.yaml")
	if err := os.WriteFile(configFile, []byte(applied+"# --config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	failed := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0"), ConfigFile: configFile})
	requireError(t, failed, codeActivate)
	if !pushed || !done {
		t.Fatalf("premise: the early push (%v) or the push after the restore (%v) did not happen", pushed, done)
	}
	if got := h.read(h.env.Layout.ConfigPath); got != applied {
		t.Fatalf("the same-content push made after the restore was overwritten:\n%s", got)
	}
}
