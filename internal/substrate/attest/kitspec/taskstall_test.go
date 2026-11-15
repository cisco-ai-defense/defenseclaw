// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Spec renders the sandbox artifacts of an image, which OpenShell does not do
// on Windows hosts (as kitspec_test.go).
//go:build !windows

package kitspec

import (
	"strings"
	"testing"
	"time"
)

// GAP-0290: the template build sets relay.task_stall_ms, within 1m..24h.
func TestTaskStallReachesTheKitConfig(t *testing.T) {
	base := Options{Connector: "claudecode", KitVersion: "1.0.10", HookBinary: []byte("x"), RelayBinary: []byte("x"), MetadataOnly: true}
	for _, bad := range []time.Duration{time.Second, 59 * time.Second, 25 * time.Hour, -time.Minute} {
		o := base
		o.TaskStall = bad
		if _, _, err := Spec(o); err == nil || !strings.Contains(err.Error(), "task_stall_ms") {
			t.Errorf("--task-stall %s: %v", bad, err)
		}
	}
	o := base
	o.TaskStall = 30 * time.Minute
	spec, _, err := Spec(o)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range spec.Files {
		if strings.Contains(string(f.Data), `"task_stall_ms": 1800000`) {
			found = true
		}
	}
	if !found {
		t.Fatal("30m is not in the kit configuration the image carries")
	}
}
