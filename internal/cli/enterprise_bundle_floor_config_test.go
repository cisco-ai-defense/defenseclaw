// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeFloorCheckConfig writes the deployed config.yaml of the floor-check
// test device.
func writeFloorCheckConfig(t *testing.T, body string) {
	t.Helper()
	env, err := newUnixLifecycleEnv(runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	path := env.P(env.Layout.ConfigPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// GAP-2035: a managed rollback to 1.0.10 over a config that sets
// ai_discovery.include_skill_manifests failed in the 1.0.10 postinstall
// (config_invalid) after its files replaced 1.0.11's. floor-check, run by the
// older preinstall before any file is replaced, refuses it and names the key.
func TestGAP2035FloorCheckRefusesADowngradeOverNewerConfigKeys(t *testing.T) {
	d := newRouteFloorDevice(t) // routing off: route-only lets every release in
	writeFloorCheckConfig(t, "deployment_mode: managed_enterprise\nai_discovery:\n  enabled: true\n  include_skill_manifests: true\n")
	msg := refusedWithFloorExit(t, d.floorCheck("1.0.10"), "config_newer_than_release")
	if !strings.Contains(msg, "ai_discovery.include_skill_manifests, which DefenseClaw 1.0.10 does not have") || !strings.Contains(msg, "ensure --config") {
		t.Fatalf("refusal = %q; want the key, the release and the fix", msg)
	}
	if !d.rendered(t, "alice") || !d.rendered(t, "bob") {
		t.Fatal("a refused downgrade took the route renders back")
	}
	for _, version := range []string{"1.0.11", "v1.0.11-rc.2", "1.0.12"} {
		if err := d.floorCheck(version); err != nil {
			t.Fatalf("floor-check %s = %v; want the same or a later release let in", version, err)
		}
	}
}

// GAP-2069: the package scripts append " Nothing was changed." to the
// refusal, which ran into the last sentence of the config and route refusals
// ("... then install the older package again Nothing was changed."). Every
// floor-check refusal ends with a full stop, so each platform prints the
// same two sentences.
func TestGAP2069FloorCheckRefusalsEndWithAFullStop(t *testing.T) {
	d := newRouteFloorDevice(t)
	writeFloorCheckConfig(t, "deployment_mode: managed_enterprise\nai_discovery:\n  include_skill_manifests: true\n")
	msg := refusedWithFloorExit(t, d.floorCheck("1.0.10"), "config_newer_than_release")
	if !strings.HasSuffix(msg, "then install the older package again.") {
		t.Fatalf("config refusal = %q; want it to end with \"install the older package again.\"", msg)
	}
	if got := msg + " Nothing was changed."; !strings.Contains(got, "again. Nothing was changed.") {
		t.Fatalf("script-joined text = %q; want the two sentences apart", got)
	}
	writeFloorCheckConfig(t, "ai_discovery: [unclosed\n")
	msg = refusedWithFloorExit(t, d.floorCheck("1.0.10"), "could not be read")
	if !strings.HasSuffix(msg, "install the older package again.") {
		t.Fatalf("unreadable-config refusal = %q; want a full stop at the end", msg)
	}
	routed := newRouteFloorDevice(t)
	routed.routed = []string{"claudecode"}
	msg = refusedWithFloorExit(t, routed.floorCheck("1.0.9"), "route_only_downgrade_refused")
	if !strings.HasSuffix(msg, ".") || strings.HasSuffix(msg, "..") {
		t.Fatalf("route refusal = %q; want exactly one full stop at the end", msg)
	}
}

func TestGAP2035FloorCheckNewerConfigKeyShapes(t *testing.T) {
	for _, test := range []struct {
		name, body, version string
		want                []string // nil: let in
	}{
		{name: "only keys the release has", version: "1.0.10",
			body: "ai_discovery:\n  enabled: true\nsubstrate:\n  enabled: false\n"},
		{name: "a key set to null still counts", version: "1.0.10",
			body: "ai_discovery:\n  include_skill_content_hashes:\n", want: []string{"ai_discovery.include_skill_content_hashes"}},
		{name: "a 1.0.11 key under a 1.0.10 block", version: "1.0.10",
			body: "substrate:\n  enabled: true\n  bundles:\n    oci:\n      enabled: false\n", want: []string{"substrate.bundles.oci"}},
		{name: "the block itself for a release before it", version: "1.0.9",
			body: "substrate:\n  bundles:\n    oci:\n      enabled: false\n", want: []string{"substrate"}},
		{name: "a key in a list item and in a map entry", version: "1.0.9",
			body: "routing:\n  models:\n    - name: a\n    - name: b\n      bedrock: {region: x}\nguardrail:\n  profiles:\n    p1:\n      cascade: {}\n",
			want: []string{"guardrail.profiles.p1.cascade", "routing.models[1].bedrock"}},
		{name: "a pre-release of the older release", version: "1.0.10-rc.1",
			body: "enterprise:\n  openshell:\n    allow_downgrade: true\n", want: []string{"enterprise.openshell.allow_downgrade"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := newRouteFloorDevice(t)
			writeFloorCheckConfig(t, test.body)
			err := d.floorCheck(test.version)
			if test.want == nil {
				if err != nil {
					t.Fatalf("floor-check %s = %v; want it let in", test.version, err)
				}
				return
			}
			msg := refusedWithFloorExit(t, err, "config_newer_than_release")
			if !strings.Contains(msg, "the managed config sets "+strings.Join(test.want, ", ")+", which") {
				t.Fatalf("refusal = %q; want exactly %v named", msg, test.want)
			}
		})
	}
}

func TestGAP2035FloorCheckRefusesAnUnreadableConfigBeforeADowngrade(t *testing.T) {
	d := newRouteFloorDevice(t)
	writeFloorCheckConfig(t, "ai_discovery: [unclosed\n")
	refusedWithFloorExit(t, d.floorCheck("1.0.10"), "could not be read")
	if err := d.floorCheck("1.0.11"); err != nil {
		t.Fatalf("floor-check 1.0.11 = %v; an upgrade must not read the config", err)
	}
}
