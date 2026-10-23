// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validManifest() *Manifest {
	return &Manifest{
		SchemaVersion: ManifestSchemaVersion,
		BundleID:      "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z2A",
		TenantID:      "acme",
		Target:        Target{DeviceGroup: "eng-laptops", Platforms: []string{PlatformLinux, PlatformDarwin}},
		Version:       7,
		Parent:        "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z29",
		CreatedAt:     "2026-10-12T08:30:00Z",
		CreatedBy:     "control-plane:acme/alice@example.com",
		ChangeSummary: "Block HIGH for the ML team",
		Files: []FileEntry{
			{Path: ConfigName, SHA256: strings.Repeat("a", 64), Size: 10},
			{Path: "policies/guardrail/strict/rules.yaml", SHA256: strings.Repeat("b", 64), Size: 3},
		},
		SecretRefs:      []SecretRef{{Ref: "secret://ai-defense-api-key", Required: true, ValueSHA256: strings.Repeat("d", 64)}},
		EffectivePolicy: EffectivePolicy{ProductVersion: "1.0.2", ComputedOn: PlatformLinux, Digests: map[string]string{PlatformLinux: testDigest, PlatformDarwin: testDigest}},
	}
}

func marshal(t testing.TB, m *Manifest) []byte {
	raw, err := m.Marshal()
	if err != nil {
		panic(err)
	}
	return raw
}

func TestDecodeManifestRoundTrip(t *testing.T) {
	want := validManifest()
	got, err := DecodeManifest(marshal(t, want))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded %+v, want %+v", got, want)
	}
}

func TestDecodeManifestRefuses(t *testing.T) {
	valid := string(marshal(t, validManifest()))
	edit := func(old, new string) []byte {
		if !strings.Contains(valid, old) {
			t.Fatalf("fixture has no %q", old)
		}
		return []byte(strings.Replace(valid, old, new, 1))
	}
	mutate := func(change func(*Manifest)) []byte {
		m := validManifest()
		change(m)
		return marshal(t, m)
	}
	cases := map[string][]byte{
		"unknown key":              edit(`"tenant_id"`, `"tenant":"x","tenant_id"`),
		"duplicate key":            edit(`"tenant_id": "acme"`, `"tenant_id": "acme","tenant_id": "evil"`),
		"case-folded key":          edit(`"tenant_id": "acme"`, `"tenant_id": "acme","TENANT_ID": "evil"`),
		"upper-case key":           edit(`"tenant_id"`, `"Tenant_id"`),
		"nested duplicate":         edit(`"device_group": "eng-laptops"`, `"device_group": "eng-laptops", "device_group": "all"`),
		"trailing object":          []byte(valid + "{}"),
		"trailing garbage":         []byte(valid + "x"),
		"byte-order mark":          append([]byte("\xef\xbb\xbf"), valid...),
		"invalid utf-8":            edit(`Block HIGH`, "Block \xff"),
		"array root":               []byte("[" + valid + "]"),
		"too deep":                 edit(`"tenant_id"`, `"x":[[[[[[[[[]]]]]]]]],"tenant_id"`),
		"too large":                []byte(valid + strings.Repeat(" ", MaxManifestBytes)),
		"schema version":           mutate(func(m *Manifest) { m.SchemaVersion = 2 }),
		"bundle id":                mutate(func(m *Manifest) { m.BundleID = "b-01j9zk3q4r5s6t7v8w9x0y1z2a" }),
		"bundle id overflow":       mutate(func(m *Manifest) { m.BundleID = "b-81J9ZK3Q4R5S6T7V8W9X0Y1Z2A" }),
		"tenant":                   mutate(func(m *Manifest) { m.TenantID = "acme corp" }),
		"device group":             mutate(func(m *Manifest) { m.Target.DeviceGroup = "" }),
		"no platform":              mutate(func(m *Manifest) { m.Target.Platforms = nil }),
		"unknown platform":         mutate(func(m *Manifest) { m.Target.Platforms = []string{"freebsd"} }),
		"repeated platform":        mutate(func(m *Manifest) { m.Target.Platforms = []string{PlatformLinux, PlatformLinux} }),
		"version zero":             mutate(func(m *Manifest) { m.Version = 0 }),
		"negative version":         edit(`"version": 7`, `"version": -7`),
		"fractional version":       edit(`"version": 7`, `"version": 7.5`),
		"string version":           edit(`"version": 7`, `"version": "7"`),
		"version past 2^53":        mutate(func(m *Manifest) { m.Version = MaxVersion + 1 }),
		"parent is self":           mutate(func(m *Manifest) { m.Parent = m.BundleID }),
		"rollback of":              mutate(func(m *Manifest) { m.RollbackOf = "b-x" }),
		"local time":               mutate(func(m *Manifest) { m.CreatedAt = "2026-10-12T08:30:00+02:00" }),
		"not a time":               mutate(func(m *Manifest) { m.CreatedAt = "yesterday" }),
		"other tenant admin":       mutate(func(m *Manifest) { m.CreatedBy = "control-plane:other/alice" }),
		"unknown principal":        mutate(func(m *Manifest) { m.CreatedBy = "alice" }),
		"empty operator":           mutate(func(m *Manifest) { m.CreatedBy = "operator:" }),
		"principal too long":       mutate(func(m *Manifest) { m.CreatedBy = "control-plane:acme/" + strings.Repeat("\u00e9", 128) }),
		"summary newline":          mutate(func(m *Manifest) { m.ChangeSummary = "ok\nconfig.change.applied fake" }),
		"summary bidi":             mutate(func(m *Manifest) { m.ChangeSummary = "ok \u202e" }),
		"summary too long":         mutate(func(m *Manifest) { m.ChangeSummary = strings.Repeat("x", MaxChangeSummary+1) }),
		"min product version":      mutate(func(m *Manifest) { m.MinProductVersion = "v1" }),
		"malformed signed minimum": mutate(func(m *Manifest) { m.MinProductVersion = "1.0.4-01" }),
		"no files":                 mutate(func(m *Manifest) { m.Files = nil }),
		"no config":                mutate(func(m *Manifest) { m.Files = m.Files[1:] }),
		"unsorted files":           mutate(func(m *Manifest) { m.Files[0], m.Files[1] = m.Files[1], m.Files[0] }),
		"duplicate file":           mutate(func(m *Manifest) { m.Files[1] = m.Files[0] }),
		"envelope listed": mutate(func(m *Manifest) {
			m.Files = append(m.Files, FileEntry{Path: SignatureName, SHA256: strings.Repeat("c", 64)})
		}),
		"traversal file":    mutate(func(m *Manifest) { m.Files[1].Path = "policies/guardrail/../../etc/passwd" }),
		"upper-case sha256": mutate(func(m *Manifest) { m.Files[0].SHA256 = strings.Repeat("A", 64) }),
		"negative size":     mutate(func(m *Manifest) { m.Files[0].Size = -1 }),
		"files too large":   mutate(func(m *Manifest) { m.Files[0].Size, m.Files[1].Size = MaxExpandedBytes, 1 }),
		"secret ref scheme": mutate(func(m *Manifest) { m.SecretRefs[0].Ref = "env://X" }),
		"secret ref name":   mutate(func(m *Manifest) { m.SecretRefs[0].Ref = "secret://../x" }),
		"secret ref twice":  mutate(func(m *Manifest) { m.SecretRefs = append(m.SecretRefs, m.SecretRefs[0]) }),
		"secret value hex":  mutate(func(m *Manifest) { m.SecretRefs[0].ValueSHA256 = strings.Repeat("D", 64) }),
		"secret value size": mutate(func(m *Manifest) { m.SecretRefs[0].ValueSHA256 = strings.Repeat("d", 63) }),
		"product version":   mutate(func(m *Manifest) { m.EffectivePolicy.ProductVersion = "" }),
		"missing digest":    mutate(func(m *Manifest) { delete(m.EffectivePolicy.Digests, PlatformDarwin) }),
		"other platform": mutate(func(m *Manifest) {
			m.EffectivePolicy.Digests = map[string]string{PlatformLinux: testDigest, PlatformWindows: testDigest}
		}),
		"bad digest":       mutate(func(m *Manifest) { m.EffectivePolicy.Digests[PlatformLinux] = "sha256:abc" }),
		"warning code":     mutate(func(m *Manifest) { m.Warnings = []Warning{{Code: "Bad Code", Message: "x"}} }),
		"warning message":  mutate(func(m *Manifest) { m.Warnings = []Warning{{Code: "x", Message: ""}} }),
		"warning platform": mutate(func(m *Manifest) { m.Warnings = []Warning{{Code: "x", Platform: "plan9", Message: "x"}} }),
		"null files":       edit(`"files": [`, `"files": null, "x": [`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeManifest(raw); CodeOf(err) != CodeManifestInvalid {
				t.Fatalf("got %v, want %s", err, CodeManifestInvalid)
			} else if bytes.Contains([]byte(err.Error()), []byte("evil")) {
				t.Fatalf("error quotes a value: %v", err)
			}
		})
	}
}

func TestDecodeManifestAcceptsOperatorAndOptionalFields(t *testing.T) {
	m := validManifest()
	m.CreatedBy = `operator:CORP\admin`
	m.Parent, m.ChangeSummary, m.SecretRefs = "", "", nil
	m.RollbackOf = "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z20"
	m.MinProductVersion = "1.0.2-rc.1"
	m.Warnings = []Warning{{Code: WarnEntraGroupMacOS, Platform: PlatformDarwin, Subject: "S-1-12-1-1-2-3-4", Message: "does not reach"}}
	if _, err := DecodeManifest(marshal(t, m)); err != nil {
		t.Fatal(err)
	}
}
