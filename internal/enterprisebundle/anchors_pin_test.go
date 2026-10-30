// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"bytes"
	"testing"
)

const pinFixture = `{"schema_version":1,"tenant_id":"acme","device_groups":%s,"min_version":3,"keys":[{"key_id":"k1","alg":"ed25519","public_key":"MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=","not_before":"2020-01-01T00:00:00Z","not_after":"2099-01-01T00:00:00Z","status":"active"}]}`

func pinInput(t *testing.T, groups string) (*Anchors, []byte) {
	t.Helper()
	raw := []byte(sprintfFixture(groups))
	a, err := DecodeAnchors(raw)
	if err != nil {
		t.Fatal(err)
	}
	return a, raw
}

func sprintfFixture(groups string) string {
	return string(bytes.Replace([]byte(pinFixture), []byte("%s"), []byte(groups), 1))
}

// PinDeviceGroup narrows the file to the one group this device is in: it
// keeps the tenant, the version floor and every key, never widens, and leaves
// a file that already names exactly that group untouched.
func TestPinDeviceGroup(t *testing.T) {
	for _, tc := range []struct {
		name, groups, pin string
		wantErr           bool
		wantSame          bool
	}{
		{"no groups", `[]`, "eng", false, false},
		{"several groups", `["eng","sales"]`, "eng", false, false},
		{"already pinned", `["eng"]`, "eng", false, true},
		{"group not listed", `["sales"]`, "eng", true, false},
		{"bad group name", `[]`, "-eng", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, raw := pinInput(t, tc.groups)
			pinned, out, err := PinDeviceGroup(a, raw, tc.pin)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v", err)
			}
			if tc.wantErr {
				if CodeOf(err) != CodeAnchorInvalid {
					t.Fatalf("code = %q", CodeOf(err))
				}
				return
			}
			if tc.wantSame != bytes.Equal(out, raw) {
				t.Fatalf("bytes kept = %v, want %v", bytes.Equal(out, raw), tc.wantSame)
			}
			again, err := DecodeAnchors(out)
			if err != nil || len(again.DeviceGroups) != 1 || again.DeviceGroups[0] != tc.pin ||
				again.TenantID != "acme" || again.MinVersion != 3 || len(again.Keys) != 1 || again.Keys[0].KeyID != "k1" {
				t.Fatalf("pinned anchors = %+v, %v", again, err)
			}
			if len(pinned.DeviceGroups) != 1 {
				t.Fatalf("returned anchors = %+v", pinned)
			}
		})
	}
}
