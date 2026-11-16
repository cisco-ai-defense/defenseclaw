// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// rel-1-0-6:GAP-0036: standalone Setup takes DEVICEGROUP= (any case, dashes
// ignored) next to TRUSTANCHORS= and hands it to the lifecycle, which pins
// the anchors it installs to that one device group.
func TestStandaloneSetupTakesTheDeviceGroupProperty(t *testing.T) {
	for _, property := range []string{"DEVICEGROUP=eng", "DeviceGroup=eng", "device-group=eng"} {
		opts, _, err := parseStandaloneEnterpriseSetupOptions([]string{"/ensure", `BUNDLE=C:\b\v7.dcbundle`, `TRUSTANCHORS=C:\b\a.json`, property})
		if err != nil || opts.DeviceGroup != "eng" || opts.TrustAnchors != `C:\b\a.json` {
			t.Fatalf("%s: device group %q, anchors %q, err %v", property, opts.DeviceGroup, opts.TrustAnchors, err)
		}
	}
}
