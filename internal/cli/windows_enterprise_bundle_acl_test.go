// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

func TestWindowsBundleCanonicalDescriptorsProtected(t *testing.T) {
	const sid = "S-1-5-80-1-2-3-4-5"
	for kind, sddl := range map[string]string{
		"BundleDirectory":         windowsBundleDirectorySDDL(sid),
		"BundleVersionDirectory":  windowsBundleVersionSDDL(sid, true),
		"BundleVersionFile":       windowsBundleVersionSDDL(sid, false),
		"BundleReceipt":           windowsBundleReceiptSDDL(sid),
		"AdminDirectory/receipts": windowsBundlePrivateSDDL(),
		"AdminFile":               windowsBundleAdminFileSDDL(),
	} {
		if !strings.Contains(sddl, "D:P(") {
			t.Errorf("%s has no protected DACL: %s", kind, sddl)
		}
		for _, ace := range strings.Split(sddl, "(")[1:] {
			flags := strings.SplitN(ace, ";", 3)
			if len(flags) < 3 || strings.Contains(flags[1], "ID") {
				t.Errorf("%s has an inherited or malformed ACE: %s", kind, ace)
			}
		}
	}
}
