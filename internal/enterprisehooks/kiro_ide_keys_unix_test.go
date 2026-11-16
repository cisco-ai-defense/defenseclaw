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

package enterprisehooks

import "testing"

// Every Kiro IDE install of a kind gets its own discovery key up to the
// number of candidates a kind has, and none is written past it.
func TestKiroIDEDiscoveryKeysAreBounded(t *testing.T) {
	older := KiroForm{Kind: KiroFormMachineIDE, Version: "1.0.150"}
	var many []KiroForm
	for i := 0; i < kiroIDEFormsPerKind+1; i++ {
		many = append(many, older)
	}
	versions := map[string]string{}
	PutUnixKiroIDEForms(many, versions, nil)
	if len(versions) != kiroIDEFormsPerKind || len(KiroIDEDiscoveryKeys()) != 2*kiroIDEFormsPerKind {
		t.Fatalf("bounded keys: versions=%v keys=%v", versions, KiroIDEDiscoveryKeys())
	}
	if got := len(kiroIDEProductCandidates("/home/alice")); got > kiroIDEFormsPerKind {
		t.Fatalf("%d IDE candidates, more than the %d installs a kind carries", got, kiroIDEFormsPerKind)
	}
}
